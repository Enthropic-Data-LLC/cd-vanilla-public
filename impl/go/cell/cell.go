// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// Sealing and opening .cell documents — spec §4, §5, §10, §12.

// CellFormatVersion is the version this package writes.
const CellFormatVersion = "1.3"

// SupportedVersions, CanonicalVersions and AADVersions are held as sets on
// purpose. §12 warns that adding a version to the supported set while leaving an
// inline `version == "1.2"` test elsewhere silently drops canonicalization, or
// decrypts new cells with no AAD, with no error raised at any point.
var (
	SupportedVersions = map[string]bool{"1.0": true, "1.1": true, "1.2": true, "1.3": true}
	CanonicalVersions = map[string]bool{"1.2": true, "1.3": true}
	AADVersions       = map[string]bool{"1.1": true, "1.2": true, "1.3": true}
)

// SerializeHeader returns the bytes header_hash and header_sig cover (§4.1.1).
//
// v1.2/v1.3 canonicalize; v1.0/v1.1 keep the original insertion-ordered
// JSON.stringify form, which means those versions can only be verified from a
// header still in its on-disk key order — the reason ParseValue preserves it.
func SerializeHeader(header *Object, version string) ([]byte, error) {
	if CanonicalVersions[version] {
		return CanonicalBytes(header)
	}
	s, err := jsStringify(header)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// CellAAD returns the additional authenticated data for the payload (§4.4).
//
// The four fields fixed before encryption, in a fixed order, as an array.
// access_map and payload_hash are absent because they do not exist yet at
// encryption time — header_hash and header_sig cover those instead. Returns nil
// for versions that bind no AAD.
func CellAAD(header *Object, version string) ([]byte, error) {
	if !AADVersions[version] {
		return nil, nil
	}
	get := func(key string) Value {
		v, _ := header.Get(key)
		return v
	}
	meta := []Value{get("prev_hash"), get("threshold"), get("lifetime"), get("policy")}
	if version == "1.1" {
		s, err := jsStringify(meta)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return CanonicalBytes(meta)
}

// ─── Recipients ─────────────────────────────────────────────────────────────

// Recipient is one access-map entry to be created.
type Recipient struct {
	Method     string
	Label      string
	SPKI       string
	Passphrase string
}

// ECDHRecipient wraps for the holder of a P-256 public key (base64 SPKI).
func ECDHRecipient(spki, label string) Recipient {
	return Recipient{Method: "ecdh-p256", Label: label, SPKI: spki}
}

// KeyRecipient wraps for the holder of a KeyRecord.
func KeyRecipient(k *KeyRecord) Recipient {
	return Recipient{Method: "ecdh-p256", Label: k.Label, SPKI: k.SPKI()}
}

// PassphraseRecipient wraps under a passphrase.
func PassphraseRecipient(passphrase, label string) Recipient {
	if label == "" {
		label = "Passphrase"
	}
	return Recipient{Method: "pbkdf2", Label: label, Passphrase: passphrase}
}

func wrapEntry(r Recipient, keyMaterial []byte, shareIndex int) (*Object, error) {
	entry := NewObject()
	entry.Set("label", r.Label)
	entry.Set("method", r.Method)

	var wrapped *Object
	switch r.Method {
	case "ecdh-p256":
		if r.SPKI == "" {
			return nil, fmt.Errorf("%w: ecdh-p256 recipient needs an spki", ErrMalformed)
		}
		der, err := DecodeB64(r.SPKI, "spki")
		if err != nil {
			return nil, err
		}
		entry.Set("fingerprint", Fingerprint(der))
		if wrapped, err = ECDHWrapCEK(keyMaterial, r.SPKI, nil, nil); err != nil {
			return nil, err
		}
	case "pbkdf2":
		var err error
		if wrapped, err = PBKDF2WrapCEK(keyMaterial, r.Passphrase, nil); err != nil {
			return nil, err
		}
		// A passphrase has no public key, so §6.2 fingerprints the salt. It
		// identifies the entry, not the holder, and proves nothing about who
		// can open it.
		salt, err := DecodeB64(wrapped.GetString("salt"), "salt")
		if err != nil {
			return nil, err
		}
		entry.Set("fingerprint", Fingerprint(salt))
	default:
		return nil, fmt.Errorf("%w: unknown access method %q", ErrMalformed, r.Method)
	}

	// §6.4: on non-quorum cells the key is OMITTED, not written as null. The
	// choice is not cosmetic — canonicalization preserves an explicit null, so
	// the two forms hash differently. Both verify; they are not byte-identical.
	if shareIndex > 0 {
		entry.Set("share_index", float64(shareIndex))
	}
	entry.Set("wrapped_cek", wrapped)
	return entry, nil
}

// ─── Sealing ────────────────────────────────────────────────────────────────

// CreateOptions configures Create. The zero value seals a permanent, unsigned,
// single-recipient cell.
type CreateOptions struct {
	ContentType string
	Threshold   int
	Lifetime    *Object
	Policy      *Object
	PrevHash    string
	Meta        any
	Sender      *KeyRecord
	DocID       string
	CreatedAt   int64
}

// Create seals data into a v1.3 cell.
//
// Threshold > 1 splits the CEK into one Shamir share per recipient, of which
// that many are needed (§7). Sender adds a header_sig; note that its ABSENCE is
// undetectable to a reader (§4.1), so a signature proves authorship while no
// signature proves nothing at all.
func Create(data []byte, filename string, recipients []Recipient, opts CreateOptions) (*Object, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: a cell needs at least one recipient", ErrMalformed)
	}
	required := opts.Threshold
	if required < 1 {
		required = 1
	}
	if required > len(recipients) {
		required = len(recipients)
	}
	contentType := opts.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Manifest-prefixed plaintext (§5): filename, type and size live inside the
	// ciphertext, so an observer of the stored cell learns none of them.
	manifest := map[string]any{"filename": filename, "content_type": contentType, "size": len(data)}
	if opts.Meta != nil {
		manifest["meta"] = opts.Meta
	}
	var manifestBuf bytes.Buffer
	encoder := json.NewEncoder(&manifestBuf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	manifestBytes := bytes.TrimRight(manifestBuf.Bytes(), "\n")

	plaintext := make([]byte, 4+len(manifestBytes)+len(data))
	binary.LittleEndian.PutUint32(plaintext[:4], uint32(len(manifestBytes)))
	copy(plaintext[4:], manifestBytes)
	copy(plaintext[4+len(manifestBytes):], data)

	body, err := GzipCompress(plaintext)
	if err != nil {
		return nil, err
	}

	cek := make([]byte, CEKLength)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	defer wipe(cek)

	// Metadata is fixed before encryption precisely so it can be bound as AAD.
	threshold := NewObject()
	threshold.Set("required", float64(required))
	threshold.Set("of_total", float64(len(recipients)))

	lifetime := NormalizeLifetime(opts.Lifetime)
	if lifetime == nil {
		lifetime = PermanentLifetime()
	}
	policy := opts.Policy
	if policy == nil {
		policy = NewObject()
		policy.Set("copy_protection", "standard")
		policy.Set("watermark_mode", "none")
		policy.Set("created_on_origin", nil)
		policy.Set("origin_sig", nil)
	}

	header := NewObject()
	if opts.PrevHash == "" {
		header.Set("prev_hash", nil)
	} else {
		header.Set("prev_hash", opts.PrevHash)
	}
	header.Set("threshold", threshold)
	header.Set("lifetime", lifetime)
	header.Set("policy", policy)

	aad, err := CellAAD(header, CellFormatVersion)
	if err != nil {
		return nil, err
	}
	iv, ciphertext, err := AESGCMEncrypt(cek, body, aad, nil)
	if err != nil {
		return nil, err
	}

	accessMap := make([]Value, 0, len(recipients))
	if required > 1 {
		shares, err := SplitSecret(cek, len(recipients), required, nil)
		if err != nil {
			return nil, err
		}
		for i, r := range recipients {
			entry, err := wrapEntry(r, shares[i].Data, i+1)
			if err != nil {
				return nil, err
			}
			accessMap = append(accessMap, entry)
		}
	} else {
		for _, r := range recipients {
			entry, err := wrapEntry(r, cek, 0)
			if err != nil {
				return nil, err
			}
			accessMap = append(accessMap, entry)
		}
	}

	header.Set("access_map", accessMap)
	header.Set("payload_hash", EncodeB64(sha256Sum(ciphertext)))

	headerBytes, err := SerializeHeader(header, CellFormatVersion)
	if err != nil {
		return nil, err
	}

	docID := opts.DocID
	if docID == "" {
		if docID, err = ULID(0, nil); err != nil {
			return nil, err
		}
	}
	createdAt := opts.CreatedAt
	if createdAt == 0 {
		createdAt = time.Now().Unix()
	}

	payload := NewObject()
	payload.Set("alg", "AES-256-GCM")
	payload.Set("encoding", "base64+gzip")
	payload.Set("iv", EncodeB64(iv))
	payload.Set("ciphertext", EncodeB64(ciphertext))

	out := NewObject()
	out.Set("version", CellFormatVersion)
	out.Set("doc_id", docID)
	out.Set("created_at", float64(createdAt))
	out.Set("header", header)
	out.Set("header_hash", EncodeB64(sha256Sum(headerBytes)))
	out.Set("header_sig", nil)
	out.Set("header_sig_by", nil)
	out.Set("header_sig_key", nil)
	out.Set("payload", payload)

	if opts.Sender != nil {
		if opts.Sender.Private == nil {
			return nil, fmt.Errorf("%w: signing requires a key record with a private key", ErrMalformed)
		}
		sig, err := ECDSASign(opts.Sender.Private, headerBytes)
		if err != nil {
			return nil, err
		}
		out.Set("header_sig", EncodeB64(sig))
		out.Set("header_sig_by", opts.Sender.Fingerprint())
		out.Set("header_sig_key", opts.Sender.SPKI())
	}
	return out, nil
}

// ─── Key-free verification — spec §10 steps 1-3 ─────────────────────────────

// VerifyResult is the outcome of the checks that need no key material at all.
type VerifyResult struct {
	Version           string
	PayloadHashOK     bool
	Signed            bool
	SignerFingerprint string // real fingerprint of header_sig_key — the only trustworthy identity
	ClaimedSigner     string // header_sig_by: self-asserted, never trusted alone (§4.1)
}

// Verify checks a cell's audit chain without opening it (§10).
//
// That this is possible with no key is the property being demonstrated: any
// third party can confirm a cell has not been altered since it was sealed.
//
// A clean return does NOT establish authorship. An attacker can strip
// header_sig entirely and the result is indistinguishable from a cell that was
// never signed, so pass expectedSigner (a fingerprint learned out of band)
// whenever authorship matters.
func Verify(c *Object, expectedSigner string) (*VerifyResult, error) {
	version, err := versionOf(c)
	if err != nil {
		return nil, err
	}
	header := c.GetObject("header")
	if header == nil {
		return nil, fmt.Errorf("%w: missing header", ErrMalformed)
	}

	// §4.1: absence of header_hash is a rejection, not licence to skip the
	// checks. Guarding this block on its own presence would mean deleting one
	// field disables the header, ciphertext and signature checks together.
	headerHash := c.GetString("header_hash")
	if headerHash == "" {
		return nil, fmt.Errorf("%w: header_hash is missing", ErrIntegrity)
	}
	headerBytes, err := SerializeHeader(header, version)
	if err != nil {
		return nil, err
	}
	if EncodeB64(sha256Sum(headerBytes)) != headerHash {
		return nil, fmt.Errorf("%w: header may be tampered", ErrIntegrity)
	}

	result := &VerifyResult{Version: version, ClaimedSigner: c.GetString("header_sig_by")}

	payload := c.GetObject("payload")
	if payload == nil {
		payload = c.GetObject("encrypted_body")
	}
	ctB64 := ""
	if payload != nil {
		if ctB64 = payload.GetString("ciphertext"); ctB64 == "" {
			ctB64 = payload.GetString("ct")
		}
	}
	if expected := header.GetString("payload_hash"); expected != "" {
		if ctB64 == "" {
			return nil, fmt.Errorf("%w: header commits to a ciphertext that is absent", ErrMalformed)
		}
		ct, err := DecodeB64(ctB64, "ciphertext")
		if err != nil {
			return nil, err
		}
		if EncodeB64(sha256Sum(ct)) != expected {
			return nil, fmt.Errorf("%w: ciphertext may be tampered", ErrIntegrity)
		}
		result.PayloadHashOK = true
	}

	sigB64, keyB64 := c.GetString("header_sig"), c.GetString("header_sig_key")
	if sigB64 != "" && keyB64 != "" {
		spkiDER, err := DecodeB64(keyB64, "header_sig_key")
		if err != nil {
			return nil, err
		}
		public, err := ParseSPKIForECDSA(spkiDER)
		if err != nil {
			return nil, err
		}
		rawSig, err := DecodeB64(sigB64, "header_sig")
		if err != nil {
			return nil, err
		}
		if err := ECDSAVerify(public, rawSig, headerBytes); err != nil {
			return nil, err
		}
		result.Signed = true
		// Trust anchors on the key's real fingerprint, never on header_sig_by,
		// which the signer writes about themselves and can say anything.
		result.SignerFingerprint = Fingerprint(spkiDER)
	}

	if expectedSigner != "" {
		if !result.Signed {
			return nil, fmt.Errorf("%w: expected a cell signed by %s, but it carries no signature "+
				"(removal is undetectable — see spec §4.1)", ErrSignature, expectedSigner)
		}
		if result.SignerFingerprint != expectedSigner {
			return nil, fmt.Errorf("%w: cell is signed by %s, not the expected %s",
				ErrSignature, result.SignerFingerprint, expectedSigner)
		}
	}
	return result, nil
}

// ─── Opening ────────────────────────────────────────────────────────────────

// OpenResult is a successfully opened cell.
type OpenResult struct {
	Data              []byte
	Filename          string
	ContentType       string
	Meta              any
	UsedRecipient     string
	Signed            bool
	SignerFingerprint string
	ClaimedSigner     string
	Lifetime          *Lifetime
}

// OpenOptions supplies key material and policy for Open. The zero value
// enforces the advisory gates and requires no particular signer.
type OpenOptions struct {
	Keys        []*KeyRecord
	Passphrases []string
	// PRFOutputs maps a base64 credential_id to its 32-byte WebAuthn PRF
	// output. Entries with no supplied output are skipped, which is conforming.
	PRFOutputs map[string][]byte
	// Now overrides the clock for the advisory gates; zero means time.Now().
	Now int64
	// IgnoreAdvisory skips the §8.1 gates. This is not a bypass of a security
	// control: those gates are advisory BY SPECIFICATION, unenforceable against
	// anyone holding a key, and this field documents that honestly rather than
	// pretending otherwise.
	IgnoreAdvisory bool
	// ExpectedSigner is a fingerprint learned out of band that the cell must be
	// signed by. Leave empty only when authorship does not matter.
	ExpectedSigner string
}

// Open opens a cell and returns its plaintext.
//
// Verification order is normative (§10) and this follows it: the advisory
// lifetime gates, then header_hash, payload_hash and header_sig — all of which
// need no key — and only then any access-map work. An opener that unwraps first
// performs a decryption under a header it has not authenticated, and makes the
// user pay a 600,000-iteration PBKDF2 derivation or a hardware touch on behalf
// of a cell it is about to reject.
func Open(c *Object, opts OpenOptions) (*OpenResult, error) {
	version, err := versionOf(c)
	if err != nil {
		return nil, err
	}
	isLegacy := c.GetString("version") == "" && c.GetString("cd_version") != ""

	now := opts.Now
	if now == 0 {
		now = time.Now().Unix()
	}

	// Step 0: advisory gates. Cheapest of all, and they need nothing but the clock.
	lifetime := ReadLifetime(c.GetObject("header").GetObject("lifetime"))
	if lifetime != nil && !opts.IgnoreAdvisory {
		if lifetime.Type == "timed_release" && lifetime.ReleaseAt > now {
			return nil, fmt.Errorf("%w: timed release — unlocks %s", ErrLifetime, formatTS(lifetime.ReleaseAt))
		}
		if lifetime.RetainUntil != 0 && lifetime.RetainUntil < now {
			return nil, fmt.Errorf("%w: retention period ended %s", ErrLifetime, formatTS(lifetime.RetainUntil))
		}
	}
	// Note disposal is never consulted: a passed disposal date describes the
	// operator's retention schedule, not the recipient's permission (§8.2).

	// Steps 1-3: integrity and authenticity, before any key material is touched.
	var verified *VerifyResult
	if !isLegacy {
		if verified, err = Verify(c, opts.ExpectedSigner); err != nil {
			return nil, err
		}
	} else if opts.ExpectedSigner != "" {
		return nil, fmt.Errorf("%w: legacy v2.x cells carry no signature to check", ErrSignature)
	}

	header := c.GetObject("header")
	if header == nil {
		header = NewObject()
	}
	accessMap := header.GetArray("access_map")
	if accessMap == nil {
		accessMap = c.GetArray("recipients")
	}
	payload := c.GetObject("payload")
	if payload == nil {
		payload = c.GetObject("encrypted_body")
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: payload is missing", ErrMalformed)
	}
	ivB64 := payload.GetString("iv")
	ctB64 := payload.GetString("ciphertext")
	if ctB64 == "" {
		ctB64 = payload.GetString("ct")
	}
	if ivB64 == "" || ctB64 == "" {
		return nil, fmt.Errorf("%w: payload is missing iv or ciphertext", ErrMalformed)
	}
	required := header.GetObject("threshold").GetInt("required", 1)
	if required < 1 {
		required = 1
	}

	// Step 4: recover the CEK.
	var cek []byte
	usedRecipient := ""
	if required > 1 {
		shares := make([]Share, 0, required)
		for index, entryValue := range accessMap {
			entry, ok := entryValue.(*Object)
			if !ok {
				continue
			}
			material := tryUnwrap(entry, opts)
			if material == nil {
				continue // a wrong key here says nothing about the next entry
			}
			x := entry.GetInt("share_index", index+1)
			shares = append(shares, Share{X: x, Data: material})
			if len(shares) >= required {
				break
			}
		}
		if len(shares) < required {
			return nil, fmt.Errorf("%w: need %d, unlocked %d", ErrQuorumNotMet, required, len(shares))
		}
		if cek, err = CombineShares(shares); err != nil {
			return nil, err
		}
		usedRecipient = fmt.Sprintf("%d-of-%d quorum", len(shares), len(accessMap))
	} else {
		for _, entryValue := range accessMap {
			entry, ok := entryValue.(*Object)
			if !ok {
				continue
			}
			if material := tryUnwrap(entry, opts); material != nil {
				cek = material
				usedRecipient = entry.GetString("label")
				break
			}
		}
		if cek == nil {
			return nil, fmt.Errorf("%w: check your key method and try again", ErrNoMatchingKey)
		}
	}
	defer wipe(cek)

	var aad []byte
	if !isLegacy {
		if aad, err = CellAAD(header, version); err != nil {
			return nil, err
		}
	}
	iv, err := DecodeB64(ivB64, "iv")
	if err != nil {
		return nil, err
	}
	ct, err := DecodeB64(ctB64, "ciphertext")
	if err != nil {
		return nil, err
	}
	compressed, err := AESGCMDecrypt(cek, iv, ct, aad)
	if err != nil {
		return nil, err
	}
	plain, err := GzipDecompress(compressed)
	if err != nil {
		return nil, err
	}

	result := &OpenResult{UsedRecipient: usedRecipient, Lifetime: lifetime}
	if verified != nil {
		result.Signed = verified.Signed
		result.SignerFingerprint = verified.SignerFingerprint
		result.ClaimedSigner = verified.ClaimedSigner
	}

	// Manifest-prefixed payload (§5), or a legacy cell with plaintext metadata.
	if c.Has("original_filename") {
		result.Filename = orDefault(c.GetString("original_filename"), c.GetString("doc_id"), "decrypted")
		result.ContentType = orDefault(c.GetString("content_type"), "application/octet-stream")
		result.Data = plain
		return result, nil
	}
	if len(plain) < 4 {
		return nil, fmt.Errorf("%w: payload too short to hold a manifest length", ErrMalformed)
	}
	manifestLen := int(binary.LittleEndian.Uint32(plain[:4]))
	if manifestLen < 0 || 4+manifestLen > len(plain) {
		return nil, fmt.Errorf("%w: manifest length runs past the plaintext", ErrMalformed)
	}
	manifestValue, err := ParseValue(plain[4 : 4+manifestLen])
	if err != nil {
		return nil, fmt.Errorf("%w: manifest is not valid JSON", ErrMalformed)
	}
	manifest, ok := manifestValue.(*Object)
	if !ok {
		return nil, fmt.Errorf("%w: manifest is not a JSON object", ErrMalformed)
	}
	result.Filename = orDefault(manifest.GetString("filename"), c.GetString("doc_id"), "decrypted")
	result.ContentType = orDefault(manifest.GetString("content_type"), "application/octet-stream")
	if meta, ok := manifest.Get("meta"); ok {
		result.Meta = meta
	}
	result.Data = plain[4+manifestLen:]
	return result, nil
}

// tryUnwrap attempts one access-map entry with whatever material was supplied,
// returning nil rather than an error: a wrong key for this entry says nothing
// about the next one.
func tryUnwrap(entry *Object, opts OpenOptions) []byte {
	wrapped := entry.GetObject("wrapped_cek")
	if wrapped == nil {
		return nil
	}
	switch entry.GetString("method") {
	case "ecdh-p256":
		// Match by fingerprint first so a cell addressed to ten recipients does
		// not run ten ECDH exchanges. Fall back to trying everything, because
		// the fingerprint is a hint and a cell may omit or mangle it.
		fingerprint := entry.GetString("fingerprint")
		var candidates []*KeyRecord
		for _, k := range opts.Keys {
			if k.Private == nil {
				continue
			}
			if fingerprint != "" && k.Fingerprint() == fingerprint {
				candidates = []*KeyRecord{k}
				break
			}
			candidates = append(candidates, k)
		}
		for _, k := range candidates {
			priv, err := k.ECDH()
			if err != nil {
				continue
			}
			if material, err := ECDHUnwrapCEK(wrapped, priv); err == nil {
				return material
			}
		}
	case "pbkdf2":
		for _, passphrase := range opts.Passphrases {
			if material, err := PBKDF2UnwrapCEK(wrapped, passphrase); err == nil {
				return material
			}
		}
	case "yubikey-prf":
		output, ok := opts.PRFOutputs[wrapped.GetString("credential_id")]
		if !ok {
			return nil // no token here; skipping is conforming
		}
		if material, err := PRFUnwrapCEK(wrapped, output); err == nil {
			return material
		}
	}
	return nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// ParseCell decodes a .cell document, preserving key order.
func ParseCell(data []byte) (*Object, error) {
	value, err := ParseValue(data)
	if err != nil {
		return nil, err
	}
	c, ok := value.(*Object)
	if !ok {
		return nil, fmt.Errorf("%w: cell is not a JSON object", ErrMalformed)
	}
	return c, nil
}

// MarshalCell renders a cell as indented JSON.
func MarshalCell(c *Object) ([]byte, error) {
	var b bytes.Buffer
	if err := writeIndented(&b, c, ""); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

func writeIndented(b *bytes.Buffer, v Value, indent string) error {
	inner := indent + "  "
	switch value := v.(type) {
	case *Object:
		if len(value.keys) == 0 {
			b.WriteString("{}")
			return nil
		}
		b.WriteString("{\n")
		for i, key := range value.keys {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			b.WriteString(jsString(key))
			b.WriteString(": ")
			if err := writeIndented(b, value.values[key], inner); err != nil {
				return err
			}
		}
		b.WriteString("\n" + indent + "}")
		return nil
	case []Value:
		if len(value) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[\n")
		for i, item := range value {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			if err := writeIndented(b, item, inner); err != nil {
				return err
			}
		}
		b.WriteString("\n" + indent + "]")
		return nil
	default:
		s, err := Canonicalize(v)
		if err != nil {
			return err
		}
		b.WriteString(s)
		return nil
	}
}

func versionOf(c *Object) (string, error) {
	if version := c.GetString("version"); version != "" {
		if !SupportedVersions[version] {
			return "", fmt.Errorf("%w %q — update the app to open this cell", ErrUnsupportedVersion, version)
		}
		return version, nil
	}
	if legacy := c.GetString("cd_version"); legacy != "" {
		return legacy, nil // legacy v2.x (§12)
	}
	return "", fmt.Errorf("%w: cell has no version field", ErrUnsupportedVersion)
}

func formatTS(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func orDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// wipe is best-effort zeroization. Go's garbage collector may have copied the
// bytes and will not say so; this overwrites what we can reach and no more.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
