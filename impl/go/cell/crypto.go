// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Cryptographic primitives — spec §6, §14.
//
// Everything here is standard library. Go 1.24 moved HKDF and PBKDF2 into
// crypto/, so the only primitive that needed writing is AES-KW (see aeskw.go).

const (
	// HKDFInfo is the fixed info string for the ECDH key-wrap derivation (§6.1).
	HKDFInfo = "cellular-defense-cek-wrap-v1"
	// PBKDF2Iterations is the iteration count for passphrase entries (§6.2).
	PBKDF2Iterations = 600000
	// PBKDF2MaxIterations caps the count read from a file: header_hash is unkeyed, so an edited entry could otherwise stall the opener.
	PBKDF2MaxIterations = 10000000
	// IVLength is the AES-GCM nonce length in bytes.
	IVLength = 12
	// CEKLength is the content encryption key length in bytes.
	CEKLength = 32
	// MaxDecompressed caps gzip expansion. The spec sets no limit; the reference
	// caps at 2 GiB. A few KB of crafted gzip expands to many GB, and an opener
	// that streams it into memory is a denial of service needing no key at all.
	MaxDecompressed = 2 * 1024 * 1024 * 1024
)

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// Fingerprint is SHA-256(SPKI)[:8] as 16 lowercase hex characters — spec §13.3.
func Fingerprint(spkiDER []byte) string {
	return hex.EncodeToString(sha256Sum(spkiDER))[:16]
}

// ─── Binary field encoding — spec §4.0 ──────────────────────────────────────

// EncodeB64 emits standard base64 with padding, the only form this library
// writes. It is not base64url: atob() throws on '-' and '_', so a base64url
// cell is unparseable by the reference rather than merely non-canonical.
func EncodeB64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeB64 accepts standard base64 and, per §4.0's SHOULD, tolerates the
// base64url alphabet and missing padding on input.
func DecodeB64(s string, field string) ([]byte, error) {
	normalized := make([]byte, 0, len(s)+3)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-':
			normalized = append(normalized, '+')
		case '_':
			normalized = append(normalized, '/')
		default:
			normalized = append(normalized, s[i])
		}
	}
	for len(normalized)%4 != 0 {
		normalized = append(normalized, '=')
	}
	out, err := base64.StdEncoding.DecodeString(string(normalized))
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not valid base64: %v", ErrMalformed, field, err)
	}
	return out, nil
}

// ─── Compression — spec §5 ──────────────────────────────────────────────────

// GzipCompress gzips data with a zeroed mtime.
//
// The reference uses CompressionStream('gzip'), whose output is not
// byte-identical to any particular zlib configuration and need not be: the
// format commits to the ciphertext, and gzip framing is decided before
// encryption. Two conforming implementations sealing the same file produce
// different bytes for this reason alone and both are correct.
func GzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GzipDecompress decompresses exactly one gzip member, refusing to exceed
// MaxDecompressed. Nothing may follow the member: not a second member, not
// trailing bytes. Implementations once disagreed on both (some joined members,
// some read only the first; some ignored trailing bytes, some refused), so one
// file opened as different documents in different programs.
func GzipDecompress(data []byte) ([]byte, error) {
	// A *bytes.Reader is an io.ByteReader, so gzip reads from it directly and
	// never past the trailer: whatever is left in src afterwards follows the member.
	src := bytes.NewReader(data)
	reader, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not a valid gzip stream: %v", ErrMalformed, err)
	}
	defer reader.Close()
	reader.Multistream(false)
	// One byte over the cap, so a stream that is exactly at the limit still
	// reads and anything larger is detected rather than silently truncated.
	out, err := io.ReadAll(io.LimitReader(reader, MaxDecompressed+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(out) > MaxDecompressed {
		return nil, fmt.Errorf("%w: decompressed size exceeds safety limit", ErrMalformed)
	}
	if src.Len() != 0 {
		return nil, fmt.Errorf("%w: data after the end of the gzip member — refusing", ErrMalformed)
	}
	return out, nil
}

// ─── Content encryption — AES-256-GCM, spec §4.3 ────────────────────────────

// AESGCMEncrypt encrypts with AES-256-GCM, returning (iv, ciphertext||tag).
// The 128-bit tag is appended to the ciphertext, matching WebCrypto.
func AESGCMEncrypt(cek, plaintext, aad, iv []byte) ([]byte, []byte, error) {
	if len(cek) != CEKLength {
		return nil, nil, fmt.Errorf("%w: CEK must be %d bytes, got %d", ErrMalformed, CEKLength, len(cek))
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	if iv == nil {
		iv = make([]byte, IVLength)
		if _, err := rand.Read(iv); err != nil {
			return nil, nil, err
		}
	}
	return iv, aead.Seal(nil, iv, plaintext, aad), nil
}

// AESGCMDecrypt decrypts and verifies. A tag failure here is equally an AAD
// mismatch: the two are indistinguishable by design (§4.4).
func AESGCMDecrypt(cek, iv, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: IV is not %d bytes", ErrDecryption, aead.NonceSize())
	}
	plaintext, err := aead.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: the ciphertext or the AAD-bound metadata "+
			"(prev_hash/threshold/lifetime/policy) does not match what was sealed", ErrDecryption)
	}
	return plaintext, nil
}

// ─── CEK wrapping — ECDH P-256 → HKDF-SHA256 → AES-KW, spec §6.1 ────────────

func hkdfWrapKey(sharedSecret, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, sharedSecret, salt, HKDFInfo, 32)
}

// ECDHWrapCEK wraps key material for one ECDH recipient. A fresh ephemeral
// keypair per recipient per cell is what gives the format its per-cell forward
// secrecy; ephemeral and hkdfSalt are injectable only so vectors can be pinned.
func ECDHWrapCEK(keyMaterial []byte, recipientSPKI string, ephemeral *ecdh.PrivateKey, hkdfSalt []byte) (*Object, error) {
	spkiDER, err := DecodeB64(recipientSPKI, "spki")
	if err != nil {
		return nil, err
	}
	recipient, err := ParseSPKI(spkiDER)
	if err != nil {
		return nil, err
	}
	if ephemeral == nil {
		if ephemeral, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	if hkdfSalt == nil {
		hkdfSalt = make([]byte, 32)
		if _, err := rand.Read(hkdfSalt); err != nil {
			return nil, err
		}
	}

	// WebCrypto's deriveBits(..., 256) on P-256 is the X coordinate of the
	// shared point, which is exactly what ECDH() returns. Neither side applies
	// a KDF at this step — HKDF is the next line, not implied here.
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %v", ErrMalformed, err)
	}
	wrappingKey, err := hkdfWrapKey(shared, hkdfSalt)
	if err != nil {
		return nil, err
	}
	wrapped, err := AESKeyWrap(wrappingKey, keyMaterial)
	if err != nil {
		return nil, err
	}

	ephSPKI, err := x509.MarshalPKIXPublicKey(ecdhPublicToECDSA(ephemeral.PublicKey()))
	if err != nil {
		return nil, err
	}
	out := NewObject()
	out.Set("eph_spki", EncodeB64(ephSPKI))
	out.Set("hkdf_salt", EncodeB64(hkdfSalt))
	out.Set("ct", EncodeB64(wrapped))
	return out, nil
}

// ECDHUnwrapCEK unwraps an ECDH entry.
//
// An entry with no hkdf_salt is a pre-spec legacy v2.0 cell, whose wrapping key
// is the raw ECDH output truncated to 32 bytes with no HKDF at all (§12). No
// conforming writer may produce that shape.
func ECDHUnwrapCEK(wrapped *Object, private *ecdh.PrivateKey) ([]byte, error) {
	ephDER, err := DecodeB64(wrapped.GetString("eph_spki"), "eph_spki")
	if err != nil {
		return nil, err
	}
	eph, err := ParseSPKI(ephDER)
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(eph)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH failed: %v", ErrMalformed, err)
	}

	var wrappingKey []byte
	if salt := wrapped.GetString("hkdf_salt"); salt != "" {
		saltBytes, err := DecodeB64(salt, "hkdf_salt")
		if err != nil {
			return nil, err
		}
		if wrappingKey, err = hkdfWrapKey(shared, saltBytes); err != nil {
			return nil, err
		}
	} else {
		wrappingKey = shared[:32]
	}

	ct, err := DecodeB64(wrapped.GetString("ct"), "ct")
	if err != nil {
		return nil, err
	}
	return AESKeyUnwrap(wrappingKey, ct)
}

// ─── CEK wrapping — PBKDF2, spec §6.2 ───────────────────────────────────────

// PBKDF2WrapCEK wraps key material under a passphrase.
func PBKDF2WrapCEK(keyMaterial []byte, passphrase string, salt []byte) (*Object, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	wrappingKey, err := derivePassphraseKey(passphrase, salt, PBKDF2Iterations)
	if err != nil {
		return nil, err
	}
	wrapped, err := AESKeyWrap(wrappingKey, keyMaterial)
	if err != nil {
		return nil, err
	}
	out := NewObject()
	out.Set("salt", EncodeB64(salt))
	out.Set("iterations", float64(PBKDF2Iterations))
	out.Set("ct", EncodeB64(wrapped))
	return out, nil
}

// jsonInt reads a JSON number with an integral value, as JavaScript's
// Number.isInteger does: 65536.0 is 65536; 1.5, true and "5" are not integers.
// Every implementation reads entry parameters this way, so they agree on which
// entries are tried and on what each one costs.
func jsonInt(v Value) (int64, bool) {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// PBKDF2IterationCount reads an entry's iteration count: absent, null or 0
// means the default; anything else must be a whole number in 1…10,000,000.
func PBKDF2IterationCount(wrapped *Object) (int, error) {
	v, ok := wrapped.Get("iterations")
	if !ok || v == nil {
		return PBKDF2Iterations, nil
	}
	n, isInt := jsonInt(v)
	if isInt && n == 0 {
		return PBKDF2Iterations, nil
	}
	if !isInt || n < 1 || n > PBKDF2MaxIterations {
		return 0, fmt.Errorf("%w: PBKDF2 iteration count out of range — refusing", ErrMalformed)
	}
	return int(n), nil
}

// PBKDF2UnwrapCEK unwraps a passphrase entry.
func PBKDF2UnwrapCEK(wrapped *Object, passphrase string) ([]byte, error) {
	salt, err := DecodeB64(wrapped.GetString("salt"), "salt")
	if err != nil {
		return nil, err
	}
	iterations, err := PBKDF2IterationCount(wrapped)
	if err != nil {
		return nil, err
	}
	wrappingKey, err := derivePassphraseKey(passphrase, salt, iterations)
	if err != nil {
		return nil, err
	}
	ct, err := DecodeB64(wrapped.GetString("ct"), "ct")
	if err != nil {
		return nil, err
	}
	return AESKeyUnwrap(wrappingKey, ct)
}

// derivePassphraseKey runs PBKDF2-HMAC-SHA256 over the UTF-8 bytes of the
// passphrase, with no Unicode normalization — WebCrypto has no opinion about
// text encoding and the reference feeds it TextEncoder().encode(passphrase).
// Composed and decomposed accents are therefore two different passphrases, on
// every implementation.
func derivePassphraseKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32)
}

// ─── CEK wrapping — WebAuthn/FIDO2 PRF, spec §6.3 ───────────────────────────

// PRFUnwrapCEK unwraps under a 32-byte WebAuthn PRF output used directly as the
// AES-KW key.
//
// This library cannot obtain a PRF output: the hmac-secret extension is
// reachable only through WebAuthn, in a browser, with the token present. A
// non-browser implementation can handle these entries only when something else
// supplies the 32 bytes. Openers that cannot are conforming — they skip such
// entries, as Open does.
func PRFUnwrapCEK(wrapped *Object, prfOutput []byte) ([]byte, error) {
	if len(prfOutput) != 32 {
		return nil, fmt.Errorf("%w: PRF output must be 32 bytes, got %d", ErrMalformed, len(prfOutput))
	}
	ct, err := DecodeB64(wrapped.GetString("ct"), "ct")
	if err != nil {
		return nil, err
	}
	return AESKeyUnwrap(prfOutput, ct)
}

// ─── Key encoding and ECDSA — spec §4.1, §13 ────────────────────────────────

// ParseSPKI parses a DER SubjectPublicKeyInfo and requires P-256.
func ParseSPKI(der []byte) (*ecdh.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid SPKI public key: %v", ErrMalformed, err)
	}
	ecdsaKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: public key is not P-256", ErrMalformed)
	}
	return ecdsaKey.ECDH()
}

// ParseSPKIForECDSA parses a DER SPKI as an ECDSA verification key. The same
// P-256 point serves both roles: §4.1 re-imports the ECDH key with ECDSA usage.
func ParseSPKIForECDSA(der []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid SPKI public key: %v", ErrMalformed, err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: public key is not P-256", ErrMalformed)
	}
	return key, nil
}

// ParsePKCS8 parses a DER PKCS#8 private key and requires P-256.
func ParsePKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid PKCS#8 private key: %v", ErrMalformed, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: private key is not P-256", ErrMalformed)
	}
	return key, nil
}

func ecdhPublicToECDSA(pub *ecdh.PublicKey) *ecdsa.PublicKey {
	raw := pub.Bytes() // uncompressed point: 0x04 || X || Y
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:]),
	}
}

// ECDSASign signs data with ECDSA-SHA256, returning raw r||s.
//
// Spec §4.1 names this the single most likely point of failure outside a
// browser, and it is: Go's ecdsa.SignASN1, OpenSSL, Java and python-cryptography
// all produce DER by default, while WebCrypto produces and expects the raw
// 64-byte IEEE P1363 form. The two are never interchangeable.
func ECDSASign(private *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// ECDSAVerify verifies a raw 64-byte r||s header_sig. A DER signature is
// refused outright rather than being decoded as a courtesy: accepting DER here
// would interoperate with nothing and hide the bug until a browser saw the cell.
func ECDSAVerify(public *ecdsa.PublicKey, rawSig, data []byte) error {
	return ecdsaVerifyNamed(public, rawSig, data, "header_sig", ErrSignature)
}

// ECDSAVerifySender verifies the v1.4 inner sender.sig (spec §4.5) — the same
// check as ECDSAVerify, but reported through ErrSenderSignature rather than
// ErrSignature: a v1.4 cell carries no header_sig at all, and before this
// split a failure here was reported as "header signature invalid", which sent
// readers to the wrong field name and the wrong spec section.
func ECDSAVerifySender(public *ecdsa.PublicKey, rawSig, data []byte) error {
	return ecdsaVerifyNamed(public, rawSig, data, "sender.sig", ErrSenderSignature)
}

func ecdsaVerifyNamed(public *ecdsa.PublicKey, rawSig, data []byte, field string, sentinel error) error {
	if len(rawSig) != 64 {
		return fmt.Errorf("%w: %s must be 64 bytes of raw r||s (IEEE P1363), got %d; "+
			"a DER-encoded signature is not accepted (spec §4.1)", ErrMalformed, field, len(rawSig))
	}
	digest := sha256.Sum256(data)
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	if !ecdsa.Verify(public, digest[:], r, s) {
		if sentinel == ErrSenderSignature {
			return senderSignatureError("sender signature invalid: cell may be forged")
		}
		return fmt.Errorf("%w: cell may be forged", sentinel)
	}
	return nil
}

// ─── CEK wrapping — Argon2id, spec §6.5 (v1.4) ──────────────────────────────

// Argon2Defaults are written by default: RFC 9106 §4's second recommended option.
var Argon2Defaults = [3]int{65536, 3, 4} // m (KiB), t, p

const (
	argon2MMin        = 19456
	argon2MMax        = 1048576
	argon2OnePassMinM = 47104
)

// Argon2Check refuses parameters outside the bounds of §6.5, exactly as the
// reference does: below the floor the passphrase is barely protected; above the
// ceiling a hostile cell can exhaust the opener's memory or time.
func Argon2Check(m, t, p int) error {
	if m < argon2MMin || m > argon2MMax || t < 1 || t > 16 || p < 1 || p > 16 {
		return fmt.Errorf("%w: Argon2id parameters out of range — refusing (§6.5)", ErrMalformed)
	}
	if t == 1 && m < argon2OnePassMinM {
		return fmt.Errorf("%w: Argon2id with one pass needs at least 46 MiB — refusing (§6.5)", ErrMalformed)
	}
	return nil
}

// argon2Key is Argon2id v0x13, 32-byte tag, over the UTF-8 of the passphrase's
// NFC form. Unlike PBKDF2 entries (§6.2), v1.4 normalizes: a passphrase typed
// with a composed é on one machine and a decomposed é on another is one
// passphrase.
func argon2Key(passphrase string, salt []byte, m, t, p int) []byte {
	return argon2.IDKey([]byte(norm.NFC.String(passphrase)), salt, uint32(t), uint32(m), uint8(p), 32)
}

// Argon2idWrapCEK wraps key material under an Argon2id-derived key. params is
// (m, t, p) or nil for the defaults.
func Argon2idWrapCEK(keyMaterial []byte, passphrase string, params *[3]int, salt []byte) (*Object, error) {
	pr := Argon2Defaults
	if params != nil {
		pr = *params
	}
	if err := Argon2Check(pr[0], pr[1], pr[2]); err != nil {
		return nil, err
	}
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	wrapped, err := AESKeyWrap(argon2Key(passphrase, salt, pr[0], pr[1], pr[2]), keyMaterial)
	if err != nil {
		return nil, err
	}
	out := NewObject()
	out.Set("salt", EncodeB64(salt))
	out.Set("m", float64(pr[0]))
	out.Set("t", float64(pr[1]))
	out.Set("p", float64(pr[2]))
	out.Set("ct", EncodeB64(wrapped))
	return out, nil
}

// Argon2Params reads and checks an entry's m, t and p (§6.5).
func Argon2Params(wrapped *Object) (m, t, p int, err error) {
	var vals [3]int
	for i, k := range []string{"m", "t", "p"} {
		v, _ := wrapped.Get(k)
		n, ok := jsonInt(v)
		if !ok || n < 0 || n > math.MaxInt32 {
			return 0, 0, 0, fmt.Errorf("%w: Argon2id parameters out of range — refusing (§6.5)", ErrMalformed)
		}
		vals[i] = int(n)
	}
	if err := Argon2Check(vals[0], vals[1], vals[2]); err != nil {
		return 0, 0, 0, err
	}
	return vals[0], vals[1], vals[2], nil
}

// Argon2idUnwrapCEK unwraps an Argon2id entry's wrapped_cek object.
func Argon2idUnwrapCEK(wrapped *Object, passphrase string) ([]byte, error) {
	m, t, p, err := Argon2Params(wrapped)
	if err != nil {
		return nil, err
	}
	salt, err := DecodeB64(wrapped.GetString("salt"), "salt")
	if err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("%w: Argon2id salt shorter than 16 bytes — refusing (§6.5)", ErrMalformed)
	}
	ct, err := DecodeB64(wrapped.GetString("ct"), "ct")
	if err != nil {
		return nil, err
	}
	return AESKeyUnwrap(argon2Key(passphrase, salt, m, t, p), ct)
}

// ─── Padding — Padmé, spec §5.4 (v1.4) ──────────────────────────────────────

const padFloor = 512

// PadmeLength is Padmé (Nikitin et al., PETS 2019) with a 512-byte floor.
func PadmeLength(n int) int {
	if n <= padFloor {
		return padFloor
	}
	e := bits.Len(uint(n)) - 1 // floor(log2 n), exact for integers
	s := bits.Len(uint(e))     // floor(log2 e) + 1
	step := 1 << (e - s)
	return (n + step - 1) / step * step
}

// ─── Passphrase work bound — spec §6, §6.2, §6.5 ─────────────────────────────
//
// The limits above bound one entry. header_hash is unkeyed, so anyone who can
// rewrite a file can add entries, each within those limits, and an opener would
// derive a key for every one. So one open is bounded too: passphrase entries are
// tried cheapest first, and the opener stops before its key-derivation work
// would pass that of one maximum-parameter entry. Any single entry within the
// limits still opens. Work is counted in integers, as in the reference:
// PBKDF2 = iterations × 2^24, Argon2id = m × t × 10^7, limit = 10^7 × 2^24.

const argon2MaxWork = argon2MMax * 16 // 2^24

// MaxKDFWork is the passphrase work one open may spend (see KDFWork).
const MaxKDFWork int64 = PBKDF2MaxIterations * argon2MaxWork

// KDFWork is the work for one derivation against entry; 0 when its parameters
// are refused (the unwrap then fails without deriving anything).
func KDFWork(entry *Object) int64 {
	wrapped := entry.GetObject("wrapped_cek")
	switch entry.GetString("method") {
	case "pbkdf2":
		if n, err := PBKDF2IterationCount(wrapped); err == nil {
			return int64(n) * argon2MaxWork
		}
	case "argon2id":
		if m, t, _, err := Argon2Params(wrapped); err == nil {
			return int64(m) * int64(t) * PBKDF2MaxIterations
		}
	}
	return 0
}

// PadBody is LE32(len(gz)) || gz || zeros up to PadmeLength(4 + len(gz)).
func PadBody(gz []byte) ([]byte, error) {
	if uint64(len(gz)) >= 1<<32 {
		return nil, fmt.Errorf("%w: body of 2^32 bytes or more is out of scope", ErrMalformed)
	}
	out := make([]byte, PadmeLength(4+len(gz)))
	out[0], out[1], out[2], out[3] = byte(len(gz)), byte(len(gz)>>8), byte(len(gz)>>16), byte(len(gz)>>24)
	copy(out[4:], gz)
	return out, nil
}

// UnpadBody inverts PadBody: it rejects a length that runs past the end or any
// non-zero padding byte.
func UnpadBody(body []byte) ([]byte, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: malformed padded body", ErrMalformed)
	}
	n := int(uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16 | uint32(body[3])<<24)
	if n < 0 || 4+n > len(body) {
		return nil, fmt.Errorf("%w: malformed padded body — length exceeds body", ErrMalformed)
	}
	// Exactly the Padmé length: any other would let a writer pad to a size of its
	// choosing, and give a crafted body room that a conforming one lacks.
	if len(body) != PadmeLength(4+n) {
		return nil, fmt.Errorf("%w: malformed padded body — not the Padmé length", ErrMalformed)
	}
	for _, b := range body[4+n:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: malformed padded body — non-zero padding", ErrMalformed)
		}
	}
	return body[4 : 4+n], nil
}
