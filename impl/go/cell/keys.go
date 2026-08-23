// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"
)

// KeyRecord is one P-256 keypair, or a public key alone when Private is nil.
//
// The same key material serves both ECDH (wrapping) and ECDSA (header
// signatures): §4.1 re-imports the identical P-256 scalar under a different
// algorithm label. Go models the key by its curve rather than its use, so one
// value does both jobs — ECDH() converts for key agreement.
type KeyRecord struct {
	Label     string
	Private   *ecdsa.PrivateKey
	Public    *ecdsa.PublicKey
	KeyID     string
	CreatedAt int64
}

// GenerateKey creates a fresh P-256 keypair.
func GenerateKey(label string) (*KeyRecord, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyRecord{
		Label:     label,
		Private:   private,
		Public:    &private.PublicKey,
		KeyID:     randomKeyID(),
		CreatedAt: time.Now().Unix(),
	}, nil
}

func randomKeyID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "key"
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// SPKIBytes returns the DER SubjectPublicKeyInfo encoding.
func (k *KeyRecord) SPKIBytes() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.Public)
}

// SPKI returns the base64 SPKI as it appears in a cell.
func (k *KeyRecord) SPKI() string {
	der, err := k.SPKIBytes()
	if err != nil {
		return ""
	}
	return EncodeB64(der)
}

// Fingerprint is SHA-256(SPKI)[:8] in hex — spec §13.3.
func (k *KeyRecord) Fingerprint() string {
	der, err := k.SPKIBytes()
	if err != nil {
		return ""
	}
	return Fingerprint(der)
}

// ECDH converts the private key for key agreement.
func (k *KeyRecord) ECDH() (*ecdh.PrivateKey, error) {
	if k.Private == nil {
		return nil, fmt.Errorf("%w: key record has no private key", ErrMalformed)
	}
	return k.Private.ECDH()
}

// ToCDPub renders the .cdpub public key export — spec §13.1.
func (k *KeyRecord) ToCDPub() *Object {
	out := NewObject()
	out.Set("cd_pubkey", "2.0")
	out.Set("label", k.Label)
	out.Set("fingerprint", k.Fingerprint())
	out.Set("method", "ecdh-p256")
	out.Set("spki", k.SPKI())
	return out
}

// ToCDKey renders the .cdkey full key export — spec §13.2.
func (k *KeyRecord) ToCDKey() (*Object, error) {
	if k.Private == nil {
		return nil, fmt.Errorf("%w: cannot export a .cdkey from a public-only record", ErrMalformed)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}
	out := NewObject()
	out.Set("cd_key", "2.0")
	out.Set("keyId", k.KeyID)
	out.Set("label", k.Label)
	out.Set("method", "ecdh-p256")
	out.Set("fingerprint", k.Fingerprint())
	out.Set("spki", k.SPKI())
	out.Set("pkcs8", EncodeB64(pkcs8))
	out.Set("created_at", float64(k.CreatedAt))
	out.Set("exported_at", float64(time.Now().Unix()))
	return out, nil
}

// ParseCDPub loads a .cdpub document.
func ParseCDPub(data []byte) (*KeyRecord, error) {
	value, err := ParseValue(data)
	if err != nil {
		return nil, err
	}
	doc, ok := value.(*Object)
	if !ok {
		return nil, fmt.Errorf("%w: .cdpub is not a JSON object", ErrMalformed)
	}
	spki := doc.GetString("spki")
	if spki == "" {
		return nil, fmt.Errorf("%w: .cdpub is missing its spki field", ErrMalformed)
	}
	der, err := DecodeB64(spki, "spki")
	if err != nil {
		return nil, err
	}
	public, err := ParseSPKIForECDSA(der)
	if err != nil {
		return nil, err
	}
	record := &KeyRecord{Label: labelOr(doc.GetString("label")), Public: public}

	// The fingerprint is derived, not authoritative. A mismatch means the file
	// was edited or corrupted, and trusting the claim would let an attacker
	// point a known-good label at a key they control.
	if claimed := doc.GetString("fingerprint"); claimed != "" && claimed != record.Fingerprint() {
		return nil, fmt.Errorf("%w: .cdpub fingerprint %q does not match its own SPKI (%s)",
			ErrMalformed, claimed, record.Fingerprint())
	}
	return record, nil
}

// ParseCDKey loads a .cdkey document.
func ParseCDKey(data []byte) (*KeyRecord, error) {
	value, err := ParseValue(data)
	if err != nil {
		return nil, err
	}
	doc, ok := value.(*Object)
	if !ok {
		return nil, fmt.Errorf("%w: .cdkey is not a JSON object", ErrMalformed)
	}
	pkcs8 := doc.GetString("pkcs8")
	if pkcs8 == "" {
		return nil, fmt.Errorf("%w: .cdkey is missing its pkcs8 field", ErrMalformed)
	}
	der, err := DecodeB64(pkcs8, "pkcs8")
	if err != nil {
		return nil, err
	}
	private, err := ParsePKCS8(der)
	if err != nil {
		return nil, err
	}
	record := &KeyRecord{
		Label:     labelOr(doc.GetString("label")),
		Private:   private,
		Public:    &private.PublicKey,
		KeyID:     safeKeyID(doc.GetString("keyId")),
		CreatedAt: int64(doc.GetInt("created_at", 0)),
	}
	if spki := doc.GetString("spki"); spki != "" && spki != record.SPKI() {
		return nil, fmt.Errorf("%w: .cdkey spki does not match its own private key", ErrMalformed)
	}
	return record, nil
}

func labelOr(label string) string {
	if label == "" {
		return "(unnamed)"
	}
	return label
}

// safeKeyID constrains an imported keyId to a safe charset, else mints a fresh
// one. Imported key files are attacker-supplied; the reference sanitises this
// because it reaches the DOM there, and it reaches filenames and logs here.
func safeKeyID(id string) string {
	if id == "" || len(id) > 64 {
		return randomKeyID()
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return randomKeyID()
		}
	}
	return id
}
