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
	"math/big"
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

// GzipDecompress decompresses a gzip stream, refusing to exceed MaxDecompressed.
func GzipDecompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not a valid gzip stream: %v", ErrMalformed, err)
	}
	defer reader.Close()
	// One byte over the cap, so a stream that is exactly at the limit still
	// reads and anything larger is detected rather than silently truncated.
	out, err := io.ReadAll(io.LimitReader(reader, MaxDecompressed+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(out) > MaxDecompressed {
		return nil, fmt.Errorf("%w: decompressed size exceeds safety limit", ErrMalformed)
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

// PBKDF2UnwrapCEK unwraps a passphrase entry.
func PBKDF2UnwrapCEK(wrapped *Object, passphrase string) ([]byte, error) {
	salt, err := DecodeB64(wrapped.GetString("salt"), "salt")
	if err != nil {
		return nil, err
	}
	iterations := wrapped.GetInt("iterations", PBKDF2Iterations)
	if iterations <= 0 {
		iterations = PBKDF2Iterations
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

// ECDSAVerify verifies a raw 64-byte r||s signature. A DER signature is
// refused outright rather than being decoded as a courtesy: accepting DER here
// would interoperate with nothing and hide the bug until a browser saw the cell.
func ECDSAVerify(public *ecdsa.PublicKey, rawSig, data []byte) error {
	if len(rawSig) != 64 {
		return fmt.Errorf("%w: header_sig must be 64 bytes of raw r||s (IEEE P1363), got %d; "+
			"a DER-encoded signature is not accepted (spec §4.1)", ErrMalformed, len(rawSig))
	}
	digest := sha256.Sum256(data)
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	if !ecdsa.Verify(public, digest[:], r, s) {
		return fmt.Errorf("%w: cell may be forged", ErrSignature)
	}
	return nil
}
