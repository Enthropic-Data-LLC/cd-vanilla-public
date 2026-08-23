// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives — spec §6, §14.
//!
//! All RustCrypto, plus `flate2` for gzip. Notably `aes-kw` exists as a crate,
//! so unlike the Go port nothing here had to be written from the RFC; and
//! `p256`'s ECDSA signature type is *already* the fixed 64-byte `r ‖ s` form
//! the format requires, so the DER trap of §4.1 never arises unless you
//! deliberately reach for the DER encoding.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_kw::Kek;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::error::{Error, Result};

/// Fixed info string for the ECDH key-wrap derivation (§6.1).
pub const HKDF_INFO: &[u8] = b"cellular-defense-cek-wrap-v1";
/// Iteration count for passphrase entries (§6.2).
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// AES-GCM nonce length in bytes.
pub const IV_LENGTH: usize = 12;
/// Content encryption key length in bytes.
pub const CEK_LENGTH: usize = 32;
/// Cap on gzip expansion. The spec sets no limit; the reference caps at 2 GiB.
/// A few KB of crafted gzip expands to many GB, and an opener that streams it
/// into memory is a denial of service needing no key at all.
pub const MAX_DECOMPRESSED: u64 = 2 * 1024 * 1024 * 1024;

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// `SHA-256(SPKI)[..8]` as 16 lowercase hex characters — spec §13.3.
pub fn fingerprint(spki_der: &[u8]) -> String {
    sha256(spki_der)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ─── Binary field encoding — spec §4.0 ──────────────────────────────────────

/// Emit standard base64 with padding, the only form this crate writes.
///
/// It is not base64url: `atob()` throws on `-` and `_`, so a base64url cell is
/// unparseable by the reference rather than merely non-canonical.
pub fn encode_b64(data: &[u8]) -> String {
    B64.encode(data)
}

/// Decode standard base64, tolerating the base64url alphabet and missing
/// padding on input, as §4.0's SHOULD asks.
pub fn decode_b64(text: &str, field: &str) -> Result<Vec<u8>> {
    let mut normalized: String = text.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        other => other,
    }).collect();
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }
    B64.decode(normalized.as_bytes())
        .map_err(|e| Error::Malformed(format!("{field} is not valid base64: {e}")))
}

// ─── Compression — spec §5 ──────────────────────────────────────────────────

/// gzip `data`.
///
/// The reference uses `CompressionStream('gzip')`, whose output is not
/// byte-identical to any particular zlib configuration and need not be: the
/// format commits to the ciphertext, and gzip framing is decided before
/// encryption. Two conforming implementations sealing the same file produce
/// different bytes for this reason alone and both are correct.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| Error::Malformed(format!("gzip: {e}")))?;
    encoder
        .finish()
        .map_err(|e| Error::Malformed(format!("gzip: {e}")))
}

/// Decompress a gzip stream, refusing to exceed [`MAX_DECOMPRESSED`].
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // One byte over the cap, so a stream exactly at the limit still reads and
    // anything larger is detected rather than silently truncated.
    let mut reader = GzDecoder::new(data).take(MAX_DECOMPRESSED + 1);
    reader
        .read_to_end(&mut out)
        .map_err(|e| Error::Malformed(format!("payload is not a valid gzip stream: {e}")))?;
    if out.len() as u64 > MAX_DECOMPRESSED {
        return Err(Error::Malformed(
            "decompressed size exceeds safety limit".into(),
        ));
    }
    Ok(out)
}

// ─── Content encryption — AES-256-GCM, spec §4.3 ────────────────────────────

/// Encrypt with AES-256-GCM, returning `(iv, ciphertext || tag)`.
///
/// The 128-bit tag is appended to the ciphertext, matching WebCrypto.
pub fn aes_gcm_encrypt(
    cek: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if cek.len() != CEK_LENGTH {
        return Err(Error::Malformed(format!(
            "CEK must be {CEK_LENGTH} bytes, got {}",
            cek.len()
        )));
    }
    let iv = match iv {
        Some(v) => v.to_vec(),
        None => random_bytes(IV_LENGTH),
    };
    let cipher = Aes256Gcm::new(cek.into());
    let ciphertext = cipher
        .encrypt(
            iv.as_slice().into(),
            Payload {
                msg: plaintext,
                aad: aad.unwrap_or(&[]),
            },
        )
        .map_err(|_| Error::Malformed("AES-GCM encryption failed".into()))?;
    Ok((iv, ciphertext))
}

/// Decrypt and verify. A tag failure here is equally an AAD mismatch: the two
/// are indistinguishable by design (§4.4).
pub fn aes_gcm_decrypt(
    cek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if iv.len() != IV_LENGTH {
        return Err(Error::Malformed(format!(
            "iv must be {IV_LENGTH} bytes, got {}",
            iv.len()
        )));
    }
    let cipher = Aes256Gcm::new(cek.into());
    cipher
        .decrypt(
            iv.into(),
            Payload {
                msg: ciphertext,
                aad: aad.unwrap_or(&[]),
            },
        )
        .map_err(|_| Error::Decryption)
}

// ─── CEK wrapping — ECDH P-256 → HKDF-SHA256 → AES-KW, spec §6.1 ────────────

fn hkdf_wrap_key(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| Error::Malformed(format!("HKDF: {e}")))?;
    Ok(okm)
}

/// Wrap key material for one ECDH recipient.
///
/// A fresh ephemeral keypair per recipient per cell is what gives the format
/// its per-cell forward secrecy; `ephemeral` and `hkdf_salt` are injectable
/// only so vectors can be pinned.
pub fn ecdh_wrap_cek(
    key_material: &[u8],
    recipient_spki_b64: &str,
    ephemeral: Option<SecretKey>,
    hkdf_salt: Option<&[u8]>,
) -> Result<(String, String, String)> {
    let recipient = parse_spki(&decode_b64(recipient_spki_b64, "spki")?)?;
    let ephemeral = ephemeral.unwrap_or_else(|| SecretKey::random(&mut OsRng));
    let salt = match hkdf_salt {
        Some(s) => s.to_vec(),
        None => random_bytes(32),
    };

    // WebCrypto's deriveBits(..., 256) on P-256 is the X coordinate of the
    // shared point, which is exactly what raw_secret_bytes() returns. Neither
    // side applies a KDF at this step — HKDF is the next line, not implied here.
    let shared = p256::ecdh::diffie_hellman(
        ephemeral.to_nonzero_scalar(),
        recipient.as_affine(),
    );
    let wrapping_key = hkdf_wrap_key(shared.raw_secret_bytes(), &salt)?;
    let wrapped = aes_kw_wrap(&wrapping_key, key_material)?;

    let eph_spki = ephemeral
        .public_key()
        .to_public_key_der()
        .map_err(|e| Error::Malformed(format!("encoding ephemeral SPKI: {e}")))?;

    Ok((
        encode_b64(eph_spki.as_bytes()),
        encode_b64(&salt),
        encode_b64(&wrapped),
    ))
}

/// Unwrap an ECDH entry.
///
/// An entry with no `hkdf_salt` is a pre-spec legacy v2.0 cell, whose wrapping
/// key is the raw ECDH output truncated to 32 bytes with no HKDF at all (§12).
/// No conforming writer may produce that shape.
pub fn ecdh_unwrap_cek(
    eph_spki_b64: &str,
    hkdf_salt_b64: Option<&str>,
    ct_b64: &str,
    private: &SecretKey,
) -> Result<Vec<u8>> {
    let eph = parse_spki(&decode_b64(eph_spki_b64, "eph_spki")?)?;
    let shared = p256::ecdh::diffie_hellman(private.to_nonzero_scalar(), eph.as_affine());

    let wrapping_key: [u8; 32] = match hkdf_salt_b64 {
        Some(salt_b64) if !salt_b64.is_empty() => {
            hkdf_wrap_key(shared.raw_secret_bytes(), &decode_b64(salt_b64, "hkdf_salt")?)?
        }
        _ => {
            let raw = shared.raw_secret_bytes();
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw[..32]);
            key
        }
    };
    aes_kw_unwrap(&wrapping_key, &decode_b64(ct_b64, "ct")?)
}

// ─── CEK wrapping — PBKDF2, spec §6.2 ───────────────────────────────────────

/// Derive a wrapping key from a passphrase.
///
/// PBKDF2-HMAC-SHA256 over the UTF-8 bytes of the passphrase, with **no**
/// Unicode normalization — WebCrypto has no opinion about text encoding and the
/// reference feeds it `TextEncoder().encode(passphrase)`. Composed and
/// decomposed accents are therefore two different passphrases, on every
/// implementation.
pub fn derive_passphrase_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
    key
}

pub fn pbkdf2_wrap_cek(
    key_material: &[u8],
    passphrase: &str,
    salt: Option<&[u8]>,
) -> Result<(String, u32, String)> {
    let salt = match salt {
        Some(s) => s.to_vec(),
        None => random_bytes(32),
    };
    let wrapping_key = derive_passphrase_key(passphrase, &salt, PBKDF2_ITERATIONS);
    let wrapped = aes_kw_wrap(&wrapping_key, key_material)?;
    Ok((encode_b64(&salt), PBKDF2_ITERATIONS, encode_b64(&wrapped)))
}

pub fn pbkdf2_unwrap_cek(
    salt_b64: &str,
    iterations: u32,
    ct_b64: &str,
    passphrase: &str,
) -> Result<Vec<u8>> {
    let salt = decode_b64(salt_b64, "salt")?;
    let iterations = if iterations == 0 {
        PBKDF2_ITERATIONS
    } else {
        iterations
    };
    let wrapping_key = derive_passphrase_key(passphrase, &salt, iterations);
    aes_kw_unwrap(&wrapping_key, &decode_b64(ct_b64, "ct")?)
}

// ─── CEK wrapping — WebAuthn/FIDO2 PRF, spec §6.3 ───────────────────────────

/// Unwrap under a 32-byte WebAuthn PRF output used directly as the AES-KW key.
///
/// This crate cannot *obtain* a PRF output: the hmac-secret extension is
/// reachable only through WebAuthn, in a browser, with the token present. A
/// non-browser implementation can handle these entries only when something else
/// supplies the 32 bytes. Openers that cannot are conforming — they skip such
/// entries.
pub fn prf_unwrap_cek(ct_b64: &str, prf_output: &[u8]) -> Result<Vec<u8>> {
    if prf_output.len() != 32 {
        return Err(Error::Malformed(format!(
            "PRF output must be 32 bytes, got {}",
            prf_output.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(prf_output);
    aes_kw_unwrap(&key, &decode_b64(ct_b64, "ct")?)
}

// ─── AES Key Wrap (RFC 3394) ────────────────────────────────────────────────

fn aes_kw_wrap(kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let kek = Kek::from(*kek);
    let mut out = vec![0u8; plaintext.len() + 8];
    kek.wrap(plaintext, &mut out)
        .map_err(|e| Error::Malformed(format!("AES-KW wrap: {e}")))?;
    Ok(out)
}

fn aes_kw_unwrap(kek: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 || ciphertext.len() % 8 != 0 {
        return Err(Error::Malformed(format!(
            "AES-KW ciphertext must be a multiple of 8 bytes and at least 24, got {}",
            ciphertext.len()
        )));
    }
    let kek = Kek::from(*kek);
    let mut out = vec![0u8; ciphertext.len() - 8];
    // A failure here is the integrity check value not matching, which is how a
    // wrong wrapping key is detected at all.
    kek.unwrap(ciphertext, &mut out)
        .map_err(|_| Error::NoMatchingKey)?;
    Ok(out)
}

// ─── Key encoding and ECDSA — spec §4.1, §13 ────────────────────────────────

pub fn parse_spki(der: &[u8]) -> Result<PublicKey> {
    PublicKey::from_public_key_der(der)
        .map_err(|e| Error::Malformed(format!("invalid SPKI public key: {e}")))
}

pub fn export_spki(key: &PublicKey) -> Result<Vec<u8>> {
    Ok(key
        .to_public_key_der()
        .map_err(|e| Error::Malformed(format!("encoding SPKI: {e}")))?
        .as_bytes()
        .to_vec())
}

pub fn parse_pkcs8(der: &[u8]) -> Result<SecretKey> {
    SecretKey::from_pkcs8_der(der)
        .map_err(|e| Error::Malformed(format!("invalid PKCS#8 private key: {e}")))
}

pub fn export_pkcs8(key: &SecretKey) -> Result<Vec<u8>> {
    Ok(key
        .to_pkcs8_der()
        .map_err(|e| Error::Malformed(format!("encoding PKCS#8: {e}")))?
        .as_bytes()
        .to_vec())
}

/// Sign with ECDSA-SHA256, returning raw `r ‖ s`.
///
/// Spec §4.1 names DER-vs-P1363 the single most likely point of failure outside
/// a browser. It is a non-issue here: `p256::ecdsa::Signature` *is* the fixed
/// 64-byte form, and producing DER would take a deliberate `to_der()` call.
/// Go, Java, OpenSSL and python-cryptography all default the other way.
pub fn ecdsa_sign(private: &SecretKey, data: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::from(private);
    let signature: Signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify a raw 64-byte `r ‖ s` signature.
///
/// A signature of any other length is refused outright rather than decoded as a
/// courtesy: accepting DER here would interoperate with nothing and hide the
/// bug until a browser saw the cell.
pub fn ecdsa_verify(public: &PublicKey, raw_sig: &[u8], data: &[u8]) -> Result<()> {
    if raw_sig.len() != 64 {
        return Err(Error::Malformed(format!(
            "header_sig must be 64 bytes of raw r||s (IEEE P1363), got {}; \
             a DER-encoded signature is not accepted (spec §4.1)",
            raw_sig.len()
        )));
    }
    let signature = Signature::from_slice(raw_sig)
        .map_err(|e| Error::Malformed(format!("header_sig is not a valid P-256 signature: {e}")))?;
    VerifyingKey::from(public)
        .verify(data, &signature)
        .map_err(|_| Error::Signature("cell may be forged".into()))
}
