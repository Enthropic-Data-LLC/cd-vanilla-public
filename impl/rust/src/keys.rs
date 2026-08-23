// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Key records and the `.cdpub` / `.cdkey` file formats — spec §13.

use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use serde_json::{json, Value};

use crate::crypto;
use crate::error::{Error, Result};

/// One P-256 keypair, or a public key alone when `private` is `None`.
///
/// The same key material serves both ECDH (wrapping) and ECDSA (header
/// signatures): §4.1 re-imports the identical P-256 scalar under a different
/// algorithm label. `p256` models the key by its curve rather than its use, so
/// one value does both jobs.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub label: String,
    pub private: Option<SecretKey>,
    pub public: PublicKey,
    pub key_id: String,
    pub created_at: i64,
}

impl KeyRecord {
    /// Create a fresh P-256 keypair.
    pub fn generate(label: &str) -> Self {
        let private = SecretKey::random(&mut OsRng);
        let public = private.public_key();
        Self {
            label: label.to_string(),
            private: Some(private),
            public,
            key_id: random_key_id(),
            created_at: now(),
        }
    }

    /// DER SubjectPublicKeyInfo bytes.
    pub fn spki_bytes(&self) -> Result<Vec<u8>> {
        crypto::export_spki(&self.public)
    }

    /// Base64 SPKI as it appears in a cell.
    pub fn spki(&self) -> Result<String> {
        Ok(crypto::encode_b64(&self.spki_bytes()?))
    }

    /// `SHA-256(SPKI)[..8]` in hex — spec §13.3.
    pub fn fingerprint(&self) -> Result<String> {
        Ok(crypto::fingerprint(&self.spki_bytes()?))
    }

    /// Render the `.cdpub` public key export — spec §13.1.
    pub fn to_cdpub(&self) -> Result<Value> {
        Ok(json!({
            "cd_pubkey": "2.0",
            "label": self.label,
            "fingerprint": self.fingerprint()?,
            "method": "ecdh-p256",
            "spki": self.spki()?,
        }))
    }

    /// Render the `.cdkey` full key export — spec §13.2.
    pub fn to_cdkey(&self) -> Result<Value> {
        let private = self
            .private
            .as_ref()
            .ok_or_else(|| Error::Malformed("cannot export a .cdkey from a public-only record".into()))?;
        Ok(json!({
            "cd_key": "2.0",
            "keyId": self.key_id,
            "label": self.label,
            "method": "ecdh-p256",
            "fingerprint": self.fingerprint()?,
            "spki": self.spki()?,
            "pkcs8": crypto::encode_b64(&crypto::export_pkcs8(private)?),
            "created_at": self.created_at,
            "exported_at": now(),
        }))
    }

    /// Load a `.cdpub` document.
    pub fn from_cdpub(doc: &Value) -> Result<Self> {
        let spki = doc
            .get("spki")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Malformed(".cdpub is missing its spki field".into()))?;
        let public = crypto::parse_spki(&crypto::decode_b64(spki, "spki")?)?;
        let record = Self {
            label: label_or(doc.get("label").and_then(|v| v.as_str())),
            private: None,
            public,
            key_id: random_key_id(),
            created_at: 0,
        };

        // The fingerprint is derived, not authoritative. A mismatch means the
        // file was edited or corrupted, and trusting the claim would let an
        // attacker point a known-good label at a key they control.
        if let Some(claimed) = doc.get("fingerprint").and_then(|v| v.as_str()) {
            let actual = record.fingerprint()?;
            if claimed != actual {
                return Err(Error::Malformed(format!(
                    ".cdpub fingerprint {claimed:?} does not match its own SPKI ({actual})"
                )));
            }
        }
        Ok(record)
    }

    /// Load a `.cdkey` document.
    pub fn from_cdkey(doc: &Value) -> Result<Self> {
        let pkcs8 = doc
            .get("pkcs8")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Malformed(".cdkey is missing its pkcs8 field".into()))?;
        let private = crypto::parse_pkcs8(&crypto::decode_b64(pkcs8, "pkcs8")?)?;
        let public = private.public_key();
        let record = Self {
            label: label_or(doc.get("label").and_then(|v| v.as_str())),
            private: Some(private),
            public,
            key_id: safe_key_id(doc.get("keyId").and_then(|v| v.as_str())),
            created_at: doc.get("created_at").and_then(|v| v.as_i64()).unwrap_or(0),
        };
        if let Some(spki) = doc.get("spki").and_then(|v| v.as_str()) {
            if spki != record.spki()? {
                return Err(Error::Malformed(
                    ".cdkey spki does not match its own private key".into(),
                ));
            }
        }
        Ok(record)
    }
}

fn label_or(label: Option<&str>) -> String {
    match label {
        Some(l) if !l.is_empty() => l.to_string(),
        _ => "(unnamed)".to_string(),
    }
}

/// Constrain an imported `keyId` to a safe charset, else mint a fresh one.
///
/// Imported key files are attacker-supplied. The reference sanitises this
/// because it reaches the DOM there; it reaches filenames and logs here.
fn safe_key_id(id: Option<&str>) -> String {
    match id {
        Some(id)
            if !id.is_empty()
                && id.len() <= 64
                && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') =>
        {
            id.to_string()
        }
        _ => random_key_id(),
    }
}

fn random_key_id() -> String {
    let b = crypto::random_bytes(16);
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seconds since the Unix epoch. Exposed so callers can pin the clock in
/// tests and vectors without reaching for a time crate.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
