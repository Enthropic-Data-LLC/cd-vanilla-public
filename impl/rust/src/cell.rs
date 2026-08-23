// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Sealing and opening `.cell` documents — spec §4, §5, §10, §12.

use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::canonical::{canonical_bytes, js_stringify};
use crate::crypto;
use crate::error::{Error, Result};
use crate::keys::KeyRecord;
use crate::lifetime::{self, Lifetime};
use crate::ulid::ulid;

/// The version this crate writes.
pub const CELL_FORMAT_VERSION: &str = "1.3";

/// Versions this crate can read (spec §12).
pub const SUPPORTED_VERSIONS: &[&str] = &["1.0", "1.1", "1.2", "1.3"];

/// Versions whose hash/signature/AAD use the canonical serialization (§4.1.1).
///
/// Held as a list on purpose. §12 warns that adding a version to the supported
/// set while leaving an inline `version == "1.2"` test elsewhere silently drops
/// canonicalization, or decrypts new cells with no AAD, with no error raised.
pub const CANONICAL_VERSIONS: &[&str] = &["1.2", "1.3"];

/// Versions that bind metadata to the ciphertext as AES-GCM AAD (§4.4).
pub const AAD_VERSIONS: &[&str] = &["1.1", "1.2", "1.3"];

/// Bytes that `header_hash` and `header_sig` cover (§4.1.1).
///
/// v1.2/v1.3 canonicalize; v1.0/v1.1 keep the original insertion-ordered
/// `JSON.stringify` form, which means those versions can only be verified from
/// a header still in its on-disk key order.
pub fn serialize_header(header: &Value, version: &str) -> Result<Vec<u8>> {
    if CANONICAL_VERSIONS.contains(&version) {
        canonical_bytes(header)
    } else {
        Ok(js_stringify(header)?.into_bytes())
    }
}

/// Additional authenticated data for the payload (§4.4).
///
/// The four fields fixed *before* encryption, in a fixed order, as an array.
/// `access_map` and `payload_hash` are absent because they do not exist yet at
/// encryption time — `header_hash` and `header_sig` cover those instead.
pub fn cell_aad(header: &Value, version: &str) -> Result<Option<Vec<u8>>> {
    if !AAD_VERSIONS.contains(&version) {
        return Ok(None);
    }
    let get = |key: &str| header.get(key).cloned().unwrap_or(Value::Null);
    let meta = Value::Array(vec![
        get("prev_hash"),
        get("threshold"),
        get("lifetime"),
        get("policy"),
    ]);
    if version == "1.1" {
        Ok(Some(js_stringify(&meta)?.into_bytes()))
    } else {
        Ok(Some(canonical_bytes(&meta)?))
    }
}

// ─── Recipients ─────────────────────────────────────────────────────────────

/// One access-map entry to be created.
#[derive(Debug, Clone)]
pub enum Recipient {
    Ecdh { spki: String, label: String },
    Passphrase { passphrase: String, label: String },
}

impl Recipient {
    /// Wrap for the holder of a P-256 public key (base64 SPKI).
    pub fn ecdh(spki: &str, label: &str) -> Self {
        Recipient::Ecdh {
            spki: spki.to_string(),
            label: label.to_string(),
        }
    }

    /// Wrap for the holder of a [`KeyRecord`].
    pub fn for_key(key: &KeyRecord) -> Result<Self> {
        Ok(Recipient::Ecdh {
            spki: key.spki()?,
            label: key.label.clone(),
        })
    }

    /// Wrap under a passphrase.
    pub fn passphrase(passphrase: &str, label: &str) -> Self {
        Recipient::Passphrase {
            passphrase: passphrase.to_string(),
            label: if label.is_empty() { "Passphrase".into() } else { label.to_string() },
        }
    }
}

fn wrap_entry(recipient: &Recipient, key_material: &[u8], share_index: Option<usize>) -> Result<Value> {
    let mut entry = Map::new();
    let (fingerprint, wrapped, label, method) = match recipient {
        Recipient::Ecdh { spki, label } => {
            let der = crypto::decode_b64(spki, "spki")?;
            let (eph_spki, hkdf_salt, ct) = crypto::ecdh_wrap_cek(key_material, spki, None, None)?;
            (
                crypto::fingerprint(&der),
                json!({ "eph_spki": eph_spki, "hkdf_salt": hkdf_salt, "ct": ct }),
                label.clone(),
                "ecdh-p256",
            )
        }
        Recipient::Passphrase { passphrase, label } => {
            let (salt, iterations, ct) = crypto::pbkdf2_wrap_cek(key_material, passphrase, None)?;
            // A passphrase has no public key, so §6.2 fingerprints the salt. It
            // identifies the entry, not the holder, and proves nothing about who
            // can open it.
            let salt_bytes = crypto::decode_b64(&salt, "salt")?;
            (
                crypto::fingerprint(&salt_bytes),
                json!({ "salt": salt, "iterations": iterations, "ct": ct }),
                label.clone(),
                "pbkdf2",
            )
        }
    };

    entry.insert("label".into(), Value::String(label));
    entry.insert("method".into(), Value::String(method.into()));
    entry.insert("fingerprint".into(), Value::String(fingerprint));
    // §6.4: on non-quorum cells the key is OMITTED, not written as null. The
    // choice is not cosmetic — canonicalization preserves an explicit null, so
    // the two forms hash differently. Both verify; they are not byte-identical.
    if let Some(index) = share_index {
        entry.insert("share_index".into(), json!(index));
    }
    entry.insert("wrapped_cek".into(), wrapped);
    Ok(Value::Object(entry))
}

// ─── Sealing ────────────────────────────────────────────────────────────────

/// Options for [`create`]. `Default` seals a permanent, unsigned cell.
#[derive(Debug, Default, Clone)]
pub struct CreateOptions {
    pub content_type: Option<String>,
    pub threshold: usize,
    pub lifetime: Option<Value>,
    pub policy: Option<Value>,
    pub prev_hash: Option<String>,
    pub meta: Option<Value>,
    pub sender: Option<KeyRecord>,
    pub doc_id: Option<String>,
    pub created_at: Option<i64>,
}

/// Seal `data` into a v1.3 cell.
///
/// A threshold above 1 splits the CEK into one Shamir share per recipient, of
/// which that many are needed (§7). `sender` adds a `header_sig`; note that its
/// *absence* is undetectable to a reader (§4.1), so a signature proves
/// authorship while no signature proves nothing at all.
pub fn create(
    data: &[u8],
    filename: &str,
    recipients: &[Recipient],
    opts: &CreateOptions,
) -> Result<Value> {
    if recipients.is_empty() {
        return Err(Error::Malformed("a cell needs at least one recipient".into()));
    }
    let required = opts.threshold.clamp(1, recipients.len());
    let content_type = opts
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // Manifest-prefixed plaintext (§5): filename, type and size live inside the
    // ciphertext, so an observer of the stored cell learns none of them.
    let mut manifest = Map::new();
    manifest.insert("filename".into(), Value::String(filename.into()));
    manifest.insert("content_type".into(), Value::String(content_type.clone()));
    manifest.insert("size".into(), json!(data.len()));
    if let Some(meta) = &opts.meta {
        manifest.insert("meta".into(), meta.clone());
    }
    let manifest_bytes = serde_json::to_vec(&Value::Object(manifest))
        .map_err(|e| Error::Malformed(format!("encoding manifest: {e}")))?;

    let mut plaintext = Vec::with_capacity(4 + manifest_bytes.len() + data.len());
    plaintext.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&manifest_bytes);
    plaintext.extend_from_slice(data);
    let body = crypto::gzip_compress(&plaintext)?;

    let cek = crypto::random_bytes(crypto::CEK_LENGTH);

    // Metadata is fixed before encryption precisely so it can be bound as AAD.
    let mut header = Map::new();
    header.insert(
        "prev_hash".into(),
        opts.prev_hash
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    header.insert(
        "threshold".into(),
        json!({ "required": required, "of_total": recipients.len() }),
    );
    header.insert(
        "lifetime".into(),
        lifetime::normalize(opts.lifetime.as_ref()).unwrap_or_else(lifetime::permanent),
    );
    header.insert(
        "policy".into(),
        opts.policy.clone().unwrap_or_else(|| {
            json!({
                "copy_protection": "standard",
                "watermark_mode": "none",
                "created_on_origin": Value::Null,
                "origin_sig": Value::Null,
            })
        }),
    );

    let header_value = Value::Object(header.clone());
    let aad = cell_aad(&header_value, CELL_FORMAT_VERSION)?;
    let (iv, ciphertext) = crypto::aes_gcm_encrypt(&cek, &body, aad.as_deref(), None)?;

    let access_map: Vec<Value> = if required > 1 {
        let shares = crate::gf256::split(&cek, recipients.len(), required, None)?;
        recipients
            .iter()
            .enumerate()
            .map(|(i, r)| wrap_entry(r, &shares[i].data, Some(i + 1)))
            .collect::<Result<Vec<_>>>()?
    } else {
        recipients
            .iter()
            .map(|r| wrap_entry(r, &cek, None))
            .collect::<Result<Vec<_>>>()?
    };

    header.insert("access_map".into(), Value::Array(access_map));
    header.insert(
        "payload_hash".into(),
        Value::String(crypto::encode_b64(&crypto::sha256(&ciphertext))),
    );
    let header_value = Value::Object(header);

    let header_bytes = serialize_header(&header_value, CELL_FORMAT_VERSION)?;
    let doc_id = match &opts.doc_id {
        Some(id) => id.clone(),
        None => ulid(None, None)?,
    };

    let mut cell = Map::new();
    cell.insert("version".into(), Value::String(CELL_FORMAT_VERSION.into()));
    cell.insert("doc_id".into(), Value::String(doc_id));
    cell.insert(
        "created_at".into(),
        json!(opts.created_at.unwrap_or_else(crate::keys::now)),
    );
    cell.insert("header".into(), header_value);
    cell.insert(
        "header_hash".into(),
        Value::String(crypto::encode_b64(&crypto::sha256(&header_bytes))),
    );

    let (sig, sig_by, sig_key) = match &opts.sender {
        Some(sender) => {
            let private = sender.private.as_ref().ok_or_else(|| {
                Error::Malformed("signing requires a key record with a private key".into())
            })?;
            (
                Value::String(crypto::encode_b64(&crypto::ecdsa_sign(private, &header_bytes))),
                Value::String(sender.fingerprint()?),
                Value::String(sender.spki()?),
            )
        }
        None => (Value::Null, Value::Null, Value::Null),
    };
    cell.insert("header_sig".into(), sig);
    cell.insert("header_sig_by".into(), sig_by);
    cell.insert("header_sig_key".into(), sig_key);
    cell.insert(
        "payload".into(),
        json!({
            "alg": "AES-256-GCM",
            "encoding": "base64+gzip",
            "iv": crypto::encode_b64(&iv),
            "ciphertext": crypto::encode_b64(&ciphertext),
        }),
    );
    Ok(Value::Object(cell))
}

// ─── Key-free verification — spec §10 steps 1-3 ─────────────────────────────

/// Outcome of the checks that need no key material at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub version: String,
    pub payload_hash_ok: bool,
    pub signed: bool,
    /// Real fingerprint of `header_sig_key` — the only trustworthy identity here.
    pub signer_fingerprint: Option<String>,
    /// `header_sig_by`: self-asserted, never to be trusted on its own (§4.1).
    pub claimed_signer: Option<String>,
}

/// Verify a cell's audit chain without opening it (§10).
///
/// That this is possible with no key is the property being demonstrated: any
/// third party can confirm a cell has not been altered since it was sealed.
///
/// A clean return does **not** establish authorship. An attacker can strip
/// `header_sig` entirely and the result is indistinguishable from a cell that
/// was never signed, so pass `expected_signer` (a fingerprint learned out of
/// band) whenever authorship matters.
pub fn verify(cell: &Value, expected_signer: Option<&str>) -> Result<VerifyResult> {
    let version = version_of(cell)?;
    let header = cell
        .get("header")
        .filter(|v| v.is_object())
        .ok_or_else(|| Error::Malformed("missing header".into()))?;

    // §4.1: absence of header_hash is a rejection, not licence to skip the
    // checks. Guarding this block on its own presence would mean deleting one
    // field disables the header, ciphertext and signature checks together.
    let header_hash = cell
        .get("header_hash")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Integrity("header_hash is missing".into()))?;

    let header_bytes = serialize_header(header, &version)?;
    if crypto::encode_b64(&crypto::sha256(&header_bytes)) != header_hash {
        return Err(Error::Integrity("header may be tampered".into()));
    }

    let payload = cell.get("payload").or_else(|| cell.get("encrypted_body"));
    let ct_b64 = payload.and_then(|p| {
        p.get("ciphertext")
            .or_else(|| p.get("ct"))
            .and_then(|v| v.as_str())
    });

    let mut payload_hash_ok = false;
    if let Some(expected) = header.get("payload_hash").and_then(|v| v.as_str()) {
        let ct_b64 = ct_b64.ok_or_else(|| {
            Error::Malformed("header commits to a ciphertext that is absent".into())
        })?;
        let ct = crypto::decode_b64(ct_b64, "ciphertext")?;
        if crypto::encode_b64(&crypto::sha256(&ct)) != expected {
            return Err(Error::Integrity("ciphertext may be tampered".into()));
        }
        payload_hash_ok = true;
    }

    let mut result = VerifyResult {
        version,
        payload_hash_ok,
        signed: false,
        signer_fingerprint: None,
        claimed_signer: cell
            .get("header_sig_by")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };

    let sig_b64 = cell.get("header_sig").and_then(|v| v.as_str());
    let key_b64 = cell.get("header_sig_key").and_then(|v| v.as_str());
    if let (Some(sig_b64), Some(key_b64)) = (sig_b64, key_b64) {
        let spki_der = crypto::decode_b64(key_b64, "header_sig_key")?;
        let public = crypto::parse_spki(&spki_der)?;
        let raw_sig = crypto::decode_b64(sig_b64, "header_sig")?;
        crypto::ecdsa_verify(&public, &raw_sig, &header_bytes)?;
        result.signed = true;
        // Trust anchors on the key's real fingerprint, never on header_sig_by,
        // which the signer writes about themselves and can say anything.
        result.signer_fingerprint = Some(crypto::fingerprint(&spki_der));
    }

    if let Some(expected) = expected_signer {
        if !result.signed {
            return Err(Error::Signature(format!(
                "expected a cell signed by {expected}, but it carries no signature \
                 (removal is undetectable — see spec §4.1)"
            )));
        }
        if result.signer_fingerprint.as_deref() != Some(expected) {
            return Err(Error::Signature(format!(
                "cell is signed by {}, not the expected {expected}",
                result.signer_fingerprint.as_deref().unwrap_or("(none)")
            )));
        }
    }
    Ok(result)
}

// ─── Opening ────────────────────────────────────────────────────────────────

/// A successfully opened cell.
#[derive(Debug, Clone)]
pub struct OpenResult {
    pub data: Vec<u8>,
    pub filename: String,
    pub content_type: String,
    pub meta: Option<Value>,
    pub used_recipient: String,
    pub signed: bool,
    pub signer_fingerprint: Option<String>,
    pub claimed_signer: Option<String>,
    pub lifetime: Option<Lifetime>,
}

/// Key material and policy for [`open`]. `Default` enforces the advisory gates
/// and requires no particular signer.
#[derive(Debug, Default, Clone)]
pub struct OpenOptions {
    pub keys: Vec<KeyRecord>,
    pub passphrases: Vec<String>,
    /// Maps a base64 `credential_id` to its 32-byte WebAuthn PRF output.
    /// Entries with no supplied output are skipped, which is conforming.
    pub prf_outputs: HashMap<String, Vec<u8>>,
    /// Overrides the clock for the advisory gates.
    pub now: Option<i64>,
    /// Skip the §8.1 gates. This is not a bypass of a security control: those
    /// gates are advisory **by specification**, unenforceable against anyone
    /// holding a key, and this field documents that honestly rather than
    /// pretending otherwise.
    pub ignore_advisory: bool,
    /// A fingerprint learned out of band that the cell must be signed by.
    pub expected_signer: Option<String>,
}

/// Open a cell and return its plaintext.
///
/// Verification order is normative (§10) and this follows it: the advisory
/// lifetime gates, then `header_hash`, `payload_hash` and `header_sig` — all of
/// which need no key — and only then any access-map work. An opener that
/// unwraps first performs a decryption under a header it has not authenticated,
/// and makes the user pay a 600,000-iteration PBKDF2 derivation or a hardware
/// touch on behalf of a cell it is about to reject.
pub fn open(cell: &Value, opts: &OpenOptions) -> Result<OpenResult> {
    let version = version_of(cell)?;
    let is_legacy = cell.get("version").and_then(|v| v.as_str()).is_none()
        && cell.get("cd_version").is_some();
    let now = opts.now.unwrap_or_else(crate::keys::now);

    // Step 0: advisory gates. Cheapest of all, and they need nothing but the clock.
    let lt = lifetime::read(cell.get("header").and_then(|h| h.get("lifetime")));
    if let Some(lt) = &lt {
        if !opts.ignore_advisory {
            if lt.type_ == "timed_release" {
                if let Some(release_at) = lt.release_at {
                    if release_at > now {
                        return Err(Error::Lifetime(format!(
                            "timed release — unlocks {release_at}"
                        )));
                    }
                }
            }
            if let Some(retain_until) = lt.retain_until {
                if retain_until < now {
                    return Err(Error::Lifetime(format!(
                        "retention period ended {retain_until}"
                    )));
                }
            }
        }
    }
    // Note `disposal` is never consulted: a passed disposal date describes the
    // operator's retention schedule, not the recipient's permission (§8.2).

    // Steps 1-3: integrity and authenticity, before any key material is touched.
    let verified = if !is_legacy {
        Some(verify(cell, opts.expected_signer.as_deref())?)
    } else {
        if opts.expected_signer.is_some() {
            return Err(Error::Signature(
                "legacy v2.x cells carry no signature to check".into(),
            ));
        }
        None
    };

    let empty = Value::Object(Map::new());
    let header = cell.get("header").unwrap_or(&empty);
    let access_map = header
        .get("access_map")
        .or_else(|| cell.get("recipients"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let payload = cell
        .get("payload")
        .or_else(|| cell.get("encrypted_body"))
        .ok_or_else(|| Error::Malformed("payload is missing".into()))?;
    let iv_b64 = payload
        .get("iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Malformed("payload is missing iv".into()))?;
    let ct_b64 = payload
        .get("ciphertext")
        .or_else(|| payload.get("ct"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Malformed("payload is missing ciphertext".into()))?;
    let required = header
        .get("threshold")
        .and_then(|t| t.get("required"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
        .max(1) as usize;

    // Step 4: recover the CEK.
    let (cek, used_recipient) = if required > 1 {
        let mut shares = Vec::new();
        for (index, entry) in access_map.iter().enumerate() {
            // A wrong key here says nothing about the next entry.
            if let Some(material) = try_unwrap(entry, opts) {
                let x = entry
                    .get("share_index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or((index + 1) as u64) as u8;
                shares.push(crate::gf256::Share { x, data: material });
                if shares.len() >= required {
                    break;
                }
            }
        }
        if shares.len() < required {
            return Err(Error::QuorumNotMet {
                needed: required,
                unlocked: shares.len(),
            });
        }
        let count = shares.len();
        (
            crate::gf256::combine(&shares)?,
            format!("{count}-of-{} quorum", access_map.len()),
        )
    } else {
        let mut found = None;
        for entry in &access_map {
            if let Some(material) = try_unwrap(entry, opts) {
                let label = entry
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                found = Some((material, label));
                break;
            }
        }
        found.ok_or(Error::NoMatchingKey)?
    };

    let aad = if is_legacy {
        None
    } else {
        cell_aad(header, &version)?
    };
    let compressed = crypto::aes_gcm_decrypt(
        &cek,
        &crypto::decode_b64(iv_b64, "iv")?,
        &crypto::decode_b64(ct_b64, "ciphertext")?,
        aad.as_deref(),
    )?;
    let plain = crypto::gzip_decompress(&compressed)?;

    let (signed, signer_fingerprint, claimed_signer) = match &verified {
        Some(v) => (v.signed, v.signer_fingerprint.clone(), v.claimed_signer.clone()),
        None => (false, None, None),
    };

    // Manifest-prefixed payload (§5), or a legacy cell with plaintext metadata.
    if let Some(original) = cell.get("original_filename") {
        return Ok(OpenResult {
            data: plain,
            filename: original
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("decrypted")
                .to_string(),
            content_type: cell
                .get("content_type")
                .and_then(|v| v.as_str())
                .unwrap_or("application/octet-stream")
                .to_string(),
            meta: None,
            used_recipient,
            signed,
            signer_fingerprint,
            claimed_signer,
            lifetime: lt,
        });
    }

    if plain.len() < 4 {
        return Err(Error::Malformed(
            "payload too short to hold a manifest length".into(),
        ));
    }
    let manifest_len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if 4 + manifest_len > plain.len() {
        return Err(Error::Malformed(
            "manifest length runs past the plaintext".into(),
        ));
    }
    let manifest: Value = serde_json::from_slice(&plain[4..4 + manifest_len])
        .map_err(|e| Error::Malformed(format!("manifest is not valid JSON: {e}")))?;

    Ok(OpenResult {
        data: plain[4 + manifest_len..].to_vec(),
        filename: manifest
            .get("filename")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("decrypted")
            .to_string(),
        content_type: manifest
            .get("content_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("application/octet-stream")
            .to_string(),
        meta: manifest.get("meta").cloned(),
        used_recipient,
        signed,
        signer_fingerprint,
        claimed_signer,
        lifetime: lt,
    })
}

/// Attempt one access-map entry with whatever material was supplied.
///
/// Returns `None` rather than an error: a wrong key for this entry says nothing
/// about the next one.
fn try_unwrap(entry: &Value, opts: &OpenOptions) -> Option<Vec<u8>> {
    let wrapped = entry.get("wrapped_cek")?;
    let method = entry.get("method").and_then(|v| v.as_str())?;
    let field = |name: &str| wrapped.get(name).and_then(|v| v.as_str());

    match method {
        "ecdh-p256" => {
            let eph_spki = field("eph_spki")?;
            let ct = field("ct")?;
            let hkdf_salt = field("hkdf_salt");
            // Match by fingerprint first so a cell addressed to ten recipients
            // does not run ten ECDH exchanges. Fall back to trying everything,
            // because the fingerprint is a hint and a cell may omit or mangle it.
            let wanted = entry.get("fingerprint").and_then(|v| v.as_str());
            let mut ordered: Vec<&KeyRecord> = Vec::new();
            for key in &opts.keys {
                if key.private.is_none() {
                    continue;
                }
                if wanted.is_some() && key.fingerprint().ok().as_deref() == wanted {
                    ordered.insert(0, key);
                } else {
                    ordered.push(key);
                }
            }
            for key in ordered {
                let private = key.private.as_ref()?;
                if let Ok(material) = crypto::ecdh_unwrap_cek(eph_spki, hkdf_salt, ct, private) {
                    return Some(material);
                }
            }
            None
        }
        "pbkdf2" => {
            let salt = field("salt")?;
            let ct = field("ct")?;
            let iterations = wrapped
                .get("iterations")
                .and_then(|v| v.as_u64())
                .unwrap_or(crypto::PBKDF2_ITERATIONS as u64) as u32;
            for passphrase in &opts.passphrases {
                if let Ok(material) = crypto::pbkdf2_unwrap_cek(salt, iterations, ct, passphrase) {
                    return Some(material);
                }
            }
            None
        }
        "yubikey-prf" => {
            let ct = field("ct")?;
            let credential_id = field("credential_id")?;
            // No token here; skipping is conforming.
            let output = opts.prf_outputs.get(credential_id)?;
            crypto::prf_unwrap_cek(ct, output).ok()
        }
        _ => None,
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn version_of(cell: &Value) -> Result<String> {
    if let Some(version) = cell.get("version").and_then(|v| v.as_str()) {
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(Error::UnsupportedVersion(version.to_string()));
        }
        return Ok(version.to_string());
    }
    if let Some(legacy) = cell.get("cd_version").and_then(|v| v.as_str()) {
        return Ok(legacy.to_string()); // legacy v2.x (§12)
    }
    Err(Error::UnsupportedVersion("(absent)".into()))
}
