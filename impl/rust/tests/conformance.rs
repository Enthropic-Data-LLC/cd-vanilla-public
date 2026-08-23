// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Runs the shared conformance vectors in `conformance/vectors`.
//!
//! This is the test a new language port writes first. It reads a
//! language-neutral manifest and asserts two things per vector: the cells that
//! must open produce the exact expected plaintext, filename, media type and
//! sender meta; and the cells that must be refused are refused.
//!
//! The refusals carry most of the weight. An implementation that opens every
//! positive vector and also opens `reject-tampered-aad` is not a partial pass —
//! it has no metadata authentication at all.

use cellular_defense::canonical::canonicalize;
use cellular_defense::cell::{open, OpenOptions};
use cellular_defense::error::Error;
use cellular_defense::keys::KeyRecord;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn vectors_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    dir.join("manifest.json").exists().then_some(dir)
}

fn load_json(path: &Path) -> Value {
    let data = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parsing {path:?}: {e}"))
}

fn load_key(dir: &Path, name: &str) -> KeyRecord {
    let doc = load_json(&dir.join("../keys").join(format!("{name}.cdkey")));
    KeyRecord::from_cdkey(&doc).expect("parsing key")
}

fn options_for(dir: &Path, spec: &Value) -> OpenOptions {
    let mut opts = OpenOptions::default();
    if let Some(keys) = spec.get("keys").and_then(|v| v.as_array()) {
        for name in keys {
            opts.keys.push(load_key(dir, name.as_str().unwrap()));
        }
    }
    if let Some(passphrases) = spec.get("passphrases").and_then(|v| v.as_array()) {
        for p in passphrases {
            opts.passphrases.push(p.as_str().unwrap().to_string());
        }
    }
    opts
}

/// Map the manifest's portable reason codes onto this crate's error variants.
///
/// A port in another language substitutes its own; the reason codes are the
/// portable part, and the manifest is explicit that the refusal is normative
/// while the specific reason code is not.
fn matches_reason(err: &Error, reason: &str) -> bool {
    matches!(
        (reason, err),
        ("header-hash-missing", Error::Integrity(_))
            | ("header-hash-mismatch", Error::Integrity(_))
            | ("payload-hash-mismatch", Error::Integrity(_))
            | ("signature-invalid", Error::Signature(_))
            | ("signature-der-encoded", Error::Malformed(_))
            | ("aad-mismatch", Error::Decryption)
            | ("unsupported-version", Error::UnsupportedVersion(_))
            | ("quorum-not-met", Error::QuorumNotMet { .. })
            | ("no-matching-key", Error::NoMatchingKey)
            | ("retention-expired", Error::Lifetime(_))
            | ("timed-release-locked", Error::Lifetime(_))
    )
}

#[test]
fn conformance_vectors() {
    let Some(dir) = vectors_dir() else {
        eprintln!("skipping: conformance vectors not present");
        return;
    };
    let manifest = load_json(&dir.join("manifest.json"));
    let vectors = manifest["vectors"].as_array().expect("vectors array");

    let mut opened = 0;
    let mut refused = 0;
    let mut failures: Vec<String> = Vec::new();

    for vector in vectors {
        let id = vector["id"].as_str().unwrap();
        let cell = load_json(&dir.join(vector["file"].as_str().unwrap()));
        let opts = options_for(&dir, &vector["open_with"]);

        if vector["expect"] == "open" {
            match open(&cell, &opts) {
                Err(e) => failures.push(format!("{id}: should have opened: {e}")),
                Ok(result) => {
                    opened += 1;
                    let expected = &vector["plaintext"];
                    let digest = hex(&Sha256::digest(&result.data));
                    if digest != expected["sha256"].as_str().unwrap() {
                        failures.push(format!("{id}: plaintext sha256 differs"));
                    }
                    if result.data.len() as u64 != expected["size"].as_u64().unwrap() {
                        failures.push(format!("{id}: plaintext size differs"));
                    }
                    let payload = std::fs::read(dir.join(expected["file"].as_str().unwrap()))
                        .expect("reading payload");
                    if result.data != payload {
                        failures.push(format!("{id}: plaintext differs from the payload file"));
                    }
                    if result.filename != vector["filename"].as_str().unwrap() {
                        failures.push(format!("{id}: filename = {}", result.filename));
                    }
                    if result.content_type != vector["content_type"].as_str().unwrap() {
                        failures.push(format!("{id}: content_type = {}", result.content_type));
                    }
                    if let Some(want_meta) = vector.get("meta") {
                        let got = result.meta.as_ref().map(|m| canonicalize(m).unwrap());
                        let want = canonicalize(want_meta).unwrap();
                        if got.as_deref() != Some(want.as_str()) {
                            failures.push(format!("{id}: meta = {got:?}, want {want}"));
                        }
                    }
                    if let Some(signer) = vector.get("signer").and_then(|v| v.as_str()) {
                        let want = load_key(&dir, signer).fingerprint().unwrap();
                        if !result.signed || result.signer_fingerprint.as_deref() != Some(&want) {
                            failures.push(format!("{id}: signer = {:?}", result.signer_fingerprint));
                        }
                    }
                    // also_opens_with: every listed combination must produce
                    // byte-identical plaintext.
                    if let Some(alts) = vector["open_with"].get("also_opens_with").and_then(|v| v.as_array()) {
                        for (i, alt) in alts.iter().enumerate() {
                            match open(&cell, &options_for(&dir, alt)) {
                                Ok(other) if other.data == result.data => {}
                                Ok(_) => failures
                                    .push(format!("{id}: also_opens_with[{i}] gave different plaintext")),
                                Err(e) => {
                                    failures.push(format!("{id}: also_opens_with[{i}] failed: {e}"))
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let reason = vector["reject_reason"].as_str().unwrap();
            match open(&cell, &opts) {
                Ok(_) => failures.push(format!("{id}: opened but must be refused ({reason})")),
                Err(e) => {
                    refused += 1;
                    if !matches_reason(&e, reason) {
                        failures.push(format!("{id}: refused with {e:?}, expected {reason}"));
                    }
                }
            }
        }

        if let Some(must_not) = vector.get("must_not_open_with") {
            if open(&cell, &options_for(&dir, must_not)).is_ok() {
                failures.push(format!("{id}: opened with key material that must not open it"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("conformance: {opened} opened, {refused} refused");
    assert!(opened > 0 && refused > 0, "manifest produced no vectors");
}

#[test]
fn every_supported_version_has_a_vector() {
    let Some(dir) = vectors_dir() else { return };
    let manifest = load_json(&dir.join("manifest.json"));
    let covered: Vec<&str> = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["cell_version"].as_str())
        .collect();
    // §12 requires 1.0-1.3 plus legacy v2.x to stay readable. A version with no
    // vector is a version nobody actually tests.
    for version in ["1.0", "1.1", "1.2", "1.3", "2.0"] {
        assert!(covered.contains(&version), "no vector covers version {version}");
    }
}

/// Documents §8.1 rather than merely testing it: the advisory half of lifetime
/// is not enforced against a keyholder, and an opener written from the spec can
/// disregard it. The vector still requires refusal by DEFAULT — that is the
/// conformance claim — but an explicit override is not a violation.
#[test]
fn advisory_gates_are_advisory() {
    let Some(dir) = vectors_dir() else { return };
    let manifest = load_json(&dir.join("manifest.json"));
    for vector in manifest["vectors"].as_array().unwrap() {
        if vector.get("reject_reason").and_then(|v| v.as_str()) != Some("retention-expired") {
            continue;
        }
        let cell = load_json(&dir.join(vector["file"].as_str().unwrap()));
        let mut opts = options_for(&dir, &vector["open_with"]);
        opts.ignore_advisory = true;
        let result = open(&cell, &opts).expect("should open with ignore_advisory");
        assert!(!result.data.is_empty());
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
