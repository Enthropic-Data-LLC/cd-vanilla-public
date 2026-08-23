// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Sealing and opening, with the negative cases carrying most of the weight.
//!
//! Round-trips prove only that the crate agrees with itself. What matters is
//! that the *refusals* happen.
//!
//! Note these run PBKDF2 at 600,000 iterations; use `cargo test --release` or
//! expect a debug build to take a while.

use cellular_defense::canonical::canonicalize;
use cellular_defense::cell::{create, open, serialize_header, verify, CreateOptions, OpenOptions, Recipient};
use cellular_defense::crypto;
use cellular_defense::error::Error;
use cellular_defense::keys::KeyRecord;
use serde_json::{json, Value};

const DAY: i64 = 86400;

fn seal(data: &[u8], recipients: &[Recipient], opts: CreateOptions) -> Value {
    create(data, "f.txt", recipients, &opts).expect("sealing")
}

/// Recompute `header_hash` — what any attacker editing a header does first,
/// since the hash is unkeyed. Every "attacker edits the header" test needs it,
/// and that is precisely why the AAD binding and the signature exist.
fn rehash(cell: &mut Value) {
    let version = cell["version"].as_str().unwrap().to_string();
    let bytes = serialize_header(&cell["header"], &version).unwrap();
    cell["header_hash"] = json!(crypto::encode_b64(&crypto::sha256(&bytes)));
}

fn keys_for(records: &[&KeyRecord]) -> OpenOptions {
    OpenOptions {
        keys: records.iter().map(|k| (*k).clone()).collect(),
        ..Default::default()
    }
}

#[test]
fn round_trip() {
    let alice = KeyRecord::generate("Alice");
    let cell = seal(
        b"hello",
        &[Recipient::for_key(&alice).unwrap()],
        CreateOptions { content_type: Some("text/plain".into()), ..Default::default() },
    );
    let result = open(&cell, &keys_for(&[&alice])).unwrap();
    assert_eq!(result.data, b"hello");
    assert_eq!(result.content_type, "text/plain");
    assert!(!result.signed);
}

#[test]
fn payload_edge_cases() {
    let alice = KeyRecord::generate("Alice");
    for size in [0usize, 1, 4096] {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let cell = seal(&data, &[Recipient::for_key(&alice).unwrap()], CreateOptions::default());
        assert_eq!(open(&cell, &keys_for(&[&alice])).unwrap().data, data, "size {size}");
    }
}

#[test]
fn metadata_is_not_visible_in_the_cell() {
    // §5: the manifest lives inside the ciphertext. If the filename appears
    // anywhere in the serialized cell, metadata confidentiality is broken.
    let alice = KeyRecord::generate("Alice");
    let cell = create(
        &vec![b'x'; 1000],
        "secret-merger-terms.pdf",
        &[Recipient::for_key(&alice).unwrap()],
        &CreateOptions::default(),
    )
    .unwrap();
    let text = serde_json::to_string(&cell).unwrap();
    assert!(!text.contains("secret-merger-terms"), "filename leaked into the cell");
}

#[test]
fn reformatting_does_not_break_verification() {
    // The point of canonicalization (§4.1.1): a cell pretty-printed or
    // key-reordered in transit still verifies.
    let alice = KeyRecord::generate("Alice");
    let cell = seal(b"x", &[Recipient::for_key(&alice).unwrap()], CreateOptions::default());
    let reparsed: Value = serde_json::from_str(&serde_json::to_string_pretty(&cell).unwrap()).unwrap();
    verify(&reparsed, None).expect("re-serialized cell must still verify");
    assert_eq!(open(&reparsed, &keys_for(&[&alice])).unwrap().data, b"x");
}

#[test]
fn integrity_refusals() {
    let alice = KeyRecord::generate("Alice");
    let bob = KeyRecord::generate("Bob");
    let opts = keys_for(&[&alice]);
    let base = || seal(b"x", &[Recipient::for_key(&alice).unwrap()], CreateOptions::default());

    // §4.1: absence must not be licence to skip the checks — deleting one field
    // would otherwise disable header, ciphertext and signature verification.
    let mut cell = base();
    cell.as_object_mut().unwrap().remove("header_hash");
    assert!(matches!(open(&cell, &opts), Err(Error::Integrity(_))));

    let mut cell = base();
    cell["header"]["policy"]["copy_protection"] = json!("none");
    assert!(matches!(open(&cell, &opts), Err(Error::Integrity(_))), "edited header, no rehash");

    let mut cell = base();
    let mut ct = crypto::decode_b64(cell["payload"]["ciphertext"].as_str().unwrap(), "ct").unwrap();
    ct[0] ^= 1;
    cell["payload"]["ciphertext"] = json!(crypto::encode_b64(&ct));
    assert!(matches!(open(&cell, &opts), Err(Error::Integrity(_))), "tampered ciphertext");

    // The attacker edits AAD-bound metadata AND recomputes the unkeyed
    // header_hash, so §10 steps 1-3 all pass. The AAD binding is the only thing
    // left, and it must catch this.
    let mut cell = base();
    cell["header"]["policy"]["copy_protection"] = json!("none");
    rehash(&mut cell);
    assert!(matches!(open(&cell, &opts), Err(Error::Decryption)), "tampered AAD");

    // §4.4: rewriting version to 1.0 would strip the AAD from the decrypt. The
    // ciphertext was produced WITH AAD, so the tag fails; an attacker cannot
    // re-encrypt without the CEK.
    let mut cell = base();
    cell["version"] = json!("1.0");
    rehash(&mut cell);
    assert!(matches!(open(&cell, &opts), Err(Error::Decryption)), "version downgrade");

    let mut cell = base();
    cell["version"] = json!("9.9");
    assert!(matches!(open(&cell, &opts), Err(Error::UnsupportedVersion(_))));

    // access_map is not in the AAD (it does not exist at encryption time), so
    // header_hash covers it — and an attacker who recomputes that unkeyed hash
    // is caught by the signature.
    let mut cell = seal(
        b"x",
        &[Recipient::for_key(&alice).unwrap()],
        CreateOptions { sender: Some(alice.clone()), ..Default::default() },
    );
    let other = seal(b"x", &[Recipient::for_key(&bob).unwrap()], CreateOptions::default());
    cell["header"]["access_map"] = other["header"]["access_map"].clone();
    rehash(&mut cell);
    assert!(matches!(open(&cell, &keys_for(&[&bob])), Err(Error::Signature(_))));
}

#[test]
fn signatures() {
    let alice = KeyRecord::generate("Alice");
    let bob = KeyRecord::generate("Bob");
    let opts = keys_for(&[&alice]);
    let signed = || {
        seal(
            b"x",
            &[Recipient::for_key(&alice).unwrap()],
            CreateOptions { sender: Some(bob.clone()), ..Default::default() },
        )
    };

    let result = open(&signed(), &opts).unwrap();
    assert!(result.signed);
    assert_eq!(result.signer_fingerprint, Some(bob.fingerprint().unwrap()));

    // §4.1: header_sig_by is a self-asserted label. Changing it must not change
    // who the cell is attributed to.
    let mut cell = signed();
    cell["header_sig_by"] = json!("Trust Me Inc");
    rehash(&mut cell);
    let result = open(&cell, &opts).unwrap();
    assert_eq!(result.signer_fingerprint, Some(bob.fingerprint().unwrap()));
    assert_eq!(result.claimed_signer.as_deref(), Some("Trust Me Inc"));

    // §4.1's named trap: DER in header_sig must not verify. p256 makes this
    // hard to do by accident — its Signature type is already P1363 — but a
    // cell arriving from a DER-defaulting implementation must still be refused.
    let mut cell = signed();
    let raw = crypto::decode_b64(cell["header_sig"].as_str().unwrap(), "sig").unwrap();
    let mut der = vec![0x30, 0x44, 0x02, 0x20];
    der.extend_from_slice(&raw[..32]);
    der.extend_from_slice(&[0x02, 0x20]);
    der.extend_from_slice(&raw[32..]);
    cell["header_sig"] = json!(crypto::encode_b64(&der));
    assert!(matches!(open(&cell, &opts), Err(Error::Malformed(_))), "DER signature");

    // §4.1: an attacker can delete the signature and the result is
    // byte-indistinguishable from a cell that was never signed. "Opened without
    // error" is not evidence of authorship.
    let mut cell = signed();
    for key in ["header_sig", "header_sig_by", "header_sig_key"] {
        cell[key] = Value::Null;
    }
    rehash(&mut cell);
    assert!(!open(&cell, &opts).unwrap().signed, "stripped cell still opens");
    let strict = OpenOptions {
        expected_signer: Some(bob.fingerprint().unwrap()),
        ..keys_for(&[&alice])
    };
    assert!(matches!(open(&cell, &strict), Err(Error::Signature(_))));
}

#[test]
fn access_control() {
    let alice = KeyRecord::generate("Alice");
    let bob = KeyRecord::generate("Bob");
    let cell = seal(b"x", &[Recipient::for_key(&alice).unwrap()], CreateOptions::default());
    assert!(matches!(open(&cell, &keys_for(&[&bob])), Err(Error::NoMatchingKey)));

    // §6.4: share_index is omitted, not null, on non-quorum cells — the two
    // forms hash differently.
    assert!(cell["header"]["access_map"][0].get("share_index").is_none());

    let quorum_keys: Vec<KeyRecord> = (0..3).map(|i| KeyRecord::generate(&format!("K{i}"))).collect();
    let recipients: Vec<Recipient> = quorum_keys.iter().map(|k| Recipient::for_key(k).unwrap()).collect();
    let cell = seal(b"quorum", &recipients, CreateOptions { threshold: 2, ..Default::default() });
    for (i, entry) in cell["header"]["access_map"].as_array().unwrap().iter().enumerate() {
        assert_eq!(entry["share_index"].as_u64().unwrap(), (i + 1) as u64);
    }
    let two: Vec<&KeyRecord> = quorum_keys.iter().take(2).collect();
    assert_eq!(open(&cell, &keys_for(&two)).unwrap().data, b"quorum");
    let one: Vec<&KeyRecord> = quorum_keys.iter().take(1).collect();
    assert!(matches!(
        open(&cell, &keys_for(&one)),
        Err(Error::QuorumNotMet { needed: 2, unlocked: 1 })
    ));
}

#[test]
fn passphrase_entries() {
    let cell = seal(b"x", &[Recipient::passphrase("right", "")], CreateOptions::default());
    let right = OpenOptions { passphrases: vec!["right".into()], ..Default::default() };
    let wrong = OpenOptions { passphrases: vec!["wrong".into()], ..Default::default() };
    assert_eq!(open(&cell, &right).unwrap().data, b"x");
    assert!(matches!(open(&cell, &wrong), Err(Error::NoMatchingKey)));
    assert_eq!(cell["header"]["access_map"][0]["wrapped_cek"]["iterations"], 600_000);
}

#[test]
fn lifetime_gates() {
    let alice = KeyRecord::generate("Alice");
    let opts = keys_for(&[&alice]);
    let now = cellular_defense::keys::now();

    let expired = seal(
        b"x",
        &[Recipient::for_key(&alice).unwrap()],
        CreateOptions {
            lifetime: Some(json!({ "type": "record", "advisory": { "retain_until": now - DAY } })),
            ..Default::default()
        },
    );
    assert!(matches!(open(&expired, &opts), Err(Error::Lifetime(_))));
    // §8.1 is explicit that a keyholder can disregard this, and this crate is
    // the independent opener the spec describes. Making the bypass an honest
    // option beats pretending it does not exist.
    let bypass = OpenOptions { ignore_advisory: true, ..keys_for(&[&alice]) };
    assert!(open(&expired, &bypass).is_ok());

    let locked = seal(
        b"x",
        &[Recipient::for_key(&alice).unwrap()],
        CreateOptions {
            lifetime: Some(json!({ "type": "timed_release", "advisory": { "release_at": now + DAY } })),
            ..Default::default()
        },
    );
    assert!(matches!(open(&locked, &opts), Err(Error::Lifetime(_))));
    let later = OpenOptions { now: Some(now + DAY + 1), ..keys_for(&[&alice]) };
    assert!(open(&locked, &later).is_ok());

    // §8.2: a passed disposal date describes the operator's retention schedule,
    // not the recipient's permission. It must never block an open.
    let disposed = seal(
        b"x",
        &[Recipient::for_key(&alice).unwrap()],
        CreateOptions {
            lifetime: Some(json!({ "type": "record", "disposal": { "at": now - DAY, "action": "delete" } })),
            ..Default::default()
        },
    );
    assert!(open(&disposed, &opts).is_ok(), "disposal must not block an open");
}

#[test]
fn key_files() {
    let alice = KeyRecord::generate("Alice");
    let restored = KeyRecord::from_cdpub(&alice.to_cdpub().unwrap()).unwrap();
    assert_eq!(restored.fingerprint().unwrap(), alice.fingerprint().unwrap());
    let restored = KeyRecord::from_cdkey(&alice.to_cdkey().unwrap()).unwrap();
    assert_eq!(restored.fingerprint().unwrap(), alice.fingerprint().unwrap());

    // A lying fingerprint must be refused: the value is derived, not
    // authoritative, and trusting it lets an attacker point a known-good label
    // at a key they control.
    let mut doc = alice.to_cdpub().unwrap();
    doc["fingerprint"] = json!("0000000000000000");
    assert!(KeyRecord::from_cdpub(&doc).is_err());
}

#[test]
fn encoding_rules() {
    // §4.0: base64url is not merely non-canonical, it is unparseable by the
    // reference — atob() throws on '-' and '_'.
    let alice = KeyRecord::generate("Alice");
    let cell = seal(
        &(0..512).map(|i| i as u8).collect::<Vec<u8>>(),
        &[Recipient::for_key(&alice).unwrap()],
        CreateOptions { sender: Some(alice.clone()), ..Default::default() },
    );
    for field in [&cell["payload"]["ciphertext"], &cell["payload"]["iv"], &cell["header_hash"], &cell["header_sig"]] {
        let s = field.as_str().unwrap();
        assert!(!s.contains('-') && !s.contains('_'), "base64url characters in {s}");
    }
    // Decoders SHOULD accept base64url on input; emitting it breaks readers.
    assert_eq!(
        crypto::decode_b64("-_8=", "t").unwrap(),
        crypto::decode_b64("+/8=", "t").unwrap()
    );
    // Sanity: the cell canonicalizes without error, which the hash relies on.
    assert!(canonicalize(&cell["header"]).is_ok());
}
