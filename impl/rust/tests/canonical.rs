// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! The shared canonical serialization vectors.
//!
//! Their expected strings come from the reference implementation and nowhere
//! else: §4.1.1 defines the canonical form by deferring to JavaScript's
//! `JSON.stringify`, so JavaScript is the authority on the right answer and
//! every other implementation checks itself against it. These run first in a
//! new port — no crypto, loud failures, and they catch the divergences that
//! otherwise surface only as a `header_hash` that never matches.

use cellular_defense::canonical::{canonicalize, js_number};
use serde_json::Value;
use std::path::PathBuf;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/canonical.json")
}

#[test]
fn shared_canonical_vectors() {
    let path = vectors_path();
    let Ok(data) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: canonical vectors not present at {}", path.display());
        return;
    };
    let file: Value = serde_json::from_str(&data).expect("parsing canonical vectors");
    let cases = file["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "canonical vector file is empty");

    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or("(unnamed)");
        let expected = case["expected"].as_str().expect("expected string");
        match canonicalize(&case["input"]) {
            Ok(got) if got == expected => {}
            Ok(got) => failures.push(format!("{name}:\n  got  {got}\n  want {expected}")),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} canonical vectors failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
    println!("checked {} canonical vectors against the reference", cases.len());
}

#[test]
fn js_number_edge_cases() {
    // Rust's Display for f64 never uses exponential form, so it disagrees with
    // JavaScript at both ends of the range.
    assert_eq!(js_number(1.0).unwrap(), "1");
    assert_eq!(js_number(-0.0).unwrap(), "0");
    assert_eq!(js_number(1e-7).unwrap(), "1e-7");
    assert_eq!(js_number(1e-6).unwrap(), "0.000001");
    assert_eq!(js_number(1e21).unwrap(), "1e+21");
    assert_eq!(js_number(1e20).unwrap(), "100000000000000000000");
    assert_eq!(js_number(0.1).unwrap(), "0.1");
    assert_eq!(js_number(5e-324).unwrap(), "5e-324");
    assert_eq!(js_number(f64::MAX).unwrap(), "1.7976931348623157e+308");
    assert!(js_number(f64::NAN).is_err());
    assert!(js_number(f64::INFINITY).is_err());
}

#[test]
fn key_order_is_preserved_on_parse() {
    // v1.0/v1.1 hash their header as JSON.stringify wrote it, in insertion
    // order. A parser backed by a sorted or hashed map could never reproduce
    // those bytes — hence serde_json's preserve_order feature.
    let value: Value = serde_json::from_str(r#"{"z":1,"a":2,"m":3}"#).unwrap();
    let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
    assert_eq!(keys, vec!["z", "a", "m"], "insertion order was not preserved");
    assert_eq!(canonicalize(&value).unwrap(), r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn explicit_null_is_not_an_absent_key() {
    // §6.4: share_index is omitted, not null, on non-quorum cells, and the two
    // forms hash differently. Both are internally valid.
    let with_null: Value = serde_json::from_str(r#"{"share_index":null}"#).unwrap();
    let without: Value = serde_json::from_str("{}").unwrap();
    assert_ne!(
        canonicalize(&with_null).unwrap(),
        canonicalize(&without).unwrap()
    );
}
