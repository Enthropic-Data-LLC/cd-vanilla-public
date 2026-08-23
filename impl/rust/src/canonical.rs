// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Canonical JSON serialization — spec §4.1.1.
//!
//! `header_hash`, `header_sig` and the AES-GCM AAD are computed over these
//! bytes, so disagreeing with the reference by one byte means verifying
//! nothing. The spec defines the canonical form by deferring to JavaScript's
//! `JSON.stringify`, which imports three behaviours Rust does not share:
//!
//! 1. **Number formatting.** JS prints the shortest round-tripping decimal and
//!    never a trailing `.0` — `1.0` is `1`, `1e-7` is `1e-7`. Rust's `Display`
//!    for `f64` prints `1` and `0.0000001`: it never uses exponential form, so
//!    it disagrees at both ends of the range. [`js_number`] implements
//!    ECMA-262 6.1.6.1.20 instead.
//!
//! 2. **Key ordering.** JS sorts strings by UTF-16 code unit. Rust's `Ord` for
//!    `str` compares UTF-8 bytes, which is code-point order — the two disagree
//!    for any character above the BMP, which sorts *below* U+E000..U+FFFF in
//!    JavaScript and above it in Rust.
//!
//! 3. **String escaping.** `serde_json` escapes correctly for JSON but is not
//!    a `JSON.stringify` workalike in every detail, and relying on another
//!    crate's escaping choices for bytes that get hashed is a hostage to
//!    fortune. [`js_string`] does it by hand.
//!
//! `serde_json` is built with the `preserve_order` feature so object keys keep
//! their insertion order: v1.0 and v1.1 hash their header as `JSON.stringify`
//! wrote it, not sorted (§12), and a header parsed into a sorted or hashed map
//! could never be re-serialized to the bytes it was signed over.

use serde_json::Value;
use std::fmt::Write as _;

use crate::error::{Error, Result};

/// Format a number exactly as JavaScript's `String(n)` would.
///
/// Implements ECMA-262 6.1.6.1.20 (Number::toString, radix 10), which is what
/// `JSON.stringify` uses for finite numbers.
pub fn js_number(value: f64) -> Result<String> {
    if value.is_nan() || value.is_infinite() {
        return Err(Error::Canonicalization(format!(
            "{value} is not representable in JSON"
        )));
    }
    if value == 0.0 {
        return Ok("0".to_string()); // JS prints -0 as "0" too
    }

    let sign = if value < 0.0 { "-" } else { "" };
    let magnitude = value.abs();

    // `{:e}` gives the shortest round-tripping digits in exponential form, from
    // which the ECMA-262 s/k/n triple falls out directly.
    let formatted = format!("{magnitude:e}");
    let (mantissa, exponent_text) = formatted
        .split_once('e')
        .ok_or_else(|| Error::Canonicalization(format!("cannot decompose {value}")))?;
    let exponent: i32 = exponent_text
        .parse()
        .map_err(|_| Error::Canonicalization(format!("cannot decompose {value}")))?;

    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exponent + 1; // value == 0.<digits> * 10^n

    if k <= n && n <= 21 {
        return Ok(format!("{sign}{digits}{}", "0".repeat((n - k) as usize)));
    }
    if 0 < n && n <= 21 {
        let (head, tail) = digits.split_at(n as usize);
        return Ok(format!("{sign}{head}.{tail}"));
    }
    if -6 < n && n <= 0 {
        return Ok(format!(
            "{sign}0.{}{digits}",
            "0".repeat((-n) as usize)
        ));
    }

    let e = n - 1;
    let exponent_sign = if e >= 0 { '+' } else { '-' };
    let magnitude_of_e = e.abs();
    if k == 1 {
        Ok(format!("{sign}{digits}e{exponent_sign}{magnitude_of_e}"))
    } else {
        let (head, tail) = digits.split_at(1);
        Ok(format!(
            "{sign}{head}.{tail}e{exponent_sign}{magnitude_of_e}"
        ))
    }
}

/// Quote and escape a string exactly as `JSON.stringify` does.
///
/// Note what is *not* escaped: `/`, `<`, `>`, `&`, U+2028 and U+2029. Several
/// JSON encoders escape some of those for HTML or JavaScript-source safety, and
/// every one of those escapes changes the hash.
pub fn js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Compare two strings by UTF-16 code unit, which is JavaScript's string order.
///
/// `Array.prototype.sort` compares UTF-16 code units, so a character above the
/// BMP compares as its surrogate pair (0xD800-0xDFFF) and sorts *before*
/// U+E000..U+FFFF. Rust's byte-wise `Ord` would sort it after.
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Return the canonical JSON serialization of `value` (spec §4.1.1).
pub fn canonicalize(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(&mut out, value)?;
    Ok(out)
}

/// UTF-8 bytes of [`canonicalize`] — what actually gets hashed and signed.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(canonicalize(value)?.into_bytes())
}

fn write_canonical(out: &mut String, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => out.push_str(&js_string(s)),
        Value::Number(n) => {
            let f = n.as_f64().ok_or_else(|| {
                Error::Canonicalization(format!("number {n} is not representable as f64"))
            })?;
            out.push_str(&js_number(f)?);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&js_string(key));
                out.push(':');
                write_canonical(out, &map[key.as_str()])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `JSON.stringify(v)` with *insertion* order — the v1.0/v1.1 serialization.
///
/// Those versions hash and sign their header in the order the reference
/// happened to build it (§12). This is why the crate depends on `serde_json`
/// with `preserve_order`.
pub fn js_stringify(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_stringify(&mut out, value)?;
    Ok(out)
}

fn write_stringify(out: &mut String, value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&js_string(key));
                out.push(':');
                write_stringify(out, item)?;
            }
            out.push('}');
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_stringify(out, item)?;
            }
            out.push(']');
            Ok(())
        }
        other => write_canonical(out, other),
    }
}
