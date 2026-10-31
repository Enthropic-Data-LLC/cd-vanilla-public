// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Error type.
//!
//! The variants exist because the distinctions matter to a caller: "this file
//! is not a cell I can read", "this cell has been tampered with" and "you gave
//! me the wrong key" call for three different responses, and the reference
//! implementation collapses all of them into `Error(string)`.

use std::fmt;

/// Every failure this crate can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `cell.version` is present but not in [`SUPPORTED_VERSIONS`](crate::SUPPORTED_VERSIONS).
    UnsupportedVersion(String),
    /// Structurally invalid: missing header, bad base64, truncated manifest,
    /// a signature of the wrong length.
    Malformed(String),
    /// `header_hash` or `payload_hash` mismatch, or a missing `header_hash`.
    Integrity(String),
    /// `header_sig` is present and does not verify, or an expected signer was
    /// required and did not match.
    Signature(String),
    /// The v1.4 inner `sender.sig` (spec §4.5) does not verify, or an expected
    /// signer was required and did not match. Kept distinct from `Signature`
    /// — both are checked the same way, but a v1.4 cell carries no
    /// `header_sig` at all, and a failure reported as "header signature
    /// invalid" sent readers to the wrong field name and the wrong spec
    /// section (found in pen test, 2026-10-31).
    SenderSignature(String),
    /// An advisory lifetime gate refused the open (spec §8.1). Advisory means
    /// advisory: a keyholder can bypass this and the specification says so.
    Lifetime(String),
    /// No access-map entry could be unwrapped with the material provided.
    NoMatchingKey,
    /// Fewer than `threshold.required` shares were recovered.
    QuorumNotMet { needed: usize, unlocked: usize },
    /// The AES-GCM tag failed: the ciphertext or the AAD-bound metadata does
    /// not match what was sealed (spec §4.4).
    Decryption,
    /// A value cannot be serialized compatibly with the reference (spec §4.1.1).
    Canonicalization(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedVersion(v) => write!(
                f,
                "unsupported cell format version {v:?} — update the app to open this cell"
            ),
            Error::Malformed(m) => write!(f, "malformed cell: {m}"),
            Error::Integrity(m) => write!(f, "integrity check failed — {m}"),
            Error::Signature(m) => write!(f, "header signature invalid — {m}"),
            Error::SenderSignature(m) => write!(f, "sender signature invalid — {m}"),
            Error::Lifetime(m) => write!(f, "{m}"),
            Error::NoMatchingKey => {
                write!(f, "no matching key — check your key method and try again")
            }
            Error::QuorumNotMet { needed, unlocked } => {
                write!(f, "quorum not met — need {needed}, unlocked {unlocked}")
            }
            Error::Decryption => write!(
                f,
                "authentication failed — the ciphertext or the AAD-bound metadata \
                 (prev_hash/threshold/lifetime/policy) does not match what was sealed"
            ),
            Error::Canonicalization(m) => write!(f, "cannot canonicalize value: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Format a Unix timestamp (seconds, UTC) as `YYYY-MM-DD HH:MM UTC`, matching
/// the Python and Go ports' lifetime-gate error text. No `chrono`/`time`
/// dependency: the crate is otherwise dependency-light, and this is the one
/// place that needed a calendar, so it is hand-rolled rather than adding one
/// for a single error message (found in pen test, 2026-10-31 — this used to
/// print the raw epoch integer).
///
/// `civil_from_days` is Howard Hinnant's proleptic-Gregorian algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>),
/// correct for the full `i64` range this format needs.
pub(crate) fn format_unix_utc(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs_of_day = ts.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs_of_day / 3600, (secs_of_day % 3600) / 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod format_tests {
    use super::format_unix_utc;

    #[test]
    fn known_instants() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_unix_utc(1577836800), "2020-01-01 00:00 UTC");
        assert_eq!(format_unix_utc(4102444800), "2100-01-01 00:00 UTC");
        assert_eq!(format_unix_utc(-1), "1969-12-31 23:59 UTC");
    }
}
