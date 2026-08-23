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
