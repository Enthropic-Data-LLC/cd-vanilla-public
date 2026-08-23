// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! ULID document identifiers — spec §4.1, §14.
//!
//! 26 characters of Crockford base32: a 48-bit millisecond timestamp in the
//! first 10, 80 bits of CSPRNG output in the last 16. Lexicographically
//! sortable by creation time, which is the only property the format relies on.

use crate::crypto;
use crate::error::{Error, Result};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a ULID. The arguments exist so vectors can be reproduced; pass
/// `None` in production.
pub fn ulid(timestamp_ms: Option<u64>, randomness: Option<&[u8]>) -> Result<String> {
    let mut t = timestamp_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    if t >= 1 << 48 {
        return Err(Error::Malformed("ULID timestamp must fit in 48 bits".into()));
    }
    let owned;
    let rand = match randomness {
        Some(r) if r.len() == 10 => r,
        Some(_) => {
            return Err(Error::Malformed(
                "ULID randomness must be exactly 10 bytes".into(),
            ))
        }
        None => {
            owned = crypto::random_bytes(10);
            &owned
        }
    };

    let mut out = [0u8; 26];
    for i in (0..10).rev() {
        out[i] = CROCKFORD[(t & 31) as usize];
        t >>= 5;
    }
    let mut value: u128 = 0;
    for b in rand {
        value = (value << 8) | *b as u128;
    }
    for i in (10..26).rev() {
        out[i] = CROCKFORD[(value & 31) as usize];
        value >>= 5;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}
