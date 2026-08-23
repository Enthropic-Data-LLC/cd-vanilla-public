// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Shamir Secret Sharing over GF(256) — spec §7.
//!
//! There is no interoperable standard for Shamir's scheme, so every
//! implementation hand-rolls it and every one is free to be subtly
//! incompatible: split/combine round-trips pass no matter which field,
//! evaluation order or x-coordinates you picked. The spec pins the three
//! choices that matter and this implements exactly those — GF(2^8) modulo
//! 0x11b, one polynomial per secret byte with the byte as constant term, share
//! `i` evaluated at `x = i`, and reconstruction by Lagrange interpolation at
//! `x = 0`.

use rand_core::{OsRng, RngCore};
use std::sync::LazyLock;

use crate::error::{Error, Result};

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u8 = 1;
    for i in 0..255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        // multiply by the generator 3 (== x + 1)
        let hi = x & 0x80;
        x = (x << 1) ^ x;
        if hi != 0 {
            x ^= 0x1B;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    Tables { exp, log }
});

/// Multiply in GF(2^8).
///
/// Agrees with the Russian-peasant loop the spec describes on all 65,536
/// products; a test asserts that rather than assuming it.
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = &*TABLES;
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

/// Multiplicative inverse. The spec gives `x^254` (Fermat); the table gives the
/// same value in one lookup.
pub fn gf_inv(x: u8) -> Result<u8> {
    if x == 0 {
        return Err(Error::Malformed("0 has no inverse in GF(2^8)".into()));
    }
    let t = &*TABLES;
    Ok(t.exp[255 - t.log[x as usize] as usize])
}

/// One Shamir share: an x-coordinate and one y byte per secret byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub x: u8,
    pub data: Vec<u8>,
}

/// Split `secret` into `n` shares of which any `k` reconstruct it.
///
/// `coefficients`, when `Some`, supplies the polynomial coefficients so a test
/// vector can pin the exact shares; it must be `(k - 1) * secret.len()` bytes,
/// ordered coefficient-major per byte position. Production callers pass `None`.
pub fn split(secret: &[u8], n: usize, k: usize, coefficients: Option<&[u8]>) -> Result<Vec<Share>> {
    if k < 1 || n < k || n > 255 {
        return Err(Error::Malformed(format!(
            "invalid Shamir parameters {k}-of-{n} (need 1 <= k <= n <= 255)"
        )));
    }
    let needed = (k - 1) * secret.len();
    let owned;
    let coefficients = match coefficients {
        Some(c) if c.len() == needed => c,
        Some(c) => {
            return Err(Error::Malformed(format!(
                "expected {needed} coefficient bytes, got {}",
                c.len()
            )))
        }
        None => {
            let mut buf = vec![0u8; needed];
            OsRng.fill_bytes(&mut buf);
            owned = buf;
            &owned
        }
    };

    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x: x as u8,
            data: vec![0u8; secret.len()],
        })
        .collect();

    let mut poly = vec![0u8; k];
    for (bi, byte) in secret.iter().enumerate() {
        poly[0] = *byte;
        poly[1..].copy_from_slice(&coefficients[bi * (k - 1)..(bi + 1) * (k - 1)]);
        for share in shares.iter_mut() {
            // Horner from the high coefficient down — the reference's order.
            let mut y = poly[k - 1];
            for i in (0..k - 1).rev() {
                y = gf_mul(y, share.x) ^ poly[i];
            }
            share.data[bi] = y;
        }
    }
    Ok(shares)
}

/// Reconstruct the secret by Lagrange interpolation at `x = 0`.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(Error::Malformed("no shares to combine".into()));
    }
    let length = shares[0].data.len();
    let mut seen = [false; 256];
    for share in shares {
        if share.x == 0 {
            return Err(Error::Malformed(
                "invalid share index 0 — must be 1..255".into(),
            ));
        }
        if seen[share.x as usize] {
            return Err(Error::Malformed(format!(
                "duplicate share index {}",
                share.x
            )));
        }
        seen[share.x as usize] = true;
        if share.data.len() != length {
            return Err(Error::Malformed(
                "shares differ in length — they are not from one secret".into(),
            ));
        }
    }

    let mut out = vec![0u8; length];
    for (bi, slot) in out.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, si) in shares.iter().enumerate() {
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = gf_mul(num, sj.x);
                den = gf_mul(den, si.x ^ sj.x);
            }
            acc ^= gf_mul(si.data[bi], gf_mul(num, gf_inv(den)?));
        }
        *slot = acc;
    }
    Ok(out)
}
