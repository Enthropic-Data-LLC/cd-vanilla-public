// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Shamir over GF(256) — spec §7.
//!
//! No interoperable standard exists for Shamir's scheme, which makes this the
//! largest interop risk in the format: split/combine round-trips pass no matter
//! which field or evaluation order was chosen, and disagreement only surfaces
//! when someone else's shares arrive. The fixed vector is what pins it down.

use cellular_defense::gf256::{combine, gf_inv, gf_mul, split, Share};

#[test]
fn known_products() {
    // AES's own field, so the MixColumns constants are the obvious probes.
    assert_eq!(gf_mul(0x57, 0x83), 0xC1);
    assert_eq!(gf_mul(0x57, 0x13), 0xFE);
    assert_eq!(gf_mul(0x02, 0x80), 0x1B); // reduction by 0x11b
}

#[test]
fn matches_the_russian_peasant_definition() {
    // The spec describes the shift-and-xor loop; this crate uses log tables.
    // They must agree on all 65,536 products or the tables are wrong.
    fn peasant(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(gf_mul(a, b), peasant(a, b), "{a:#x} * {b:#x}");
        }
    }
}

#[test]
fn inverses() {
    for x in 1..=255u8 {
        assert_eq!(gf_mul(x, gf_inv(x).unwrap()), 1);
    }
    assert!(gf_inv(0).is_err());
}

#[test]
fn split_and_combine() {
    let secret: Vec<u8> = (0..32).collect();
    let shares = split(&secret, 5, 3, None).unwrap();
    assert_eq!(shares.iter().map(|s| s.x).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5]);

    for combo in [[0, 1, 2], [0, 2, 4], [2, 3, 4], [1, 3, 4]] {
        let picked: Vec<Share> = combo.iter().map(|i| shares[*i].clone()).collect();
        assert_eq!(combine(&picked).unwrap(), secret, "combo {combo:?}");
    }
    assert_ne!(combine(&shares[..2]).unwrap(), secret, "k-1 shares must not reconstruct");
}

#[test]
fn deterministic_share_vector() {
    // Fixed coefficients, so these bytes are a conformance vector rather than a
    // round-trip: any implementation agreeing on the field, the evaluation order
    // and the x-coordinates produces exactly this. Matches the Python and Go
    // ports byte for byte.
    let shares = split(&[0x01, 0x02, 0x03], 3, 2, Some(&[0x10, 0x20, 0x30])).unwrap();
    let hex: Vec<String> = shares
        .iter()
        .map(|s| s.data.iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    assert_eq!(hex, vec!["112233", "214263", "316253"]);
    assert_eq!(combine(&shares[..2]).unwrap(), vec![0x01, 0x02, 0x03]);
}

#[test]
fn bad_input_is_refused() {
    let secret = [1u8, 2, 3, 4];
    let shares = split(&secret, 3, 2, None).unwrap();
    assert!(combine(&[]).is_err(), "no shares");
    assert!(
        combine(&[shares[0].clone(), shares[0].clone()]).is_err(),
        "duplicate indices"
    );
    let truncated = Share { x: shares[1].x, data: shares[1].data[..2].to_vec() };
    assert!(combine(&[shares[0].clone(), truncated]).is_err(), "length mismatch");
    assert!(split(&secret, 2, 3, None).is_err(), "k > n");
    assert!(split(&secret, 256, 2, None).is_err(), "n > 255");
}
