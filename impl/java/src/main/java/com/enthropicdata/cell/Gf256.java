// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.util.ArrayList;
import java.util.List;

/**
 * Shamir Secret Sharing over GF(256) — spec §7.
 *
 * <p>There is no interoperable standard for Shamir's scheme, so every
 * implementation hand-rolls it and every one is free to be subtly incompatible:
 * split/combine round-trips pass no matter which field, evaluation order or
 * x-coordinates you picked. The spec pins the three choices that matter and this
 * implements exactly those — GF(2^8) modulo 0x11b, one polynomial per secret
 * byte with the byte as constant term, share {@code i} evaluated at {@code x = i},
 * and reconstruction by Lagrange interpolation at {@code x = 0}.
 */
public final class Gf256 {

    private Gf256() {}

    private static final int[] EXP = new int[512];
    private static final int[] LOG = new int[256];

    static {
        int x = 1;
        for (int i = 0; i < 255; i++) {
            EXP[i] = x;
            LOG[x] = i;
            // multiply by the generator 3 (== x + 1)
            int hi = x & 0x80;
            x = (x << 1) ^ x;
            if (hi != 0) {
                x ^= 0x1B;
            }
            x &= 0xFF;
        }
        for (int i = 255; i < 512; i++) {
            EXP[i] = EXP[i - 255];
        }
    }

    /**
     * Multiply in GF(2^8).
     *
     * <p>Agrees with the Russian-peasant loop the spec describes on all 65,536
     * products; a test asserts that rather than assuming it.
     */
    public static int mul(int a, int b) {
        a &= 0xFF;
        b &= 0xFF;
        if (a == 0 || b == 0) {
            return 0;
        }
        return EXP[LOG[a] + LOG[b]];
    }

    /**
     * Multiplicative inverse. The spec gives {@code x^254} (Fermat); the table
     * gives the same value in one lookup.
     */
    public static int inv(int x) {
        x &= 0xFF;
        if (x == 0) {
            throw new CellException.Malformed("0 has no inverse in GF(2^8)");
        }
        return EXP[255 - LOG[x]];
    }

    /** One Shamir share: an x-coordinate and one y byte per secret byte. */
    public record Share(int x, byte[] data) {}

    /**
     * Split {@code secret} into {@code n} shares of which any {@code k}
     * reconstruct it.
     *
     * <p>{@code coefficients}, when non-null, supplies the polynomial
     * coefficients so a test vector can pin the exact shares; it must be
     * {@code (k - 1) * secret.length} bytes, ordered coefficient-major per byte
     * position. Production callers pass null.
     */
    public static List<Share> split(byte[] secret, int n, int k, byte[] coefficients) {
        if (k < 1 || n < k || n > 255) {
            throw new CellException.Malformed(
                    "invalid Shamir parameters " + k + "-of-" + n + " (need 1 <= k <= n <= 255)");
        }
        int needed = (k - 1) * secret.length;
        if (coefficients == null) {
            coefficients = CellCrypto.randomBytes(needed);
        } else if (coefficients.length != needed) {
            throw new CellException.Malformed(
                    "expected " + needed + " coefficient bytes, got " + coefficients.length);
        }

        List<Share> shares = new ArrayList<>(n);
        for (int i = 1; i <= n; i++) {
            shares.add(new Share(i, new byte[secret.length]));
        }
        int[] poly = new int[k];
        for (int bi = 0; bi < secret.length; bi++) {
            poly[0] = secret[bi] & 0xFF;
            for (int c = 1; c < k; c++) {
                poly[c] = coefficients[bi * (k - 1) + c - 1] & 0xFF;
            }
            for (Share share : shares) {
                // Horner from the high coefficient down — the reference's order.
                int y = poly[k - 1];
                for (int i = k - 2; i >= 0; i--) {
                    y = mul(y, share.x()) ^ poly[i];
                }
                share.data()[bi] = (byte) y;
            }
        }
        return shares;
    }

    /** Reconstruct the secret by Lagrange interpolation at {@code x = 0}. */
    public static byte[] combine(List<Share> shares) {
        if (shares == null || shares.isEmpty()) {
            throw new CellException.Malformed("no shares to combine");
        }
        int length = shares.get(0).data().length;
        boolean[] seen = new boolean[256];
        for (Share share : shares) {
            if (share.x() < 1 || share.x() > 255) {
                throw new CellException.Malformed(
                        "invalid share index " + share.x() + " — must be 1..255");
            }
            if (seen[share.x()]) {
                throw new CellException.Malformed("duplicate share index " + share.x());
            }
            seen[share.x()] = true;
            if (share.data().length != length) {
                throw new CellException.Malformed(
                        "shares differ in length — they are not from one secret");
            }
        }

        byte[] out = new byte[length];
        for (int bi = 0; bi < length; bi++) {
            int acc = 0;
            for (int i = 0; i < shares.size(); i++) {
                int num = 1;
                int den = 1;
                for (int j = 0; j < shares.size(); j++) {
                    if (i == j) {
                        continue;
                    }
                    num = mul(num, shares.get(j).x());
                    den = mul(den, shares.get(i).x() ^ shares.get(j).x());
                }
                acc ^= mul(shares.get(i).data()[bi] & 0xFF, mul(num, inv(den)));
            }
            out[bi] = (byte) acc;
        }
        return out;
    }
}
