// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Shamir over GF(256) — spec §7.
 *
 * <p>No interoperable standard exists for Shamir's scheme, which makes this the
 * largest interop risk in the format: split/combine round-trips pass no matter
 * which field or evaluation order was chosen, and disagreement only surfaces
 * when someone else's shares arrive. The fixed vector is what pins it down.
 */
class Gf256Test {

    @Test
    void knownProducts() {
        // AES's own field, so the MixColumns constants are the obvious probes.
        assertEquals(0xC1, Gf256.mul(0x57, 0x83));
        assertEquals(0xFE, Gf256.mul(0x57, 0x13));
        assertEquals(0x1B, Gf256.mul(0x02, 0x80)); // reduction by 0x11b
    }

    @Test
    void matchesTheRussianPeasantDefinition() {
        // The spec describes the shift-and-xor loop; this class uses log tables.
        // They must agree on all 65,536 products or the tables are wrong.
        for (int a = 0; a < 256; a++) {
            for (int b = 0; b < 256; b++) {
                assertEquals(peasant(a, b), Gf256.mul(a, b), a + " * " + b);
            }
        }
    }

    private static int peasant(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            int hi = a & 0x80;
            a = (a << 1) & 0xFF;
            if (hi != 0) {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        return p;
    }

    @Test
    void inverses() {
        for (int x = 1; x < 256; x++) {
            assertEquals(1, Gf256.mul(x, Gf256.inv(x)));
        }
        assertThrows(CellException.Malformed.class, () -> Gf256.inv(0));
    }

    @Test
    void splitAndCombine() {
        byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) i;
        }
        List<Gf256.Share> shares = Gf256.split(secret, 5, 3, null);
        for (int i = 0; i < shares.size(); i++) {
            assertEquals(i + 1, shares.get(i).x());
        }
        for (int[] combo : new int[][] {{0, 1, 2}, {0, 2, 4}, {2, 3, 4}, {1, 3, 4}}) {
            List<Gf256.Share> picked = new ArrayList<>();
            for (int index : combo) {
                picked.add(shares.get(index));
            }
            assertArrayEquals(secret, Gf256.combine(picked));
        }
        assertFalse(java.util.Arrays.equals(secret, Gf256.combine(shares.subList(0, 2))),
                "fewer than k shares must not reconstruct");
    }

    @Test
    void deterministicShareVector() {
        // Fixed coefficients, so these bytes are a conformance vector rather
        // than a round-trip: any implementation agreeing on the field, the
        // evaluation order and the x-coordinates produces exactly this. Matches
        // the Python, Go and Rust ports byte for byte.
        List<Gf256.Share> shares = Gf256.split(
                new byte[] {0x01, 0x02, 0x03}, 3, 2, new byte[] {0x10, 0x20, 0x30});
        String[] expected = {"112233", "214263", "316253"};
        for (int i = 0; i < shares.size(); i++) {
            assertEquals(expected[i], hex(shares.get(i).data()));
        }
        assertArrayEquals(new byte[] {0x01, 0x02, 0x03}, Gf256.combine(shares.subList(0, 2)));
    }

    @Test
    void badInputIsRefused() {
        byte[] secret = {1, 2, 3, 4};
        List<Gf256.Share> shares = Gf256.split(secret, 3, 2, null);
        assertThrows(CellException.Malformed.class, () -> Gf256.combine(List.of()));
        assertThrows(CellException.Malformed.class,
                () -> Gf256.combine(List.of(shares.get(0), shares.get(0))));
        Gf256.Share truncated = new Gf256.Share(shares.get(1).x(),
                java.util.Arrays.copyOf(shares.get(1).data(), 2));
        assertThrows(CellException.Malformed.class,
                () -> Gf256.combine(List.of(shares.get(0), truncated)));
        assertThrows(CellException.Malformed.class, () -> Gf256.split(secret, 2, 3, null));
        assertThrows(CellException.Malformed.class, () -> Gf256.split(secret, 256, 2, null));
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }
}
