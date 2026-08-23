// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

/**
 * ULID document identifiers — spec §4.1, §14.
 *
 * <p>26 characters of Crockford base32: a 48-bit millisecond timestamp in the
 * first 10, 80 bits of CSPRNG output in the last 16. Lexicographically sortable
 * by creation time, which is the only property the format relies on.
 */
public final class Ulid {

    private Ulid() {}

    private static final char[] CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();

    public static String generate() {
        return generate(System.currentTimeMillis(), CellCrypto.randomBytes(10));
    }

    /** Generate a ULID with a fixed timestamp and randomness, for vectors. */
    public static String generate(long timestampMs, byte[] randomness) {
        if (timestampMs < 0 || timestampMs >= (1L << 48)) {
            throw new CellException.Malformed("ULID timestamp must fit in 48 bits");
        }
        if (randomness.length != 10) {
            throw new CellException.Malformed("ULID randomness must be exactly 10 bytes");
        }
        char[] out = new char[26];
        long t = timestampMs;
        for (int i = 9; i >= 0; i--) {
            out[i] = CROCKFORD[(int) (t & 31)];
            t >>= 5;
        }
        // 80 bits of randomness is exactly sixteen 5-bit groups, so read it as a
        // bit stream MSB-first rather than trying to hold it in a long.
        int bitPosition = 0;
        for (int i = 10; i < 26; i++) {
            int value = 0;
            for (int bit = 0; bit < 5; bit++, bitPosition++) {
                int byteIndex = bitPosition >>> 3;
                int shift = 7 - (bitPosition & 7);
                value = (value << 1) | ((randomness[byteIndex] >>> shift) & 1);
            }
            out[i] = CROCKFORD[value];
        }
        return new String(out);
    }
}
