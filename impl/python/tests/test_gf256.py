# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Shamir over GF(256) — spec §7.

There is no interoperable standard for Shamir's scheme, which makes this the
single largest interop risk in the format: every implementation hand-rolls it,
split/combine round-trips pass no matter what field or evaluation order you
chose, and the disagreement only surfaces when someone else's shares arrive.
The fixed vectors here are what actually pin the choices down.
"""

import unittest

from cellular_defense import gf256
from cellular_defense.errors import CellError


class TestFieldArithmetic(unittest.TestCase):
    def test_known_products(self):
        # AES's own field, so the MixColumns constants are the obvious probes.
        self.assertEqual(gf256.gf_mul(0x57, 0x83), 0xC1)
        self.assertEqual(gf256.gf_mul(0x57, 0x13), 0xFE)
        self.assertEqual(gf256.gf_mul(0x02, 0x80), 0x1B)  # reduction by 0x11b

    def test_zero_and_identity(self):
        for x in range(256):
            self.assertEqual(gf256.gf_mul(x, 0), 0)
            self.assertEqual(gf256.gf_mul(x, 1), x)

    def test_commutative_and_inverse(self):
        for x in range(1, 256):
            self.assertEqual(gf256.gf_mul(x, gf256.gf_inv(x)), 1)
        with self.assertRaises(ZeroDivisionError):
            gf256.gf_inv(0)

    def test_matches_the_russian_peasant_definition(self):
        # The spec describes the shift-and-xor loop; this module uses log tables.
        # They must agree on all 65,536 products or the tables are wrong.
        def peasant(a: int, b: int) -> int:
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xFF
                if hi:
                    a ^= 0x1B
                b >>= 1
            return p

        for a in range(256):
            for b in range(256):
                self.assertEqual(gf256.gf_mul(a, b), peasant(a, b), f"{a:#x}*{b:#x}")


class TestSplitCombine(unittest.TestCase):
    SECRET = bytes(range(32))

    def test_any_k_of_n_reconstructs(self):
        shares = gf256.split(self.SECRET, 5, 3)
        self.assertEqual([s.x for s in shares], [1, 2, 3, 4, 5])
        for combo in ((0, 1, 2), (0, 2, 4), (2, 3, 4), (1, 3, 4)):
            picked = [shares[i] for i in combo]
            self.assertEqual(gf256.combine(picked), self.SECRET)

    def test_fewer_than_k_reveals_nothing(self):
        shares = gf256.split(self.SECRET, 5, 3)
        self.assertNotEqual(gf256.combine(shares[:2]), self.SECRET)

    def test_more_than_k_still_reconstructs(self):
        shares = gf256.split(self.SECRET, 5, 3)
        self.assertEqual(gf256.combine(shares), self.SECRET)

    def test_one_of_one_is_the_secret_itself(self):
        # k=1 means a degree-0 polynomial: every share IS the secret. Worth
        # stating, because it is why non-quorum cells wrap the CEK directly
        # rather than running a pointless split.
        shares = gf256.split(self.SECRET, 3, 1)
        for share in shares:
            self.assertEqual(share.data, self.SECRET)

    def test_deterministic_vector(self):
        # Fixed coefficients, so these bytes are a conformance vector rather
        # than a round-trip: any implementation that agrees on the field, the
        # evaluation order and the x-coordinates produces exactly this.
        secret = bytes([0x01, 0x02, 0x03])
        rand = bytes([0x10, 0x20, 0x30])  # one coefficient per byte, k=2
        shares = gf256.split(secret, 3, 2, rand=rand)
        self.assertEqual(
            [(s.x, s.data.hex()) for s in shares],
            [(1, "112233"), (2, "214263"), (3, "316253")],
        )
        self.assertEqual(gf256.combine(shares[:2]), secret)
        self.assertEqual(gf256.combine([shares[0], shares[2]]), secret)

    def test_duplicate_indices_are_refused(self):
        shares = gf256.split(self.SECRET, 3, 2)
        with self.assertRaises(CellError):
            gf256.combine([shares[0], shares[0]])

    def test_invalid_parameters_are_refused(self):
        with self.assertRaises(CellError):
            gf256.split(self.SECRET, 2, 3)  # k > n
        with self.assertRaises(CellError):
            gf256.split(self.SECRET, 256, 2)  # n > 255 x-coordinates available
        with self.assertRaises(CellError):
            gf256.combine([])

    def test_mismatched_share_lengths_are_refused(self):
        shares = gf256.split(self.SECRET, 3, 2)
        truncated = gf256.Share(shares[1].x, shares[1].data[:16])
        with self.assertRaises(CellError):
            gf256.combine([shares[0], truncated])


if __name__ == "__main__":
    unittest.main()
