# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""The shared conformance test keys in ``conformance/keys/``.

These fixtures are the fixed cast every vector refers to by name, so their
fingerprints are part of the conformance contract: if a change to SPKI encoding
or fingerprint derivation moves them, every vector in every language port
silently stops matching. Pinning them here is what turns that into a test
failure instead of a mystery.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cellular_defense import KeyRecord, Recipient, cell_create, cell_open
from cellular_defense.errors import NoMatchingKeyError

KEYS_DIR = Path(__file__).resolve().parents[3] / "conformance" / "keys"

#: Derived from a documented string (see conformance/make-test-keys.py), so any
#: implementation can regenerate them from nothing but the label.
EXPECTED_FINGERPRINTS = {
    "alice": "97017b8bf3caab2d",
    "bob": "aff6a52990ce2335",
    "carol": "e3acafc957ac89fb",
    "dave": "6574194ee815c0f2",
    "mallory": "425f2c9a0c017fa6",
}


def load(name: str, suffix: str = "cdkey") -> KeyRecord:
    doc = json.loads((KEYS_DIR / f"{name}.{suffix}").read_text())
    return KeyRecord.from_cdkey(doc) if suffix == "cdkey" else KeyRecord.from_cdpub(doc)


@unittest.skipUnless(KEYS_DIR.is_dir(), "conformance keys are not present")
class TestConformanceKeys(unittest.TestCase):
    def test_fingerprints_are_pinned(self):
        for name, expected in EXPECTED_FINGERPRINTS.items():
            with self.subTest(key=name):
                self.assertEqual(load(name).fingerprint, expected)

    def test_public_and_private_files_agree(self):
        for name in EXPECTED_FINGERPRINTS:
            with self.subTest(key=name):
                self.assertEqual(load(name, "cdpub").spki, load(name, "cdkey").spki)

    def test_manifest_matches_the_key_files(self):
        manifest = json.loads((KEYS_DIR / "keys.json").read_text())
        self.assertEqual(
            {name: entry["fingerprint"] for name, entry in manifest["keys"].items()},
            EXPECTED_FINGERPRINTS,
        )

    def test_derivation_is_reproducible(self):
        # Re-derive from the documented rule and check we land on the same key.
        import hashlib

        from cryptography.hazmat.primitives.asymmetric import ec

        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        seed = b"cellular-defense conformance key v1: alice"
        d = int.from_bytes(hashlib.sha256(seed).digest(), "big") % n
        derived = KeyRecord("Alice", ec.derive_private_key(d, ec.SECP256R1()).public_key())
        self.assertEqual(derived.fingerprint, EXPECTED_FINGERPRINTS["alice"])

    def test_round_trip_with_the_fixture_cast(self):
        alice, bob, mallory = load("alice"), load("bob"), load("mallory")
        cell = cell_create(b"conformance payload", "p.txt", [Recipient.for_key(alice)], sender=bob)
        result = cell_open(cell, keys=[alice], expected_signer=bob.fingerprint)
        self.assertEqual(result.data, b"conformance payload")
        with self.assertRaises(NoMatchingKeyError):
            cell_open(cell, keys=[mallory])

    def test_quorum_with_the_fixture_cast(self):
        cast = [load(n) for n in ("alice", "bob", "carol", "dave")]
        manifest = json.loads((KEYS_DIR / "keys.json").read_text())
        cell = cell_create(
            b"quorum payload",
            "q.txt",
            [Recipient.for_key(k) for k in cast]
            + [Recipient.passphrase_(manifest["passphrase"])],
            threshold=3,
        )
        self.assertEqual(cell_open(cell, keys=cast[:3]).data, b"quorum payload")
        self.assertEqual(
            cell_open(cell, keys=cast[:2], passphrases=[manifest["passphrase"]]).data,
            b"quorum payload",
        )


if __name__ == "__main__":
    unittest.main()
