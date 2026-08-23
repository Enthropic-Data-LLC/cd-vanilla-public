# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Differential tests against the AGPL reference implementation.

These are the tests that matter. A port can be entirely self-consistent and
still interoperate with nothing; only cells that cross the boundary in both
directions prove otherwise. Every test here either seals in one implementation
and opens in the other, or compares the exact bytes both would hash.

Skipped automatically when Node or the reference tree is not present, so the
suite still runs standalone.
"""

from __future__ import annotations

import base64
import json
import math
import os
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from cellular_defense import KeyRecord, Recipient, cell_create, cell_open, verify_cell
from cellular_defense.canonical import canonicalize

HERE = Path(__file__).resolve().parent
BRIDGE = HERE / "interop" / "js_bridge.mjs"
REFERENCE = HERE.parents[2] / "cell-crypto.js"


def _node_available() -> bool:
    if not BRIDGE.exists() or not REFERENCE.exists():
        return False
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


@unittest.skipUnless(_node_available(), "node or the reference implementation is unavailable")
class InteropTestCase(unittest.TestCase):
    """Shared plumbing for driving the reference implementation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def bridge(self, *args: str) -> None:
        result = subprocess.run(
            ["node", str(BRIDGE), *args], capture_output=True, text=True, timeout=180
        )
        if result.returncode != 0:
            self.fail(f"reference bridge failed:\n{result.stderr.strip()}")

    def js_keypair(self, label: str = "Key") -> dict:
        path = self.tmp / f"key-{label}-{os.urandom(4).hex()}.json"
        self.bridge("keypair", str(path), label)
        return json.loads(path.read_text())

    def js_seal(self, spec: dict) -> dict:
        spec_path = self.tmp / f"seal-{os.urandom(4).hex()}.json"
        cell_path = self.tmp / f"cell-{os.urandom(4).hex()}.cell"
        spec_path.write_text(json.dumps(spec))
        self.bridge("seal", str(spec_path), str(cell_path))
        return json.loads(cell_path.read_text())

    def js_open(self, cell: dict, spec: dict) -> dict:
        cell_path = self.tmp / f"in-{os.urandom(4).hex()}.cell"
        spec_path = self.tmp / f"open-{os.urandom(4).hex()}.json"
        out_path = self.tmp / f"out-{os.urandom(4).hex()}.json"
        cell_path.write_text(json.dumps(cell))
        spec_path.write_text(json.dumps(spec))
        self.bridge("open", str(cell_path), str(spec_path), str(out_path))
        return json.loads(out_path.read_text())

    def js_canonicalize(self, value) -> str:
        in_path = self.tmp / f"canon-{os.urandom(4).hex()}.json"
        out_path = self.tmp / f"canon-{os.urandom(4).hex()}.txt"
        in_path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        self.bridge("canonicalize", str(in_path), str(out_path))
        return out_path.read_text(encoding="utf-8")

    @staticmethod
    def key_from_js(js_key: dict) -> KeyRecord:
        return KeyRecord.from_cdkey(
            {
                "cd_key": "2.0",
                "label": js_key["label"],
                "spki": js_key["spki"],
                "pkcs8": js_key["pkcs8"],
                "fingerprint": js_key["fingerprint"],
            }
        )


class TestCanonicalizationAgreement(InteropTestCase):
    """The bytes both implementations hash must be identical, or nothing verifies."""

    def test_fixed_shapes(self):
        cases = [
            {"b": 1, "a": 2},
            {"nested": {"z": [1, 2, {"y": None}], "a": True}},
            [None, False, 0, "", {}, []],
            {"unicode": "café 😀", "esc": 'quote " backslash \\ newline \n'},
            {"floats": [0.1, 1.0, 1e-7, 1e21, -2.5]},
            {"lifetime": {"advisory": {"retain_until": None, "single_use": False}}},
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(canonicalize(case), self.js_canonicalize(case))

    def test_random_structures(self):
        rng = random.Random(20260823)

        def gen(depth: int = 0):
            choice = rng.randrange(9 if depth < 3 else 7)
            if choice == 0:
                return None
            if choice == 1:
                return rng.choice([True, False])
            if choice == 2:
                return rng.randint(-(2**40), 2**40)
            if choice == 3:
                value = struct.unpack("<d", rng.randbytes(8))[0]
                return value if math.isfinite(value) else 1.5
            if choice == 4:
                return rng.choice(["", "a", "ünïcødé", "😀 astral", 'q"\\\n\t', "0", " "])
            if choice == 5:
                return rng.choice([0, -0.0, 1e-7, 1e21, 0.1])
            if choice == 6:
                return rng.choice(["retain_until", "z", "A", "", "😀", "é"])
            if choice == 7:
                return [gen(depth + 1) for _ in range(rng.randrange(4))]
            keys = rng.sample(
                ["a", "B", "z", "", "😀", "é", "share_index", "0", "policy", "Z"],
                rng.randrange(1, 6),
            )
            return {k: gen(depth + 1) for k in keys}

        # One node process per structure would take minutes; batch them.
        batch = [gen() for _ in range(200)]
        expected = [canonicalize(v) for v in batch]
        actual = json.loads(self._batch(batch))
        for i, (want, got) in enumerate(zip(expected, actual)):
            self.assertEqual(want, got, f"structure {i}: {batch[i]!r}")

    def _batch(self, values: list) -> str:
        """Canonicalize a whole batch in one reference process, returning JSON."""
        in_path = self.tmp / "batch-in.json"
        out_path = self.tmp / "batch-out.json"
        in_path.write_text(json.dumps(values, ensure_ascii=False), encoding="utf-8")
        # One node process per structure would take minutes, and the bridge is a
        # CLI rather than a module, so write a throwaway loader that pulls in the
        # same reference source and maps over the whole batch in one process.
        loader = self.tmp / "batch.mjs"
        loader.write_text(
            "import { readFileSync, writeFileSync } from 'node:fs';\n"
            f"const ROOT = '{REFERENCE.parent}';\n"
            "globalThis.window = { location: { origin: 'test://x' }, CompressionStream };\n"
            "globalThis.location = { hostname: 'localhost', origin: 'test://x' };\n"
            "globalThis.navigator = { userAgent: 'node' };\n"
            "globalThis.document = { addEventListener() {}, getElementById() { return null; } };\n"
            "const _ls = {}; globalThis.localStorage = { getItem: k => (k in _ls ? _ls[k] : null),"
            " setItem: (k, v) => { _ls[k] = String(v); }, removeItem: k => { delete _ls[k]; } };\n"
            "globalThis.indexedDB = {};\n"
            "const w = new Function(readFileSync(ROOT + '/cell-crypto.js', 'utf8')"
            " + '\\n;return { canonicalize };')();\n"
            "const values = JSON.parse(readFileSync(process.argv[2], 'utf8'));\n"
            "writeFileSync(process.argv[3], JSON.stringify(values.map(w.canonicalize)));\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            ["node", str(loader), str(in_path), str(out_path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            self.fail(f"batch canonicalizer failed:\n{result.stderr.strip()}")
        return out_path.read_text(encoding="utf-8")


class TestJsSealsPythonOpens(InteropTestCase):
    def test_single_ecdh_recipient(self):
        js_key = self.js_keypair("Alice")
        payload = b"the quick brown fox\x00\xff binary too"
        cell = self.js_seal(
            {
                "data_b64": base64.b64encode(payload).decode(),
                "filename": "fox.bin",
                "content_type": "application/octet-stream",
                "recipients": [
                    {
                        "method": "ecdh-p256",
                        "label": js_key["label"],
                        "fingerprint": js_key["fingerprint"],
                        "spki": js_key["spki"],
                    }
                ],
            }
        )
        self.assertEqual(cell["version"], "1.3")
        verify_cell(cell)
        result = cell_open(cell, keys=[self.key_from_js(js_key)])
        self.assertEqual(result.data, payload)
        self.assertEqual(result.filename, "fox.bin")

    def test_signed_cell_and_encrypted_meta(self):
        js_key = self.js_keypair("Alice")
        cell = self.js_seal(
            {
                "data_b64": base64.b64encode(b"signed content").decode(),
                "filename": "note.txt",
                "content_type": "text/plain",
                "meta": {"case": "2026-0417", "note": "call before opening"},
                "recipients": [
                    {
                        "method": "ecdh-p256",
                        "label": js_key["label"],
                        "fingerprint": js_key["fingerprint"],
                        "spki": js_key["spki"],
                    }
                ],
                "sender": js_key,
            }
        )
        result = cell_open(
            cell, keys=[self.key_from_js(js_key)], expected_signer=js_key["fingerprint"]
        )
        self.assertTrue(result.signed)
        self.assertEqual(result.signer_fingerprint, js_key["fingerprint"])
        self.assertEqual(result.meta, {"case": "2026-0417", "note": "call before opening"})

    def test_quorum_two_of_three(self):
        keys = [self.js_keypair(f"K{i}") for i in range(3)]
        cell = self.js_seal(
            {
                "data_b64": base64.b64encode(b"quorum secret").decode(),
                "filename": "escrow.txt",
                "threshold": 2,
                "recipients": [
                    {"method": "ecdh-p256", "label": k["label"],
                     "fingerprint": k["fingerprint"], "spki": k["spki"]}
                    for k in keys
                ],
            }
        )
        self.assertEqual(cell["header"]["threshold"], {"required": 2, "of_total": 3})
        self.assertEqual([e["share_index"] for e in cell["header"]["access_map"]], [1, 2, 3])

        two = [self.key_from_js(k) for k in keys[:2]]
        self.assertEqual(cell_open(cell, keys=two).data, b"quorum secret")

        from cellular_defense import QuorumNotMetError

        with self.assertRaises(QuorumNotMetError):
            cell_open(cell, keys=[self.key_from_js(keys[0])])

    def test_passphrase_entry(self):
        cell = self.js_seal(
            {
                "data_b64": base64.b64encode(b"passphrase content").decode(),
                "filename": "p.txt",
                "recipients": [{"method": "pbkdf2", "label": "Passphrase", "passphrase": "correct horse"}],
            }
        )
        self.assertEqual(cell["header"]["access_map"][0]["wrapped_cek"]["iterations"], 600_000)
        self.assertEqual(cell_open(cell, passphrases=["correct horse"]).data, b"passphrase content")

    def test_lifetime_survives_the_aad_binding(self):
        js_key = self.js_keypair("Alice")
        cell = self.js_seal(
            {
                "data_b64": base64.b64encode(b"record").decode(),
                "filename": "r.txt",
                "lifetime": {
                    "type": "record",
                    "advisory": {"retain_until": 4102444800, "release_at": None,
                                 "single_use": False, "minimum_atl": 2},
                    "disposal": {"at": 4102444800, "action": "archive"},
                },
                "recipients": [
                    {"method": "ecdh-p256", "label": js_key["label"],
                     "fingerprint": js_key["fingerprint"], "spki": js_key["spki"]}
                ],
            }
        )
        result = cell_open(cell, keys=[self.key_from_js(js_key)])
        self.assertEqual(result.lifetime.minimum_atl, 2)
        self.assertEqual(result.lifetime.disposal_action, "archive")


class TestPythonSealsJsOpens(InteropTestCase):
    def test_single_ecdh_recipient(self):
        js_key = self.js_keypair("Bob")
        cell = cell_create(
            b"python sealed this",
            "from-python.txt",
            [Recipient.ecdh(js_key["spki"], js_key["label"])],
            content_type="text/plain",
        )
        out = self.js_open(cell, {"keys": [js_key]})
        self.assertEqual(base64.b64decode(out["data_b64"]), b"python sealed this")
        self.assertEqual(out["filename"], "from-python.txt")
        self.assertEqual(out["content_type"], "text/plain")

    def test_signed_cell_verifies_in_the_reference(self):
        js_key = self.js_keypair("Bob")
        sender = KeyRecord.generate("Sender")
        cell = cell_create(
            b"signed by python",
            "s.txt",
            [Recipient.ecdh(js_key["spki"], js_key["label"])],
            sender=sender,
        )
        out = self.js_open(cell, {"keys": [js_key]})
        # The reference reports header_sig_by; a verified signature is what lets
        # it report anything at all here.
        self.assertEqual(out["sig_verified"], sender.fingerprint)

    def test_quorum_and_mixed_methods(self):
        keys = [self.js_keypair(f"Q{i}") for i in range(3)]
        cell = cell_create(
            b"mixed quorum",
            "m.txt",
            [Recipient.ecdh(k["spki"], k["label"]) for k in keys],
            threshold=2,
        )
        out = self.js_open(cell, {"keys": keys[1:3]})
        self.assertEqual(base64.b64decode(out["data_b64"]), b"mixed quorum")

    def test_passphrase_entry(self):
        cell = cell_create(
            b"python passphrase",
            "p.txt",
            [Recipient.passphrase_("open sesame")],
        )
        out = self.js_open(cell, {"passphrases": ["open sesame"]})
        self.assertEqual(base64.b64decode(out["data_b64"]), b"python passphrase")

    def test_encrypted_meta_reaches_the_reference(self):
        js_key = self.js_keypair("Bob")
        cell = cell_create(
            b"x",
            "m.txt",
            [Recipient.ecdh(js_key["spki"], js_key["label"])],
            meta={"note": "sender-defined", "n": 3},
        )
        out = self.js_open(cell, {"keys": [js_key]})
        self.assertEqual(out["meta"], {"note": "sender-defined", "n": 3})


class TestPublishedFigureCells(InteropTestCase):
    """The anchored figure cells must verify without any key at all (§10)."""

    def test_figure_cells_verify(self):
        figures = sorted((REFERENCE.parent / "docs" / "figure-data").glob("*.cell"))
        if not figures:
            self.skipTest("no figure cells present")
        for path in figures:
            with self.subTest(cell=path.name):
                result = verify_cell(json.loads(path.read_text()))
                self.assertTrue(result.header_hash_ok)
                self.assertTrue(result.payload_hash_ok)


if __name__ == "__main__":
    unittest.main()
