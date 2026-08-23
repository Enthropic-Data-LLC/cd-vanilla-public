# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the shared conformance vectors in ``conformance/vectors/``.

This is the test a new language port writes first. It reads a language-neutral
manifest and asserts two things per vector: the cells that must open produce the
exact expected plaintext, filename, media type and sender meta; and the cells
that must be refused are refused, at the §10 step the manifest names.

The refusals carry most of the weight. An implementation that opens every
positive vector and also opens ``reject-tampered-aad`` is not a partial pass —
it has no metadata authentication at all.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from cellular_defense import (
    DecryptionError,
    IntegrityError,
    KeyRecord,
    LifetimeError,
    MalformedCellError,
    NoMatchingKeyError,
    QuorumNotMetError,
    SignatureError,
    UnsupportedVersionError,
    cell_open,
)

VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors"
KEYS = VECTORS.parent / "keys"

#: The manifest names a reason; each maps to the exception this library raises.
#: A port in another language substitutes its own error types here — the reasons
#: themselves are the portable part.
REASON_TO_ERROR: dict[str, type[Exception]] = {
    "header-hash-missing": IntegrityError,
    "header-hash-mismatch": IntegrityError,
    "payload-hash-mismatch": IntegrityError,
    "signature-invalid": SignatureError,
    "signature-der-encoded": MalformedCellError,
    "aad-mismatch": DecryptionError,
    "unsupported-version": UnsupportedVersionError,
    "quorum-not-met": QuorumNotMetError,
    "no-matching-key": NoMatchingKeyError,
    "retention-expired": LifetimeError,
    "timed-release-locked": LifetimeError,
}


def load_manifest() -> dict:
    return json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))


def load_key(name: str) -> KeyRecord:
    return KeyRecord.from_cdkey(json.loads((KEYS / f"{name}.cdkey").read_text()))


def open_args(spec: dict) -> dict:
    return {
        "keys": [load_key(n) for n in spec.get("keys", [])],
        "passphrases": list(spec.get("passphrases", [])),
    }


@unittest.skipUnless(VECTORS.is_dir(), "conformance vectors are not present")
class TestConformanceVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest()

    def test_manifest_is_self_consistent(self):
        ids = [v["id"] for v in self.manifest["vectors"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate vector ids")
        for vector in self.manifest["vectors"]:
            with self.subTest(vector=vector["id"]):
                self.assertTrue((VECTORS / vector["file"]).is_file())
                if vector["expect"] == "reject":
                    self.assertIn(vector["reject_reason"], self.manifest["reject_reasons"])

    def test_every_supported_version_has_a_vector(self):
        # §12 requires 1.0-1.3 plus legacy v2.x to stay readable. A version with
        # no vector is a version nobody actually tests.
        covered = {v["cell_version"] for v in self.manifest["vectors"]}
        for version in ("1.0", "1.1", "1.2", "1.3", "2.0"):
            self.assertIn(version, covered, f"no vector covers version {version}")

    def test_every_access_method_has_a_vector(self):
        methods = set()
        for vector in self.manifest["vectors"]:
            cell = json.loads((VECTORS / vector["file"]).read_text(encoding="utf-8"))
            entries = (cell.get("header") or {}).get("access_map") or cell.get("recipients") or []
            methods.update(e.get("method") for e in entries)
        self.assertIn("ecdh-p256", methods)
        self.assertIn("pbkdf2", methods)
        # yubikey-prf is intentionally absent: its key material comes from a
        # WebAuthn PRF evaluation that no file can carry and no headless runner
        # can perform. A vector for it would have to ship the PRF output, which
        # would test AES-KW rather than the access method.

    def test_open_vectors(self):
        for vector in self.manifest["vectors"]:
            if vector["expect"] != "open":
                continue
            with self.subTest(vector=vector["id"]):
                cell = json.loads((VECTORS / vector["file"]).read_text(encoding="utf-8"))
                spec = vector["open_with"]
                result = cell_open(cell, **open_args(spec))

                expected = vector["plaintext"]
                self.assertEqual(len(result.data), expected["size"])
                self.assertEqual(hashlib.sha256(result.data).hexdigest(), expected["sha256"])
                self.assertEqual(
                    result.data, (VECTORS / expected["file"]).read_bytes(),
                    "plaintext differs from the committed payload file",
                )
                self.assertEqual(result.filename, vector["filename"])
                self.assertEqual(result.content_type, vector["content_type"])
                if "meta" in vector:
                    self.assertEqual(result.meta, vector["meta"])
                if "signer" in vector:
                    self.assertTrue(result.signed)
                    self.assertEqual(
                        result.signer_fingerprint, load_key(vector["signer"]).fingerprint
                    )

                for alternative in spec.get("also_opens_with", []):
                    self.assertEqual(cell_open(cell, **open_args(alternative)).data, result.data)

    def test_reject_vectors(self):
        for vector in self.manifest["vectors"]:
            if vector["expect"] != "reject":
                continue
            with self.subTest(vector=vector["id"], reason=vector["reject_reason"]):
                cell = json.loads((VECTORS / vector["file"]).read_text(encoding="utf-8"))
                expected = REASON_TO_ERROR[vector["reject_reason"]]
                with self.assertRaises(expected):
                    cell_open(cell, **open_args(vector["open_with"]))

    def test_must_not_open_with(self):
        for vector in self.manifest["vectors"]:
            spec = vector.get("must_not_open_with")
            if not spec:
                continue
            with self.subTest(vector=vector["id"]):
                cell = json.loads((VECTORS / vector["file"]).read_text(encoding="utf-8"))
                with self.assertRaises((NoMatchingKeyError, QuorumNotMetError)):
                    cell_open(cell, **open_args(spec))

    def test_advisory_gates_can_be_overridden(self):
        # §8.1: the advisory half of lifetime is not enforced against a
        # keyholder, and an opener written from the spec can disregard it. The
        # vector still requires refusal by DEFAULT — that is the conformance
        # claim — but an explicit override is not a violation.
        for vector in self.manifest["vectors"]:
            if vector.get("reject_reason") != "retention-expired":
                continue
            cell = json.loads((VECTORS / vector["file"]).read_text(encoding="utf-8"))
            result = cell_open(
                cell, enforce_advisory=False, **open_args(vector["open_with"])
            )
            self.assertEqual(len(result.data), 81)


if __name__ == "__main__":
    unittest.main()
