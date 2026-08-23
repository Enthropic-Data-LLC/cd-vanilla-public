# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end CLI tests — keygen, seal, verify, inspect, open."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cellular_defense.cli import main


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.source = self.tmp / "report.txt"
        self.source.write_text("confidential contents")

    def run_cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def keygen(self, label: str = "Alice") -> Path:
        stem = self.tmp / label.lower()
        code, _ = self.run_cli("keygen", "--label", label, "--out", str(stem))
        self.assertEqual(code, 0)
        return stem

    def test_full_round_trip(self):
        stem = self.keygen()
        cell = self.tmp / "report.cell"
        code, _ = self.run_cli(
            "seal", str(self.source), "--to", f"{stem}.cdpub",
            "--sign", f"{stem}.cdkey", "--out", str(cell),
        )
        self.assertEqual(code, 0)

        code, output = self.run_cli("verify", str(cell))
        self.assertEqual(code, 0)
        self.assertIn("header_hash    ok", output)
        self.assertIn("signature      valid", output)

        destination = self.tmp / "out"
        code, output = self.run_cli(
            "open", str(cell), "--key", f"{stem}.cdkey", "--out", f"{destination}/"
        )
        self.assertEqual(code, 0)
        self.assertEqual((destination / "report.txt").read_text(), "confidential contents")

    def test_private_key_file_is_not_world_readable(self):
        stem = self.keygen()
        mode = Path(f"{stem}.cdkey").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_inspect_shows_no_plaintext_metadata(self):
        stem = self.keygen()
        cell = self.tmp / "report.cell"
        self.run_cli("seal", str(self.source), "--to", f"{stem}.cdpub", "--out", str(cell))
        code, output = self.run_cli("inspect", str(cell))
        self.assertEqual(code, 0)
        self.assertNotIn("report.txt", output)
        self.assertIn("ecdh-p256", output)

    def test_celz_is_gzip_and_round_trips(self):
        stem = self.keygen()
        cell = self.tmp / "report.celz"
        self.run_cli("seal", str(self.source), "--to", f"{stem}.cdpub", "--out", str(cell))
        self.assertEqual(cell.read_bytes()[:2], b"\x1f\x8b")
        code, _ = self.run_cli("verify", str(cell))
        self.assertEqual(code, 0)

    def test_quorum_seal_and_open(self):
        stems = [self.keygen(f"K{i}") for i in range(3)]
        cell = self.tmp / "q.cell"
        argv = ["seal", str(self.source), "--threshold", "2", "--out", str(cell)]
        for stem in stems:
            argv += ["--to", f"{stem}.cdpub"]
        self.run_cli(*argv)
        header = json.loads(cell.read_text())["header"]
        self.assertEqual(header["threshold"], {"required": 2, "of_total": 3})

        code, _ = self.run_cli(
            "open", str(cell), "--key", f"{stems[0]}.cdkey", "--key", f"{stems[2]}.cdkey",
            "--out", f"{self.tmp / 'q'}/",
        )
        self.assertEqual(code, 0)

    def test_seal_without_a_recipient_is_refused(self):
        code, _ = self.run_cli("seal", str(self.source), "--out", str(self.tmp / "x.cell"))
        self.assertEqual(code, 1)

    def test_verify_reports_a_tampered_cell(self):
        stem = self.keygen()
        cell = self.tmp / "report.cell"
        self.run_cli("seal", str(self.source), "--to", f"{stem}.cdpub", "--out", str(cell))
        doc = json.loads(cell.read_text())
        doc["header"]["policy"]["copy_protection"] = "none"
        cell.write_text(json.dumps(doc))
        code, _ = self.run_cli("verify", str(cell))
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
