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
        # v1.4: the signature is inside the ciphertext; verify cannot see it
        self.assertIn("signature      inside the encrypted payload", output)
        # …so a required signer is refused here, never passed: `open` checks it.
        code, _ = self.run_cli("verify", str(cell), "--expect-signer", "deadbeefdeadbeef")
        self.assertEqual(code, 2)

        destination = self.tmp / "out"
        code, output = self.run_cli(
            "open", str(cell), "--key", f"{stem}.cdkey", "--out", f"{destination}/"
        )
        self.assertEqual(code, 0)
        self.assertIn("signed by key", output)
        self.assertEqual((destination / "report.txt").read_text(), "confidential contents")

    def test_open_warns_when_the_key_is_not_one_the_signer_addressed(self):
        # §4.5: anyone holding the cell can add an access-map entry; the
        # signature still verifies, so the opener has to compare `to` itself.
        alice, bob, carol = self.keygen("Alice"), self.keygen("Bob"), self.keygen("Carol")
        cell_path = self.tmp / "signed.cell"
        code, _ = self.run_cli("seal", str(self.source), "--to", f"{alice}.cdpub", "--to", f"{carol}.cdpub",
                               "--sign", f"{bob}.cdkey", "--out", str(cell_path))
        self.assertEqual(code, 0)
        code, output = self.run_cli("open", str(cell_path), "--key", f"{alice}.cdkey",
                                    "--out", f"{self.tmp}/a/")
        self.assertEqual(code, 0)
        self.assertNotIn("warning", output)

        # A cell signed for Alice alone, with an entry for Carol added afterwards
        # by someone who could open it. Nothing the signature covers changes.
        forwarded = self.tmp / "forwarded.cell"
        code, _ = self.run_cli("seal", str(self.source), "--to", f"{alice}.cdpub",
                               "--sign", f"{bob}.cdkey", "--out", str(forwarded))
        self.assertEqual(code, 0)
        from cellular_defense import KeyRecord, crypto
        from cellular_defense.cell import serialize_header
        from cellular_defense.codec import b64encode
        cell = json.loads(forwarded.read_text())
        alice_key = KeyRecord.from_cdkey(json.loads(Path(f"{alice}.cdkey").read_text()))
        carol_pub = json.loads(Path(f"{carol}.cdpub").read_text())["spki"]
        cek = crypto.ecdh_unwrap_cek(cell["header"]["access_map"][0]["wrapped_cek"], alice_key.private)
        cell["header"]["access_map"].append(
            {"method": "ecdh-p256", "wrapped_cek": crypto.ecdh_wrap_cek(cek, carol_pub)})
        cell["header_hash"] = b64encode(crypto.sha256(serialize_header(cell["header"], cell["version"])))
        forwarded.write_text(json.dumps(cell))
        code, output = self.run_cli("open", str(forwarded), "--key", f"{carol}.cdkey",
                                    "--out", f"{self.tmp}/c/")
        self.assertEqual(code, 0)
        self.assertIn("signed by key", output)
        self.assertIn("warning        none of your keys is among them", output)

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

    # ── Sender-chosen filename and text (pen test 2026-11-09, M1/M2) ─────────

    def hostile_cell(self, filename: str, content_type: str = "text/plain") -> tuple[Path, Path]:
        """An unsigned cell for Alice whose sender picked the name and media type."""
        from cellular_defense import KeyRecord, Recipient, cell_create

        stem = self.keygen()
        alice = KeyRecord.from_cdpub(json.loads(Path(f"{stem}.cdpub").read_text()))
        cell = cell_create(b"attacker bytes", filename, [Recipient.for_key(alice)],
                           content_type=content_type)
        path = self.tmp / "hostile.cell"
        path.write_text(json.dumps(cell))
        return path, Path(f"{stem}.cdkey")

    def test_open_never_overwrites_and_never_writes_a_dotfile(self):
        cell, key = self.hostile_cell(".bashrc")
        home = self.tmp / "home"
        home.mkdir()
        (home / ".bashrc").write_text("mine")
        code, _ = self.run_cli("open", str(cell), "--key", str(key), "--out", f"{home}/")
        self.assertEqual(code, 0)
        self.assertEqual((home / ".bashrc").read_text(), "mine")
        self.assertEqual((home / "bashrc").read_bytes(), b"attacker bytes")
        self.assertEqual((home / "bashrc").stat().st_mode & 0o777, 0o600)

        # The same name again, or an explicit --out that exists: refused.
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = self.run_cli("open", str(cell), "--key", str(key), "--out", f"{home}/")
            self.assertEqual(code, 1)
            code, _ = self.run_cli("open", str(cell), "--key", str(key), "--out", str(home / ".bashrc"))
            self.assertEqual(code, 1)
        self.assertEqual((home / ".bashrc").read_text(), "mine")
        self.assertEqual((home / "bashrc").read_bytes(), b"attacker bytes")

    def test_sender_text_cannot_print_a_signer_line(self):
        forged = "application/pdf\nsigned by key aff6a52990ce2335\x1b[8m"
        cell, key = self.hostile_cell("contract\u202efdp.exe", forged)
        out = self.tmp / "o"
        code, output = self.run_cli("open", str(cell), "--key", str(key), "--out", f"{out}/")
        self.assertEqual(code, 0)
        lines = output.splitlines()
        self.assertTrue(lines[0].startswith("not signed"), output)
        self.assertFalse(any(line.startswith("signed by key") for line in lines), output)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\u202e", output)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["contractfdp.exe"])

    def test_safe_filename(self):
        from cellular_defense.cli import safe_filename

        for raw, want in [("report.pdf", "report.pdf"), ("../../etc/passwd", "passwd"),
                          ("a\\b\\c.txt", "c.txt"), (".bashrc", "bashrc"), (". .envrc", "envrc"),
                          ("..", "decrypted"), ("/", "decrypted"), ("", "decrypted"),
                          ("x\x00y\nz", "xyz"), ("\ud800.txt", "txt"), (None, "decrypted"),
                          (7, "decrypted"), ("é" * 150, "é" * 100)]:
            self.assertEqual(safe_filename(raw), want, repr(raw))

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
