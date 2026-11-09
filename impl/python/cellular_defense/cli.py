# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""``cdcell`` — a command-line opener, sealer and verifier for ``.cell`` files.

    cdcell keygen --label Alice --out alice
    cdcell seal report.pdf --to alice.cdpub --out report.cell
    cdcell verify report.cell
    cdcell inspect report.cell
    cdcell open report.cell --key alice.cdkey --out ./

``verify`` and ``inspect`` need no key material at all: that a third party can
confirm a cell has not been altered, and see exactly what it does and does not
leak, without being able to read it, is the property the format is built on.
"""

from __future__ import annotations

import argparse
import getpass
import gzip
import json
import mimetypes
import os
import re
import sys
from pathlib import Path

from . import crypto, lifetime as lifetime_mod
from .cell import INNER_SIG_VERSIONS, Recipient, cell_create, cell_open, verify_cell
from .codec import b64decode
from .errors import CellError
from .keys import KeyRecord


def _read_cell(path: Path) -> dict:
    """Read a ``.cell`` or a gzip-compressed ``.celz`` (§3)."""
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8"))


def _write_cell(cell: dict, path: Path) -> None:
    text = json.dumps(cell, ensure_ascii=False, indent=2).encode("utf-8")
    if path.suffix == ".celz":
        path.write_bytes(gzip.compress(text, mtime=0))
    else:
        path.write_bytes(text)


def _load_keys(paths: list[str]) -> list[KeyRecord]:
    return [KeyRecord.from_cdkey(json.loads(Path(p).read_text())) for p in paths]


# ── Sender-chosen text ───────────────────────────────────────────────────────
# The filename, media type and meta come from whoever sealed the cell, and
# inspect's header fields from anyone who handled it. None of it may reach the
# filesystem or the terminal as is: a newline or ESC can print a fake
# "signed by key" line, bidi controls can reverse what a name appears to say.


def _unsafe(ch: str) -> bool:
    """C0/C1 controls, bidi and zero-width format characters, line and paragraph
    separators, lone surrogates. The same set in every port's CLI."""
    o = ord(ch)
    return (o < 0x20 or 0x7F <= o <= 0x9F or o == 0x061C or 0x200B <= o <= 0x200F
            or 0x2028 <= o <= 0x202E or 0x2060 <= o <= 0x2069 or o == 0xFEFF
            or 0xD800 <= o <= 0xDFFF)


def shown(value: object) -> str:
    """Text safe to print: every unsafe character as a visible \\uXXXX escape."""
    text = value if isinstance(value, str) else str(value)
    return "".join(f"\\u{ord(c):04x}" if _unsafe(c) else c for c in text)


def safe_filename(name: object) -> str:
    """The sender's filename as a plain name in the output directory: no path,
    no unsafe characters, no leading dot (no .bashrc, .envrc), at most 200 bytes."""
    base = re.split(r"[\\/]", name)[-1] if isinstance(name, str) else ""
    base = "".join(c for c in base if not _unsafe(c))
    base = re.sub(r"^[\s.]+", "", base)
    base = base.encode("utf-8")[:200].decode("utf-8", "ignore").rstrip()
    return base or "decrypted"


def _write_new(path: Path, data: bytes) -> None:
    """Create the file; never overwrite or follow a symlink. Owner-only: it is
    the plaintext of an encrypted file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


# ─────────────────────────────────────────────────────────────────────────────


def cmd_keygen(args: argparse.Namespace) -> int:
    key = KeyRecord.generate(args.label)
    stem = Path(args.out)
    pub_path = stem.with_suffix(".cdpub")
    key_path = stem.with_suffix(".cdkey")
    pub_path.write_text(json.dumps(key.to_cdpub(), indent=2))
    key_path.write_text(json.dumps(key.to_cdkey(), indent=2))
    key_path.chmod(0o600)
    print(f"fingerprint  {key.fingerprint}")
    print(f"public key   {pub_path}   (share this — it is how others encrypt to you)")
    print(f"private key  {key_path}   (never share; there is no recovery)")
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    recipients: list[Recipient] = []
    for pub in args.to or []:
        record = KeyRecord.from_cdpub(json.loads(Path(pub).read_text()))
        recipients.append(Recipient.for_key(record))
    if args.passphrase:
        passphrase = getpass.getpass("Passphrase for this cell: ")
        if passphrase != getpass.getpass("Repeat: "):
            print("passphrases do not match", file=sys.stderr)
            return 1
        recipients.append(Recipient.argon2id(passphrase))   # v1.4 §6.5; PBKDF2 stays readable
    if not recipients:
        print("a cell needs at least one recipient (--to or --passphrase)", file=sys.stderr)
        return 1

    source = Path(args.file)
    lifetime = json.loads(args.lifetime) if args.lifetime else None
    cell = cell_create(
        source.read_bytes(),
        source.name,
        recipients,
        content_type=mimetypes.guess_type(source.name)[0] or "application/octet-stream",
        threshold=args.threshold,
        lifetime=lifetime,
        meta=json.loads(args.meta) if args.meta else None,
        sender=_load_keys([args.sign])[0] if args.sign else None,
    )
    out = Path(args.out) if args.out else source.with_suffix(source.suffix + ".cell")
    _write_cell(cell, out)
    count = len(cell["header"]["access_map"])
    threshold = cell["header"]["threshold"]
    print(f"sealed {out}  ({count} recipient{'' if count == 1 else 's'}, "
          f"{threshold['required']}-of-{threshold['of_total']})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cell = _read_cell(Path(args.cell))
    result = verify_cell(cell, expected_signer=args.expect_signer)
    print(f"version        {result.version}")
    print("header_hash    ok")
    print(f"payload_hash   {'ok' if result.payload_hash_ok else 'absent'}")
    if result.version in INNER_SIG_VERSIONS:
        # §4.5: the signature is inside the ciphertext, so who signed is not
        # visible here — by design. `open` verifies it.
        print("signature      inside the encrypted payload — `open` verifies it")
        if args.expect_signer:
            print("--expect-signer needs `open` for a v1.4 cell", file=sys.stderr)
            return 2
        return 0
    if result.signed:
        print(f"signature      valid, by key {result.signer_fingerprint}")
        print(f"               (claims to be {result.claimed_signer!r} — self-asserted, "
              f"check the fingerprint against a contact you already trust)")
    else:
        print("signature      none present")
        print("               a signature can be stripped undetectably; absence proves nothing")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Print exactly what an observer of the stored cell can see (§2.2)."""
    cell = _read_cell(Path(args.cell))
    header = cell.get("header") or {}
    # Every value here can be edited by anyone who handled the file.
    print(f"version      {shown(cell.get('version') or cell.get('cd_version'))}")
    print(f"doc_id       {shown(cell.get('doc_id'))}")
    print(f"created_at   {shown(cell.get('created_at'))}")
    threshold = header.get("threshold") or {}
    print(f"threshold    {shown(threshold.get('required'))}-of-{shown(threshold.get('of_total'))}")
    lt = lifetime_mod.read(header.get("lifetime"))
    if lt:
        print(f"lifetime     type={shown(lt.type)}")
        print(f"  advisory   retain_until={shown(lt.retain_until)} release_at={shown(lt.release_at)} "
              f"single_use={shown(lt.single_use)} minimum_atl={shown(lt.minimum_atl)}")
        print(f"             (advisory: honoured by conforming software, NOT enforced "
              f"against a keyholder)")
        print(f"  disposal   at={shown(lt.disposal_at)} action={shown(lt.disposal_action)}")
        print(f"             (enforced by whoever stores the ciphertext)")
    print(f"prev_hash    {shown(header.get('prev_hash'))}")
    print("access_map:")
    for entry in header.get("access_map") or cell.get("recipients") or []:
        index = entry.get("share_index")
        print(f"  - {shown(entry.get('method')):<12} {shown(entry.get('fingerprint'))}  "
              f"{shown(repr(entry.get('label')))}" + (f"  share {shown(index)}" if index else ""))
    payload = cell.get("payload") or cell.get("encrypted_body") or {}
    if payload.get("ciphertext"):
        size = len(b64decode(payload["ciphertext"], field="ciphertext"))
        print(f"ciphertext   {size} bytes ({shown(payload.get('alg'))})")
    print("\nnot visible here: the plaintext, the filename, the media type, the original "
          "size, and any sender-defined meta — all of them live inside the ciphertext (§5).")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    cell = _read_cell(Path(args.cell))
    passphrases = []
    if args.passphrase:
        passphrases.append(getpass.getpass("Passphrase: "))
    result = cell_open(
        cell,
        keys=_load_keys(args.key or []),
        passphrases=passphrases,
        expected_signer=args.expect_signer,
        enforce_advisory=not args.ignore_advisory,
    )
    destination = Path(args.out or ".")
    # A trailing separator means "into this directory" even if it does not exist
    # yet; the filename only becomes known once the manifest is decrypted (§5),
    # so the caller cannot always name the output file in advance.
    if destination.is_dir() or (args.out or "").endswith("/"):
        destination.mkdir(parents=True, exist_ok=True)
        destination = destination / safe_filename(result.filename)
    try:
        _write_new(destination, result.data)
    except FileExistsError:
        print(f"error: {shown(destination)} already exists — not overwriting it; "
              f"name a new file with --out", file=sys.stderr)
        return 1
    # Who signed comes first, before any text the sender chose.
    if result.signed:
        print(f"signed by key {result.signer_fingerprint}")
        if result.signed_to is not None:
            print(f"signed for     {shown(', '.join(result.signed_to)) or '(no key recipients)'}")
    else:
        print("not signed     nothing in this cell says who sent it")
    print(f"wrote {shown(destination)}  ({len(result.data)} bytes, {shown(result.content_type)})")
    if result.meta:
        print(f"sender meta: {shown(json.dumps(result.meta, ensure_ascii=False))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cdcell", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a P-256 keypair (.cdpub + .cdkey)")
    p.add_argument("--label", default="My Key")
    p.add_argument("--out", required=True, help="output path stem")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("seal", help="encrypt a file into a .cell")
    p.add_argument("file")
    p.add_argument("--to", action="append", help="recipient .cdpub (repeatable)")
    p.add_argument("--passphrase", action="store_true", help="add a passphrase recipient")
    p.add_argument("--threshold", type=int, default=1, help="M in an M-of-N quorum")
    p.add_argument("--sign", help=".cdkey to sign the header with")
    p.add_argument("--lifetime", help="lifetime object as JSON (spec §8)")
    p.add_argument("--meta", help="sender-defined JSON carried inside the ciphertext")
    p.add_argument("--out")
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("verify", help="check the audit chain without any key")
    p.add_argument("cell")
    p.add_argument("--expect-signer", help="fingerprint the cell must be signed by")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("inspect", help="show what an observer of the cell can see")
    p.add_argument("cell")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("open", help="decrypt a .cell")
    p.add_argument("cell")
    p.add_argument("--key", action="append", help=".cdkey to try (repeatable)")
    p.add_argument("--passphrase", action="store_true")
    p.add_argument("--expect-signer", help="fingerprint the cell must be signed by")
    p.add_argument(
        "--ignore-advisory",
        action="store_true",
        help="skip the §8.1 advisory gates (they are advisory by specification)",
    )
    p.add_argument("--out", help="output file or directory")
    p.set_defaults(func=cmd_open)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CellError as exc:
        print(f"error: {shown(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
