#!/usr/bin/env python3
"""Check that every OpenTimestamps proof in the repository matches its file.

    python3 tools/check-proofs.py            # every tracked *.ots
    python3 tools/check-proofs.py X.ots ...  # just these

A proof `X.ots` attests to the SHA-256 of `X`. If `X` is edited and the proof is
not replaced, the proof silently stops covering the file next to it. That
happened from 2026-10-20 to 2026-10-31, and nothing noticed. This check reads the
digest from the proof's header and compares it with the file. It does not
verify the proof against Bitcoin, and needs no network; `ots verify` does that.

Standard library only, so it runs anywhere CI does.
"""
import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
SHA256 = 0x08


def proof_digest(ots: pathlib.Path) -> bytes:
    data = ots.read_bytes()
    if not data.startswith(MAGIC):
        raise ValueError("not an OpenTimestamps proof")
    pos = len(MAGIC)
    if data[pos] != 1:
        raise ValueError(f"unsupported proof version {data[pos]}")
    if data[pos + 1] != SHA256:
        raise ValueError(f"file hash is not SHA-256 (op 0x{data[pos + 1]:02x})")
    return data[pos + 2:pos + 34]


def main(argv: list[str]) -> int:
    if argv:
        proofs = [pathlib.Path(a).resolve() for a in argv]
    else:
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.ots"],
                                capture_output=True, text=True, check=True).stdout.split()
        proofs = [ROOT / p for p in listed]
    if not proofs:
        print("check-proofs: no proofs found", file=sys.stderr)
        return 1
    bad = 0
    for ots in proofs:
        target = ots.with_suffix("")
        name = target.relative_to(ROOT) if target.is_relative_to(ROOT) else target
        try:
            want = proof_digest(ots)
            have = hashlib.sha256(target.read_bytes()).digest()
        except (OSError, ValueError, IndexError) as e:
            print(f"✗ {name}: {e}")
            bad += 1
            continue
        if have == want:
            print(f"✓ {name}  {have.hex()[:16]}…")
        else:
            print(f"✗ {name}: file is {have.hex()[:16]}…, proof covers {want.hex()[:16]}… — "
                  "restamp it (ots stamp) or restore the file")
            bad += 1
    print(f"{len(proofs) - bad}/{len(proofs)} proofs match their files")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
