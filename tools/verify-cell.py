#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Independent verifier for .cell v1.2/v1.3/v1.4 envelopes.

Written from docs/SPEC.md alone, in a different language, using a
general-purpose cryptographic library (`cryptography`, i.e. OpenSSL) and no
code from this project. It exists to keep the disclosure's enablement claim
honest: if the specification is precise enough for a third party to verify a
cell without our source, this script must pass — and if a spec change breaks
it, the specification has become imprecise.

It verifies, per §10:
  1. header_hash  = SHA-256(canonicalize(header))          §4.1.1
  2. payload_hash = SHA-256(base64decode(ciphertext))       §4.2
  3. fingerprint  = SHA-256(SPKI)[:16]                      §13.3
  4. header_sig   = ECDSA-P256-SHA256 over the header bytes §4.1

It does not decrypt: verification of the audit chain requires no key, which is
the property being demonstrated.

    python3 tools/verify-cell.py docs/figure-data/*.cell

Requires: pip install cryptography
"""
import base64
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key

CANONICAL_VERSIONS = {"1.2", "1.3", "1.4"}
INNER_SIG_VERSIONS = {"1.4"}  # §4.5: the signature is inside the ciphertext


def canonicalize(v):
    """§4.1.1 — deterministic serialization: recursive lexicographic key sort,
    no insignificant whitespace, JSON.stringify-compatible primitive encoding."""
    if v is None or not isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonicalize(e) for e in v) + "]"
    return (
        "{"
        + ",".join(
            json.dumps(k, separators=(",", ":"), ensure_ascii=False)
            + ":"
            + canonicalize(v[k])
            for k in sorted(v)
        )
        + "}"
    )


def serialize_header(header, version):
    """§4.1.1 — canonical for v1.2+, insertion-ordered JSON for v1.0/v1.1.
    Python cannot reproduce JavaScript insertion order, so the legacy branch is
    best-effort and only correct if the file's key order was preserved."""
    if version in CANONICAL_VERSIONS:
        return canonicalize(header).encode()
    return json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()


def verify(path):
    cell = json.load(open(path))
    version = cell.get("version", "?")
    print(f"=== {path}  (v{version}) ===")
    ok = True

    def check(label, passed, detail=""):
        nonlocal ok
        ok = ok and passed
        print(f"  {'PASS' if passed else 'FAIL'}  {label}{'  ' + detail if detail else ''}")

    header_bytes = serialize_header(cell["header"], version)

    # 1. header_hash — §4.1. Mandatory; absence is a rejection, not a skip.
    if not cell.get("header_hash"):
        check("header_hash present", False, "missing — reject the cell (§4.1)")
        return False
    computed = base64.b64encode(hashlib.sha256(header_bytes).digest()).decode()
    check("header_hash", computed == cell["header_hash"])

    # 2. payload_hash — §4.2, over the raw base64-decoded ciphertext bytes.
    ct = base64.b64decode(cell["payload"]["ciphertext"])
    ph = base64.b64encode(hashlib.sha256(ct).digest()).decode()
    check("payload_hash", ph == cell["header"]["payload_hash"])

    # 3/4. Signature — §4.1. Optional, but if present it must verify.
    if version in INNER_SIG_VERSIONS:
        misplaced = any(cell.get(k) for k in ("header_sig", "header_sig_by", "header_sig_key"))
        if misplaced:
            check("no header signature (v1.4)", False, "v1.4 signs inside the payload (§4.5)")
        else:
            print("  ----  signature (if any) is inside the encrypted payload — v1.4 §4.5; "
                  "only a recipient can see or verify it")
        entries = cell["header"].get("access_map") or []
        check("blind access map (v1.4)",
              all("fingerprint" not in e and "label" not in e for e in entries) and len(entries) <= 256,
              f"{len(entries)} entries, none naming a recipient")
    elif cell.get("header_sig") and cell.get("header_sig_key"):
        spki = base64.b64decode(cell["header_sig_key"])
        fpr = hashlib.sha256(spki).hexdigest()[:16]
        check(
            "signing-key fingerprint",
            fpr == cell.get("header_sig_by"),
            f"{fpr} (header_sig_by is self-asserted; anchor trust here, §4.1)",
        )
        sig = base64.b64decode(cell["header_sig"])
        # §4.1: raw 64-byte r||s (IEEE P1363), NOT the DER this library expects.
        if len(sig) != 64:
            check("header_sig", False, f"expected 64-byte P1363, got {len(sig)}")
        else:
            der = utils.encode_dss_signature(
                int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            )
            try:
                load_der_public_key(spki).verify(
                    der, header_bytes, ec.ECDSA(hashes.SHA256())
                )
                check("header_sig", True, "ECDSA P-256, 64-byte P1363")
            except InvalidSignature:
                check("header_sig", False)
    else:
        print("  ----  header_sig absent — unsigned, OR stripped (§4.1: "
              "removal is undetectable; check the fingerprint out of band)")

    # Encoding sanity — §4.0. base64url would not survive the reference reader.
    b64 = cell["payload"]["ciphertext"]
    if any(c in b64 for c in "-_"):
        check("base64 alphabet", False, "contains base64url characters (§4.0)")

    return ok


if __name__ == "__main__":
    paths = sys.argv[1:]
    if not paths:
        sys.exit(__doc__)
    results = [verify(p) for p in paths]
    print(f"\n{sum(results)}/{len(results)} cells verified")
    sys.exit(0 if all(results) else 1)
