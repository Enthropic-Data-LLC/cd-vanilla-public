#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the conformance test keys.

The keys are **deterministic**: each private scalar is derived from a fixed
label string, so every run of this script reproduces the same keypairs
byte-for-byte and any implementation can regenerate them without downloading
anything. That matters for a conformance suite — a vector whose keys drift is
not a vector.

    d = int(SHA-256("cellular-defense conformance key v1: " + label)) mod n
    (retry with an incrementing counter in the vanishingly unlikely case that
     d falls outside 1..n-1)

This is a deliberately terrible way to generate a real key and a perfectly good
way to generate a published one. Run from anywhere:

    python3 conformance/make-test-keys.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Order of the P-256 group.
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
DOMAIN = "cellular-defense conformance key v1: "

#: Every key the vectors use, and what each one is for. Roles are fixed so a
#: vector can say "opens with carol" and mean something in any language.
KEYS = {
    "alice": "Alice — primary recipient in most single-recipient vectors",
    "bob": "Bob — second recipient; also the signer in signed-cell vectors",
    "carol": "Carol — third recipient, used for quorum vectors",
    "dave": "Dave — fourth recipient, used for 3-of-4 quorum vectors",
    "mallory": "Mallory — never a recipient; the wrong-key negative case",
}

#: The passphrase every pbkdf2 vector uses. Published, therefore worthless as a
#: secret, which is the point.
PASSPHRASE = "conformance-test-passphrase"


def derive(label: str) -> ec.EllipticCurvePrivateKey:
    for counter in range(256):
        seed = f"{DOMAIN}{label}".encode("utf-8")
        if counter:
            seed += bytes([counter])
        d = int.from_bytes(hashlib.sha256(seed).digest(), "big") % N
        if 1 <= d < N:
            return ec.derive_private_key(d, ec.SECP256R1())
    raise AssertionError("unreachable: no valid scalar found")


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "keys"
    out_dir.mkdir(exist_ok=True)
    manifest = {
        "note": (
            "PUBLISHED TEST KEYS. The private keys are in this repository and "
            "derived from a documented string. They protect nothing. Never use "
            "them for anything real."
        ),
        "derivation": "d = SHA-256(\"" + DOMAIN + '" + label) mod n, P-256',
        "passphrase": PASSPHRASE,
        "keys": {},
    }

    for label, purpose in KEYS.items():
        private = derive(label)
        spki = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pkcs8 = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        import base64

        spki_b64 = base64.b64encode(spki).decode()
        fingerprint = hashlib.sha256(spki).hexdigest()[:16]
        name = label.capitalize()

        (out_dir / f"{label}.cdpub").write_text(
            json.dumps(
                {
                    "cd_pubkey": "2.0",
                    "label": name,
                    "fingerprint": fingerprint,
                    "method": "ecdh-p256",
                    "spki": spki_b64,
                },
                indent=2,
            )
            + "\n"
        )
        (out_dir / f"{label}.cdkey").write_text(
            json.dumps(
                {
                    "cd_key": "2.0",
                    "keyId": f"conformance-{label}",
                    "label": name,
                    "method": "ecdh-p256",
                    "fingerprint": fingerprint,
                    "spki": spki_b64,
                    "pkcs8": base64.b64encode(pkcs8).decode(),
                    "created_at": 0,
                    "exported_at": 0,
                },
                indent=2,
            )
            + "\n"
        )
        manifest["keys"][label] = {"fingerprint": fingerprint, "purpose": purpose}
        print(f"{label:<8} {fingerprint}  {purpose}")

    (out_dir / "keys.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
