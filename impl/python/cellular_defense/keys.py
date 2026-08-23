# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Key records and the ``.cdpub`` / ``.cdkey`` file formats — spec §13."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto
from .codec import b64decode, b64encode
from .errors import MalformedCellError


@dataclass
class KeyRecord:
    """One P-256 keypair, or a public key alone when ``private`` is None.

    The same key material serves both ECDH (wrapping) and ECDSA (header
    signatures): §4.1 re-imports the identical P-256 scalar under a different
    algorithm label. In a library that does not tag keys by algorithm, that
    happens for free — one object does both jobs.
    """

    label: str
    public: ec.EllipticCurvePublicKey
    private: ec.EllipticCurvePrivateKey | None = None
    key_id: str = ""
    created_at: int = 0

    def __post_init__(self) -> None:
        if not self.key_id:
            self.key_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = int(time.time())

    @property
    def spki(self) -> str:
        return b64encode(crypto.export_spki(self.public))

    @property
    def fingerprint(self) -> str:
        return crypto.fingerprint(crypto.export_spki(self.public))

    @classmethod
    def generate(cls, label: str = "My Key") -> "KeyRecord":
        private = ec.generate_private_key(crypto.CURVE)
        return cls(label=label, public=private.public_key(), private=private)

    # ── .cdpub (§13.1) ────────────────────────────────────────────────────
    def to_cdpub(self) -> dict:
        return {
            "cd_pubkey": "2.0",
            "label": self.label,
            "fingerprint": self.fingerprint,
            "method": "ecdh-p256",
            "spki": self.spki,
        }

    @classmethod
    def from_cdpub(cls, doc: dict) -> "KeyRecord":
        spki = doc.get("spki")
        if not spki:
            raise MalformedCellError(".cdpub is missing its spki field")
        public = crypto.load_spki(b64decode(spki, field="spki"))
        record = cls(label=doc.get("label") or "(unnamed)", public=public)
        claimed = doc.get("fingerprint")
        if claimed and claimed != record.fingerprint:
            # The fingerprint is derived, not authoritative. A mismatch means the
            # file was edited or corrupted; trusting the claim would let an
            # attacker point a known-good label at a key they control.
            raise MalformedCellError(
                f".cdpub fingerprint {claimed!r} does not match its own SPKI "
                f"({record.fingerprint})"
            )
        return record

    # ── .cdkey (§13.2) ────────────────────────────────────────────────────
    def to_cdkey(self) -> dict:
        if self.private is None:
            raise MalformedCellError("cannot export a .cdkey from a public-only record")
        return {
            "cd_key": "2.0",
            "keyId": self.key_id,
            "label": self.label,
            "method": "ecdh-p256",
            "fingerprint": self.fingerprint,
            "spki": self.spki,
            "pkcs8": b64encode(crypto.export_pkcs8(self.private)),
            "created_at": self.created_at,
            "exported_at": int(time.time()),
        }

    @classmethod
    def from_cdkey(cls, doc: dict) -> "KeyRecord":
        pkcs8 = doc.get("pkcs8")
        if not pkcs8:
            raise MalformedCellError(".cdkey is missing its pkcs8 field")
        private = crypto.load_pkcs8(b64decode(pkcs8, field="pkcs8"))
        record = cls(
            label=doc.get("label") or "(unnamed)",
            public=private.public_key(),
            private=private,
            key_id=_safe_key_id(doc.get("keyId")),
            created_at=int(doc.get("created_at") or 0),
        )
        if doc.get("spki") and doc["spki"] != record.spki:
            raise MalformedCellError(".cdkey spki does not match its own private key")
        return record


def _safe_key_id(value: object) -> str:
    """Constrain an imported keyId to a safe charset, else mint a fresh one.

    Imported key files are attacker-supplied. The reference sanitises keyId and
    fingerprint for exactly this reason — they reach the DOM there, and they
    reach filenames and logs here.
    """
    if isinstance(value, str) and 1 <= len(value) <= 64 and all(
        c.isalnum() or c in "_-" for c in value
    ):
        return value
    return str(uuid.uuid4())
