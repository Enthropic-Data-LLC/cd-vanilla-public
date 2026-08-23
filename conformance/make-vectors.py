#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Generate the conformance vector set.

Vectors are **captured, not reproduced**. Sealing is randomized — a fresh
ephemeral keypair per recipient, a fresh IV, fresh HKDF and PBKDF2 salts — and
no field commits to the gzip framing, so two conforming implementations sealing
the same file produce different bytes and both are correct. What a vector
asserts is therefore what *opens* and what is *refused*, never byte-identical
sealing. Re-running this script produces a new, equally valid set; do not do so
casually, because the point of a committed vector is that it stays put.

Older format versions are built here by hand from the primitives. Nothing writes
1.0, 1.1 or 1.2 any more — the library deliberately writes 1.3 only — but §12
requires readers to keep opening them, and a version nobody has a vector for is
a version nobody actually tests.

    python3 conformance/make-vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "impl" / "python"))

from cryptography.hazmat.primitives import keywrap  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from cellular_defense import KeyRecord, Recipient, cell_create, cell_open  # noqa: E402
from cellular_defense import crypto  # noqa: E402
from cellular_defense.cell import cell_aad, serialize_header  # noqa: E402
from cellular_defense.codec import b64encode  # noqa: E402

KEYS = ROOT / "keys"
VECTORS = ROOT / "vectors"
PASSPHRASE = json.loads((KEYS / "keys.json").read_text())["passphrase"]

#: Fixed so the vectors do not drift with the clock.
CREATED_AT = 1787500000  # 2026-08-23
PAST = 1577836800        # 2020-01-01 — always expired
FUTURE = 4102444800      # 2100-01-01 — always locked

DEAL = (
    b"Cellular Defense cross-implementation test\n"
    b"Sealed: 2026-08-23\n"
    b"Amount: $4,250,000\n"
)
UNICODE = "rapport financiér — 😀 café\n".encode("utf-8")
BINARY = bytes(range(256)) * 4
EMPTY = b""

vectors: list[dict] = []


def key(name: str) -> KeyRecord:
    return KeyRecord.from_cdkey(json.loads((KEYS / f"{name}.cdkey").read_text()))


def write_payload(name: str, data: bytes) -> str:
    (VECTORS / "payloads" / name).write_bytes(data)
    return f"payloads/{name}"


def add(
    vector_id: str,
    cell: dict,
    *,
    expect: str,
    description: str,
    sealed_by: str = "python",
    open_with: dict | None = None,
    plaintext: bytes | None = None,
    payload_file: str | None = None,
    filename: str | None = None,
    content_type: str | None = None,
    meta: dict | None = None,
    signer: str | None = None,
    reject_reason: str | None = None,
    reject_at_step: int | None = None,
    must_not_open_with: dict | None = None,
    notes: str | None = None,
) -> None:
    folder = "open" if expect == "open" else "reject"
    path = VECTORS / folder / f"{vector_id}.cell"
    path.write_text(json.dumps(cell, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    entry: dict = {
        "id": vector_id,
        "file": f"{folder}/{vector_id}.cell",
        "description": description,
        "expect": expect,
        "sealed_by": sealed_by,
        "cell_version": cell.get("version") or cell.get("cd_version"),
        "open_with": open_with or {},
    }
    if expect == "open":
        assert plaintext is not None
        entry["plaintext"] = {
            "file": payload_file,
            "sha256": hashlib.sha256(plaintext).hexdigest(),
            "size": len(plaintext),
        }
        entry["filename"] = filename
        entry["content_type"] = content_type
        if meta is not None:
            entry["meta"] = meta
        if signer:
            entry["signer"] = signer
    else:
        entry["reject_reason"] = reject_reason
        entry["reject_at_step"] = reject_at_step
    if must_not_open_with:
        entry["must_not_open_with"] = must_not_open_with
    if notes:
        entry["notes"] = notes
    vectors.append(entry)


# ─────────────────────────────────────────────────────────────────────────────
# Building cells at superseded versions, by hand.
#
# The library writes 1.3 and nothing else, on purpose. These reconstruct the
# older shapes from the same primitives so §12's read path has something to be
# tested against: 1.2 differs from 1.3 only in the flat lifetime; 1.1 hashes and
# binds AAD over insertion-ordered JSON.stringify; 1.0 binds no AAD at all.
# ─────────────────────────────────────────────────────────────────────────────

FLAT_LIFETIME = {
    "type": "session",
    "expires_at": None,
    "release_at": None,
    "single_use": False,
    "minimum_atl": 1,
    "on_expiry": "delete",
}


def seal_at_version(version: str, data: bytes, filename: str, recipients: list[KeyRecord],
                    *, content_type: str = "text/plain", doc_id: str = "") -> dict:
    manifest = {"filename": filename, "content_type": content_type, "size": len(data)}
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    body = crypto.gzip_compress(struct.pack("<I", len(manifest_bytes)) + manifest_bytes + data)

    cek = secrets.token_bytes(32)
    header: dict = {
        "prev_hash": None,
        "threshold": {"required": 1, "of_total": len(recipients)},
        "lifetime": dict(FLAT_LIFETIME),
        "policy": {
            "copy_protection": "standard",
            "watermark_mode": "none",
            "created_on_origin": "https://conformance.invalid",
            "origin_sig": None,
        },
    }
    iv, ciphertext = crypto.aes_gcm_encrypt(cek, body, cell_aad(header, version))
    header["access_map"] = [
        {
            "label": record.label,
            "method": "ecdh-p256",
            "fingerprint": record.fingerprint,
            "wrapped_cek": crypto.ecdh_wrap_cek(cek, record.spki),
        }
        for record in recipients
    ]
    header["payload_hash"] = b64encode(crypto.sha256(ciphertext))
    header_bytes = serialize_header(header, version)
    return {
        "version": version,
        "doc_id": doc_id or f"01CONFORMANCE{version.replace('.', '')}0000000000",
        "created_at": CREATED_AT,
        "header": header,
        "header_hash": b64encode(crypto.sha256(header_bytes)),
        "header_sig": None,
        "header_sig_by": None,
        "header_sig_key": None,
        "payload": {
            "alg": "AES-256-GCM",
            "encoding": "base64+gzip",
            "iv": b64encode(iv),
            "ciphertext": b64encode(ciphertext),
        },
    }


def seal_legacy_v2(data: bytes, filename: str, recipient: KeyRecord) -> dict:
    """Pre-spec v2.0: no header, no HKDF, plaintext filename, no manifest."""
    cek = secrets.token_bytes(32)
    ephemeral = ec.generate_private_key(crypto.CURVE)
    shared = ephemeral.exchange(ec.ECDH(), recipient.public)
    iv, ciphertext = crypto.aes_gcm_encrypt(cek, crypto.gzip_compress(data), None)
    return {
        "cd_version": "2.0",
        "doc_id": "legacy-conformance-0001",
        "created_at": CREATED_AT,
        "original_filename": filename,
        "content_type": "text/plain",
        "recipients": [
            {
                "method": "ecdh-p256",
                "label": recipient.label,
                "fingerprint": recipient.fingerprint,
                "wrapped_cek": {
                    "eph_spki": b64encode(crypto.export_spki(ephemeral.public_key())),
                    "ct": b64encode(keywrap.aes_key_wrap(shared[:32], cek)),
                },
            }
        ],
        "encrypted_body": {"iv": b64encode(iv), "ciphertext": b64encode(ciphertext)},
    }


def rehash(cell: dict) -> dict:
    """Recompute header_hash — what any attacker editing a header does first."""
    cell["header_hash"] = b64encode(
        crypto.sha256(serialize_header(cell["header"], cell["version"]))
    )
    return cell


def main() -> int:
    alice, bob, carol, dave = (key(n) for n in ("alice", "bob", "carol", "dave"))
    deal_file = write_payload("deal.txt", DEAL)
    unicode_file = write_payload("unicode.txt", UNICODE)
    binary_file = write_payload("binary-1024.bin", BINARY)
    empty_file = write_payload("empty.bin", EMPTY)
    mallory_only = {"keys": ["mallory"]}

    # ── Positive: v1.3, every access method ──────────────────────────────
    add(
        "v13-ecdh-single",
        cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)],
                    content_type="text/plain", created_at=CREATED_AT),
        expect="open", description="v1.3, one ECDH recipient, unsigned",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", must_not_open_with=mallory_only,
    )

    add(
        "v13-ecdh-signed",
        cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)], sender=bob,
                    content_type="text/plain", meta={"case": "2026-0417"},
                    created_at=CREATED_AT),
        expect="open",
        description="v1.3, ECDH recipient, signed by bob, sender-defined meta inside the ciphertext",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", meta={"case": "2026-0417"},
        signer="bob", must_not_open_with=mallory_only,
        notes="An opener that requires authorship must compare the verified key "
              "fingerprint against bob's; header_sig_by is self-asserted (§4.1).",
    )

    add(
        "v13-pbkdf2",
        cell_create(DEAL, "deal.txt", [Recipient.passphrase_(PASSPHRASE)],
                    content_type="text/plain", created_at=CREATED_AT),
        expect="open", description="v1.3, passphrase entry, PBKDF2-SHA256 600,000 iterations",
        open_with={"passphrases": [PASSPHRASE]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", must_not_open_with=mallory_only,
    )

    add(
        "v13-multi-recipient",
        cell_create(DEAL, "deal.txt",
                    [Recipient.for_key(alice), Recipient.for_key(bob), Recipient.for_key(carol),
                     Recipient.passphrase_(PASSPHRASE)],
                    content_type="text/plain", created_at=CREATED_AT),
        expect="open",
        description="v1.3, four entries at threshold 1 — each opens the cell independently",
        open_with={"keys": ["alice"], "also_opens_with": [
            {"keys": ["bob"]}, {"keys": ["carol"]}, {"passphrases": [PASSPHRASE]}]},
        plaintext=DEAL, payload_file=deal_file, filename="deal.txt",
        content_type="text/plain", must_not_open_with=mallory_only,
        notes="share_index is absent from every entry (§6.4): omitted, not null.",
    )

    add(
        "v13-quorum-3of4",
        cell_create(DEAL, "deal.txt",
                    [Recipient.for_key(k) for k in (alice, bob, carol, dave)],
                    content_type="text/plain", threshold=3, created_at=CREATED_AT),
        expect="open", description="v1.3, 3-of-4 Shamir quorum over GF(256)",
        open_with={"keys": ["alice", "bob", "carol"], "also_opens_with": [
            {"keys": ["carol", "dave", "alice"]}, {"keys": ["bob", "carol", "dave"]}]},
        plaintext=DEAL, payload_file=deal_file, filename="deal.txt",
        content_type="text/plain",
        must_not_open_with={"keys": ["alice", "bob"]},
        notes="share_index carries the x-coordinate 1..4. Fewer than 3 shares reveal "
              "nothing information-theoretically (§16).",
    )

    add(
        "v13-quorum-2of3-mixed",
        cell_create(DEAL, "deal.txt",
                    [Recipient.for_key(alice), Recipient.for_key(bob),
                     Recipient.passphrase_(PASSPHRASE)],
                    content_type="text/plain", threshold=2, created_at=CREATED_AT),
        expect="open",
        description="v1.3, 2-of-3 quorum mixing ECDH shares with a passphrase share",
        open_with={"keys": ["alice"], "passphrases": [PASSPHRASE]},
        plaintext=DEAL, payload_file=deal_file, filename="deal.txt",
        content_type="text/plain", must_not_open_with={"keys": ["alice"]},
    )

    # ── Positive: payload edge cases ─────────────────────────────────────
    add(
        "v13-empty-payload",
        cell_create(EMPTY, "empty.bin", [Recipient.for_key(alice)], created_at=CREATED_AT),
        expect="open", description="v1.3, zero-byte file — the manifest is the whole plaintext",
        open_with={"keys": ["alice"]}, plaintext=EMPTY, payload_file=empty_file,
        filename="empty.bin", content_type="application/octet-stream",
    )

    add(
        "v13-binary-payload",
        cell_create(BINARY, "binary-1024.bin", [Recipient.for_key(alice)],
                    created_at=CREATED_AT),
        expect="open", description="v1.3, all 256 byte values — catches text-mode handling",
        open_with={"keys": ["alice"]}, plaintext=BINARY, payload_file=binary_file,
        filename="binary-1024.bin", content_type="application/octet-stream",
    )

    add(
        "v13-unicode-manifest",
        cell_create(UNICODE, "rapport-financiér-😀.txt", [Recipient.for_key(alice)],
                    content_type="text/plain", meta={"note": "café ☕", "n": 3},
                    created_at=CREATED_AT),
        expect="open",
        description="v1.3, astral filename and non-ASCII meta inside the encrypted manifest",
        open_with={"keys": ["alice"]}, plaintext=UNICODE, payload_file=unicode_file,
        filename="rapport-financiér-😀.txt", content_type="text/plain",
        meta={"note": "café ☕", "n": 3},
    )

    add(
        "v13-lifetime-split",
        cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)], content_type="text/plain",
                    lifetime={"type": "record",
                              "advisory": {"retain_until": FUTURE, "release_at": None,
                                           "single_use": False, "minimum_atl": 2},
                              "disposal": {"at": PAST, "action": "archive"}},
                    created_at=CREATED_AT),
        expect="open",
        description="v1.3 lifetime split by enforcer — a PASSED disposal date must not block an open",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        notes="§8.2: disposal describes the operator's retention schedule, not the "
              "recipient's permission. An opener that refuses this cell is wrong.",
    )

    # ── Positive: superseded versions (§12) ──────────────────────────────
    for version, note in (
        ("1.2", "canonical serialization, flat lifetime (expires_at/on_expiry)"),
        ("1.1", "AAD over JSON.stringify; hash over insertion-ordered JSON.stringify"),
        ("1.0", "no AAD at all; hash over insertion-ordered JSON.stringify"),
    ):
        add(
            f"v{version.replace('.', '')}-ecdh-single",
            seal_at_version(version, DEAL, "deal.txt", [alice]),
            expect="open", description=f"v{version} read path — {note}",
            open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
            filename="deal.txt", content_type="text/plain",
            notes="Key order in this file is significant for 1.0/1.1: they hash the "
                  "header as written, not canonicalized. Reformatting breaks them, "
                  "which is exactly why 1.2 introduced canonicalization."
                  if version != "1.2" else None,
        )

    add(
        "legacy-v2-no-hkdf",
        seal_legacy_v2(DEAL, "deal.txt", alice),
        expect="open",
        description="Pre-spec legacy v2.0 — raw ECDH output as the AES-KW key, no HKDF, "
                    "no header, plaintext filename, no manifest prefix",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        notes="Read-only. No conforming writer may produce this shape (§12).",
    )

    # ── Negative: the refusals are the contract ──────────────────────────
    good = cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)],
                       content_type="text/plain", created_at=CREATED_AT)
    signed = cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)], sender=bob,
                         content_type="text/plain", created_at=CREATED_AT)

    def clone(source: dict) -> dict:
        return json.loads(json.dumps(source))

    c = clone(good)
    del c["header_hash"]
    add("reject-header-hash-missing", c, expect="reject",
        description="header_hash deleted — absence is a rejection, not licence to skip §10",
        open_with={"keys": ["alice"]}, reject_reason="header-hash-missing", reject_at_step=1,
        notes="Guarding the integrity block on header_hash's own presence would let "
              "deleting one field disable the header, ciphertext and signature checks "
              "together (§4.1).")

    c = clone(good)
    c["header"]["policy"]["copy_protection"] = "none"
    add("reject-header-hash-mismatch", c, expect="reject",
        description="header edited without recomputing header_hash",
        open_with={"keys": ["alice"]}, reject_reason="header-hash-mismatch", reject_at_step=1)

    c = clone(good)
    raw = bytearray(base64.b64decode(c["payload"]["ciphertext"]))
    raw[0] ^= 0x01
    c["payload"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    add("reject-payload-hash-mismatch", c, expect="reject",
        description="ciphertext flipped by one bit; payload_hash in the header no longer matches",
        open_with={"keys": ["alice"]}, reject_reason="payload-hash-mismatch", reject_at_step=2)

    c = clone(signed)
    raw = bytearray(base64.b64decode(c["header_sig"]))
    raw[0] ^= 0xFF
    c["header_sig"] = base64.b64encode(bytes(raw)).decode()
    add("reject-signature-invalid", c, expect="reject",
        description="header_sig corrupted",
        open_with={"keys": ["alice"]}, reject_reason="signature-invalid", reject_at_step=3)

    c = clone(signed)
    c["header_sig"] = base64.b64encode(
        crypto.p1363_to_der(base64.b64decode(c["header_sig"]))
    ).decode()
    add("reject-signature-der", c, expect="reject",
        description="header_sig re-encoded as DER — the named trap of §4.1",
        open_with={"keys": ["alice"]}, reject_reason="signature-der-encoded", reject_at_step=3,
        notes="OpenSSL, Java, Go and python-cryptography all produce DER by default. "
              "The format requires raw 64-byte r||s (IEEE P1363). An implementation "
              "that accepts DER here interoperates with nothing.")

    c = clone(signed)
    c["header"]["access_map"] = clone(
        cell_create(DEAL, "deal.txt", [Recipient.for_key(dave)], created_at=CREATED_AT)
    )["header"]["access_map"]
    rehash(c)
    add("reject-forged-access-map", c, expect="reject",
        description="access_map swapped for one addressed to dave, header_hash recomputed",
        open_with={"keys": ["dave"]}, reject_reason="signature-invalid", reject_at_step=3,
        notes="access_map is not in the AAD (it does not exist at encryption time), so "
              "header_hash covers it — and an attacker who recomputes that unkeyed hash "
              "is caught by the signature. On an UNSIGNED cell this substitution is "
              "detected only when the GCM tag fails at step 4.")

    c = clone(good)
    c["header"]["policy"]["copy_protection"] = "none"
    rehash(c)
    add("reject-tampered-aad", c, expect="reject",
        description="AAD-bound policy edited AND header_hash recomputed — steps 1-3 all pass",
        open_with={"keys": ["alice"]}, reject_reason="aad-mismatch", reject_at_step=4,
        notes="The cell is internally consistent. Only the AES-GCM tag catches this, "
              "which is the whole point of §4.4: metadata tampering is not strippable.")

    c = clone(good)
    c["version"] = "1.0"
    rehash(c)
    add("reject-version-downgrade", c, expect="reject",
        description="version rewritten to 1.0 to strip the AAD from the decrypt",
        open_with={"keys": ["alice"]}, reject_reason="aad-mismatch", reject_at_step=4,
        notes="The ciphertext was produced WITH AAD, so decrypting without it fails the "
              "tag. An attacker cannot re-encrypt without the CEK (§4.4).")

    c = clone(good)
    c["version"] = "9.9"
    add("reject-unsupported-version", c, expect="reject",
        description="version not in SUPPORTED_VERSIONS",
        open_with={"keys": ["alice"]}, reject_reason="unsupported-version", reject_at_step=0)

    add("reject-quorum-short",
        cell_create(DEAL, "deal.txt",
                    [Recipient.for_key(k) for k in (alice, bob, carol, dave)],
                    content_type="text/plain", threshold=3, created_at=CREATED_AT),
        expect="reject", description="valid 3-of-4 quorum opened with only two shares",
        open_with={"keys": ["alice", "bob"]}, reject_reason="quorum-not-met", reject_at_step=4)

    add("reject-wrong-key", clone(good), expect="reject",
        description="valid cell, key that is not a recipient",
        open_with={"keys": ["mallory"]}, reject_reason="no-matching-key", reject_at_step=4)

    add("reject-retention-expired",
        cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)], content_type="text/plain",
                    lifetime={"type": "record", "advisory": {"retain_until": PAST}},
                    created_at=CREATED_AT),
        expect="reject",
        description="advisory.retain_until in the past — conforming software refuses",
        open_with={"keys": ["alice"]}, reject_reason="retention-expired", reject_at_step=0,
        notes="ADVISORY ONLY (§8.1). A keyholder can bypass this and the specification "
              "says so; an implementation offering an explicit override is conforming, "
              "and its DEFAULT must still be to refuse.")

    add("reject-timed-release-locked",
        cell_create(DEAL, "deal.txt", [Recipient.for_key(alice)], content_type="text/plain",
                    lifetime={"type": "timed_release", "advisory": {"release_at": FUTURE}},
                    created_at=CREATED_AT),
        expect="reject",
        description="timed_release with release_at in the future",
        open_with={"keys": ["alice"]}, reject_reason="timed-release-locked", reject_at_step=0,
        notes="Same advisory caveat as reject-retention-expired. Evaluated against the "
              "wall clock: this vector expires as a test on 2100-01-01.")

    manifest = {
        "version": 1,
        "spec": "1.3",
        "generated_by": "conformance/make-vectors.py",
        "keys_dir": "../keys",
        "passphrase": PASSPHRASE,
        "reject_reasons": [
            "header-hash-missing", "header-hash-mismatch", "payload-hash-mismatch",
            "signature-invalid", "signature-der-encoded", "aad-mismatch",
            "unsupported-version", "quorum-not-met", "no-matching-key",
            "retention-expired", "timed-release-locked",
        ],
        "vectors": vectors,
    }
    (VECTORS / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    opens = sum(1 for v in vectors if v["expect"] == "open")
    print(f"wrote {len(vectors)} vectors ({opens} open, {len(vectors) - opens} reject)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
