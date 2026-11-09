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
1.0, 1.1 or 1.2 any more — the library writes 1.4, and 1.3 on request — but §12
requires readers to keep opening them, and a version nobody has a vector for is
a version nobody actually tests.

    python3 conformance/make-vectors.py              # regenerate EVERYTHING (rarely)
    python3 conformance/make-vectors.py --add-v14    # (re)write only the v1.4 vectors,
                                                     # leaving every committed vector as is
    python3 conformance/make-vectors.py --add-derived  # (re)write only the vectors derived
                                                       # from committed ones (DERIVED_IDS)
    python3 conformance/make-vectors.py --add-hardening  # (re)write only HARDENING_IDS
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

from cellular_defense import KeyRecord, Recipient, cell_open  # noqa: E402
from cellular_defense import cell_create as _cell_create  # noqa: E402
from cellular_defense import crypto  # noqa: E402
from cellular_defense.cell import cell_aad, serialize_header  # noqa: E402
from cellular_defense.codec import b64encode  # noqa: E402

def cell_create(*args, **kwargs):
    """The v1.3 vectors stay v1.3: the library writes 1.4 by default now."""
    kwargs.setdefault("version", "1.3")
    return _cell_create(*args, **kwargs)


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


REJECT_REASONS = [
    "header-hash-missing", "header-hash-mismatch", "payload-hash-mismatch",
    "signature-invalid", "signature-der-encoded", "aad-mismatch",
    "unsupported-version", "quorum-not-met", "no-matching-key",
    "retention-expired", "timed-release-locked",
    # v1.4
    "signature-misplaced", "padding-invalid", "access-map-too-large",
    # 2026-11-08 (pen test of 2026-11-05, M2/L5/M4)
    "gzip-invalid", "kdf-work-exceeded",
]


def seal_v14_with_body(data: bytes, filename: str, recipient: KeyRecord, body_hook) -> dict:
    """A v1.4 cell sealed by hand, so the padded body can be malformed on purpose."""
    manifest = {"filename": filename, "content_type": "text/plain", "size": len(data)}
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    gz = crypto.gzip_compress(struct.pack("<I", len(manifest_bytes)) + manifest_bytes + data)
    body = body_hook(bytearray(crypto.pad_body(gz)))
    cek = secrets.token_bytes(32)
    header: dict = {
        "prev_hash": None,
        "threshold": {"required": 1, "of_total": 1},
        "lifetime": {"type": "permanent",
                     "advisory": {"retain_until": None, "release_at": None, "single_use": False, "minimum_atl": 1},
                     "disposal": {"at": None, "action": "none"}},
        "policy": {"copy_protection": "standard", "watermark_mode": "none",
                   "created_on_origin": None, "origin_sig": None},
    }
    iv, ciphertext = crypto.aes_gcm_encrypt(cek, bytes(body), cell_aad(header, "1.4"))
    header["access_map"] = [{"method": "ecdh-p256", "wrapped_cek": crypto.ecdh_wrap_cek(cek, recipient.spki)}]
    header["payload_hash"] = b64encode(crypto.sha256(ciphertext))
    return {
        "version": "1.4", "doc_id": "01CONFORMANCE14PAD000000000", "created_at": CREATED_AT,
        "header": header,
        "header_hash": b64encode(crypto.sha256(serialize_header(header, "1.4"))),
        "payload": {"alg": "AES-256-GCM", "encoding": "base64+gzip+padme",
                    "iv": b64encode(iv), "ciphertext": b64encode(ciphertext)},
    }


def build_v14(deal_file: str, unicode_file: str) -> None:
    """v1.4 vectors: blind entries, inner signature, Padmé, Argon2id (§4.5, §5.4, §6)."""
    alice, bob, carol = (key(n) for n in ("alice", "bob", "carol"))
    mallory_only = {"keys": ["mallory"]}

    def seal(*args, **kwargs):
        kwargs.setdefault("version", "1.4")
        kwargs.setdefault("created_at", CREATED_AT)
        return _cell_create(*args, **kwargs)

    def clone(source: dict) -> dict:
        return json.loads(json.dumps(source))

    add("v14-ecdh-single",
        seal(DEAL, "deal.txt", [Recipient.for_key(alice)], content_type="text/plain"),
        expect="open", description="v1.4, one ECDH recipient, unsigned; entry carries no fingerprint or label",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", must_not_open_with=mallory_only,
        notes="Openers find their entry by trial decryption: AES-KW's integrity check "
              "rejects a wrong key (§6).")

    add("v14-ecdh-signed",
        seal(DEAL, "deal.txt", [Recipient.for_key(alice)], sender=bob,
             content_type="text/plain", meta={"case": "2026-0417"}),
        expect="open",
        description="v1.4, signed by bob INSIDE the encrypted manifest; nothing outside the "
                    "ciphertext names bob",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", meta={"case": "2026-0417"},
        signer="bob", must_not_open_with=mallory_only,
        notes="sender.to lists alice's fingerprint; the signer is the fingerprint of "
              "sender.spki, recomputed (§4.5).")

    add("v14-multi-recipient",
        seal(DEAL, "deal.txt", [Recipient.for_key(k) for k in (alice, bob, carol)], content_type="text/plain"),
        expect="open", description="v1.4, three blind ECDH entries; carol's is the last one tried",
        open_with={"keys": ["carol"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", must_not_open_with=mallory_only)

    add("v14-quorum-2of3",
        seal(DEAL, "deal.txt", [Recipient.for_key(k) for k in (alice, bob, carol)],
             threshold=2, content_type="text/plain"),
        expect="open", description="v1.4, 2-of-3 Shamir quorum over blind entries",
        open_with={"keys": ["carol", "alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain")

    add("v14-argon2id",
        seal(DEAL, "deal.txt", [Recipient.argon2id(PASSPHRASE)], content_type="text/plain"),
        expect="open",
        description="v1.4, Argon2id passphrase entry at the default parameters (m=65536 KiB, t=3, p=4)",
        open_with={"passphrases": [PASSPHRASE]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        notes="The KDF input is the UTF-8 of the passphrase's NFC form (§6.5).")

    add("v14-pbkdf2",
        seal(DEAL, "deal.txt", [Recipient.passphrase_(PASSPHRASE)], content_type="text/plain"),
        expect="open", description="v1.4 still accepts a PBKDF2 entry; it is blind like every other",
        open_with={"passphrases": [PASSPHRASE]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain")

    add("v14-unicode-signed",
        seal(UNICODE, "rapport-financiér-😀.txt", [Recipient.for_key(alice)], sender=bob,
             content_type="text/plain; charset=utf-8", meta={"note": "é 😀", "n": [1, 2.5, None]}),
        expect="open",
        description="v1.4 signed cell whose manifest is non-ASCII — the signed bytes are the "
                    "canonical JSON of the manifest, so every port must canonicalize identically",
        open_with={"keys": ["alice"]}, plaintext=UNICODE, payload_file=unicode_file,
        filename="rapport-financiér-😀.txt", content_type="text/plain; charset=utf-8",
        meta={"note": "é 😀", "n": [1, 2.5, None]}, signer="bob")

    good = seal(DEAL, "deal.txt", [Recipient.for_key(alice)], content_type="text/plain")
    signed = seal(DEAL, "deal.txt", [Recipient.for_key(alice)], sender=bob, content_type="text/plain")

    c = clone(good)
    c["header_sig"], c["header_sig_by"], c["header_sig_key"] = "AAAA", "bob", bob.spki
    add("reject-v14-header-signature", c, expect="reject",
        description="a v1.4 cell carrying a header signature", open_with={"keys": ["alice"]},
        reject_reason="signature-misplaced", reject_at_step=1,
        notes="v1.4 signatures live inside the payload; a header_sig here is malformed (§4.5).")

    c = clone(good)
    c["version"] = "1.3"
    add("reject-v14-version-relabelled", c, expect="reject",
        description="a v1.4 cell relabelled 1.3 (header_hash is unchanged: both canonicalize)",
        open_with={"keys": ["alice"]}, reject_reason="aad-mismatch", reject_at_step=4,
        notes="v1.4's AAD includes the version, so the GCM tag fails (§4.4).")

    c = clone(signed)
    c["created_at"] += 1
    add("reject-v14-inner-signature", c, expect="reject",
        description="signed v1.4 cell whose created_at was changed after sealing",
        open_with={"keys": ["alice"]}, reject_reason="signature-invalid", reject_at_step=5,
        notes="created_at and doc_id are outside the AAD but inside the signed input (§4.5); "
              "the check runs after decryption, when the signature becomes visible.")

    add("reject-v14-padding-nonzero",
        seal_v14_with_body(DEAL, "deal.txt", alice, lambda b: (b.__setitem__(len(b) - 1, 7), b)[1]),
        expect="reject", description="padding bytes after the framed body are not all zero",
        open_with={"keys": ["alice"]}, reject_reason="padding-invalid", reject_at_step=5)

    add("reject-v14-padding-length",
        seal_v14_with_body(DEAL, "deal.txt", alice,
                           lambda b: (b.__setitem__(slice(0, 4), struct.pack("<I", len(b))), b)[1]),
        expect="reject", description="the framed length runs past the end of the body",
        open_with={"keys": ["alice"]}, reject_reason="padding-invalid", reject_at_step=5)

    c = clone(good)
    c["header"]["access_map"] = c["header"]["access_map"] * 257
    add("reject-v14-access-map-too-large", rehash(c), expect="reject",
        description="257 access-map entries (the limit is 256)", open_with={"keys": ["alice"]},
        reject_reason="access-map-too-large", reject_at_step=1,
        notes="Trial decryption costs one ECDH per entry and key; the bound is a DoS guard (§6).")

    c = seal(DEAL, "deal.txt", [Recipient.argon2id(PASSPHRASE, {"m": 19456, "t": 2, "p": 1})],
             content_type="text/plain")
    c["header"]["access_map"][0]["wrapped_cek"].update({"m": 8, "t": 1, "p": 1})
    add("reject-v14-argon2id-weak", rehash(c), expect="reject",
        description="Argon2id entry claiming m=8 KiB, t=1", open_with={"passphrases": [PASSPHRASE]},
        reject_reason="no-matching-key", reject_at_step=4,
        notes="Openers refuse the parameters (§6.5) and so recover no key from this entry.")


#: Vectors made by editing a committed vector outside its authenticated bytes,
#: so they re-derive deterministically from it.
DERIVED_IDS = (
    "v14-legacy-fields-ignored",
    # Added 2026-11-09 after the pen test of the same day (KB #2309, #2311).
    "v13-header-sig-by-not-trusted",
    "reject-retention-expired-float", "reject-timed-release-locked-exponent",
    "v13-quorum-3of4-float", "v14-quorum-2of3-exponent",
)


def committed(folder: str, vector_id: str) -> dict:
    return json.loads((VECTORS / folder / f"{vector_id}.cell").read_text(encoding="utf-8"))


def retext(folder: str, vector_id: str, *subs: tuple[str, str]) -> None:
    """Rewrite numbers in a written vector as text. json.dumps cannot emit `2e0`."""
    import re
    path = VECTORS / folder / f"{vector_id}.cell"
    text = path.read_text(encoding="utf-8")
    for pattern, repl in subs:
        text, n = re.subn(pattern, repl, text)
        assert n, f"{vector_id}: {pattern!r} matched nothing"
    path.write_text(text, encoding="utf-8")


def build_derived(deal_file: str) -> None:
    """Edits a third party can make without any key, which a reader must not act on."""
    signed = committed("open", "v14-ecdh-signed")
    # Top-level original_filename / content_type / original_size are fields of the
    # pre-spec v2.0 envelope (§12), which kept its metadata outside the ciphertext.
    # They are covered by nothing: not header_hash, not the AAD. Reading them on a
    # supported version once switched every implementation onto the legacy
    # plaintext path, which skipped the manifest — and with it the v1.4 sender
    # signature and any expected-signer requirement — and handed the editor the
    # filename and media type.
    signed.update(original_filename="contract-final.html", content_type="text/html",
                  original_size=1)
    add("v14-legacy-fields-ignored", signed,
        expect="open",
        description="v14-ecdh-signed plus top-level original_filename/content_type/original_size, "
                    "added by a third party; a v1.x reader ignores them",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", meta={"case": "2026-0417"},
        signer="bob", must_not_open_with={"keys": ["mallory"]},
        notes="Those three fields belong to legacy v2.0 cells (cd_version, no version) only. "
              "On any supported version the manifest is always parsed and the inner signature "
              "always verified; the filename, media type and signer come from inside the "
              "ciphertext.")
    build_derived_2026_11_09(deal_file)


def build_derived_2026_11_09(deal_file: str) -> None:
    mallory = key("mallory")

    # ≤v1.3 header_sig_by is a label the signer writes about themselves, and
    # neither header_hash nor header_sig covers it. The reference once returned
    # it as the verified signer, so any sender could claim another's key.
    c = committed("open", "v13-ecdh-signed")
    c["header_sig_by"] = mallory.fingerprint
    add("v13-header-sig-by-not-trusted", c, expect="open",
        description="v13-ecdh-signed (signed by bob) with header_sig_by changed to mallory's "
                    "fingerprint; the signer is still bob",
        open_with={"keys": ["alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain", meta={"case": "2026-0417"},
        signer="bob", must_not_open_with={"keys": ["mallory"]},
        notes="The signer an opener reports is the fingerprint of header_sig_key, the key that "
              "verified. header_sig_by changes no authenticated byte, so it can say anything (§4.1).")

    # A number's canonical form is JavaScript's (§4.1.1): 1577836800.0, 1.5778368e9
    # and 1577836800 all serialize as 1577836800, so the rewrite changes neither
    # header_hash nor the AAD and the cell still decrypts. A reader must treat
    # the rewritten value exactly as the integer; one that read it as "absent"
    # let any third party switch the retention and release checks off.
    c = committed("reject", "reject-retention-expired")
    c["header"]["lifetime"]["advisory"]["retain_until"] = 1577836800.0
    add("reject-retention-expired-float", c, expect="reject",
        description="reject-retention-expired with retain_until written 1577836800.0",
        open_with={"keys": ["alice"]}, reject_reason="retention-expired", reject_at_step=0,
        notes="Same canonical bytes as the integer form (§4.1.1); a reader that only "
              "recognises integer tokens skips the check. Advisory caveat as for "
              "reject-retention-expired.")

    add("reject-timed-release-locked-exponent", committed("reject", "reject-timed-release-locked"),
        expect="reject",
        description="reject-timed-release-locked with release_at written 4.1024448e9",
        open_with={"keys": ["alice"]}, reject_reason="timed-release-locked", reject_at_step=0,
        notes="Same canonical bytes as the integer form (§4.1.1). Expires as a test on 2100-01-01.")
    retext("reject", "reject-timed-release-locked-exponent",
           (r'"release_at": 4102444800\b', '"release_at": 4.1024448e9'))

    c = committed("open", "v13-quorum-3of4")
    c["header"]["threshold"] = {"required": 3.0, "of_total": 4.0}
    for entry in c["header"]["access_map"]:
        entry["share_index"] = float(entry["share_index"])
    add("v13-quorum-3of4-float", c, expect="open",
        description="v13-quorum-3of4 with required, of_total and every share_index written as N.0",
        open_with={"keys": ["alice", "bob", "carol"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        must_not_open_with={"keys": ["alice", "bob"]},
        notes="Same canonical bytes as the integer form (§4.1.1): still 3-of-4, still the same "
              "x-coordinates.")

    add("v14-quorum-2of3-exponent", committed("open", "v14-quorum-2of3"), expect="open",
        description="v14-quorum-2of3 with required, of_total and every share_index written Ne0",
        open_with={"keys": ["carol", "alice"]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        must_not_open_with={"keys": ["alice"]},
        notes="Same canonical bytes as the integer form (§4.1.1).")
    retext("open", "v14-quorum-2of3-exponent",
           (r'("(?:required|of_total|share_index)": )(\d+)\b', r'\g<1>\g<2>e0'))


def add_derived_only() -> int:
    """Rewrite just the derived vectors; every other committed vector stays byte-for-byte."""
    existing = json.loads((VECTORS / "manifest.json").read_text())
    for v in existing["vectors"]:
        if v["id"] in DERIVED_IDS:
            (VECTORS / v["file"]).unlink(missing_ok=True)
    vectors.extend(v for v in existing["vectors"] if v["id"] not in DERIVED_IDS)
    build_derived("payloads/deal.txt")
    write_manifest()
    print(f"wrote {len(DERIVED_IDS)} derived vector(s); manifest now holds {len(vectors)}")
    return 0


#: Vectors added 2026-11-08 after the pen test of 2026-11-05 (KB #2251, #2252).
HARDENING_IDS = (
    "reject-v14-gzip-two-members", "reject-v14-gzip-empty-first-member",
    "reject-v14-gzip-trailing-bytes", "reject-v14-gzip-trailing-zeros",
    "reject-v13-gzip-two-members",
    "reject-v14-padding-oversized", "reject-v14-padding-unpadded",
    "v14-kdf-cheapest-first", "v14-kdf-max-single", "reject-v14-kdf-work-bound",
)


def seal_hand(version: str, body: bytes, recipient: KeyRecord) -> dict:
    """A 1.3 or 1.4 cell sealed by hand around an exact body, so it can be malformed on purpose."""
    cek = secrets.token_bytes(32)
    header: dict = {
        "prev_hash": None,
        "threshold": {"required": 1, "of_total": 1},
        "lifetime": {"type": "permanent",
                     "advisory": {"retain_until": None, "release_at": None, "single_use": False, "minimum_atl": 1},
                     "disposal": {"at": None, "action": "none"}},
        "policy": {"copy_protection": "standard", "watermark_mode": "none",
                   "created_on_origin": None, "origin_sig": None},
    }
    iv, ciphertext = crypto.aes_gcm_encrypt(cek, body, cell_aad(header, version))
    entry = {"method": "ecdh-p256", "wrapped_cek": crypto.ecdh_wrap_cek(cek, recipient.spki)}
    if version == "1.3":
        entry = {"method": "ecdh-p256", "label": "alice", "fingerprint": recipient.fingerprint, **entry}
    header["access_map"] = [entry]
    header["payload_hash"] = b64encode(crypto.sha256(ciphertext))
    return {
        "version": version, "doc_id": "01CONFORMANCEGZIP0000000000", "created_at": CREATED_AT,
        "header": header,
        "header_hash": b64encode(crypto.sha256(serialize_header(header, version))),
        "payload": {"alg": "AES-256-GCM",
                    "encoding": "base64+gzip+padme" if version == "1.4" else "base64+gzip",
                    "iv": b64encode(iv), "ciphertext": b64encode(ciphertext)},
    }


def build_hardening(deal_file: str) -> None:
    """One file, one document (§5, §5.4), and a bounded passphrase cost per open (§6)."""
    alice = key("alice")
    manifest = json.dumps({"filename": "deal.txt", "content_type": "text/plain", "size": len(DEAL)},
                          separators=(",", ":")).encode("utf-8")
    framed = struct.pack("<I", len(manifest)) + manifest + DEAL
    gz = crypto.gzip_compress(framed)
    second = crypto.gzip_compress(b"SECOND MEMBER: a different document\n")
    one_doc = ("A body is exactly one gzip member with nothing after it. Implementations once "
               "disagreed: some joined members, some read only the first; some ignored trailing "
               "bytes, some refused. One file then opened as different documents.")

    for vid, body, what in [
        ("reject-v14-gzip-two-members", gz + second, "two gzip members"),
        ("reject-v14-gzip-empty-first-member", crypto.gzip_compress(b"") + gz,
         "an empty gzip member followed by the real one"),
        ("reject-v14-gzip-trailing-bytes", gz + b"JUNK", "one gzip member plus four trailing bytes"),
        ("reject-v14-gzip-trailing-zeros", gz + bytes(8),
         "one gzip member plus eight zero bytes (zlib's gunzip skips these)"),
    ]:
        add(vid, seal_hand("1.4", crypto.pad_body(body), alice), expect="reject",
            description=f"v1.4 body holding {what}; the padding is correct",
            open_with={"keys": ["alice"]}, reject_reason="gzip-invalid", reject_at_step=5,
            notes=one_doc)

    add("reject-v13-gzip-two-members", seal_hand("1.3", gz + second, alice), expect="reject",
        description="v1.3 (unpadded) body holding two gzip members: the rule is not v1.4-only",
        open_with={"keys": ["alice"]}, reject_reason="gzip-invalid", reject_at_step=5,
        notes=one_doc)

    padded = crypto.pad_body(gz)
    add("reject-v14-padding-oversized", seal_hand("1.4", padded + bytes(512), alice), expect="reject",
        description="v1.4 body padded 512 zero bytes past its Padmé length",
        open_with={"keys": ["alice"]}, reject_reason="padding-invalid", reject_at_step=5,
        notes="The padded body is exactly padme(4 + n) bytes (§5.4); any other length is refused.")
    add("reject-v14-padding-unpadded", seal_hand("1.4", padded[:4 + len(gz)], alice), expect="reject",
        description="v1.4 body framed but not padded",
        open_with={"keys": ["alice"]}, reject_reason="padding-invalid", reject_at_step=5,
        notes="The padded body is exactly padme(4 + n) bytes (§5.4); any other length is refused.")

    # ── Passphrase work bound (§6) ────────────────────────────────────────
    bound = ("Work per derivation: PBKDF2 = iterations × 2^24; Argon2id = m × t × 10^7. One open "
             "spends at most 10^7 × 2^24, the cost of one maximum-parameter entry. Passphrase "
             "entries are tried cheapest first.")
    base = _cell_create(DEAL, "deal.txt", [Recipient.passphrase_(PASSPHRASE)], version="1.4",
                        content_type="text/plain", created_at=CREATED_AT)
    real600k = base["header"]["access_map"][0]

    def clone(source: dict) -> dict:
        return json.loads(json.dumps(source))

    decoy = clone(real600k)
    decoy["wrapped_cek"]["iterations"] = 10_000_000   # a different key: unwraps nothing
    c = clone(base)
    c["header"]["access_map"] = [decoy, real600k]
    add("v14-kdf-cheapest-first", rehash(c), expect="open",
        description="v1.4 passphrase cell with a 10,000,000-iteration decoy entry placed before "
                    "the real 600,000-iteration one",
        open_with={"passphrases": [PASSPHRASE]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        notes=bound + " The real entry is cheaper, so it is tried first and opens the cell; an "
                      "opener that tried the decoy first would have spent the whole budget on it.")

    # The same ciphertext, its key rewrapped at the PBKDF2 maximum.
    cek = crypto.pbkdf2_unwrap_cek(real600k["wrapped_cek"], PASSPHRASE)
    salt = secrets.token_bytes(32)
    real10m = {"method": "pbkdf2", "wrapped_cek": {
        "salt": b64encode(salt), "iterations": 10_000_000,
        "ct": b64encode(keywrap.aes_key_wrap(crypto._pbkdf2(PASSPHRASE, salt, 10_000_000), cek))}}
    c = clone(base)
    c["header"]["access_map"] = [real10m]
    add("v14-kdf-max-single", rehash(c), expect="open",
        description="v1.4 cell whose only entry is PBKDF2 at 10,000,000 iterations, the maximum",
        open_with={"passphrases": [PASSPHRASE]}, plaintext=DEAL, payload_file=deal_file,
        filename="deal.txt", content_type="text/plain",
        notes=bound + " A single entry within the limits always fits. This vector runs one "
                      "maximum-cost derivation.")

    cheap = clone(real10m)
    cheap["wrapped_cek"]["iterations"] = 600_000      # a different key: unwraps nothing
    c = clone(base)
    c["header"]["access_map"] = [real10m, cheap]
    add("reject-v14-kdf-work-bound", rehash(c), expect="reject",
        description="v1.4 cell: the real PBKDF2 entry at 10,000,000 iterations plus a cheaper "
                    "600,000-iteration decoy",
        open_with={"passphrases": [PASSPHRASE]}, reject_reason="kdf-work-exceeded", reject_at_step=4,
        notes=bound + " The decoy is tried first (600,000 × 2^24); the real entry would take the "
                      "total past the limit, so it is never derived. An opener without the bound "
                      "opens this cell.")


def add_hardening_only() -> int:
    """Rewrite just HARDENING_IDS; every other committed vector stays byte-for-byte."""
    existing = json.loads((VECTORS / "manifest.json").read_text())
    for v in existing["vectors"]:
        if v["id"] in HARDENING_IDS:
            (VECTORS / v["file"]).unlink(missing_ok=True)
    vectors.extend(v for v in existing["vectors"] if v["id"] not in HARDENING_IDS)
    build_hardening("payloads/deal.txt")
    write_manifest()
    print(f"wrote {len(HARDENING_IDS)} hardening vectors; manifest now holds {len(vectors)}")
    return 0


def write_manifest() -> None:
    manifest = {
        "version": 1,
        "spec": "1.4",
        "generated_by": "conformance/make-vectors.py",
        "keys_dir": "../keys",
        "passphrase": PASSPHRASE,
        "reject_reasons": REJECT_REASONS,
        "vectors": vectors,
    }
    (VECTORS / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def add_v14_only() -> int:
    """Rewrite just the v1.4 vectors; every committed vector stays byte-for-byte."""
    existing = json.loads((VECTORS / "manifest.json").read_text())
    is_v14 = lambda v: v["id"].startswith(("v14-", "reject-v14-")) or v["id"] in HARDENING_IDS
    for v in existing["vectors"]:
        if is_v14(v):
            (VECTORS / v["file"]).unlink(missing_ok=True)
    vectors.extend(v for v in existing["vectors"] if not is_v14(v))
    build_v14("payloads/deal.txt", "payloads/unicode.txt")
    build_derived("payloads/deal.txt")
    build_hardening("payloads/deal.txt")
    write_manifest()
    added = sum(1 for v in vectors if is_v14(v))
    print(f"wrote {added} v1.4 vectors; manifest now holds {len(vectors)}")
    return 0


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

    build_v14(deal_file, unicode_file)
    build_derived(deal_file)
    build_hardening(deal_file)
    write_manifest()

    opens =sum(1 for v in vectors if v["expect"] == "open")
    print(f"wrote {len(vectors)} vectors ({opens} open, {len(vectors) - opens} reject)")
    return 0


if __name__ == "__main__":
    if "--add-derived" in sys.argv[1:]:
        raise SystemExit(add_derived_only())
    if "--add-hardening" in sys.argv[1:]:
        raise SystemExit(add_hardening_only())
    raise SystemExit(add_v14_only() if "--add-v14" in sys.argv[1:] else main())
