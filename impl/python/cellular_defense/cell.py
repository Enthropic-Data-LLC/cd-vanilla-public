# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Sealing and opening ``.cell`` documents — spec §4, §5, §10, §12."""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto, gf256, lifetime as lifetime_mod
from .canonical import canonical_bytes, js_stringify
from .codec import b64decode, b64encode
from .errors import (
    CellError,
    IntegrityError,
    LifetimeError,
    MalformedCellError,
    NoMatchingKeyError,
    QuorumNotMetError,
    SignatureError,
    UnsupportedVersionError,
)
from .keys import KeyRecord
from .ulid import ulid

#: The version this library writes.
CELL_FORMAT_VERSION = "1.3"

#: Versions this library can read (spec §12).
SUPPORTED_VERSIONS = frozenset({"1.0", "1.1", "1.2", "1.3"})

#: Versions whose hash/signature/AAD use the canonical serialization (§4.1.1).
#: Held as a set on purpose: §12 warns that adding a version to
#: SUPPORTED_VERSIONS while leaving an inline ``version == "1.2"`` test
#: somewhere silently drops canonicalization, with no error raised anywhere.
CANONICAL_VERSIONS = frozenset({"1.2", "1.3"})

#: Versions that bind metadata to the ciphertext as AES-GCM AAD (§4.4).
AAD_VERSIONS = frozenset({"1.1", "1.2", "1.3"})

DEFAULT_POLICY: dict = {
    "copy_protection": "standard",
    "watermark_mode": "none",
    "created_on_origin": None,
    "origin_sig": None,
}


# ─────────────────────────────────────────────────────────────────────────────
# Serialization — what gets hashed, signed and authenticated
# ─────────────────────────────────────────────────────────────────────────────


def serialize_header(header: dict, version: str) -> bytes:
    """Bytes that ``header_hash`` and ``header_sig`` are computed over (§4.1.1).

    v1.2/v1.3 canonicalize; v1.0/v1.1 keep the original insertion-ordered
    ``JSON.stringify`` form, which means those two versions can only be verified
    from a header still in its on-disk key order (§12).
    """
    if version in CANONICAL_VERSIONS:
        return canonical_bytes(header)
    return js_stringify(header).encode("utf-8")


def cell_aad(header: dict, version: str) -> bytes | None:
    """Additional authenticated data for the payload (§4.4).

    The four fields fixed *before* encryption, in a fixed order, as an array.
    ``access_map`` and ``payload_hash`` are absent because they do not exist yet
    at encryption time — they are covered by ``header_hash``/``header_sig``
    instead. Returns None for versions that bind no AAD.
    """
    if version not in AAD_VERSIONS:
        return None
    meta = [
        header.get("prev_hash"),
        header.get("threshold"),
        header.get("lifetime"),
        header.get("policy"),
    ]
    if version == "1.1":
        return js_stringify(meta).encode("utf-8")
    return canonical_bytes(meta)


# ─────────────────────────────────────────────────────────────────────────────
# Recipients
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Recipient:
    """One access-map entry to be created. Use the classmethods, not the fields."""

    method: str
    label: str
    spki: str | None = None
    passphrase: str | None = None
    credential_id: str | None = None
    prf_salt: str | None = None
    prf_output: bytes | None = None

    @classmethod
    def ecdh(cls, spki: str, label: str = "Recipient") -> "Recipient":
        """Wrap for the holder of a P-256 public key (base64 SPKI)."""
        return cls(method="ecdh-p256", label=label, spki=spki)

    @classmethod
    def for_key(cls, key: KeyRecord) -> "Recipient":
        return cls(method="ecdh-p256", label=key.label, spki=key.spki)

    @classmethod
    def passphrase_(cls, passphrase: str, label: str = "Passphrase") -> "Recipient":
        return cls(method="pbkdf2", label=label, passphrase=passphrase)

    @classmethod
    def prf(cls, credential_id: str, prf_salt: str, prf_output: bytes, label: str = "Security key") -> "Recipient":
        """Wrap under a WebAuthn PRF output the caller has already obtained."""
        return cls(
            method="yubikey-prf",
            label=label,
            credential_id=credential_id,
            prf_salt=prf_salt,
            prf_output=prf_output,
        )


def _wrap_entry(recipient: Recipient, key_material: bytes, share_index: int | None) -> dict:
    entry: dict[str, Any] = {"label": recipient.label, "method": recipient.method}

    if recipient.method == "ecdh-p256":
        if not recipient.spki:
            raise CellError("ecdh-p256 recipient needs an spki")
        entry["fingerprint"] = crypto.fingerprint(b64decode(recipient.spki, field="spki"))
        wrapped = crypto.ecdh_wrap_cek(key_material, recipient.spki)
    elif recipient.method == "pbkdf2":
        if recipient.passphrase is None:
            raise CellError("pbkdf2 recipient needs a passphrase")
        wrapped = crypto.pbkdf2_wrap_cek(key_material, recipient.passphrase)
        # A passphrase has no public key, so §6.2 fingerprints the salt instead.
        # It identifies the entry, not the holder — it is not a key fingerprint
        # and proves nothing about who can open it.
        entry["fingerprint"] = crypto.sha256(b64decode(wrapped["salt"], field="salt")).hex()[:16]
    elif recipient.method == "yubikey-prf":
        if not (recipient.credential_id and recipient.prf_salt and recipient.prf_output):
            raise CellError("yubikey-prf recipient needs credential_id, prf_salt and prf_output")
        entry["fingerprint"] = crypto.sha256(
            b64decode(recipient.credential_id, field="credential_id")
        ).hex()[:16]
        wrapped = crypto.prf_wrap_cek(
            key_material, recipient.credential_id, recipient.prf_salt, recipient.prf_output
        )
    else:
        raise CellError(f"unknown access method {recipient.method!r}")

    # §6.4: on non-quorum cells the key is OMITTED, not written as null. The
    # choice is not cosmetic — canonicalization preserves an explicit null, so
    # the two forms hash differently. Both verify; they are not byte-identical.
    if share_index is not None:
        entry["share_index"] = share_index
    entry["wrapped_cek"] = wrapped
    return entry


# ─────────────────────────────────────────────────────────────────────────────
# Sealing
# ─────────────────────────────────────────────────────────────────────────────


def cell_create(
    data: bytes,
    filename: str,
    recipients: Sequence[Recipient],
    *,
    content_type: str = "application/octet-stream",
    threshold: int = 1,
    lifetime: dict | None = None,
    policy: dict | None = None,
    prev_hash: str | None = None,
    meta: dict | None = None,
    sender: KeyRecord | None = None,
    doc_id: str | None = None,
    created_at: int | None = None,
) -> dict:
    """Seal ``data`` into a v1.3 cell.

    ``threshold`` > 1 splits the CEK into one Shamir share per recipient, of
    which that many are needed (§7). ``sender`` adds a ``header_sig``; note that
    its *absence* is undetectable to a reader (§4.1), so a signature proves
    authorship while no signature proves nothing at all.

    ``meta`` is sender-defined JSON carried inside the encrypted manifest — the
    server and any observer never see it.
    """
    if not recipients:
        raise CellError("a cell needs at least one recipient")
    required = max(1, min(threshold, len(recipients)))

    # ── Manifest-prefixed plaintext (§5): filename, type and size live inside
    # the ciphertext, so an observer of the stored cell learns none of them.
    manifest: dict[str, Any] = {
        "filename": filename,
        "content_type": content_type or "application/octet-stream",
        "size": len(data),
    }
    if meta:
        manifest["meta"] = meta
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    plaintext = struct.pack("<I", len(manifest_bytes)) + manifest_bytes + data
    body = crypto.gzip_compress(plaintext)

    cek = bytearray(__import__("secrets").token_bytes(crypto.CEK_LENGTH))

    # ── Metadata is fixed before encryption precisely so it can be bound as AAD.
    header: dict[str, Any] = {
        "prev_hash": prev_hash,
        "threshold": {"required": required, "of_total": len(recipients)},
        "lifetime": lifetime_mod.normalize(lifetime) or dict(lifetime_mod.PERMANENT),
        "policy": policy or dict(DEFAULT_POLICY),
    }
    iv, ciphertext = crypto.aes_gcm_encrypt(
        bytes(cek), body, cell_aad(header, CELL_FORMAT_VERSION)
    )

    try:
        if required > 1:
            shares = gf256.split(bytes(cek), len(recipients), required)
            access_map = [
                _wrap_entry(r, shares[i].data, i + 1) for i, r in enumerate(recipients)
            ]
        else:
            access_map = [_wrap_entry(r, bytes(cek), None) for r in recipients]
    finally:
        _wipe(cek)

    header["access_map"] = access_map
    header["payload_hash"] = b64encode(crypto.sha256(ciphertext))

    header_bytes = serialize_header(header, CELL_FORMAT_VERSION)
    cell: dict[str, Any] = {
        "version": CELL_FORMAT_VERSION,
        "doc_id": doc_id or ulid(),
        "created_at": created_at if created_at is not None else int(time.time()),
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

    if sender is not None:
        if sender.private is None:
            raise CellError("signing requires a KeyRecord with a private key")
        cell["header_sig"] = b64encode(crypto.ecdsa_sign(sender.private, header_bytes))
        cell["header_sig_by"] = sender.fingerprint
        cell["header_sig_key"] = sender.spki

    return cell


# ─────────────────────────────────────────────────────────────────────────────
# Key-free verification — spec §10 steps 1-3
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class VerifyResult:
    """Outcome of the checks that need no key material at all."""

    version: str
    header_hash_ok: bool
    payload_hash_ok: bool
    #: True if a signature was present and verified; False if absent.
    signed: bool
    #: Real fingerprint of ``header_sig_key`` — the only trustworthy identity here.
    signer_fingerprint: str | None = None
    #: ``header_sig_by``: self-asserted, never to be trusted on its own (§4.1).
    claimed_signer: str | None = None


def verify_cell(cell: dict, *, expected_signer: str | None = None) -> VerifyResult:
    """Verify a cell's audit chain without opening it (§10).

    That this is possible with no key is the property being demonstrated: any
    third party can confirm a cell has not been altered since it was sealed.

    Raises :class:`.IntegrityError` or :class:`.SignatureError` on failure. A
    clean return does **not** establish authorship: an attacker can strip
    ``header_sig`` entirely and the result is indistinguishable from a cell that
    was never signed. Pass ``expected_signer`` (a fingerprint learned out of
    band) whenever authorship matters.
    """
    version = _version_of(cell)
    header = cell.get("header")
    if not isinstance(header, dict):
        raise MalformedCellError("malformed cell — missing header")

    # §4.1: absence of header_hash is a rejection, not licence to skip the
    # checks. Guarding this block on its own presence would mean deleting one
    # field disables the header, ciphertext and signature checks together.
    if not cell.get("header_hash"):
        raise IntegrityError("integrity check failed — header_hash is missing")

    header_bytes = serialize_header(header, version)
    if b64encode(crypto.sha256(header_bytes)) != cell["header_hash"]:
        raise IntegrityError("integrity check failed — header may be tampered")

    payload = cell.get("payload") or cell.get("encrypted_body") or {}
    ct_b64 = payload.get("ciphertext") or payload.get("ct")
    payload_hash_ok = False
    if header.get("payload_hash"):
        if not ct_b64:
            raise MalformedCellError("malformed cell — header commits to a ciphertext that is absent")
        if b64encode(crypto.sha256(b64decode(ct_b64, field="ciphertext"))) != header["payload_hash"]:
            raise IntegrityError("integrity check failed — ciphertext may be tampered")
        payload_hash_ok = True

    signed = False
    signer_fp: str | None = None
    if cell.get("header_sig") and cell.get("header_sig_key"):
        spki_der = b64decode(cell["header_sig_key"], field="header_sig_key")
        public = crypto.load_spki(spki_der)
        raw_sig = b64decode(cell["header_sig"], field="header_sig")
        if not crypto.ecdsa_verify(public, raw_sig, header_bytes):
            raise SignatureError("header signature invalid — cell may be forged")
        signed = True
        # Trust anchors on the key's real fingerprint, never on header_sig_by,
        # which the signer writes about themselves and can say anything.
        signer_fp = crypto.fingerprint(spki_der)

    if expected_signer is not None:
        if not signed:
            raise SignatureError(
                f"expected a cell signed by {expected_signer}, but it carries no signature "
                f"(removal is undetectable — see spec §4.1)"
            )
        if signer_fp != expected_signer:
            raise SignatureError(
                f"cell is signed by {signer_fp}, not the expected {expected_signer}"
            )

    return VerifyResult(
        version=version,
        header_hash_ok=True,
        payload_hash_ok=payload_hash_ok,
        signed=signed,
        signer_fingerprint=signer_fp,
        claimed_signer=cell.get("header_sig_by"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Opening
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class OpenResult:
    """A successfully opened cell."""

    data: bytes
    filename: str
    content_type: str
    meta: dict | None = None
    used_recipient: dict | None = None
    signed: bool = False
    signer_fingerprint: str | None = None
    claimed_signer: str | None = None
    lifetime: lifetime_mod.Lifetime | None = None


#: An unwrap callback: given one access-map entry, return the key material it
#: holds (the CEK, or one Shamir share), or None if it is not for you.
Unwrapper = Callable[[dict], "bytes | None"]


def cell_open(
    cell: dict,
    *,
    keys: Iterable[KeyRecord] | None = None,
    passphrases: Iterable[str] | None = None,
    prf_outputs: dict[str, bytes] | None = None,
    unwrap: Unwrapper | None = None,
    now: int | None = None,
    enforce_advisory: bool = True,
    expected_signer: str | None = None,
) -> OpenResult:
    """Open a cell and return its plaintext.

    Verification order is normative (§10) and this function follows it: the
    advisory lifetime gates, then ``header_hash``, ``payload_hash`` and
    ``header_sig`` — all of which need no key — and only then any access-map
    work. An opener that unwraps first performs a decryption under a header it
    has not authenticated, and makes the user pay a 600,000-iteration PBKDF2
    derivation or a hardware touch on behalf of a cell it is about to reject.

    ``enforce_advisory=False`` skips the §8.1 gates. This is not a bypass of a
    security control: those gates are advisory *by specification*, unenforceable
    against anyone holding a key, and this parameter documents that honestly
    rather than pretending otherwise. ``disposal`` is never consulted here — a
    passed disposal date says something about the operator's retention schedule,
    not about the recipient's permission (§8.2).
    """
    version = _version_of(cell)
    is_legacy = not cell.get("version") and bool(cell.get("cd_version"))
    now = int(time.time()) if now is None else now

    # ── Step 0: advisory gates. Cheapest of all, and they need nothing but the clock.
    lt = lifetime_mod.read((cell.get("header") or {}).get("lifetime"))
    if lt and enforce_advisory:
        if lt.type == "timed_release" and lt.release_at and lt.release_at > now:
            raise LifetimeError(f"timed release — unlocks {_fmt_ts(lt.release_at)}")
        if lt.retain_until and lt.retain_until < now:
            raise LifetimeError(f"retention period ended {_fmt_ts(lt.retain_until)}")

    # ── Steps 1-3: integrity and authenticity, before any key material is touched.
    verified = None
    if not is_legacy:
        verified = verify_cell(cell, expected_signer=expected_signer)
    elif expected_signer is not None:
        raise SignatureError("legacy v2.x cells carry no signature to check")

    header = cell.get("header") or {}
    access_map = header.get("access_map") or cell.get("recipients") or []
    payload = cell.get("payload") or cell.get("encrypted_body") or {}
    iv_b64 = payload.get("iv")
    ct_b64 = payload.get("ciphertext") or payload.get("ct")
    if not iv_b64 or not ct_b64:
        raise MalformedCellError("malformed cell — payload is missing iv or ciphertext")
    required = int((header.get("threshold") or {}).get("required") or 1)

    unwrapper = unwrap or _default_unwrapper(keys, passphrases, prf_outputs)

    # ── Step 4: recover the CEK.
    cek: bytes
    used_recipient: dict | None
    if required > 1:
        shares: list[gf256.Share] = []
        for index, entry in enumerate(access_map):
            try:
                material = unwrapper(entry)
            except Exception:
                continue  # a wrong key for this entry says nothing about the next
            if material:
                shares.append(gf256.Share(int(entry.get("share_index") or index + 1), material))
                if len(shares) >= required:
                    break
        if len(shares) < required:
            raise QuorumNotMetError(
                f"quorum not met — need {required}, unlocked {len(shares)}"
            )
        cek = gf256.combine(shares)
        used_recipient = {"label": f"{len(shares)}-of-{len(access_map)} quorum"}
    else:
        cek = b""
        used_recipient = None
        for entry in access_map:
            try:
                material = unwrapper(entry)
            except Exception:
                continue
            if material:
                cek, used_recipient = material, entry
                break
        if not cek:
            raise NoMatchingKeyError("no matching key — check your key method and try again")

    aad = cell_aad(header, version) if not is_legacy else None
    compressed = crypto.aes_gcm_decrypt(
        cek, b64decode(iv_b64, field="iv"), b64decode(ct_b64, field="ciphertext"), aad
    )
    plain = crypto.gzip_decompress(compressed)

    # ── Manifest-prefixed payload (§5), or a legacy cell with plaintext metadata.
    if cell.get("original_filename") is not None:
        filename = cell.get("original_filename") or cell.get("doc_id") or "decrypted"
        content_type = cell.get("content_type") or "application/octet-stream"
        data, file_meta = plain, None
    else:
        if len(plain) < 4:
            raise MalformedCellError("malformed payload — too short to hold a manifest length")
        (manifest_len,) = struct.unpack("<I", plain[:4])
        if 4 + manifest_len > len(plain):
            raise MalformedCellError("malformed payload — manifest length runs past the plaintext")
        try:
            manifest = json.loads(plain[4 : 4 + manifest_len].decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise MalformedCellError(f"malformed payload — manifest is not valid JSON ({exc})") from exc
        filename = manifest.get("filename") or cell.get("doc_id") or "decrypted"
        content_type = manifest.get("content_type") or "application/octet-stream"
        file_meta = manifest.get("meta")
        data = plain[4 + manifest_len :]

    return OpenResult(
        data=data,
        filename=filename,
        content_type=content_type,
        meta=file_meta,
        used_recipient=used_recipient,
        signed=bool(verified and verified.signed),
        signer_fingerprint=verified.signer_fingerprint if verified else None,
        claimed_signer=verified.claimed_signer if verified else None,
        lifetime=lt,
    )


def _default_unwrapper(
    keys: Iterable[KeyRecord] | None,
    passphrases: Iterable[str] | None,
    prf_outputs: dict[str, bytes] | None,
) -> Unwrapper:
    """Build an unwrapper from whatever key material the caller supplied.

    Private keys are matched by fingerprint first so that a cell addressed to
    ten recipients does not run ten ECDH exchanges; passphrases have no such
    hint and must be tried, which is why §10 insists the header verifies first.
    """
    key_list = list(keys or [])
    by_fingerprint = {k.fingerprint: k for k in key_list if k.private is not None}
    passphrase_list = list(passphrases or [])
    prf_map = prf_outputs or {}

    def unwrapper(entry: dict) -> bytes | None:
        method = entry.get("method")
        wrapped = entry.get("wrapped_cek") or {}
        if method == "ecdh-p256":
            candidates: list[KeyRecord] = []
            fp = entry.get("fingerprint")
            if fp and fp in by_fingerprint:
                candidates = [by_fingerprint[fp]]
            else:
                candidates = [k for k in key_list if k.private is not None]
            for record in candidates:
                try:
                    return crypto.ecdh_unwrap_cek(wrapped, record.private)  # type: ignore[arg-type]
                except Exception:
                    continue
            return None
        if method == "pbkdf2":
            for passphrase in passphrase_list:
                try:
                    return crypto.pbkdf2_unwrap_cek(wrapped, passphrase)
                except Exception:
                    continue
            return None
        if method == "yubikey-prf":
            output = prf_map.get(wrapped.get("credential_id") or "")
            if output is None:
                return None  # no token here; skipping is conforming
            try:
                return crypto.prf_unwrap_cek(wrapped, output)
            except Exception:
                return None
        return None

    return unwrapper


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _version_of(cell: dict) -> str:
    version = cell.get("version")
    if version is None:
        if cell.get("cd_version"):
            return str(cell["cd_version"])  # legacy v2.x (§12)
        raise UnsupportedVersionError("cell has no version field")
    if version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(
            f'unsupported cell format version "{version}" — update the app to open this cell'
        )
    return version


def _fmt_ts(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def _wipe(buf: bytearray) -> None:
    """Best-effort zeroization.

    Python offers no real guarantee here — the interpreter may have copied the
    bytes during ``bytes(cek)`` and will not tell us. This overwrites what we can
    reach and no more; do not mistake it for the property a C implementation
    could offer.
    """
    for i in range(len(buf)):
        buf[i] = 0
