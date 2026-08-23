# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Cryptographic primitives — spec §6, §14.

Every operation here has a one-line counterpart in the reference implementation
because the reference calls WebCrypto, which makes several choices implicitly.
Where a general-purpose library would default differently, the difference is
noted in the docstring — those notes are the substance of this module.

Nothing in this file is constant-time beyond what OpenSSL provides, and the
Shamir arithmetic in :mod:`.gf256` is explicitly not. The threat model the
format addresses (an untrusted server holding ciphertext) does not include an
attacker who can time the opener's CPU.
"""

from __future__ import annotations

import hashlib
import io
import zlib

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .codec import b64decode, b64encode
from .errors import CellError, DecryptionError, MalformedCellError

CURVE = ec.SECP256R1()
HKDF_INFO = b"cellular-defense-cek-wrap-v1"
PBKDF2_ITERATIONS = 600_000
IV_LENGTH = 12
CEK_LENGTH = 32

#: Decompression ceiling (spec has none; the reference caps at 2 GiB). A few KB
#: of crafted gzip expands to many GB, and an opener that streams it into memory
#: is a denial of service with no key material required.
MAX_DECOMPRESSED = 2 * 1024 * 1024 * 1024


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def fingerprint(spki_der: bytes) -> str:
    """``SHA-256(SPKI)[:8]`` as 16 lowercase hex characters — spec §13.3."""
    return sha256(spki_der).hex()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Compression — spec §5
# ─────────────────────────────────────────────────────────────────────────────


def gzip_compress(data: bytes) -> bytes:
    """gzip ``data`` with a zeroed mtime.

    The reference uses ``CompressionStream('gzip')``, whose output is not
    byte-identical to any particular zlib configuration and need not be: the
    format commits to the *ciphertext*, and gzip framing is decided before
    encryption. Two conforming implementations sealing the same file will
    produce different bytes for this reason alone, and both are correct. mtime
    is zeroed anyway so this library's own output is reproducible.
    """
    buf = io.BytesIO()
    with __import__("gzip").GzipFile(fileobj=buf, mode="wb", compresslevel=6, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def gzip_decompress(data: bytes, *, max_bytes: int = MAX_DECOMPRESSED) -> bytes:
    """Decompress a gzip stream, refusing to exceed ``max_bytes``."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    chunks: list[bytes] = []
    total = 0
    view = memoryview(data)
    for offset in range(0, len(view), 65536):
        try:
            chunk = decompressor.decompress(view[offset : offset + 65536], max_bytes - total + 1)
        except zlib.error as exc:
            raise MalformedCellError(f"payload is not a valid gzip stream ({exc})") from exc
        total += len(chunk)
        if total > max_bytes:
            raise MalformedCellError("decompressed size exceeds safety limit")
        chunks.append(chunk)
    if not decompressor.eof:
        raise MalformedCellError("truncated gzip stream")
    return b"".join(chunks)


# ─────────────────────────────────────────────────────────────────────────────
# Content encryption — AES-256-GCM, spec §4.3
# ─────────────────────────────────────────────────────────────────────────────


def aes_gcm_encrypt(cek: bytes, plaintext: bytes, aad: bytes | None, *, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns ``(iv, ciphertext_with_tag)``.

    The 128-bit tag is appended to the ciphertext, matching WebCrypto. Libraries
    that return the tag separately (or default to a shorter tag) must
    concatenate a full 16-byte tag to interoperate.
    """
    if len(cek) != CEK_LENGTH:
        raise CellError(f"CEK must be {CEK_LENGTH} bytes, got {len(cek)}")
    if iv is None:
        iv = __import__("secrets").token_bytes(IV_LENGTH)
    return iv, AESGCM(cek).encrypt(iv, plaintext, aad)


def aes_gcm_decrypt(cek: bytes, iv: bytes, ciphertext: bytes, aad: bytes | None) -> bytes:
    """Decrypt and verify. A tag failure here is also an AAD mismatch (§4.4)."""
    try:
        return AESGCM(cek).decrypt(iv, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "authentication failed — the ciphertext or the AAD-bound metadata "
            "(prev_hash/threshold/lifetime/policy) does not match what was sealed"
        ) from exc


# ─────────────────────────────────────────────────────────────────────────────
# CEK wrapping — ECDH P-256 → HKDF-SHA256 → AES-KW, spec §6.1
# ─────────────────────────────────────────────────────────────────────────────


def _hkdf_wrap_key(shared_bits: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(shared_bits)


def ecdh_wrap_cek(
    cek_or_share: bytes,
    recipient_spki_b64: str,
    *,
    ephemeral: ec.EllipticCurvePrivateKey | None = None,
    hkdf_salt: bytes | None = None,
) -> dict:
    """Wrap key material for one ECDH recipient.

    A fresh ephemeral keypair per recipient per cell is what gives the format its
    per-cell forward secrecy; ``ephemeral`` and ``hkdf_salt`` are injectable only
    so test vectors can be reproduced.
    """
    recipient = load_spki(b64decode(recipient_spki_b64, field="spki"))
    if ephemeral is None:
        ephemeral = ec.generate_private_key(CURVE)
    if hkdf_salt is None:
        hkdf_salt = __import__("secrets").token_bytes(32)

    # WebCrypto's deriveBits(..., 256) on P-256 yields the X coordinate of the
    # shared point, which is exactly what exchange() returns. No KDF is applied
    # by either side at this step — HKDF is the next line, not implied here.
    shared_bits = ephemeral.exchange(ec.ECDH(), recipient)
    wrapping_key = _hkdf_wrap_key(shared_bits, hkdf_salt)
    return {
        "eph_spki": b64encode(export_spki(ephemeral.public_key())),
        "hkdf_salt": b64encode(hkdf_salt),
        "ct": b64encode(keywrap.aes_key_wrap(wrapping_key, cek_or_share)),
    }


def ecdh_unwrap_cek(wrapped: dict, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Unwrap an ECDH entry.

    A wrapped entry with no ``hkdf_salt`` is a pre-spec legacy v2.0 cell, whose
    wrapping key is the raw ECDH output truncated to 32 bytes with no HKDF at
    all (spec §12). New writers must never produce this.
    """
    eph = load_spki(b64decode(wrapped["eph_spki"], field="eph_spki"))
    shared_bits = private_key.exchange(ec.ECDH(), eph)
    salt_b64 = wrapped.get("hkdf_salt")
    if salt_b64:
        wrapping_key = _hkdf_wrap_key(shared_bits, b64decode(salt_b64, field="hkdf_salt"))
    else:
        wrapping_key = shared_bits[:32]
    return keywrap.aes_key_unwrap(wrapping_key, b64decode(wrapped["ct"], field="ct"))


# ─────────────────────────────────────────────────────────────────────────────
# CEK wrapping — PBKDF2, spec §6.2
# ─────────────────────────────────────────────────────────────────────────────


def pbkdf2_wrap_cek(cek_or_share: bytes, passphrase: str, *, salt: bytes | None = None) -> dict:
    if salt is None:
        salt = __import__("secrets").token_bytes(32)
    wrapping_key = _pbkdf2(passphrase, salt, PBKDF2_ITERATIONS)
    return {
        "salt": b64encode(salt),
        "iterations": PBKDF2_ITERATIONS,
        "ct": b64encode(keywrap.aes_key_wrap(wrapping_key, cek_or_share)),
    }


def pbkdf2_unwrap_cek(wrapped: dict, passphrase: str) -> bytes:
    salt = b64decode(wrapped["salt"], field="salt")
    iterations = wrapped.get("iterations") or PBKDF2_ITERATIONS
    wrapping_key = _pbkdf2(passphrase, salt, int(iterations))
    return keywrap.aes_key_unwrap(wrapping_key, b64decode(wrapped["ct"], field="ct"))


def _pbkdf2(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256 over the UTF-8 bytes of the passphrase.

    WebCrypto has no opinion about text encoding — the reference feeds it
    ``TextEncoder().encode(passphrase)``, i.e. UTF-8, and importantly performs no
    Unicode normalization. A passphrase containing composed vs decomposed
    accents is therefore two different passphrases, on every implementation.
    """
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(passphrase.encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# CEK wrapping — WebAuthn/FIDO2 PRF, spec §6.3
# ─────────────────────────────────────────────────────────────────────────────


def prf_wrap_cek(cek_or_share: bytes, credential_id_b64: str, prf_salt_b64: str, prf_output: bytes) -> dict:
    """Wrap under a 32-byte WebAuthn PRF output used directly as the AES-KW key.

    This library cannot *obtain* a PRF output: the hmac-secret extension is
    reachable only through WebAuthn, in a browser, with the token present. A
    non-browser implementation can therefore create and open ``yubikey-prf``
    entries only when something else supplies the 32 bytes (a CTAP2 library such
    as python-fido2, or a test vector). Openers that cannot are conforming —
    they simply skip these entries, as :func:`.cell.cell_open` does.
    """
    if len(prf_output) != 32:
        raise CellError(f"PRF output must be 32 bytes, got {len(prf_output)}")
    return {
        "credential_id": credential_id_b64,
        "prf_salt": prf_salt_b64,
        "ct": b64encode(keywrap.aes_key_wrap(prf_output, cek_or_share)),
    }


def prf_unwrap_cek(wrapped: dict, prf_output: bytes) -> bytes:
    if len(prf_output) != 32:
        raise CellError(f"PRF output must be 32 bytes, got {len(prf_output)}")
    return keywrap.aes_key_unwrap(prf_output, b64decode(wrapped["ct"], field="ct"))


# ─────────────────────────────────────────────────────────────────────────────
# Key encoding and ECDSA — spec §4.1, §13
# ─────────────────────────────────────────────────────────────────────────────


def load_spki(der: bytes) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_der_public_key(der)
    except Exception as exc:
        raise MalformedCellError(f"invalid SPKI public key ({exc})") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != CURVE.name:
        raise MalformedCellError("public key is not P-256")
    return key


def export_spki(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_pkcs8(der: bytes) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_der_private_key(der, password=None)
    except Exception as exc:
        raise MalformedCellError(f"invalid PKCS#8 private key ({exc})") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != CURVE.name:
        raise MalformedCellError("private key is not P-256")
    return key


def export_pkcs8(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def der_to_p1363(der_sig: bytes) -> bytes:
    """Convert a DER ``SEQUENCE { r, s }`` to the raw 64-byte ``r || s``.

    Spec §4.1 calls this out as the single most likely point of failure when
    verifying a cell outside a browser, and it is: ``cryptography``, OpenSSL,
    Java and Go all produce and expect DER by default, while WebCrypto produces
    and expects P1363. The two are never interchangeable and a DER signature in
    ``header_sig`` will fail verification against every conforming reader.
    """
    r, s = asym_utils.decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p1363_to_der(raw_sig: bytes) -> bytes:
    """Convert a raw 64-byte ``r || s`` signature to DER."""
    if len(raw_sig) != 64:
        raise MalformedCellError(
            f"header_sig must be 64 bytes of raw r||s (IEEE P1363), got {len(raw_sig)}; "
            f"a DER-encoded signature is not accepted (spec §4.1)"
        )
    return asym_utils.encode_dss_signature(
        int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")
    )


def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign with ECDSA-SHA256, returning raw ``r || s`` as the format requires."""
    return der_to_p1363(private_key.sign(data, ec.ECDSA(hashes.SHA256())))


def ecdsa_verify(public_key: ec.EllipticCurvePublicKey, raw_sig: bytes, data: bytes) -> bool:
    try:
        public_key.verify(p1363_to_der(raw_sig), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
