# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Binary field encoding — spec §4.0.

Every binary field in a ``.cell`` is **standard** base64 (RFC 4648 §4), with
padding. It is not base64url. Specification text up to and including the
anchored v1.2 said base64url for 23 fields; that was an error in the document,
never in the format, and following it produces cells the reference
implementation cannot parse at all (``atob()`` throws on ``-`` and ``_``).

Per §4.0, encoders MUST emit standard base64 and decoders SHOULD accept the
base64url alphabet on input. :func:`b64decode` therefore accepts both;
:func:`b64encode` only ever emits the standard alphabet.
"""

from __future__ import annotations

import base64
import binascii

from .errors import MalformedCellError


def b64encode(data: bytes) -> str:
    """Standard base64 with padding — the only form this library writes."""
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str, *, field: str = "value") -> bytes:
    """Decode standard base64, tolerating the base64url alphabet and lost padding."""
    if not isinstance(text, str):
        raise MalformedCellError(f"{field}: expected a base64 string, got {type(text).__name__}")
    normalized = text.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedCellError(f"{field}: not valid base64 ({exc})") from exc


def to_hex(data: bytes) -> str:
    return data.hex()
