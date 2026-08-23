# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""A Python implementation of the Cellular Defense ``.cell`` format.

Written from ``docs/SPEC.md`` v1.3. The format is a defensive disclosure
(TDCommons No. 11391) and no patent is asserted over it; this implementation is
Apache-2.0 so that anyone may use, embed or fork it without the obligations that
attach to the AGPL reference implementation.

    >>> from cellular_defense import KeyRecord, Recipient, cell_create, cell_open
    >>> alice = KeyRecord.generate("Alice")
    >>> cell = cell_create(b"hello", "note.txt", [Recipient.for_key(alice)])
    >>> cell_open(cell, keys=[alice]).data
    b'hello'
"""

from .canonical import canonical_bytes, canonicalize
from .cell import (
    AAD_VERSIONS,
    CANONICAL_VERSIONS,
    CELL_FORMAT_VERSION,
    SUPPORTED_VERSIONS,
    OpenResult,
    Recipient,
    VerifyResult,
    cell_aad,
    cell_create,
    cell_open,
    serialize_header,
    verify_cell,
)
from .errors import (
    CanonicalizationError,
    CellError,
    DecryptionError,
    IntegrityError,
    LifetimeError,
    MalformedCellError,
    NoMatchingKeyError,
    QuorumNotMetError,
    SignatureError,
    UnsupportedVersionError,
)
from .keys import KeyRecord

__version__ = "0.1.0"

__all__ = [
    "AAD_VERSIONS",
    "CANONICAL_VERSIONS",
    "CELL_FORMAT_VERSION",
    "SUPPORTED_VERSIONS",
    "CanonicalizationError",
    "CellError",
    "DecryptionError",
    "IntegrityError",
    "KeyRecord",
    "LifetimeError",
    "MalformedCellError",
    "NoMatchingKeyError",
    "OpenResult",
    "QuorumNotMetError",
    "Recipient",
    "SignatureError",
    "UnsupportedVersionError",
    "VerifyResult",
    "canonical_bytes",
    "canonicalize",
    "cell_aad",
    "cell_create",
    "cell_open",
    "serialize_header",
    "verify_cell",
]
