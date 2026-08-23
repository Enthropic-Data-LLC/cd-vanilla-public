# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy.

Every rejection path in :mod:`cellular_defense` raises a subclass of
:class:`CellError`, so a caller can distinguish "this file is not a cell I can
read" from "this cell has been tampered with" from "you gave me the wrong key" —
a distinction the reference implementation blurs into `Error(string)`.
"""


class CellError(Exception):
    """Base class for every error raised by this library."""


class UnsupportedVersionError(CellError):
    """`cell.version` is present but not in SUPPORTED_VERSIONS (spec §12)."""


class MalformedCellError(CellError):
    """Structurally invalid: missing header, bad base64, truncated manifest."""


class IntegrityError(CellError):
    """header_hash / payload_hash mismatch, or a missing header_hash (spec §10)."""


class SignatureError(IntegrityError):
    """`header_sig` is present and does not verify against `header_sig_key`."""


class LifetimeError(CellError):
    """An advisory lifetime gate refused the open (spec §8.1).

    Advisory means advisory: this is what *conforming* software does. A holder
    of a qualifying key can bypass it, and the specification says so.
    """


class NoMatchingKeyError(CellError):
    """No access-map entry could be unwrapped with the material provided."""


class QuorumNotMetError(NoMatchingKeyError):
    """Fewer than `threshold.required` shares were recovered (spec §7)."""


class DecryptionError(CellError):
    """The AES-GCM tag failed — ciphertext or AAD-bound metadata was altered."""


class CanonicalizationError(CellError):
    """A value cannot be canonicalized compatibly with the reference (§4.1.1)."""
