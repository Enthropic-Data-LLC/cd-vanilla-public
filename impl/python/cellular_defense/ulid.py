# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""ULID document identifiers — spec §4.1, §14.

26 characters of Crockford base32: a 48-bit millisecond timestamp in the first
10, 80 bits of CSPRNG output in the last 16. Lexicographically sortable by
creation time, which is the only property the format relies on.
"""

from __future__ import annotations

import secrets
import time

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(timestamp_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Generate a ULID. Arguments exist so test vectors can be reproduced."""
    t = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if not 0 <= t < 2**48:
        raise ValueError("ULID timestamp must fit in 48 bits")
    rand = secrets.token_bytes(10) if randomness is None else randomness
    if len(rand) != 10:
        raise ValueError("ULID randomness must be exactly 10 bytes")

    chars = [""] * 26
    for i in range(9, -1, -1):
        chars[i] = CROCKFORD[t & 31]
        t >>= 5
    value = int.from_bytes(rand, "big")
    for i in range(25, 9, -1):
        chars[i] = CROCKFORD[value & 31]
        value >>= 5
    return "".join(chars)
