# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Shamir Secret Sharing over GF(256) — spec §7.

There is no interoperable standard for Shamir's scheme, so every implementation
hand-rolls it and every implementation is free to be subtly incompatible. The
spec pins the three choices that matter — the field, the share x-coordinates,
and the interpolation point — and this module implements exactly those:

* GF(2^8) with the AES irreducible polynomial x^8+x^4+x^3+x+1 (0x11b),
* one independent polynomial per byte of the secret, constant term = that byte,
* share ``i`` is the evaluation at ``x = i`` for ``i = 1..N`` (1-indexed, and
  the x-coordinate is what lands in ``share_index``),
* reconstruction is Lagrange interpolation evaluated at ``x = 0``.

Because the split is randomized, split/combine round-trips prove nothing about
interoperability. Only fixed vectors do — see ``tests/vectors``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .errors import CellError

# Log/antilog tables over GF(2^8), generator 3, modulus 0x11b. Built once at
# import; multiplication is then two lookups and an add, and the tables also
# give the inverse without the 254-squaring loop the spec describes. The result
# is identical — Russian-peasant multiplication and table lookup agree by
# construction — but constant-time it is not, and neither is the reference.
_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply by 3 == x + 1
        x ^= (x << 1) ^ (0x1B if x & 0x80 else 0)
        x &= 0xFF
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8). Matches the reference's Russian-peasant loop."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(x: int) -> int:
    """Multiplicative inverse. The spec gives x^254; the table gives the same value."""
    if x == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return _EXP[255 - _LOG[x]]


@dataclass(frozen=True)
class Share:
    """One Shamir share: an x-coordinate and one byte of y per secret byte."""

    x: int
    data: bytes


def split(secret: bytes, n: int, k: int, *, rand: bytes | None = None) -> list[Share]:
    """Split ``secret`` into ``n`` shares of which any ``k`` reconstruct it.

    ``rand`` supplies the polynomial coefficients (``(k-1) * len(secret)`` bytes,
    ordered coefficient-major per byte position) so a test vector can pin the
    exact shares. Leave it None in production.
    """
    if not 1 <= k <= n <= 255:
        raise CellError(f"invalid Shamir parameters: {k}-of-{n} (need 1 <= k <= n <= 255)")
    needed = (k - 1) * len(secret)
    if rand is None:
        rand = secrets.token_bytes(needed)
    elif len(rand) != needed:
        raise CellError(f"expected {needed} bytes of coefficient randomness, got {len(rand)}")

    shares = [bytearray(len(secret)) for _ in range(n)]
    for bi, byte in enumerate(secret):
        coeffs = [byte] + list(rand[bi * (k - 1) : (bi + 1) * (k - 1)])
        for si in range(n):
            x = si + 1
            # Horner, high coefficient down — the reference's evaluation order.
            y = coeffs[k - 1]
            for i in range(k - 2, -1, -1):
                y = gf_mul(y, x) ^ coeffs[i]
            shares[si][bi] = y
    return [Share(i + 1, bytes(s)) for i, s in enumerate(shares)]


def combine(shares: list[Share]) -> bytes:
    """Reconstruct the secret by Lagrange interpolation at x=0."""
    if not shares:
        raise CellError("no shares to combine")
    xs = [s.x for s in shares]
    if any(not isinstance(x, int) or not 1 <= x <= 255 for x in xs):
        raise CellError("invalid share index — must be 1..255")
    if len(set(xs)) != len(xs):
        raise CellError("duplicate share indices — cannot reconstruct secret")
    length = len(shares[0].data)
    if any(len(s.data) != length for s in shares):
        raise CellError("shares differ in length — they are not from one secret")

    out = bytearray(length)
    for bi in range(length):
        acc = 0
        for i, si in enumerate(shares):
            num = den = 1
            for j, sj in enumerate(shares):
                if i == j:
                    continue
                num = gf_mul(num, sj.x)
                den = gf_mul(den, si.x ^ sj.x)
            acc ^= gf_mul(si.data[bi], gf_mul(num, gf_inv(den)))
        out[bi] = acc
    return bytes(out)
