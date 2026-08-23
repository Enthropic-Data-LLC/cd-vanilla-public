# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON serialization — spec §4.1.1.

`header_hash`, `header_sig` and the AES-GCM AAD are computed over these bytes,
so this module is where an independent implementation most easily goes wrong
without noticing: every function here must agree with the reference
implementation's `canonicalize()` *byte for byte* or nothing verifies.

The specification defines the canonical form by reference to JavaScript::

    canonicalize(v):
      if v is null or not an object:   return JSON.stringify(v)
      if v is an array:                return "[" + join(",", canonicalize(e)) + "]"
      otherwise (object):
         keys = sort(keys of v where v[k] != undefined)
         return "{" + join(",", JSON.stringify(k) + ":" + canonicalize(v[k])) + "}"

"Return JSON.stringify(v)" is doing a great deal of quiet work for anyone not
writing JavaScript. Three parts of it do not come free in Python:

1. **Number formatting.** JS renders a float64 with the shortest round-tripping
   decimal and never a trailing ``.0``: ``1.0`` prints as ``1``, ``1e-7`` as
   ``1e-7``. Python's ``json`` prints ``1.0`` and ``1e-07``. Both differences
   change the hash. :func:`js_number` implements ECMA-262 Number::toString.
2. **Key ordering.** JS sorts by UTF-16 code unit, Python by code point. These
   agree for every character in the Basic Multilingual Plane and disagree above
   it (an astral key sorts *below* U+E000..U+FFFF in JS, above in Python).
   :func:`_sort_key` sorts the JS way.
3. **Integer range.** JSON has no integers, only float64. Python does, and
   would serialize ``2**60`` exactly where JS rounds it to the nearest float64.
   :func:`js_number` rounds the same way, so the two agree; the temptation to
   raise instead is wrong, because the reference itself emits such literals for
   any float64 at or above 1e21.

Everything else — string escaping, ``true``/``false``/``null`` — Python's
``json.dumps(ensure_ascii=False)`` already matches.
"""

from __future__ import annotations

import json
import math
from typing import Any

from .errors import CanonicalizationError

# JS numbers are float64; above this integers are no longer exactly representable.
MAX_SAFE_INTEGER = 2**53 - 1


def _shortest_digits(x: float) -> tuple[str, int]:
    """Decompose a positive float into ``(digits, n)`` with ``value == 0.<digits> * 10**n``.

    ``digits`` is the shortest string that round-trips, with no leading or
    trailing zeros. This is the ``s``/``k``/``n`` triple of ECMA-262 6.1.6.1.20;
    Python's ``repr`` already gives us the shortest round-tripping digits, so we
    only have to re-normalize where it puts the decimal point.
    """
    r = repr(x)
    if "e" in r or "E" in r:
        mant, _, exp_s = r.partition("e") if "e" in r else r.partition("E")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    int_part, _, frac_part = mant.partition(".")
    raw = int_part + frac_part
    stripped = raw.lstrip("0")
    if not stripped:
        return "0", 1
    lead_zeros = len(raw) - len(stripped)
    n = len(int_part) + exp - lead_zeros
    return stripped.rstrip("0") or "0", n


def js_number(value: float | int) -> str:
    """Format a number exactly as JavaScript's ``String(n)`` would.

    Implements ECMA-262 6.1.6.1.20 (Number::toString, radix 10), which is what
    ``JSON.stringify`` uses for finite numbers.
    """
    if isinstance(value, bool):  # bool is an int in Python; JSON says otherwise
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        # Below 2^53 a Python int and a JavaScript number agree exactly, and
        # str() is both correct and cheaper. Above it they do not — but the
        # answer is to do what JavaScript does, not to refuse. JS has no
        # integers: it parses such a literal into the nearest float64 and prints
        # that back, so converting here reproduces its bytes exactly. Refusing
        # instead (as this did until the Go port ran the shared vectors) rejects
        # values the reference round-trips happily, including the ones its own
        # canonicalize() emits for any float64 at or above 1e21.
        if abs(value) <= MAX_SAFE_INTEGER:
            return str(value)
        value = float(value)
    if math.isnan(value) or math.isinf(value):
        # JSON.stringify emits null for these; they must never reach a hash.
        raise CanonicalizationError(f"{value!r} is not representable in JSON")
    if value == 0:
        return "0"  # JS prints -0 as "0" too
    sign = "-" if value < 0 else ""
    digits, n = _shortest_digits(abs(value))
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    # Exponential form.
    e = n - 1
    exp_part = f"e{'+' if e >= 0 else '-'}{abs(e)}"
    if k == 1:
        return sign + digits + exp_part
    return sign + digits[0] + "." + digits[1:] + exp_part


def js_string(value: str) -> str:
    """Quote and escape a string as ``JSON.stringify`` does.

    Python's non-ASCII-preserving dumps already matches JS: the same control
    characters get the same short escapes, ``/`` is not escaped, and everything
    at or above U+0020 other than ``"`` and ``\\`` is emitted raw.
    """
    return json.dumps(value, ensure_ascii=False)


def _utf16_units(key: str) -> tuple[int, ...]:
    """Return ``key`` as UTF-16 code units, for JavaScript's string ordering.

    ``Array.prototype.sort`` compares UTF-16 code units, so a character above the
    BMP compares as its surrogate pair (0xD800-0xDFFF) and sorts *before*
    U+E000..U+FFFF. Python compares code points and would sort it after.
    Comparing code units makes the two agree.
    """
    b = key.encode("utf-16-be")
    return tuple(int.from_bytes(b[i : i + 2], "big") for i in range(0, len(b), 2))


def canonicalize(value: Any) -> str:
    """Return the canonical JSON serialization of ``value`` (spec §4.1.1).

    Keys are sorted, insignificant whitespace is absent, and ``None`` values are
    preserved. Note that the specification's "where v[k] != undefined" filter has
    no Python equivalent — Python has one null, JavaScript has two, and only
    ``undefined`` is dropped. See :func:`omit` for writing cells that match the
    reference implementation's omission of ``share_index``.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"object key {k!r} is not a string; JSON.stringify would coerce it "
                    f"and the two implementations would disagree"
                )
        items = sorted(value.items(), key=lambda kv: _utf16_units(kv[0]))
        return "{" + ",".join(js_string(k) + ":" + canonicalize(v) for k, v in items) + "}"
    raise CanonicalizationError(f"cannot canonicalize {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 bytes of :func:`canonicalize` — what actually gets hashed/signed."""
    return canonicalize(value).encode("utf-8")


def js_stringify(value: Any) -> str:
    """``JSON.stringify(v)`` with *insertion* order — the v1.0/v1.1 serialization.

    v1.0 and v1.1 cells hash and sign their header in the order the reference
    implementation happened to build it, not in sorted order (spec §12). Python
    dicts preserve insertion order and ``json.loads`` fills them in document
    order, so a cell parsed from disk round-trips correctly here — but only if
    the caller has not rebuilt the dict in the meantime.
    """
    if isinstance(value, dict):
        return "{" + ",".join(js_string(k) + ":" + js_stringify(v) for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_stringify(v) for v in value) + "]"
    return canonicalize(value)
