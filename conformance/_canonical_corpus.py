#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Emit the canonicalization corpus on stdout. See make-canonical-vectors.sh.

Two halves. The named cases pin the specific divergences that have actually
broken a port: JavaScript's number formatting, its UTF-16 key ordering, and the
five characters its JSON.stringify does not escape but other languages' JSON
encoders do. The fuzz cases are what found several of them.
"""

import json
import math
import random
import struct
import sys

NAMED = [
    ("integral float loses the point", 1.0),
    ("negative zero prints as zero", -0.0),
    ("exponent threshold, small", 1e-7),
    ("just inside decimal form", 1e-6),
    ("exponent threshold, large", 1e21),
    ("just inside integer form", 1e20),
    ("shortest round trip", 0.1),
    ("denormal minimum", 5e-324),
    ("float64 maximum", 1.7976931348623157e308),
    ("integer above 2^53 rounds identically", 1.2345678901234568e19),
    ("keys sorted recursively", {"b": 1, "a": {"d": 2, "c": 3}}),
    ("explicit null is preserved", {"share_index": None}),
    ("empty key sorts first", {"": 1, "a": 2}),
    ("astral key sorts by UTF-16 code unit", {"": 1, "\U0001F600": 2}),
    ("BOM-adjacent key ordering", {"￿": 1, "\U0001F600": 2, "": 3}),
    ("solidus is not escaped", "a/b"),
    ("HTML characters are not escaped", "<script>&</script>"),
    ("line separators are not escaped", "a b c"),
    ("control characters use short escapes", "\b\t\n\f\r"),
    ("other control chars use \\u00xx", "\x00\x01\x1f"),
    ("quote and backslash", 'q"\\'),
    ("non-ASCII emitted raw", "café 😀"),
    ("nested arrays and nulls", [None, False, 0, "", {}, []]),
    ("lifetime shape", {"type": "record",
                        "advisory": {"retain_until": None, "release_at": None,
                                     "single_use": False, "minimum_atl": 2},
                        "disposal": {"at": None, "action": "archive"}}),
    ("AAD meta array shape", [None, {"required": 2, "of_total": 3}, None,
                              {"copy_protection": "standard"}]),
]

STRINGS = ["", "a", "ünïcødé", "😀 astral", 'q"\\\n\t', "0", " ", "a/b", "<&>", " x"]
NUMBERS = [0, -0.0, 1e-7, 1e21, 0.1, 1e-6, 1e20, 2**53 - 1]
KEYS = ["a", "B", "z", "", "😀", "é", "share_index", "0", "policy", "Z", "￿", ""]


def generate(rng: random.Random, depth: int = 0):
    choice = rng.randrange(9 if depth < 3 else 7)
    if choice == 0:
        return None
    if choice == 1:
        return rng.choice([True, False])
    if choice == 2:
        return rng.randint(-(2**40), 2**40)
    if choice == 3:
        value = struct.unpack("<d", rng.randbytes(8))[0]
        return value if math.isfinite(value) else 1.5
    if choice == 4:
        return rng.choice(STRINGS)
    if choice == 5:
        return rng.choice(NUMBERS)
    if choice == 6:
        return rng.choice(KEYS)
    if choice == 7:
        return [generate(rng, depth + 1) for _ in range(rng.randrange(4))]
    keys = rng.sample(KEYS, rng.randrange(1, 6))
    return {k: generate(rng, depth + 1) for k in keys}


def main() -> int:
    rng = random.Random(20260823)  # fixed, so the corpus is reproducible
    cases = [{"name": name, "input": value} for name, value in NAMED]
    cases += [{"name": f"fuzz-{i:03d}", "input": generate(rng)} for i in range(200)]
    json.dump(cases, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
