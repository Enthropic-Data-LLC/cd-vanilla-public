# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Canonical serialization — the highest-risk surface for a non-JS port.

Round-tripping proves nothing here: an implementation that canonicalizes
consistently but differently from the reference passes every self-test and
verifies no real cell. These tests pin the exact output bytes.
"""

import json
import unittest
from pathlib import Path

from cellular_defense.canonical import canonicalize, js_number
from cellular_defense.errors import CanonicalizationError

VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors" / "canonical.json"


class TestJsNumber(unittest.TestCase):
    """ECMA-262 Number::toString. Python's json disagrees on both of the first two."""

    def test_integral_floats_lose_the_point(self):
        self.assertEqual(js_number(1.0), "1")
        self.assertEqual(js_number(100.0), "100")
        self.assertEqual(js_number(-0.0), "0")

    def test_exponent_form_matches_javascript(self):
        self.assertEqual(js_number(1e-7), "1e-7")      # Python json: 1e-07
        self.assertEqual(js_number(1e-6), "0.000001")  # threshold is n > -6
        self.assertEqual(js_number(1e21), "1e+21")     # threshold is n > 21
        self.assertEqual(js_number(1e20), "100000000000000000000")

    def test_shortest_round_trip(self):
        self.assertEqual(js_number(0.1), "0.1")
        self.assertEqual(js_number(5e-324), "5e-324")
        self.assertEqual(js_number(1.7976931348623157e308), "1.7976931348623157e+308")

    def test_integers_beyond_2_53_round_the_way_javascript_does(self):
        # JavaScript has no integers. It parses such a literal into the nearest
        # float64 and prints that back, so agreeing with the reference means
        # rounding identically — not refusing. This implementation raised here
        # until the Go port ran the shared canonical vectors and hit the
        # reference's own output for 1e20.
        self.assertEqual(js_number(2**53 - 1), "9007199254740991")  # exact
        self.assertEqual(js_number(2**53 + 1), "9007199254740992")  # rounds down
        self.assertEqual(js_number(10**20), "100000000000000000000")
        # Shortest round-tripping decimal, not the exact value: at this magnitude
        # neighbouring float64s are far enough apart that a shorter decimal
        # identifies the same one. Verified against node: String(2**60).
        self.assertEqual(js_number(2**60), "1152921504606847000")

    def test_non_finite_values_are_refused(self):
        # JSON.stringify emits null for these; they must never reach a hash.
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(CanonicalizationError):
                js_number(value)


class TestCanonicalize(unittest.TestCase):
    def test_keys_are_sorted_recursively(self):
        self.assertEqual(
            canonicalize({"b": 1, "a": {"d": 2, "c": 3}}),
            '{"a":{"c":3,"d":2},"b":1}',
        )

    def test_no_insignificant_whitespace(self):
        self.assertEqual(canonicalize([1, {"a": 2}]), '[1,{"a":2}]')

    def test_null_is_preserved_not_dropped(self):
        # §6.4: an explicit null and an omitted key hash differently. Both are
        # internally consistent; they are simply not the same cell.
        self.assertEqual(canonicalize({"share_index": None}), '{"share_index":null}')
        self.assertNotEqual(canonicalize({"share_index": None}), canonicalize({}))

    def test_string_escaping_matches_json_stringify(self):
        self.assertEqual(canonicalize("a\"b\\c"), '"a\\"b\\\\c"')
        self.assertEqual(canonicalize("\n\t\r\b\f"), '"\\n\\t\\r\\b\\f"')
        self.assertEqual(canonicalize("\x00\x1f"), '"\\u0000\\u001f"')
        self.assertEqual(canonicalize("a/b"), '"a/b"')  # JS does not escape /

    def test_non_ascii_is_emitted_raw(self):
        self.assertEqual(canonicalize("é"), '"é"')
        self.assertEqual(canonicalize("😀"), '"😀"')

    def test_astral_keys_sort_by_utf16_code_unit(self):
        # JS compares UTF-16 code units, so "😀" (surrogate pair, 0xD83D…) sorts
        # BEFORE "". Python's default code-point ordering puts it after.
        out = canonicalize({"": 1, "😀": 2})
        self.assertEqual(out.index('"😀"'), 1)

    def test_booleans_are_not_numbers(self):
        self.assertEqual(canonicalize({"single_use": False}), '{"single_use":false}')

    def test_non_string_keys_are_refused(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({1: "a"})


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(VECTORS.is_file(), "canonical vectors are not present")
class TestSharedCanonicalVectors(unittest.TestCase):
    """The shared vectors in conformance/vectors/canonical.json.

    Their expected strings come from the reference implementation and nowhere
    else: canonical serialization is defined by deferring to JavaScript's
    JSON.stringify (§4.1.1), so JavaScript is the authority on the right answer
    and every other implementation checks itself against it. Every port runs
    this same file — it is the cheapest way to catch the number-formatting and
    key-ordering divergences before they turn into a hash that never matches.
    """

    def test_all_cases(self):
        data = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertGreater(len(data["cases"]), 0)
        for case in data["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(canonicalize(case["input"]), case["expected"])
