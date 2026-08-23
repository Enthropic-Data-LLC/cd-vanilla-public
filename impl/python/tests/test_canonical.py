# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Canonical serialization — the highest-risk surface for a non-JS port.

Round-tripping proves nothing here: an implementation that canonicalizes
consistently but differently from the reference passes every self-test and
verifies no real cell. These tests pin the exact output bytes.
"""

import unittest

from cellular_defense.canonical import canonicalize, js_number
from cellular_defense.errors import CanonicalizationError


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

    def test_unsafe_integers_are_refused_not_guessed(self):
        # JS would round this to a different value and compute a different
        # header_hash. Emitting bytes no conforming reader can reproduce is worse
        # than refusing.
        with self.assertRaises(CanonicalizationError):
            js_number(2**60)
        self.assertEqual(js_number(2**53 - 1), "9007199254740991")


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
