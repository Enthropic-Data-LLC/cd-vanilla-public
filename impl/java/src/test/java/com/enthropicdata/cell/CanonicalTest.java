// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

/**
 * The shared canonical serialization vectors.
 *
 * <p>Their expected strings come from the reference implementation and nowhere
 * else: §4.1.1 defines the canonical form by deferring to JavaScript's
 * {@code JSON.stringify}, so JavaScript is the authority on the right answer and
 * every other implementation checks itself against it. These run first in a new
 * port — no crypto, loud failures, and they catch the divergences that otherwise
 * surface only as a {@code header_hash} that never matches.
 */
class CanonicalTest {

    private static Path vectors() {
        return Path.of(System.getProperty("user.dir"), "..", "..", "conformance", "vectors")
                .normalize();
    }

    @Test
    void sharedCanonicalVectors() throws Exception {
        Path path = vectors().resolve("canonical.json");
        Assumptions.assumeTrue(Files.exists(path), "canonical vectors not present");

        Map<String, Object> file = Json.asObject(Json.parse(Files.readAllBytes(path)));
        List<Object> cases = Json.array(file, "cases");
        assertTrue(cases != null && !cases.isEmpty(), "canonical vector file is empty");

        List<String> failures = new ArrayList<>();
        for (Object entry : cases) {
            Map<String, Object> testCase = Json.asObject(entry);
            String name = Json.string(testCase, "name");
            String expected = Json.string(testCase, "expected");
            try {
                String got = Canonical.canonicalize(testCase.get("input"));
                if (!got.equals(expected)) {
                    failures.add(name + ":%n  got  ".formatted() + got + "%n  want ".formatted() + expected);
                }
            } catch (RuntimeException e) {
                failures.add(name + ": " + e.getMessage());
            }
        }
        assertTrue(failures.isEmpty(),
                failures.size() + " of " + cases.size() + " canonical vectors failed:\n"
                        + String.join("\n", failures));
        System.out.println("checked " + cases.size() + " canonical vectors against the reference");
    }

    @Test
    void jsNumberEdgeCases() {
        // Double.toString disagrees with JavaScript on every one of these.
        assertEquals("1", Canonical.jsNumber(1.0));
        assertEquals("0", Canonical.jsNumber(-0.0));
        assertEquals("1e-7", Canonical.jsNumber(1e-7));
        assertEquals("0.000001", Canonical.jsNumber(1e-6));
        assertEquals("1e+21", Canonical.jsNumber(1e21));
        assertEquals("100000000000000000000", Canonical.jsNumber(1e20));
        assertEquals("100", Canonical.jsNumber(100.0));
        assertEquals("0.1", Canonical.jsNumber(0.1));
        assertEquals("5e-324", Canonical.jsNumber(Double.MIN_VALUE));
        assertEquals("1.7976931348623157e+308", Canonical.jsNumber(Double.MAX_VALUE));
        assertThrows(CellException.Canonicalization.class, () -> Canonical.jsNumber(Double.NaN));
        assertThrows(CellException.Canonicalization.class,
                () -> Canonical.jsNumber(Double.POSITIVE_INFINITY));
    }

    @Test
    void keyOrderIsPreservedOnParse() {
        // v1.0/v1.1 hash their header as JSON.stringify wrote it, in insertion
        // order. A parser backed by a sorted or hashed map could never reproduce
        // those bytes — hence LinkedHashMap in Json.
        Map<String, Object> parsed = Json.asObject(Json.parse("{\"z\":1,\"a\":2,\"m\":3}"));
        assertEquals(List.of("z", "a", "m"), new ArrayList<>(parsed.keySet()));
        assertEquals("{\"a\":2,\"m\":3,\"z\":1}", Canonical.canonicalize(parsed));
    }

    @Test
    void astralKeysSortByUtf16CodeUnit() {
        // Java's String.compareTo is already UTF-16 code-unit order, so an
        // astral character sorts BEFORE U+E000..U+FFFF exactly as in JavaScript.
        // Go, Rust and Python all need a custom comparator here; Java does not.
        Map<String, Object> map = Json.of("", 1.0, "😀", 2.0);
        String canonical = Canonical.canonicalize(map);
        assertTrue(canonical.indexOf("😀") < canonical.indexOf(""),
                "astral key must sort first: " + canonical);
    }

    @Test
    void explicitNullIsNotAnAbsentKey() {
        // §6.4: share_index is omitted, not null, on non-quorum cells, and the
        // two forms hash differently. Both are internally valid.
        assertNotEquals(
                Canonical.canonicalize(Json.parse("{\"share_index\":null}")),
                Canonical.canonicalize(Json.parse("{}")));
    }

    @Test
    void trailingDataIsRejected() {
        assertThrows(CellException.Malformed.class, () -> Json.parse("{\"a\":1} {\"b\":2}"));
    }
}
