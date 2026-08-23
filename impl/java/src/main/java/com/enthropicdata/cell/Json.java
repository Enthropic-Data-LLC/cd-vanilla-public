// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, order-preserving JSON parser and writer.
 *
 * <p>The JDK has no JSON support at all — the one thing this format needs that
 * Java does not supply, where it supplies every cryptographic primitive
 * including the two (AES-KW, IEEE P1363 signatures) that other ports had to work
 * around. Rather than take a dependency on Jackson or Gson in a library meant to
 * be embedded, the parser is here: it is a hundred lines, and canonicalization
 * (§4.1.1) has to hand-roll its own number formatting and string escaping in
 * every language anyway, so a third-party writer would only be used for the
 * non-hashed paths.
 *
 * <p>Objects are {@link LinkedHashMap}, so key insertion order survives parsing.
 * v1.0 and v1.1 hash their header as {@code JSON.stringify} wrote it, in
 * insertion order (§12): a header parsed into a sorted or hashed map could never
 * be re-serialized to the bytes it was signed over.
 *
 * <p>Values are plain Java types — {@code null}, {@link Boolean}, {@link Double},
 * {@link String}, {@code List<Object>}, {@code Map<String,Object>}. Every JSON
 * number becomes a {@code Double}, exactly as JavaScript does, so a literal of
 * {@code 1.0} and one of {@code 1} produce identical canonical bytes and any
 * rounding JavaScript would apply has already happened.
 */
public final class Json {

    private Json() {}

    // ─── Parsing ────────────────────────────────────────────────────────────

    /** Parse a JSON document. */
    public static Object parse(String text) {
        Parser parser = new Parser(text);
        parser.skipWhitespace();
        Object value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            // A cell with a second document appended is not a cell.
            throw new CellException.Malformed("trailing data after JSON document");
        }
        return value;
    }

    /** Parse a JSON document from UTF-8 bytes. */
    public static Object parse(byte[] utf8) {
        return parse(new String(utf8, java.nio.charset.StandardCharsets.UTF_8));
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return i >= s.length();
        }

        void skipWhitespace() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    i++;
                } else {
                    break;
                }
            }
        }

        private CellException.Malformed fail(String message) {
            return new CellException.Malformed(message + " at offset " + i);
        }

        Object parseValue() {
            if (atEnd()) {
                throw fail("unexpected end of input");
            }
            char c = s.charAt(i);
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    return parseNumber();
            }
        }

        private void expect(String literal) {
            if (!s.startsWith(literal, i)) {
                throw fail("expected " + literal);
            }
            i += literal.length();
        }

        Map<String, Object> parseObject() {
            Map<String, Object> out = new LinkedHashMap<>();
            i++; // '{'
            skipWhitespace();
            if (!atEnd() && s.charAt(i) == '}') {
                i++;
                return out;
            }
            while (true) {
                skipWhitespace();
                if (atEnd() || s.charAt(i) != '"') {
                    throw fail("expected an object key");
                }
                String key = parseString();
                skipWhitespace();
                if (atEnd() || s.charAt(i) != ':') {
                    throw fail("expected ':'");
                }
                i++;
                skipWhitespace();
                out.put(key, parseValue());
                skipWhitespace();
                if (atEnd()) {
                    throw fail("unterminated object");
                }
                char c = s.charAt(i++);
                if (c == '}') {
                    return out;
                }
                if (c != ',') {
                    throw fail("expected ',' or '}'");
                }
            }
        }

        List<Object> parseArray() {
            List<Object> out = new ArrayList<>();
            i++; // '['
            skipWhitespace();
            if (!atEnd() && s.charAt(i) == ']') {
                i++;
                return out;
            }
            while (true) {
                skipWhitespace();
                out.add(parseValue());
                skipWhitespace();
                if (atEnd()) {
                    throw fail("unterminated array");
                }
                char c = s.charAt(i++);
                if (c == ']') {
                    return out;
                }
                if (c != ',') {
                    throw fail("expected ',' or ']'");
                }
            }
        }

        String parseString() {
            i++; // opening quote
            StringBuilder out = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw fail("unterminated string");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (atEnd()) {
                    throw fail("unterminated escape");
                }
                char escape = s.charAt(i++);
                switch (escape) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length()) {
                            throw fail("truncated \\u escape");
                        }
                        out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw fail("invalid escape \\" + escape);
                }
            }
        }

        Double parseNumber() {
            int start = i;
            if (!atEnd() && s.charAt(i) == '-') {
                i++;
            }
            while (!atEnd()) {
                char c = s.charAt(i);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    i++;
                } else {
                    break;
                }
            }
            if (start == i) {
                throw fail("expected a value");
            }
            String literal = s.substring(start, i);
            try {
                // Every JSON number is a double to JavaScript, and the canonical
                // form is defined by what JavaScript prints. Double.parseDouble
                // is correctly rounded, so the two agree on the resulting value
                // even above 2^53 where the literal cannot be held exactly.
                return Double.valueOf(literal);
            } catch (NumberFormatException e) {
                throw new CellException.Malformed("invalid number " + literal);
            }
        }
    }

    // ─── Convenience accessors ──────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object value) {
        if (!(value instanceof Map)) {
            throw new CellException.Malformed("expected a JSON object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Map<String, Object> parent, String key) {
        Object value = parent == null ? null : parent.get(key);
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> array(Map<String, Object> parent, String key) {
        Object value = parent == null ? null : parent.get(key);
        return value instanceof List ? (List<Object>) value : null;
    }

    public static String string(Map<String, Object> parent, String key) {
        Object value = parent == null ? null : parent.get(key);
        return value instanceof String ? (String) value : null;
    }

    public static long integer(Map<String, Object> parent, String key, long fallback) {
        Object value = parent == null ? null : parent.get(key);
        return value instanceof Double d ? (long) (double) d : fallback;
    }

    public static Long optionalInteger(Map<String, Object> parent, String key) {
        Object value = parent == null ? null : parent.get(key);
        return value instanceof Double d ? (long) (double) d : null;
    }

    public static boolean bool(Map<String, Object> parent, String key, boolean fallback) {
        Object value = parent == null ? null : parent.get(key);
        return value instanceof Boolean b ? b : fallback;
    }

    /** Build an ordered object from alternating key/value arguments. */
    public static Map<String, Object> of(Object... keyValues) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keyValues.length; i += 2) {
            out.put((String) keyValues[i], keyValues[i + 1]);
        }
        return out;
    }

    // ─── Writing ────────────────────────────────────────────────────────────

    /** Serialize with two-space indentation, for files a human may read. */
    public static String writePretty(Object value) {
        StringBuilder out = new StringBuilder();
        writeIndented(out, value, "");
        return out.toString();
    }

    private static void writeIndented(StringBuilder out, Object value, String indent) {
        String inner = indent + "  ";
        if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                out.append("{}");
                return;
            }
            out.append("{\n");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(",\n");
                }
                first = false;
                out.append(inner).append(Canonical.jsString((String) entry.getKey())).append(": ");
                writeIndented(out, entry.getValue(), inner);
            }
            out.append('\n').append(indent).append('}');
        } else if (value instanceof List<?> list) {
            if (list.isEmpty()) {
                out.append("[]");
                return;
            }
            out.append("[\n");
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    out.append(",\n");
                }
                first = false;
                out.append(inner);
                writeIndented(out, item, inner);
            }
            out.append('\n').append(indent).append(']');
        } else {
            out.append(Canonical.canonicalize(value));
        }
    }
}
