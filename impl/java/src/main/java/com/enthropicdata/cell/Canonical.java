// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Canonical JSON serialization — spec §4.1.1.
 *
 * <p>{@code header_hash}, {@code header_sig} and the AES-GCM AAD are computed
 * over these bytes, so disagreeing with the reference by one byte means
 * verifying nothing. The spec defines the canonical form by deferring to
 * JavaScript's {@code JSON.stringify}, which imports three behaviours — and
 * Java gets one of them for free while disagreeing loudly on another.
 *
 * <ol>
 *   <li><b>Number formatting.</b> {@link Double#toString} disagrees with
 *       JavaScript on essentially every input: {@code 1.0} where JS prints
 *       {@code 1}, {@code 1.0E-7} where JS prints {@code 1e-7}, {@code 1.0E20}
 *       where JS prints all twenty-one digits. {@link #jsNumber} implements
 *       ECMA-262 6.1.6.1.20 instead. Since JDK 19 {@code Double.toString} does
 *       at least produce the shortest round-tripping digits, which is the
 *       useful half of the decomposition.</li>
 *   <li><b>Key ordering.</b> JavaScript sorts by UTF-16 code unit, and so does
 *       {@link String#compareTo} — Java is the one language here that needs no
 *       special comparator. Go and Rust compare bytes and Python compares code
 *       points; all three disagree with JavaScript above the BMP.</li>
 *   <li><b>String escaping.</b> Done by hand below, because the set of
 *       characters {@code JSON.stringify} leaves unescaped ({@code /}, {@code <},
 *       {@code >}, {@code &}, U+2028, U+2029) is exactly the set that other JSON
 *       writers escape for HTML or JavaScript-source safety, and every one of
 *       those escapes changes the hash.</li>
 * </ol>
 */
public final class Canonical {

    private Canonical() {}

    /**
     * Format a number exactly as JavaScript's {@code String(n)} would.
     *
     * <p>Implements ECMA-262 6.1.6.1.20 (Number::toString, radix 10), which is
     * what {@code JSON.stringify} uses for finite numbers.
     */
    public static String jsNumber(double value) {
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            throw new CellException.Canonicalization(value + " is not representable in JSON");
        }
        if (value == 0.0) {
            return "0"; // JS prints -0 as "0" too
        }
        String sign = value < 0 ? "-" : "";
        double magnitude = Math.abs(value);

        // Find the shortest decimal that round-trips, then decompose it into
        // the ECMA-262 s/k/n triple.
        //
        // Double.toString is NOT usable for this even on JDK 19+, where it is
        // documented to give the shortest round-tripping decimal: for the
        // subnormal minimum it returns "4.9E-324" where "5E-324" round-trips
        // and is shorter, and JavaScript prints "5e-324". Rather than trust it
        // and disagree on an unknown set of inputs, search explicitly — at most
        // seventeen attempts, and correct by construction.
        //
        // Locale.ROOT is load-bearing: %e honours the default locale, and a
        // German or French JVM would format the mantissa with a comma. That
        // produces a canonical string no other implementation can reproduce,
        // and it would show up as a header_hash mismatch on some machines and
        // not others.
        String text = null;
        int exponent = 0;
        for (int precision = 0; precision <= 17; precision++) {
            String candidate = String.format(java.util.Locale.ROOT, "%." + precision + "e", magnitude);
            if (Double.parseDouble(candidate) == magnitude) {
                int marker = candidate.indexOf('e');
                text = candidate.substring(0, marker);
                exponent = Integer.parseInt(candidate.substring(marker + 1));
                break;
            }
        }
        if (text == null) {
            throw new CellException.Canonicalization("cannot decompose " + value);
        }
        // %e always yields one digit before the point, so the exponent it
        // reports is (n - 1) in ECMA-262 terms; the +1 below restores n.
        exponent += 1;

        int point = text.indexOf('.');
        String intPart = point < 0 ? text : text.substring(0, point);
        String fracPart = point < 0 ? "" : text.substring(point + 1);
        String raw = intPart + fracPart;

        int leadingZeros = 0;
        while (leadingZeros < raw.length() && raw.charAt(leadingZeros) == '0') {
            leadingZeros++;
        }
        String digits = raw.substring(leadingZeros);
        int end = digits.length();
        while (end > 1 && digits.charAt(end - 1) == '0') {
            end--;
        }
        digits = digits.substring(0, end);

        int n = intPart.length() + exponent - 1 - leadingZeros; // value == 0.<digits> * 10^n
        int k = digits.length();

        if (k <= n && n <= 21) {
            return sign + digits + "0".repeat(n - k);
        }
        if (0 < n && n <= 21) {
            return sign + digits.substring(0, n) + "." + digits.substring(n);
        }
        if (-6 < n && n <= 0) {
            return sign + "0." + "0".repeat(-n) + digits;
        }
        int exp = n - 1;
        String expSign = exp >= 0 ? "+" : "-";
        String mantissa = k == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        return sign + mantissa + "e" + expSign + Math.abs(exp);
    }

    /**
     * Quote and escape a string exactly as {@code JSON.stringify} does.
     *
     * <p>Note what is <em>not</em> escaped: {@code /}, {@code <}, {@code >},
     * {@code &}, U+2028 and U+2029.
     */
    public static String jsString(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2);
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
        return out.toString();
    }

    /** Return the canonical JSON serialization of {@code value} (§4.1.1). */
    public static String canonicalize(Object value) {
        StringBuilder out = new StringBuilder();
        writeCanonical(out, value);
        return out.toString();
    }

    /** UTF-8 bytes of {@link #canonicalize} — what actually gets hashed and signed. */
    public static byte[] canonicalBytes(Object value) {
        return canonicalize(value).getBytes(StandardCharsets.UTF_8);
    }

    private static void writeCanonical(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (value instanceof String s) {
            out.append(jsString(s));
        } else if (value instanceof Double d) {
            out.append(jsNumber(d));
        } else if (value instanceof Number n) {
            // Integers reaching here came from application code rather than the
            // parser. Convert to double first: JavaScript has no integers, and
            // agreeing with it means rounding as it does, not printing exactly.
            out.append(jsNumber(n.doubleValue()));
        } else if (value instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeCanonical(out, list.get(i));
            }
            out.append(']');
        } else if (value instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>(map.size());
            for (Object key : map.keySet()) {
                if (!(key instanceof String s)) {
                    throw new CellException.Canonicalization("object key is not a string");
                }
                keys.add(s);
            }
            // String.compareTo is UTF-16 code-unit order, which is exactly
            // JavaScript's. No custom comparator needed — see the class comment.
            Collections.sort(keys);
            out.append('{');
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(jsString(keys.get(i))).append(':');
                writeCanonical(out, map.get(keys.get(i)));
            }
            out.append('}');
        } else {
            throw new CellException.Canonicalization(value.getClass().getName());
        }
    }

    /**
     * {@code JSON.stringify(v)} with <em>insertion</em> order — the v1.0/v1.1
     * serialization.
     *
     * <p>Those versions hash and sign their header in the order the reference
     * happened to build it (§12), which is why {@link Json} parses objects into
     * a {@code LinkedHashMap}.
     */
    public static String jsStringify(Object value) {
        StringBuilder out = new StringBuilder();
        writeStringify(out, value);
        return out.toString();
    }

    private static void writeStringify(StringBuilder out, Object value) {
        if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                out.append(jsString((String) entry.getKey())).append(':');
                writeStringify(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeStringify(out, list.get(i));
            }
            out.append(']');
        } else {
            writeCanonical(out, value);
        }
    }
}
