// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical JSON serialization — spec §4.1.1.
//
// header_hash, header_sig and the AES-GCM AAD are computed over these bytes, so
// disagreeing with the reference by one byte means verifying nothing. The spec
// defines the canonical form by deferring to JavaScript's JSON.stringify, which
// imports three behaviours Go does not share:
//
//  1. Number formatting. JS prints the shortest round-tripping decimal and never
//     a trailing ".0" — 1.0 is "1", 1e-7 is "1e-7". strconv.FormatFloat with 'g'
//     produces "1" and "1e-07"; the second is wrong. jsNumber implements
//     ECMA-262 6.1.6.1.20 instead.
//
//  2. Key ordering. JS sorts strings by UTF-16 code unit. Go's sort.Strings
//     compares bytes, which is UTF-8 code-point order — the two disagree for any
//     character above the BMP, which sorts BELOW U+E000..U+FFFF in JavaScript
//     and above it in Go.
//
//  3. String escaping. encoding/json is NOT a JSON.stringify workalike: by
//     default it escapes <, > and & for HTML safety, and it escapes U+2028 and
//     U+2029 even with SetEscapeHTML(false). JSON.stringify escapes none of
//     those five. jsString does the escaping by hand for that reason.
//
// None of this is exotic. It is the gap between "the spec says JSON" and "the
// bytes agree", and it is where a port silently stops interoperating.

// jsNumber formats a float64 exactly as JavaScript's String(n) would.
func jsNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %v is not representable in JSON", ErrCanonicalization, f)
	}
	if f == 0 {
		return "0", nil // JS prints -0 as "0" too
	}
	// Note there is deliberately NO large-integer guard here. ParseValue has
	// already converted every JSON number to a float64, exactly as JavaScript
	// does, so any rounding JS would apply has happened identically and the two
	// agree by construction — including above 2^53, where the shortest
	// round-tripping decimal is shorter than the exact value (String(2**60) is
	// "1152921504606847000", not "...846976"). A language with real integers
	// has to convert before formatting to get this right; the Python port
	// refused these outright until the shared vectors caught it.

	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}

	// FormatFloat with 'e' and precision -1 gives the shortest round-tripping
	// digits, from which the ECMA-262 s/k/n triple falls out directly.
	formatted := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponentText, _ := strings.Cut(formatted, "e")
	exponent, err := strconv.Atoi(exponentText)
	if err != nil {
		return "", fmt.Errorf("%w: cannot decompose %v", ErrCanonicalization, f)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits)
	n := exponent + 1 // value == 0.<digits> * 10^n

	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	}

	e := n - 1
	exponentSign := "+"
	if e < 0 {
		exponentSign = "-"
		e = -e
	}
	if k == 1 {
		return sign + digits + "e" + exponentSign + strconv.Itoa(e), nil
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + exponentSign + strconv.Itoa(e), nil
}

// jsString quotes and escapes a string exactly as JSON.stringify does.
func jsString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(&b, `\u%04x`, r)
			case r == utf8.RuneError:
				// A lone surrogate survives JSON.parse in JavaScript and is
				// escaped by well-formed JSON.stringify (ES2019). Go's decoder
				// has already replaced it with U+FFFD by this point, so the two
				// cannot agree on such a cell. It cannot arise from anything a
				// conforming writer produced.
				b.WriteRune(r)
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// lessUTF16 reports whether a sorts before b in UTF-16 code-unit order, which
// is what Array.prototype.sort gives JavaScript.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// Canonicalize returns the canonical JSON serialization of v (spec §4.1.1).
func Canonicalize(v Value) (string, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// CanonicalBytes returns the UTF-8 bytes that are hashed and signed.
func CanonicalBytes(v Value) ([]byte, error) {
	s, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func writeCanonical(b *strings.Builder, v Value) error {
	switch value := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if value {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		b.WriteString(jsString(value))
	case float64:
		s, err := jsNumber(value)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []Value:
		b.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Object:
		keys := append([]string(nil), value.keys...)
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsString(key))
			b.WriteByte(':')
			if err := writeCanonical(b, value.values[key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: %T", ErrCanonicalization, v)
	}
	return nil
}

// jsStringify serializes in INSERTION order — the v1.0/v1.1 serialization.
//
// Those versions hash and sign their header as JSON.stringify wrote it, so the
// header must still be in the order it was parsed from disk. This is the whole
// reason Object preserves order rather than being a map (spec §12).
func jsStringify(v Value) (string, error) {
	var b strings.Builder
	if err := writeStringify(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeStringify(b *strings.Builder, v Value) error {
	switch value := v.(type) {
	case *Object:
		b.WriteByte('{')
		for i, key := range value.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsString(key))
			b.WriteByte(':')
			if err := writeStringify(b, value.values[key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
		return nil
	case []Value:
		b.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeStringify(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	default:
		return writeCanonical(b, v)
	}
}
