// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"crypto/rand"
	"fmt"
	"time"
)

// ULID document identifiers — spec §4.1, §14.
//
// 26 characters of Crockford base32: a 48-bit millisecond timestamp in the
// first 10, 80 bits of CSPRNG output in the last 16. Lexicographically sortable
// by creation time, which is the only property the format relies on.

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULID generates an identifier. The arguments exist so vectors can be
// reproduced; pass 0 and nil in production.
func ULID(timestampMS int64, randomness []byte) (string, error) {
	if timestampMS == 0 {
		timestampMS = time.Now().UnixMilli()
	}
	if timestampMS < 0 || timestampMS >= 1<<48 {
		return "", fmt.Errorf("%w: ULID timestamp must fit in 48 bits", ErrMalformed)
	}
	if randomness == nil {
		randomness = make([]byte, 10)
		if _, err := rand.Read(randomness); err != nil {
			return "", err
		}
	} else if len(randomness) != 10 {
		return "", fmt.Errorf("%w: ULID randomness must be exactly 10 bytes", ErrMalformed)
	}

	out := make([]byte, 26)
	t := timestampMS
	for i := 9; i >= 0; i-- {
		out[i] = crockford[t&31]
		t >>= 5
	}
	var value uint64
	var bits uint
	index := 25
	for i := len(randomness) - 1; i >= 0 && index >= 10; i-- {
		value |= uint64(randomness[i]) << bits
		bits += 8
		for bits >= 5 && index >= 10 {
			out[index] = crockford[value&31]
			value >>= 5
			bits -= 5
			index--
		}
	}
	for index >= 10 {
		out[index] = crockford[value&31]
		value >>= 5
		index--
	}
	return string(out), nil
}
