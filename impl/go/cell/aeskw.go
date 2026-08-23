// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// AES Key Wrap — RFC 3394.
//
// The one primitive the format needs that Go's standard library does not
// provide. Python has it (cryptography.hazmat.primitives.keywrap), Java has it
// (AESWrap), the browser has it (WebCrypto AES-KW), and Go does not — so any Go
// implementation of this format either vendors a third-party package or writes
// these sixty lines. They are worth writing: the algorithm is fixed, small, and
// has a published test vector to check against.

// defaultIV is the RFC 3394 §2.2.3.1 "alternative initial value", A6A6A6A6A6A6A6A6.
// Its purpose is integrity: unwrap recomputes it, and a wrong KEK yields a
// different value, which is how an unwrap detects a wrong key at all.
var defaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// AESKeyWrap wraps plaintext (a multiple of 8 bytes, at least 16) under kek.
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		return nil, fmt.Errorf("%w: AES-KW input must be a multiple of 8 bytes and at least 16, got %d", ErrMalformed, len(plaintext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	n := len(plaintext) / 8
	a := defaultIV
	r := make([]byte, len(plaintext))
	copy(r, plaintext)

	var buf [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a[:])
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf[:], buf[:])
			copy(a[:], buf[:8])
			// t = n*j + i, XORed into the low-order bytes of A.
			t := uint64(n*j + i)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			for k := 0; k < 8; k++ {
				a[k] ^= tb[k]
			}
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}

	out := make([]byte, 0, len(plaintext)+8)
	out = append(out, a[:]...)
	out = append(out, r...)
	return out, nil
}

// AESKeyUnwrap reverses AESKeyWrap, verifying the integrity check value.
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, fmt.Errorf("%w: AES-KW ciphertext must be a multiple of 8 bytes and at least 24, got %d", ErrMalformed, len(ciphertext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	n := len(ciphertext)/8 - 1
	var a [8]byte
	copy(a[:], ciphertext[:8])
	r := make([]byte, len(ciphertext)-8)
	copy(r, ciphertext[8:])

	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			for k := 0; k < 8; k++ {
				buf[k] = a[k] ^ tb[k]
			}
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf[:], buf[:])
			copy(a[:], buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}

	// Constant-time, because this comparison is what says "wrong key" and an
	// opener runs it once per access-map entry.
	if subtle.ConstantTimeCompare(a[:], defaultIV[:]) != 1 {
		return nil, fmt.Errorf("%w: AES-KW integrity check failed (wrong wrapping key)", ErrNoMatchingKey)
	}
	return r, nil
}
