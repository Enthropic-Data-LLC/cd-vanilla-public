// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"crypto/rand"
	"fmt"
)

// Shamir Secret Sharing over GF(256) — spec §7.
//
// There is no interoperable standard for Shamir's scheme, so every
// implementation hand-rolls it and every one is free to be subtly incompatible:
// split/combine round-trips pass no matter which field, evaluation order or
// x-coordinates you picked. The spec pins the three choices that matter and
// this implements exactly those — GF(2^8) modulo 0x11b, one polynomial per
// secret byte with the byte as constant term, share i evaluated at x = i, and
// reconstruction by Lagrange interpolation at x = 0.

var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		// multiply by the generator 3 (== x + 1)
		hi := x & 0x80
		x = (x << 1) ^ x
		if hi != 0 {
			x ^= 0x1B
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMul multiplies in GF(2^8). Agrees with the Russian-peasant loop the spec
// describes on all 65,536 products; a test asserts that rather than assuming it.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv is the multiplicative inverse. The spec gives x^254 (Fermat); the table
// gives the same value in one lookup.
func gfInv(x byte) byte {
	if x == 0 {
		panic("gf256: no inverse for 0")
	}
	return gfExp[255-int(gfLog[x])]
}

// Share is one Shamir share: an x-coordinate and one y byte per secret byte.
type Share struct {
	X    int
	Data []byte
}

// SplitSecret splits secret into n shares of which any k reconstruct it.
//
// coefficients, when non-nil, supplies the polynomial coefficients so a test
// vector can pin the exact shares; it must be (k-1)*len(secret) bytes, ordered
// coefficient-major per byte position. Production callers pass nil.
func SplitSecret(secret []byte, n, k int, coefficients []byte) ([]Share, error) {
	if k < 1 || n < k || n > 255 {
		return nil, fmt.Errorf("%w: invalid Shamir parameters %d-of-%d", ErrMalformed, k, n)
	}
	needed := (k - 1) * len(secret)
	if coefficients == nil {
		coefficients = make([]byte, needed)
		if _, err := rand.Read(coefficients); err != nil {
			return nil, err
		}
	} else if len(coefficients) != needed {
		return nil, fmt.Errorf("%w: expected %d coefficient bytes, got %d", ErrMalformed, needed, len(coefficients))
	}

	shares := make([]Share, n)
	for i := range shares {
		shares[i] = Share{X: i + 1, Data: make([]byte, len(secret))}
	}
	poly := make([]byte, k)
	for bi, b := range secret {
		poly[0] = b
		copy(poly[1:], coefficients[bi*(k-1):(bi+1)*(k-1)])
		for si := range shares {
			x := byte(shares[si].X)
			// Horner from the high coefficient down — the reference's order.
			y := poly[k-1]
			for i := k - 2; i >= 0; i-- {
				y = gfMul(y, x) ^ poly[i]
			}
			shares[si].Data[bi] = y
		}
	}
	return shares, nil
}

// CombineShares reconstructs the secret by Lagrange interpolation at x = 0.
func CombineShares(shares []Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("%w: no shares to combine", ErrMalformed)
	}
	seen := map[int]bool{}
	length := len(shares[0].Data)
	for _, s := range shares {
		if s.X < 1 || s.X > 255 {
			return nil, fmt.Errorf("%w: invalid share index %d — must be 1..255", ErrMalformed, s.X)
		}
		if seen[s.X] {
			return nil, fmt.Errorf("%w: duplicate share index %d", ErrMalformed, s.X)
		}
		seen[s.X] = true
		if len(s.Data) != length {
			return nil, fmt.Errorf("%w: shares differ in length", ErrMalformed)
		}
	}

	out := make([]byte, length)
	for bi := 0; bi < length; bi++ {
		var acc byte
		for i, si := range shares {
			num, den := byte(1), byte(1)
			for j, sj := range shares {
				if i == j {
					continue
				}
				num = gfMul(num, byte(sj.X))
				den = gfMul(den, byte(si.X)^byte(sj.X))
			}
			acc ^= gfMul(si.Data[bi], gfMul(num, gfInv(den)))
		}
		out[bi] = acc
	}
	return out, nil
}
