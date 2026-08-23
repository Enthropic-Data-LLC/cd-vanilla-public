// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell_test

import (
	"bytes"
	"testing"

	"github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell"
)

// Shamir has no interoperable standard, which makes it the largest interop risk
// in the format: split/combine round-trips pass no matter which field or
// evaluation order was chosen, and disagreement only surfaces when someone
// else's shares arrive. The fixed vector is what actually pins it down; the
// cross-implementation quorum vectors in the conformance suite are the rest.

func TestSplitCombine(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	shares, err := cell.SplitSecret(secret, 5, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range shares {
		if s.X != i+1 {
			t.Fatalf("share %d has x = %d, want %d", i, s.X, i+1)
		}
	}
	for _, combo := range [][]int{{0, 1, 2}, {0, 2, 4}, {2, 3, 4}, {1, 3, 4}} {
		picked := []cell.Share{shares[combo[0]], shares[combo[1]], shares[combo[2]]}
		got, err := cell.CombineShares(picked)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("combo %v did not reconstruct", combo)
		}
	}
	short, err := cell.CombineShares(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(short, secret) {
		t.Fatal("fewer than k shares must not reconstruct the secret")
	}
}

func TestDeterministicShareVector(t *testing.T) {
	// Fixed coefficients, so these bytes are a conformance vector rather than a
	// round-trip: any implementation agreeing on the field, the evaluation order
	// and the x-coordinates produces exactly this. Matches the Python port's
	// vector in tests/test_gf256.py.
	shares, err := cell.SplitSecret([]byte{0x01, 0x02, 0x03}, 3, 2, []byte{0x10, 0x20, 0x30})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"112233", "214263", "316253"}
	for i, s := range shares {
		if got := hexOf(s.Data); got != want[i] {
			t.Errorf("share %d = %s, want %s", s.X, got, want[i])
		}
	}
}

func TestCombineRejectsBadShares(t *testing.T) {
	secret := []byte{1, 2, 3, 4}
	shares, _ := cell.SplitSecret(secret, 3, 2, nil)
	if _, err := cell.CombineShares(nil); err == nil {
		t.Error("no shares must be refused")
	}
	if _, err := cell.CombineShares([]cell.Share{shares[0], shares[0]}); err == nil {
		t.Error("duplicate share indices must be refused")
	}
	truncated := cell.Share{X: shares[1].X, Data: shares[1].Data[:2]}
	if _, err := cell.CombineShares([]cell.Share{shares[0], truncated}); err == nil {
		t.Error("mismatched share lengths must be refused")
	}
	if _, err := cell.SplitSecret(secret, 2, 3, nil); err == nil {
		t.Error("k > n must be refused")
	}
	if _, err := cell.SplitSecret(secret, 256, 2, nil); err == nil {
		t.Error("n > 255 must be refused")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
