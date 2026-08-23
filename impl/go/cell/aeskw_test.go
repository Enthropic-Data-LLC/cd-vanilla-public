// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell"
)

// AES-KW is the one primitive Go's standard library does not provide, so it is
// the one most likely to be subtly wrong. RFC 3394 ships test vectors; these
// are them, and they are the reason writing it is preferable to trusting it.

func TestAESKeyWrapRFC3394Vectors(t *testing.T) {
	cases := []struct{ name, kek, plaintext, wrapped string }{
		{
			"4.1 128-bit data with 128-bit KEK",
			"000102030405060708090A0B0C0D0E0F",
			"00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			"4.4 192-bit data with 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{
			"4.6 256-bit data with 256-bit KEK — the case this format uses",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kek, _ := hex.DecodeString(c.kek)
			plaintext, _ := hex.DecodeString(c.plaintext)
			want, _ := hex.DecodeString(c.wrapped)

			got, err := cell.AESKeyWrap(kek, plaintext)
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("wrap = %X, want %X", got, want)
			}
			back, err := cell.AESKeyUnwrap(kek, want)
			if err != nil {
				t.Fatalf("unwrap: %v", err)
			}
			if !bytes.Equal(back, plaintext) {
				t.Fatalf("unwrap = %X, want %X", back, plaintext)
			}
		})
	}
}

func TestAESKeyUnwrapRejectsWrongKey(t *testing.T) {
	// The integrity check value is the only thing that makes a wrong key
	// detectable, and an opener runs this once per access-map entry.
	kek := bytes.Repeat([]byte{0x01}, 32)
	wrong := bytes.Repeat([]byte{0x02}, 32)
	wrapped, err := cell.AESKeyWrap(kek, bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cell.AESKeyUnwrap(wrong, wrapped); err == nil {
		t.Fatal("unwrapping with the wrong KEK must fail")
	}
}

func TestAESKeyWrapRejectsBadLengths(t *testing.T) {
	kek := bytes.Repeat([]byte{0x01}, 32)
	if _, err := cell.AESKeyWrap(kek, make([]byte, 20)); err == nil {
		t.Error("input not a multiple of 8 must be refused")
	}
	if _, err := cell.AESKeyWrap(kek, make([]byte, 8)); err == nil {
		t.Error("input shorter than 16 bytes must be refused")
	}
	if _, err := cell.AESKeyUnwrap(kek, make([]byte, 16)); err == nil {
		t.Error("ciphertext shorter than 24 bytes must be refused")
	}
}
