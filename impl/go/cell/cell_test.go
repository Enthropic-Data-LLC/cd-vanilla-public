// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell"
)

// Round-trips prove only that the library agrees with itself. What a
// conformance suite has to establish is that the refusals happen.

const day = 86400

func mustKey(t *testing.T, label string) *cell.KeyRecord {
	t.Helper()
	k, err := cell.GenerateKey(label)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, data []byte, recipients []cell.Recipient, opts cell.CreateOptions) *cell.Object {
	t.Helper()
	c, err := cell.Create(data, "f.txt", recipients, opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// rehash recomputes header_hash — what any attacker editing a header does
// first, since the hash is unkeyed. Every "attacker edits the header" test
// needs it, and that is precisely why the AAD binding and the signature exist.
func rehash(t *testing.T, c *cell.Object) *cell.Object {
	t.Helper()
	header := c.GetObject("header")
	bytesToHash, err := cell.SerializeHeader(header, c.GetString("version"))
	if err != nil {
		t.Fatal(err)
	}
	c.Set("header_hash", cell.EncodeB64(sha256Of(bytesToHash)))
	return c
}

func sha256Of(b []byte) []byte { return hashOf(b) }

func TestRoundTrip(t *testing.T) {
	alice := mustKey(t, "Alice")
	c := seal(t, []byte("hello"), []cell.Recipient{cell.KeyRecipient(alice)},
		cell.CreateOptions{ContentType: "text/plain"})
	result, err := cell.Open(c, cell.OpenOptions{Keys: []*cell.KeyRecord{alice}})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Data) != "hello" {
		t.Errorf("data = %q", result.Data)
	}
	if result.ContentType != "text/plain" {
		t.Errorf("content_type = %q", result.ContentType)
	}
	if result.Signed {
		t.Error("unsigned cell reported as signed")
	}
}

func TestRoundTripEdgeCases(t *testing.T) {
	alice := mustKey(t, "Alice")
	binary := bytes.Repeat([]byte{0}, 0)
	for _, size := range []int{0, 1, 1024} {
		binary = make([]byte, size)
		for i := range binary {
			binary[i] = byte(i)
		}
		c := seal(t, binary, []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		result, err := cell.Open(c, cell.OpenOptions{Keys: []*cell.KeyRecord{alice}})
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(result.Data, binary) {
			t.Errorf("size %d did not round-trip", size)
		}
	}
}

func TestMetadataIsNotVisibleInTheCell(t *testing.T) {
	// §5: the manifest lives inside the ciphertext. If the filename appears
	// anywhere in the serialized cell, metadata confidentiality is broken.
	alice := mustKey(t, "Alice")
	c, err := cell.Create(bytes.Repeat([]byte("x"), 1000), "secret-merger-terms.pdf",
		[]cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cell.MarshalCell(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-merger-terms") {
		t.Fatal("filename leaked into the cell")
	}
}

func TestReformattingDoesNotBreakVerification(t *testing.T) {
	// The whole point of canonicalization (§4.1.1): a cell pretty-printed or
	// key-reordered in transit still verifies.
	alice := mustKey(t, "Alice")
	c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
	encoded, err := cell.MarshalCell(c)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := cell.ParseCell(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cell.Verify(reparsed, ""); err != nil {
		t.Fatalf("re-serialized cell failed verification: %v", err)
	}
}

func TestIntegrityRefusals(t *testing.T) {
	alice := mustKey(t, "Alice")
	bob := mustKey(t, "Bob")
	opts := cell.OpenOptions{Keys: []*cell.KeyRecord{alice}}

	t.Run("missing header_hash is a rejection", func(t *testing.T) {
		// §4.1: absence must not be licence to skip the checks — deleting one
		// field would otherwise disable header, ciphertext and signature
		// verification together.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		c.Delete("header_hash")
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrIntegrity) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("edited header without rehash", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		c.GetObject("header").GetObject("policy").Set("copy_protection", "none")
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrIntegrity) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("tampered ciphertext fails payload_hash", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		payload := c.GetObject("payload")
		raw, _ := cell.DecodeB64(payload.GetString("ciphertext"), "ciphertext")
		raw[0] ^= 1
		payload.Set("ciphertext", cell.EncodeB64(raw))
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrIntegrity) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("tampered AAD fails the GCM tag", func(t *testing.T) {
		// The attacker edits bound metadata AND recomputes the unkeyed
		// header_hash, so §10 steps 1-3 all pass. The AAD binding is the only
		// thing left, and it must catch this.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		c.GetObject("header").GetObject("policy").Set("copy_protection", "none")
		rehash(t, c)
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrDecryption) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("version downgrade fails the GCM tag", func(t *testing.T) {
		// §4.4: rewriting version to 1.0 would strip the AAD from the decrypt.
		// The ciphertext was produced WITH AAD, so the tag fails; an attacker
		// cannot re-encrypt without the CEK.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		c.Set("version", "1.0")
		rehash(t, c)
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrDecryption) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unknown version", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		c.Set("version", "9.9")
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrUnsupportedVersion) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("forged access map caught by the signature", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)},
			cell.CreateOptions{Sender: alice})
		other := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(bob)}, cell.CreateOptions{})
		c.GetObject("header").Set("access_map", other.GetObject("header").GetArray("access_map"))
		rehash(t, c)
		if _, err := cell.Open(c, cell.OpenOptions{Keys: []*cell.KeyRecord{bob}}); !errors.Is(err, cell.ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSignatures(t *testing.T) {
	alice, bob := mustKey(t, "Alice"), mustKey(t, "Bob")
	opts := cell.OpenOptions{Keys: []*cell.KeyRecord{alice}}

	t.Run("reports the real fingerprint", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{Sender: bob})
		result, err := cell.Open(c, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Signed || result.SignerFingerprint != bob.Fingerprint() {
			t.Fatalf("signer = %q", result.SignerFingerprint)
		}
	})

	t.Run("header_sig_by is not trusted", func(t *testing.T) {
		// §4.1: a self-asserted label. Changing it must not change attribution.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{Sender: bob})
		c.Set("header_sig_by", "Trust Me Inc")
		rehash(t, c)
		result, err := cell.Open(c, opts)
		if err != nil {
			t.Fatal(err)
		}
		if result.SignerFingerprint != bob.Fingerprint() {
			t.Errorf("attribution moved with the label")
		}
		if result.ClaimedSigner != "Trust Me Inc" {
			t.Errorf("claimed signer = %q", result.ClaimedSigner)
		}
	})

	t.Run("DER-encoded signature is refused", func(t *testing.T) {
		// §4.1's named trap: every general-purpose library produces DER by
		// default, and DER in header_sig must not verify.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{Sender: bob})
		raw, _ := cell.DecodeB64(c.GetString("header_sig"), "header_sig")
		der := append([]byte{0x30, 0x44, 0x02, 0x20}, raw[:32]...)
		der = append(der, 0x02, 0x20)
		der = append(der, raw[32:]...)
		c.Set("header_sig", cell.EncodeB64(der))
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrMalformed) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("stripped signature is undetectable but expected_signer catches it", func(t *testing.T) {
		// §4.1: an attacker can delete the signature and the result is
		// byte-indistinguishable from a cell that was never signed. "Opened
		// without error" is not evidence of authorship.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{Sender: bob})
		for _, key := range []string{"header_sig", "header_sig_by", "header_sig_key"} {
			c.Set(key, nil)
		}
		rehash(t, c)
		result, err := cell.Open(c, opts)
		if err != nil {
			t.Fatalf("stripped cell should still open: %v", err)
		}
		if result.Signed {
			t.Error("reported as signed")
		}
		strict := opts
		strict.ExpectedSigner = bob.Fingerprint()
		if _, err := cell.Open(c, strict); !errors.Is(err, cell.ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestAccessControl(t *testing.T) {
	alice, bob := mustKey(t, "Alice"), mustKey(t, "Bob")

	t.Run("wrong key", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		if _, err := cell.Open(c, cell.OpenOptions{Keys: []*cell.KeyRecord{bob}}); !errors.Is(err, cell.ErrNoMatchingKey) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("quorum", func(t *testing.T) {
		keys := []*cell.KeyRecord{mustKey(t, "K1"), mustKey(t, "K2"), mustKey(t, "K3")}
		recipients := []cell.Recipient{cell.KeyRecipient(keys[0]), cell.KeyRecipient(keys[1]), cell.KeyRecipient(keys[2])}
		c := seal(t, []byte("quorum"), recipients, cell.CreateOptions{Threshold: 2})
		if _, err := cell.Open(c, cell.OpenOptions{Keys: keys[:2]}); err != nil {
			t.Fatalf("two shares should open: %v", err)
		}
		if _, err := cell.Open(c, cell.OpenOptions{Keys: keys[:1]}); !errors.Is(err, cell.ErrQuorumNotMet) {
			t.Fatalf("got %v", err)
		}
		for i, entryValue := range c.GetObject("header").GetArray("access_map") {
			entry := entryValue.(*cell.Object)
			if entry.GetInt("share_index", -1) != i+1 {
				t.Errorf("entry %d has share_index %d", i, entry.GetInt("share_index", -1))
			}
		}
	})

	t.Run("share_index omitted on non-quorum cells", func(t *testing.T) {
		// §6.4: omitted, not null — the two forms hash differently.
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{})
		entry := c.GetObject("header").GetArray("access_map")[0].(*cell.Object)
		if entry.Has("share_index") {
			t.Fatal("share_index must be omitted on a non-quorum cell")
		}
	})

	t.Run("passphrase", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.PassphraseRecipient("right", "")}, cell.CreateOptions{})
		if _, err := cell.Open(c, cell.OpenOptions{Passphrases: []string{"right"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := cell.Open(c, cell.OpenOptions{Passphrases: []string{"wrong"}}); !errors.Is(err, cell.ErrNoMatchingKey) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestLifetimeGates(t *testing.T) {
	alice := mustKey(t, "Alice")
	opts := cell.OpenOptions{Keys: []*cell.KeyRecord{alice}}
	now := time.Now().Unix()

	build := func(fields map[string]cell.Value) *cell.Object {
		lifetime := cell.NewObject()
		advisory := cell.NewObject()
		for k, v := range fields {
			if k == "type" {
				lifetime.Set("type", v)
			} else {
				advisory.Set(k, v)
			}
		}
		lifetime.Set("advisory", advisory)
		return lifetime
	}

	t.Run("expired retention refused by default", func(t *testing.T) {
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)},
			cell.CreateOptions{Lifetime: build(map[string]cell.Value{"type": "record", "retain_until": float64(now - day)})})
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrLifetime) {
			t.Fatalf("got %v", err)
		}
		// §8.1 is explicit that a keyholder can disregard this, and this package
		// is the independent opener the spec describes. Making the bypass an
		// honest option beats pretending it does not exist.
		bypass := opts
		bypass.IgnoreAdvisory = true
		if _, err := cell.Open(c, bypass); err != nil {
			t.Fatalf("IgnoreAdvisory should open: %v", err)
		}
	})

	t.Run("timed release locks until its date", func(t *testing.T) {
		future := now + day
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)},
			cell.CreateOptions{Lifetime: build(map[string]cell.Value{"type": "timed_release", "release_at": float64(future)})})
		if _, err := cell.Open(c, opts); !errors.Is(err, cell.ErrLifetime) {
			t.Fatalf("got %v", err)
		}
		later := opts
		later.Now = future + 1
		if _, err := cell.Open(c, later); err != nil {
			t.Fatalf("after release_at should open: %v", err)
		}
	})

	t.Run("disposal never blocks an open", func(t *testing.T) {
		// §8.2: a passed disposal date describes the operator's retention
		// schedule, not the recipient's permission.
		lifetime := cell.NewObject()
		lifetime.Set("type", "record")
		disposal := cell.NewObject()
		disposal.Set("at", float64(now-day))
		disposal.Set("action", "delete")
		lifetime.Set("disposal", disposal)
		c := seal(t, []byte("x"), []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{Lifetime: lifetime})
		if _, err := cell.Open(c, opts); err != nil {
			t.Fatalf("disposal must not block: %v", err)
		}
	})
}

func TestKeyFiles(t *testing.T) {
	alice := mustKey(t, "Alice")
	pub, err := cell.MarshalCell(alice.ToCDPub())
	if err != nil {
		t.Fatal(err)
	}
	restoredPub, err := cell.ParseCDPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	if restoredPub.Fingerprint() != alice.Fingerprint() {
		t.Error("cdpub fingerprint changed")
	}

	keyDoc, err := alice.ToCDKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cell.MarshalCell(keyDoc)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := cell.ParseCDKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Fingerprint() != alice.Fingerprint() {
		t.Error("cdkey fingerprint changed")
	}

	// A lying fingerprint must be refused: the value is derived, not
	// authoritative, and trusting it lets an attacker point a known-good label
	// at a key they control.
	bad := alice.ToCDPub()
	bad.Set("fingerprint", "0000000000000000")
	badBytes, _ := cell.MarshalCell(bad)
	if _, err := cell.ParseCDPub(badBytes); err == nil {
		t.Error("a .cdpub whose fingerprint disagrees with its SPKI must be refused")
	}
}

func TestEncoderEmitsStandardBase64(t *testing.T) {
	// §4.0: base64url is not merely non-canonical, it is unparseable by the
	// reference — atob() throws on '-' and '_'.
	alice := mustKey(t, "Alice")
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i)
	}
	c := seal(t, data, []cell.Recipient{cell.KeyRecipient(alice)}, cell.CreateOptions{Sender: alice})
	encoded, err := cell.MarshalCell(c)
	if err != nil {
		t.Fatal(err)
	}
	payload := c.GetObject("payload")
	for _, field := range []string{payload.GetString("ciphertext"), payload.GetString("iv"),
		c.GetString("header_hash"), c.GetString("header_sig")} {
		if strings.ContainsAny(field, "-_") {
			t.Errorf("field contains base64url characters: %q", field)
		}
	}
	if !bytes.Contains(encoded, []byte("AES-256-GCM")) {
		t.Error("expected the payload alg in the serialized cell")
	}
}

func TestDecoderToleratesBase64URL(t *testing.T) {
	// §4.0 says decoders SHOULD accept it for robustness. Tolerating it on
	// input costs nothing; emitting it breaks every other reader.
	a, err := cell.DecodeB64("-_8=", "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := cell.DecodeB64("+/8=", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("base64url and standard base64 decoded differently")
	}
}
