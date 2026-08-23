// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell"
)

// Runs the shared conformance vectors in conformance/vectors.
//
// This is the test a new language port writes first. It reads a
// language-neutral manifest and asserts two things per vector: the cells that
// must open produce the exact expected plaintext, filename, media type and
// sender meta; and the cells that must be refused are refused.
//
// The refusals carry most of the weight. An implementation that opens every
// positive vector and also opens reject-tampered-aad is not a partial pass — it
// has no metadata authentication at all.

type openSpec struct {
	Keys          []string   `json:"keys"`
	Passphrases   []string   `json:"passphrases"`
	AlsoOpensWith []openSpec `json:"also_opens_with"`
}

type vector struct {
	ID          string   `json:"id"`
	File        string   `json:"file"`
	Description string   `json:"description"`
	Expect      string   `json:"expect"`
	CellVersion string   `json:"cell_version"`
	OpenWith    openSpec `json:"open_with"`
	Plaintext   *struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	} `json:"plaintext"`
	Filename        string          `json:"filename"`
	ContentType     string          `json:"content_type"`
	Meta            json.RawMessage `json:"meta"`
	Signer          string          `json:"signer"`
	RejectReason    string          `json:"reject_reason"`
	MustNotOpenWith *openSpec       `json:"must_not_open_with"`
}

type manifest struct {
	Version       int      `json:"version"`
	Spec          string   `json:"spec"`
	Passphrase    string   `json:"passphrase"`
	RejectReasons []string `json:"reject_reasons"`
	Vectors       []vector `json:"vectors"`
}

// vectorsDir locates conformance/vectors relative to this package.
func vectorsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "conformance", "vectors")
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Skipf("conformance vectors not present at %s", dir)
	}
	return dir
}

func loadManifest(t *testing.T) (string, manifest) {
	t.Helper()
	dir := vectorsDir(t)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	return dir, m
}

func loadKey(t *testing.T, dir, name string) *cell.KeyRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "..", "keys", name+".cdkey"))
	if err != nil {
		t.Fatalf("reading key %s: %v", name, err)
	}
	key, err := cell.ParseCDKey(data)
	if err != nil {
		t.Fatalf("parsing key %s: %v", name, err)
	}
	return key
}

func optionsFor(t *testing.T, dir string, spec openSpec) cell.OpenOptions {
	t.Helper()
	opts := cell.OpenOptions{Passphrases: spec.Passphrases}
	for _, name := range spec.Keys {
		opts.Keys = append(opts.Keys, loadKey(t, dir, name))
	}
	return opts
}

func loadCell(t *testing.T, dir string, v vector) *cell.Object {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, v.File))
	if err != nil {
		t.Fatalf("reading %s: %v", v.File, err)
	}
	c, err := cell.ParseCell(data)
	if err != nil {
		t.Fatalf("parsing %s: %v", v.File, err)
	}
	return c
}

// rejectErrors maps the manifest's portable reason codes onto this package's
// sentinel errors. A port in another language substitutes its own; the reasons
// are the portable part, and the manifest is explicit that the refusal is
// normative while the specific reason code is not.
var rejectErrors = map[string]error{
	"header-hash-missing":   cell.ErrIntegrity,
	"header-hash-mismatch":  cell.ErrIntegrity,
	"payload-hash-mismatch": cell.ErrIntegrity,
	"signature-invalid":     cell.ErrSignature,
	"signature-der-encoded": cell.ErrMalformed,
	"aad-mismatch":          cell.ErrDecryption,
	"unsupported-version":   cell.ErrUnsupportedVersion,
	"quorum-not-met":        cell.ErrQuorumNotMet,
	"no-matching-key":       cell.ErrNoMatchingKey,
	"retention-expired":     cell.ErrLifetime,
	"timed-release-locked":  cell.ErrLifetime,
}

func TestConformanceOpenVectors(t *testing.T) {
	dir, m := loadManifest(t)
	for _, v := range m.Vectors {
		if v.Expect != "open" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			c := loadCell(t, dir, v)
			result, err := cell.Open(c, optionsFor(t, dir, v.OpenWith))
			if err != nil {
				t.Fatalf("%s should have opened: %v", v.ID, err)
			}

			if len(result.Data) != v.Plaintext.Size {
				t.Errorf("size = %d, want %d", len(result.Data), v.Plaintext.Size)
			}
			if got := hex.EncodeToString(hashOf(result.Data)); got != v.Plaintext.SHA256 {
				t.Errorf("plaintext sha256 = %s, want %s", got, v.Plaintext.SHA256)
			}
			expected, err := os.ReadFile(filepath.Join(dir, v.Plaintext.File))
			if err != nil {
				t.Fatalf("reading payload: %v", err)
			}
			if string(result.Data) != string(expected) {
				t.Errorf("plaintext differs from the committed payload file")
			}
			if result.Filename != v.Filename {
				t.Errorf("filename = %q, want %q", result.Filename, v.Filename)
			}
			if result.ContentType != v.ContentType {
				t.Errorf("content_type = %q, want %q", result.ContentType, v.ContentType)
			}
			if v.Meta != nil {
				got, err := cell.Canonicalize(result.Meta)
				if err != nil {
					t.Fatalf("canonicalizing meta: %v", err)
				}
				wantValue, err := cell.ParseValue(v.Meta)
				if err != nil {
					t.Fatalf("parsing expected meta: %v", err)
				}
				want, _ := cell.Canonicalize(wantValue)
				if got != want {
					t.Errorf("meta = %s, want %s", got, want)
				}
			}
			if v.Signer != "" {
				if !result.Signed {
					t.Errorf("expected a signed cell")
				}
				want := loadKey(t, dir, v.Signer).Fingerprint()
				if result.SignerFingerprint != want {
					t.Errorf("signer = %s, want %s", result.SignerFingerprint, want)
				}
			}

			for i, alt := range v.OpenWith.AlsoOpensWith {
				altResult, err := cell.Open(c, optionsFor(t, dir, alt))
				if err != nil {
					t.Errorf("also_opens_with[%d] failed: %v", i, err)
					continue
				}
				if string(altResult.Data) != string(result.Data) {
					t.Errorf("also_opens_with[%d] produced different plaintext", i)
				}
			}
		})
	}
}

func TestConformanceRejectVectors(t *testing.T) {
	dir, m := loadManifest(t)
	for _, v := range m.Vectors {
		if v.Expect != "reject" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			c := loadCell(t, dir, v)
			_, err := cell.Open(c, optionsFor(t, dir, v.OpenWith))
			if err == nil {
				t.Fatalf("%s opened but must be refused (%s)", v.ID, v.RejectReason)
			}
			want, ok := rejectErrors[v.RejectReason]
			if !ok {
				t.Fatalf("manifest names an unknown reject_reason %q", v.RejectReason)
			}
			if !errors.Is(err, want) {
				t.Errorf("refused with %v, expected %v", err, want)
			}
		})
	}
}

func TestConformanceMustNotOpenWith(t *testing.T) {
	dir, m := loadManifest(t)
	for _, v := range m.Vectors {
		if v.MustNotOpenWith == nil {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			c := loadCell(t, dir, v)
			if _, err := cell.Open(c, optionsFor(t, dir, *v.MustNotOpenWith)); err == nil {
				t.Fatalf("%s opened with key material that must not open it", v.ID)
			}
		})
	}
}

func TestConformanceCoverage(t *testing.T) {
	_, m := loadManifest(t)
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		seen[v.CellVersion] = true
	}
	// §12 requires 1.0-1.3 plus legacy v2.x to stay readable. A version with no
	// vector is a version nobody actually tests.
	for _, version := range []string{"1.0", "1.1", "1.2", "1.3", "2.0"} {
		if !seen[version] {
			t.Errorf("no vector covers version %s", version)
		}
	}
}

// TestAdvisoryGatesAreAdvisory documents §8.1 rather than merely testing it:
// the advisory half of lifetime is not enforced against a keyholder, and an
// opener written from the spec can disregard it. The vector still requires
// refusal by DEFAULT — that is the conformance claim — but an explicit override
// is not a violation.
func TestAdvisoryGatesAreAdvisory(t *testing.T) {
	dir, m := loadManifest(t)
	for _, v := range m.Vectors {
		if v.RejectReason != "retention-expired" {
			continue
		}
		c := loadCell(t, dir, v)
		opts := optionsFor(t, dir, v.OpenWith)
		opts.IgnoreAdvisory = true
		result, err := cell.Open(c, opts)
		if err != nil {
			t.Fatalf("%s should open with IgnoreAdvisory: %v", v.ID, err)
		}
		if len(result.Data) == 0 {
			t.Errorf("expected plaintext")
		}
	}
}

func hashOf(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
