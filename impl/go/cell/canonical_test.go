// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell"
)

// Canonical serialization is the highest-risk surface for a non-JavaScript
// port: an implementation that canonicalizes consistently but differently from
// the reference passes every self-test and verifies no real cell. These run the
// shared vectors, whose expected strings come from cell-crypto.js itself.

func TestCanonicalVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "conformance", "vectors", "canonical.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("canonical vectors not present: %v", err)
	}
	var file struct {
		Cases []struct {
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
			Expected string          `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parsing canonical vectors: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("canonical vector file is empty")
	}

	for _, c := range file.Cases {
		value, err := cell.ParseValue(c.Input)
		if err != nil {
			t.Errorf("%s: parsing input: %v", c.Name, err)
			continue
		}
		got, err := cell.Canonicalize(value)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if got != c.Expected {
			t.Errorf("%s:\n  got  %s\n  want %s", c.Name, got, c.Expected)
		}
	}
	t.Logf("checked %d canonical vectors against the reference", len(file.Cases))
}

func TestOrderPreservingParse(t *testing.T) {
	// v1.0/v1.1 hash their header as JSON.stringify wrote it, in insertion
	// order. A parser backed by a Go map could never reproduce those bytes.
	value, err := cell.ParseValue([]byte(`{"z":1,"a":2,"m":3}`))
	if err != nil {
		t.Fatal(err)
	}
	object := value.(*cell.Object)
	want := []string{"z", "a", "m"}
	for i, key := range object.Keys() {
		if key != want[i] {
			t.Fatalf("key order = %v, want %v", object.Keys(), want)
		}
	}
	canonical, _ := cell.Canonicalize(object)
	if canonical != `{"a":2,"m":3,"z":1}` {
		t.Errorf("canonical form did not sort: %s", canonical)
	}
}

func TestExplicitNullIsNotAnAbsentKey(t *testing.T) {
	// §6.4: share_index is omitted, not null, on non-quorum cells, and the two
	// forms hash differently. Both are internally valid.
	withNull, _ := cell.ParseValue([]byte(`{"share_index":null}`))
	without, _ := cell.ParseValue([]byte(`{}`))
	a, _ := cell.Canonicalize(withNull)
	b, _ := cell.Canonicalize(without)
	if a == b {
		t.Fatal("an explicit null must not canonicalize the same as an absent key")
	}
}

func TestTrailingDataIsRejected(t *testing.T) {
	if _, err := cell.ParseValue([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("expected trailing data to be refused")
	}
}
