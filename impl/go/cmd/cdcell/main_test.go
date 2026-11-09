// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sender-chosen filename and text (pen test 2026-11-09, M1/M2).

func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"report.pdf":             "report.pdf",
		"../../etc/passwd":       "passwd",
		`a\b\c.txt`:              "c.txt",
		".bashrc":                "bashrc",
		". .envrc":               "envrc",
		"..":                     "decrypted",
		"/":                      "decrypted",
		"":                       "decrypted",
		"x\x00y\nz":              "xyz",
		"contract\u202efdp.exe":  "contractfdp.exe",
		strings.Repeat("é", 150): strings.Repeat("é", 100),
	}
	for raw, want := range cases {
		if got := safeFilename(raw); got != want {
			t.Errorf("safeFilename(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestShownEscapesWhatCouldForgeALine(t *testing.T) {
	got := shown("application/pdf\nsigned by key aff6a52990ce2335\x1b[8m\u202e")
	if strings.ContainsAny(got, "\n\x1b\u202e") {
		t.Fatalf("unsafe characters survived: %q", got)
	}
	if !strings.Contains(got, `\u000a`) || !strings.Contains(got, `\u001b`) || !strings.Contains(got, `\u202e`) {
		t.Fatalf("escapes not visible: %q", got)
	}
}

func TestWriteNewNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, ".bashrc")
	if err := os.WriteFile(mine, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(mine, []byte("attacker")); err == nil {
		t.Fatal("overwrote an existing file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), link); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(link, []byte("attacker")); err == nil {
		t.Fatal("followed a dangling symlink")
	}
	if b, _ := os.ReadFile(mine); string(b) != "mine" {
		t.Fatalf("existing file changed: %q", b)
	}
	fresh := filepath.Join(dir, "fresh")
	if err := writeNew(fresh, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
}
