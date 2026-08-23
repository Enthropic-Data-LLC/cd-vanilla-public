// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

// Command cdcell is a command-line opener, sealer and verifier for .cell files.
//
//	cdcell keygen  -label Alice -out alice
//	cdcell seal    report.pdf -to alice.cdpub -out report.cell
//	cdcell verify  report.cell
//	cdcell inspect report.cell
//	cdcell open    report.cell -key alice.cdkey -out ./
//
// verify and inspect need no key material at all: that a third party can
// confirm a cell has not been altered, and see exactly what it does and does
// not leak, without being able to read it, is the property the format rests on.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "seal":
		err = cmdSeal(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "open":
		err = cmdOpen(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cdcell — seal, open and verify .cell documents

  cdcell keygen  -label NAME -out STEM      generate a P-256 keypair
  cdcell seal    FILE -to PUB [-to PUB]...  encrypt into a .cell
  cdcell verify  CELL                       check the audit chain (no key needed)
  cdcell inspect CELL                       show what an observer can see
  cdcell open    CELL -key KEY -out PATH    decrypt

Run any subcommand with -h for its flags.
`)
}

// parseArgs parses flags that may appear before OR after positional arguments.
//
// Go's flag package stops at the first non-flag argument, so "seal FILE -to X"
// would silently ignore -to and report that the cell has no recipients. Users
// write the filename first because every other tool lets them, so interleave
// rather than making the error message their problem.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return positional, nil
}

// ─── keygen ─────────────────────────────────────────────────────────────────

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	label := fs.String("label", "My Key", "key label")
	out := fs.String("out", "", "output path stem (writes STEM.cdpub and STEM.cdkey)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}

	key, err := cell.GenerateKey(*label)
	if err != nil {
		return err
	}
	pubPath, keyPath := *out+".cdpub", *out+".cdkey"

	pubBytes, err := cell.MarshalCell(key.ToCDPub())
	if err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return err
	}
	keyDoc, err := key.ToCDKey()
	if err != nil {
		return err
	}
	keyBytes, err := cell.MarshalCell(keyDoc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		return err
	}

	fmt.Printf("fingerprint  %s\n", key.Fingerprint())
	fmt.Printf("public key   %s   (share this — it is how others encrypt to you)\n", pubPath)
	fmt.Printf("private key  %s   (never share; there is no recovery)\n", keyPath)
	return nil
}

// ─── seal ───────────────────────────────────────────────────────────────────

func cmdSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	var to stringList
	fs.Var(&to, "to", "recipient .cdpub (repeatable)")
	passphrase := fs.Bool("passphrase", false, "add a passphrase recipient")
	threshold := fs.Int("threshold", 1, "M in an M-of-N quorum")
	sign := fs.String("sign", "", ".cdkey to sign the header with")
	metaJSON := fs.String("meta", "", "sender-defined JSON carried inside the ciphertext")
	out := fs.String("out", "", "output path (.cell or .celz)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return errors.New("usage: cdcell seal FILE -to RECIPIENT.cdpub")
	}
	source := positional[0]

	var recipients []cell.Recipient
	for _, path := range to {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		record, err := cell.ParseCDPub(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		recipients = append(recipients, cell.KeyRecipient(record))
	}
	if *passphrase {
		entered, err := promptPassphrase("Passphrase for this cell: ")
		if err != nil {
			return err
		}
		repeat, err := promptPassphrase("Repeat: ")
		if err != nil {
			return err
		}
		if entered != repeat {
			return errors.New("passphrases do not match")
		}
		recipients = append(recipients, cell.PassphraseRecipient(entered, ""))
	}
	if len(recipients) == 0 {
		return errors.New("a cell needs at least one recipient (-to or -passphrase)")
	}

	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	opts := cell.CreateOptions{
		ContentType: contentTypeFor(source),
		Threshold:   *threshold,
	}
	if *metaJSON != "" {
		var meta any
		if err := json.Unmarshal([]byte(*metaJSON), &meta); err != nil {
			return fmt.Errorf("-meta is not valid JSON: %w", err)
		}
		opts.Meta = meta
	}
	if *sign != "" {
		keyBytes, err := os.ReadFile(*sign)
		if err != nil {
			return err
		}
		if opts.Sender, err = cell.ParseCDKey(keyBytes); err != nil {
			return err
		}
	}

	sealed, err := cell.Create(data, filepath.Base(source), recipients, opts)
	if err != nil {
		return err
	}
	destination := *out
	if destination == "" {
		destination = source + ".cell"
	}
	if err := writeCell(sealed, destination); err != nil {
		return err
	}
	th := sealed.GetObject("header").GetObject("threshold")
	count := len(sealed.GetObject("header").GetArray("access_map"))
	plural := "s"
	if count == 1 {
		plural = ""
	}
	fmt.Printf("sealed %s  (%d recipient%s, %d-of-%d)\n", destination, count, plural,
		th.GetInt("required", 1), th.GetInt("of_total", 1))
	return nil
}

// ─── verify ─────────────────────────────────────────────────────────────────

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	expect := fs.String("expect-signer", "", "fingerprint the cell must be signed by")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return errors.New("usage: cdcell verify CELL")
	}
	c, err := readCell(positional[0])
	if err != nil {
		return err
	}
	result, err := cell.Verify(c, *expect)
	if err != nil {
		return err
	}
	fmt.Printf("version        %s\n", result.Version)
	fmt.Printf("header_hash    ok\n")
	if result.PayloadHashOK {
		fmt.Printf("payload_hash   ok\n")
	} else {
		fmt.Printf("payload_hash   absent\n")
	}
	if result.Signed {
		fmt.Printf("signature      valid, by key %s\n", result.SignerFingerprint)
		fmt.Printf("               (claims to be %q — self-asserted, check the fingerprint\n", result.ClaimedSigner)
		fmt.Printf("               against a contact you already trust)\n")
	} else {
		fmt.Printf("signature      none present\n")
		fmt.Printf("               a signature can be stripped undetectably; absence proves nothing\n")
	}
	return nil
}

// ─── inspect ────────────────────────────────────────────────────────────────

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return errors.New("usage: cdcell inspect CELL")
	}
	c, err := readCell(positional[0])
	if err != nil {
		return err
	}
	header := c.GetObject("header")
	version := c.GetString("version")
	if version == "" {
		version = c.GetString("cd_version")
	}
	fmt.Printf("version      %s\n", version)
	fmt.Printf("doc_id       %s\n", c.GetString("doc_id"))
	fmt.Printf("created_at   %d\n", header.GetInt("created_at", c.GetInt("created_at", 0)))
	th := header.GetObject("threshold")
	fmt.Printf("threshold    %d-of-%d\n", th.GetInt("required", 1), th.GetInt("of_total", 1))

	if lt := cell.ReadLifetime(header.GetObject("lifetime")); lt != nil {
		fmt.Printf("lifetime     type=%s\n", lt.Type)
		fmt.Printf("  advisory   retain_until=%d release_at=%d single_use=%t minimum_atl=%d\n",
			lt.RetainUntil, lt.ReleaseAt, lt.SingleUse, lt.MinimumATL)
		fmt.Printf("             (advisory: honoured by conforming software, NOT enforced against a keyholder)\n")
		fmt.Printf("  disposal   at=%d action=%s\n", lt.DisposalAt, lt.DisposalAction)
		fmt.Printf("             (enforced by whoever stores the ciphertext)\n")
	}

	fmt.Println("access_map:")
	entries := header.GetArray("access_map")
	if entries == nil {
		entries = c.GetArray("recipients")
	}
	for _, entryValue := range entries {
		entry, ok := entryValue.(*cell.Object)
		if !ok {
			continue
		}
		line := fmt.Sprintf("  - %-12s %s  %q", entry.GetString("method"),
			entry.GetString("fingerprint"), entry.GetString("label"))
		if entry.Has("share_index") {
			line += fmt.Sprintf("  share %d", entry.GetInt("share_index", 0))
		}
		fmt.Println(line)
	}

	payload := c.GetObject("payload")
	if payload == nil {
		payload = c.GetObject("encrypted_body")
	}
	if payload != nil {
		ctB64 := payload.GetString("ciphertext")
		if ctB64 == "" {
			ctB64 = payload.GetString("ct")
		}
		if ct, err := cell.DecodeB64(ctB64, "ciphertext"); err == nil {
			fmt.Printf("ciphertext   %d bytes (%s)\n", len(ct), payload.GetString("alg"))
		}
	}
	fmt.Println("\nnot visible here: the plaintext, the filename, the media type, the original")
	fmt.Println("size, and any sender-defined meta — all of them live inside the ciphertext (§5).")
	return nil
}

// ─── open ───────────────────────────────────────────────────────────────────

func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	var keys stringList
	fs.Var(&keys, "key", ".cdkey to try (repeatable)")
	passphrase := fs.Bool("passphrase", false, "prompt for a passphrase")
	expect := fs.String("expect-signer", "", "fingerprint the cell must be signed by")
	ignoreAdvisory := fs.Bool("ignore-advisory", false,
		"skip the §8.1 advisory gates (they are advisory by specification)")
	out := fs.String("out", ".", "output file or directory")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return errors.New("usage: cdcell open CELL -key KEY.cdkey")
	}
	c, err := readCell(positional[0])
	if err != nil {
		return err
	}

	opts := cell.OpenOptions{ExpectedSigner: *expect, IgnoreAdvisory: *ignoreAdvisory}
	for _, path := range keys {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		record, err := cell.ParseCDKey(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		opts.Keys = append(opts.Keys, record)
	}
	if *passphrase {
		entered, err := promptPassphrase("Passphrase: ")
		if err != nil {
			return err
		}
		opts.Passphrases = append(opts.Passphrases, entered)
	}

	result, err := cell.Open(c, opts)
	if err != nil {
		return err
	}

	destination := *out
	// A trailing separator means "into this directory" even if it does not
	// exist yet; the filename is only known once the manifest is decrypted (§5),
	// so the caller cannot always name the output file in advance.
	if info, statErr := os.Stat(destination); (statErr == nil && info.IsDir()) || strings.HasSuffix(destination, string(os.PathSeparator)) {
		if err := os.MkdirAll(destination, 0o755); err != nil {
			return err
		}
		destination = filepath.Join(destination, filepath.Base(result.Filename))
	}
	if err := os.WriteFile(destination, result.Data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s  (%d bytes, %s)\n", destination, len(result.Data), result.ContentType)
	if result.Signed {
		fmt.Printf("signed by key %s\n", result.SignerFingerprint)
	}
	if result.Meta != nil {
		if encoded, err := cell.Canonicalize(result.Meta); err == nil {
			fmt.Printf("sender meta: %s\n", encoded)
		}
	}
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

// readCell reads a .cell or a gzip-compressed .celz (spec §3).
func readCell(path string) (*cell.Object, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		if raw, err = io.ReadAll(io.LimitReader(reader, cell.MaxDecompressed)); err != nil {
			return nil, err
		}
	}
	return cell.ParseCell(raw)
}

func writeCell(c *cell.Object, path string) error {
	encoded, err := cell.MarshalCell(c)
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".celz") {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(encoded); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
		encoded = buf.Bytes()
	}
	return os.WriteFile(path, encoded, 0o644)
}

func contentTypeFor(path string) string {
	if t := mime.TypeByExtension(filepath.Ext(path)); t != "" {
		return strings.SplitN(t, ";", 2)[0]
	}
	return "application/octet-stream"
}

func promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	// Echo suppression via stty rather than golang.org/x/term, deliberately.
	// The cell library is meant to be embedded and has no dependencies at all;
	// adding one to the module purely so a CLI can hide a passphrase would put
	// it in every consumer's module graph — and the version that does this bumps
	// the required Go release past what current distributions package.
	restore := func() {}
	if isTerminal(os.Stdin) {
		if err := exec.Command("stty", "-F", "/dev/tty", "-echo").Run(); err == nil {
			restore = func() {
				_ = exec.Command("stty", "-F", "/dev/tty", "echo").Run()
				fmt.Fprintln(os.Stderr)
			}
		}
	}
	defer restore()

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// isTerminal reports whether f is a character device, which is close enough:
// the only consequence of being wrong is that the passphrase echoes, or that a
// piped passphrase is read with echo suppression that has no effect.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
