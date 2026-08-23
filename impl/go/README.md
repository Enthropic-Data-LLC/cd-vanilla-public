# cell (Go)

A Go implementation of the Cellular Defense **`.cell`** encrypted document
format, written from [`docs/SPEC.md`](../../docs/SPEC.md) v1.3.

**No dependencies.** `go.mod` requires nothing, and the `cell` package imports
only the standard library. Go 1.24 moved HKDF and PBKDF2 into `crypto/`, which
left AES Key Wrap as the single primitive that needed writing — see
[`cell/aeskw.go`](cell/aeskw.go), checked against the RFC 3394 test vectors.

Apache-2.0, like the rest of `impl/` — see [`LICENSING.md`](../../LICENSING.md) §3.

```bash
go get github.com/Enthropic-Data-LLC/cd-vanilla-public/impl/go/cell
```

## Library

```go
alice, _ := cell.GenerateKey("Alice")
bob, _   := cell.GenerateKey("Bob")

sealed, _ := cell.Create([]byte("quarterly numbers"), "q3.txt",
    []cell.Recipient{cell.KeyRecipient(alice), cell.KeyRecipient(bob)},
    cell.CreateOptions{
        Threshold: 2,                        // 2-of-2 Shamir quorum
        Sender:    alice,                    // adds an ECDSA header signature
        Meta:      map[string]any{"case": "2026-0417"}, // inside the ciphertext
    })

_, err := cell.Verify(sealed, "")            // audit chain — no key material needed

result, _ := cell.Open(sealed, cell.OpenOptions{
    Keys:           []*cell.KeyRecord{alice, bob},
    ExpectedSigner: alice.Fingerprint(),     // authorship, checked against a known key
})
result.Data // []byte("quarterly numbers")
```

Errors are sentinel values, comparable with `errors.Is`: `ErrIntegrity`,
`ErrSignature`, `ErrDecryption`, `ErrNoMatchingKey`, `ErrQuorumNotMet`,
`ErrLifetime`, `ErrUnsupportedVersion`, `ErrMalformed`. The distinctions matter
— "this cell was tampered with" and "you gave me the wrong key" call for
different responses.

## CLI

```bash
go build -o cdcell ./cmd/cdcell

./cdcell keygen -label Alice -out alice
./cdcell seal report.pdf -to alice.cdpub -sign alice.cdkey -out report.cell
./cdcell verify report.cell          # audit chain, no key required
./cdcell inspect report.cell         # exactly what an observer of the cell can see
./cdcell open report.cell -key alice.cdkey -out ./
```

## What it implements

| Area | Status |
|---|---|
| Seal / open v1.3 | ✅ |
| Read v1.0, v1.1, v1.2 and legacy v2.x | ✅ version-gated per cell (§12) |
| ECDH P-256 → HKDF-SHA256 → AES-KW | ✅ |
| PBKDF2 (600k) access method | ✅ |
| WebAuthn PRF access method | ⚠️ unwrap only — the PRF output must come from a CTAP2 layer; browser-only in practice |
| Shamir M-of-N quorum over GF(256) | ✅ |
| Canonical serialization, AAD binding, ECDSA `header_sig` | ✅ |
| `.cell` / `.celz` / `.cdpub` / `.cdkey` | ✅ |
| Mitosis lineage (`prev_hash`) | ✅ via `CreateOptions.PrevHash` |

## Tests

```bash
go test ./...
```

Includes the shared conformance suite in [`conformance/`](../../conformance) —
27 cells covering every format version and the refusals — plus the 225 canonical
serialization vectors, the RFC 3394 AES-KW vectors, and a deterministic Shamir
share vector that matches the Python port's byte for byte.

Interoperability is verified in both directions against the reference
implementation and the Python port: cells sealed here open in
`cell-crypto.js` and in Python with byte-identical plaintext, signatures
verified, and 3-of-4 quorums reconstructed across implementations.

## Notes for the next port

Four things cost real time here, none of them exotic. They are the gap between
"the spec says JSON" and "the bytes agree".

**`encoding/json` is not a `JSON.stringify` workalike.** Canonical
serialization (§4.1.1) is defined by deferring to JavaScript, and Go's encoder
differs in three ways that all change the hash: it escapes `<`, `>` and `&` by
default for HTML safety, it escapes U+2028/U+2029 even with
`SetEscapeHTML(false)`, and `strconv.FormatFloat` with `'g'` prints `1e-07`
where JavaScript prints `1e-7`. `cell/canonical.go` does the escaping and the
number formatting by hand.

**Key order has to survive parsing.** v1.0 and v1.1 hash their header as
`JSON.stringify` wrote it — in insertion order, not sorted (§12). A header
parsed into a `map[string]any` can never be re-serialized to the bytes it was
signed over, so this package has an ordered `Object` type instead. Any language
whose default JSON parse is an unordered map needs the same.

**Integers must round like JavaScript's, not like yours.** JSON has no
integers, only float64. Parse numbers to float64 before formatting and the two
agree by construction, including above 2^53 where the shortest round-tripping
decimal is *shorter* than the exact value — `String(2**60)` is
`1152921504606847000`. A language with real integers that formats them exactly
will disagree with the reference on any such literal.

**AES-KW is yours to write.** RFC 3394, sixty lines, with published test
vectors. Python, Java and the browser all ship it; Go does not.

Everything else the standard library covers: `crypto/ecdh` for P-256 agreement,
`crypto/hkdf` and `crypto/pbkdf2` (Go 1.24+), `cipher.NewGCM` which appends the
tag exactly as WebCrypto does, and `ecdsa.Sign` returning `r, s` as `*big.Int`
— which is P1363 already, so the DER trap of §4.1 never arises unless you reach
for `SignASN1`.
