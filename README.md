# Cell Format — cd-vanilla

Browser-native zero-knowledge encrypted document format. Single HTML file, no dependencies, no server round-trips for crypto.

## What it does

Encrypts any file into a self-contained `.cell` or `.celz` envelope. Recipients decrypt in their browser using a key from their keychain, a passphrase, or a YubiKey. The server (if any) stores only ciphertext — it cannot read the file, the filename, the MIME type, or the file size.

## Quick start

Serve over HTTPS or localhost (WebCrypto requires a secure context):

```bash
python3 -m http.server 8080
# open http://localhost:8080/index.html
```

Or open `index.html` directly in Chrome/Edge (file:// works for WebCrypto in most builds).

## Key features

| Feature | Detail |
|---------|--------|
| Encryption | AES-256-GCM, 256-bit CEK, 96-bit random IV |
| Key wrapping | ECDH P-256 + HKDF-SHA256 + AES-KW (per recipient) |
| Passphrase | Argon2id (64 MiB, 3 passes, 4 lanes; v1.4) — PBKDF2-SHA256, 600K iterations still accepted |
| YubiKey | FIDO2 PRF extension (YubiKey 5 series, HTTPS only) |
| Quorum | M-of-N Shamir Secret Sharing over GF(256) |
| Metadata | Filename, type, size, and optional sender `meta` encrypted inside payload |
| Tamper detection | SHA-256 `payload_hash` + `header_hash` audit chain |
| Authenticity | Optional ECDSA P-256 sender signature — inside the encrypted manifest from v1.4 (over the header up to v1.3) |
| Privacy (v1.4) | Blind access-map entries found by trial decryption; Padmé-padded body; format version authenticated in the AAD |
| Lineage | `prev_hash` chain for Mitosis (re-encrypt / key rotation) |
| Lifetime | 6 types, split by enforcer: `advisory` (not enforced on a keyholder) + `disposal` (operator-side, enforced) |
| Policy | copy_protection, watermark_mode, origin |
| Format | `.cell` (JSON) or `.celz` (gzip'd JSON) · all binary fields **standard base64** |
| Doc ID | ULID — lexicographically sortable by creation time |

## File layout

```
index.html          — the application shell (HTML + CSS + UI JS, no build step)
cell-crypto.js      — the crypto/format library, loaded by index.html
docs/SPEC.md        — format specification v1.4 (normative)
docs/defensive-pub/anchors/      — the anchored v1.2, v1.3 and v1.4 bytes + Bitcoin timestamp proofs
REVIEW.md           — what v1.4 changed and what we most want attacked
tests/test.html     — browser test suite (loads the library in a page)
tests/run.mjs       — headless runner for the same tests: npm test
tools/verify-cell.py — independent verifier, written from SPEC.md, no project code

impl/python/        — second implementation, in Python (Apache-2.0, pip-installable)
impl/go/            — third implementation, in Go (Apache-2.0, x/crypto + x/text)
impl/rust/          — fourth implementation, in Rust (Apache-2.0, RustCrypto)
impl/java/          — fifth implementation, in Java (Apache-2.0, Bouncy Castle for Argon2id)
conformance/        — shared test keys and .cell vectors for ANY implementation
```

`cell-crypto.js` at the root **is** the JavaScript implementation; `impl/` holds
the ports of it. Those and `conformance/` are permissively licensed on purpose —
see [`LICENSING.md`](LICENSING.md) §3. A format is only freely implementable if
the means of checking your implementation is freely usable too.

[`impl/README.md`](impl/README.md) compares the five side by side, and each
language README carries worked **encrypt** and **decrypt** examples.

## Running tests

```bash
# serve from project root
python3 -m http.server 8080 --bind 0.0.0.0

# open in browser
http://localhost:8080/tests/test.html
```

### The Python and Go implementations, and the conformance suite

```bash
cd impl/python && python3 -m unittest discover -s tests -t .    # 123 tests
cd impl/go     && go test ./...                                 # needs Go 1.24+
cd impl/rust   && cargo test --release                          # needs Rust 1.85+
cd impl/java   && mvn test                                      # needs JDK 17+
```

Three things run there, and the middle one is the reason the directory exists:

- the Python library's own tests, including the negative cases;
- **differential tests against `cell-crypto.js`** — cells sealed in JavaScript
  are opened in Python and vice versa, and the canonical bytes both
  implementations hash are compared across 200 randomly generated JSON
  structures. An implementation can be entirely self-consistent and interoperate
  with nothing; only cells that cross the boundary prove otherwise;
- the shared vectors in `conformance/` — 41 cells covering every format version
  including the superseded ones, the file-carryable access methods (ECDH,
  PBKDF2, Argon2id), and the refusals: tampered AAD, recomputed `header_hash`
  over an edited header, version downgrade and v1.4 relabelling, DER-encoded
  signature, a header signature on a v1.4 cell, bad padding, an over-large
  access map, a weak Argon2id entry, short quorum, expired retention; plus 225
  canonical-serialization vectors taken from `cell-crypto.js` itself.

All five implementations agree on all of them, and cells cross between them in
every direction (`python3 tools/interop-matrix.py` seals with each and opens with
every other). Node is needed only for the differential tests, which skip
cleanly without it.

Tests run in-browser. WebCrypto requires `localhost` or HTTPS — plain IP addresses will fail. YubiKey tests are skipped (hardware required, test manually).

Or headless, which is what CI and the figure tooling use:

```bash
npm test          # 65/65, 2 hardware-skipped, plus the 41 conformance vectors
```

## Format specification

Full spec: [`docs/SPEC.md`](docs/SPEC.md) — **v1.4**, and normative. **Not independently audited** — see [`REVIEW.md`](REVIEW.md). The format is a
defensive disclosure: implement it freely, no licence needed ([`LICENSING.md`](LICENSING.md)).
The reference *code* is AGPL-3.0.

Verify a cell against the spec without trusting this code:

```bash
python3 tools/verify-cell.py docs/figure-data/*.cell
```

Brief summary of the encrypted payload structure:

```
AES-256-GCM ciphertext
  └─ gzip(
       [4-byte LE uint32 manifest length]
       [manifest JSON: {filename, content_type, size}]
       [original file bytes]
     )
```

Header audit chain:

```
payload_hash = SHA-256(raw ciphertext bytes)   ← inside header
header_hash  = SHA-256(JSON.stringify(header)) ← top-level field
header_sig   = ECDSA-P256(header JSON bytes)   ← optional, top-level (v1.0–1.3 only)
```

From v1.4 the sender signature lives inside the encrypted manifest instead (spec §4.5).

## Key formats

```
.cdpub   — public key  (share with anyone to receive encrypted cells)
.cdkey   — private key (keep secure, use on another device)
```

## Browser support

Requires CompressionStream, WebCrypto, IndexedDB. Chrome 80+, Firefox 113+, Safari 16.4+. YubiKey PRF requires Chrome/Chromium + HTTPS.

---

*Enthropic Data LLC · enthropicdata.com*
