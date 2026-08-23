# cellular-defense (Rust)

A Rust implementation of the Cellular Defense **`.cell`** encrypted document
format, written from [`docs/SPEC.md`](../../docs/SPEC.md) v1.3.

Apache-2.0, like the rest of `impl/` — see [`LICENSING.md`](../../LICENSING.md) §3.

```toml
[dependencies]
cellular-defense = { path = "impl/rust" }
```

Builds on Rust 1.85 (what Debian trixie packages). Dependencies are RustCrypto
plus `flate2` and `serde_json`.

## Library

```rust
use cellular_defense::cell::{create, open, CreateOptions, OpenOptions, Recipient};
use cellular_defense::keys::KeyRecord;

let alice = KeyRecord::generate("Alice");
let bob = KeyRecord::generate("Bob");

let sealed = create(
    b"quarterly numbers",
    "q3.txt",
    &[Recipient::for_key(&alice)?, Recipient::for_key(&bob)?],
    &CreateOptions {
        threshold: 2,                       // 2-of-2 Shamir quorum
        sender: Some(alice.clone()),        // adds an ECDSA header signature
        ..Default::default()
    },
)?;

let result = open(&sealed, &OpenOptions {
    keys: vec![alice.clone(), bob.clone()],
    expected_signer: Some(alice.fingerprint()?),  // authorship, against a known key
    ..Default::default()
})?;
assert_eq!(result.data, b"quarterly numbers");
```

`verify(&cell, None)` checks the audit chain with no key material at all.

Errors are a single enum with meaningful variants — `Integrity`, `Signature`,
`Decryption`, `NoMatchingKey`, `QuorumNotMet`, `Lifetime`, `UnsupportedVersion`,
`Malformed`, `Canonicalization`. The distinctions matter: "this cell was
tampered with" and "you gave me the wrong key" call for different responses.

## CLI

```bash
cargo build --release
./target/release/cdcell keygen --label Alice --out alice
./target/release/cdcell seal report.pdf --to alice.cdpub --sign alice.cdkey --out report.cell
./target/release/cdcell verify report.cell      # audit chain, no key required
./target/release/cdcell inspect report.cell     # what an observer of the cell can see
./target/release/cdcell open report.cell --key alice.cdkey --out ./
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
| Mitosis lineage (`prev_hash`) | ✅ via `CreateOptions::prev_hash` |

## Tests

```bash
cargo test --release
```

**Use `--release`.** PBKDF2 at 600,000 iterations in an unoptimized build turns
a 1-second suite into a 40-second one.

24 tests: the shared conformance vectors from [`conformance/`](../../conformance),
the 225 canonical-serialization vectors, a deterministic Shamir share vector
matching the Python and Go ports byte for byte, and the negative cases —
tampered AAD, recomputed `header_hash` over an edited header, version downgrade,
DER-encoded signature, short quorum, expired retention.

Interoperability verified in every direction: cells sealed here open in
`cell-crypto.js`, Python and Go with byte-identical plaintext and verified
signatures, and vice versa.

## Notes for the next port

**`serde_json` needs the `float_roundtrip` feature, and this is not optional.**
Its default float parser is a fast path that is *not correctly rounded*: it
lands one ULP away from the true value on a meaningful fraction of literals with
large exponents, where JavaScript and Rust's own `str::parse` are exact. The
result is a different `f64`, a different canonical string, a `header_hash` that
never matches, and nothing whatsoever to indicate why. The shared canonical
vectors caught this; without them it would have shipped.

**`preserve_order` is equally load-bearing.** v1.0 and v1.1 hash their header as
`JSON.stringify` wrote it, in insertion order (§12). A header parsed into a
sorted or hashed map can never be re-serialized to the bytes it was signed over.

**Rust's `Display` for `f64` never uses exponential form**, so it disagrees with
JavaScript at both ends of the range — `1e-7` prints as `0.0000001`.
`canonical::js_number` implements ECMA-262 6.1.6.1.20 instead. `{:e}` *does*
give shortest round-trip digits, which is the useful half of the decomposition.

**Key ordering is by UTF-16 code unit**, not Rust's byte-wise `Ord`. The two
disagree for any character above the BMP, which sorts *below* U+E000..U+FFFF in
JavaScript.

Two things that are *easier* here than elsewhere, worth knowing before you reach
for a workaround that isn't needed:

- **`aes-kw` exists as a crate**, so unlike Go nothing had to be written from
  RFC 3394.
- **`p256::ecdsa::Signature` is already the fixed 64-byte `r ‖ s` form** the
  format requires. The DER trap that §4.1 names the most likely point of failure
  outside a browser simply never arises — producing DER would take a deliberate
  `to_der()` call. Go, Java, OpenSSL and python-cryptography all default the
  other way.
