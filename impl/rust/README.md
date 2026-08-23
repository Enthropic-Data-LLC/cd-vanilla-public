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

## Encrypt

```rust
use cellular_defense::cell::{create, CreateOptions, Recipient};
use cellular_defense::keys::KeyRecord;
use serde_json::Value;
use std::fs;

// The recipient's public key. They generated it with `cdcell keygen` and sent
// you the .cdpub; you never see their private key.
let pub_doc: Value = serde_json::from_slice(&fs::read("alice.cdpub")?)?;
let alice = KeyRecord::from_cdpub(&pub_doc)?;

// Your own key, used to sign the header so Alice can confirm you sealed it.
let key_doc: Value = serde_json::from_slice(&fs::read("me.cdkey")?)?;
let me = KeyRecord::from_cdkey(&key_doc)?;

let sealed = create(
    &fs::read("q3-results.pdf")?,
    "q3-results.pdf",
    &[Recipient::for_key(&alice)?],
    &CreateOptions {
        content_type: Some("application/pdf".into()),
        sender: Some(me),                                  // optional signature
        meta: Some(serde_json::json!({"case": "2026-0417"})), // INSIDE the ciphertext
        ..Default::default()
    },
)?;

fs::write("q3-results.cell", serde_json::to_string_pretty(&sealed)?)?;
```

The filename, media type, size and `meta` are all encrypted: an observer of the
stored cell sees none of them (§5).

**Several recipients, any one of whom can open it:**

```rust
let recipients = [
    Recipient::for_key(&alice)?,
    Recipient::for_key(&bob)?,
    Recipient::passphrase("break glass in emergency", ""),
];
let sealed = create(&data, "q3-results.pdf", &recipients, &CreateOptions::default())?;
```

**A quorum — two of the three together, and no fewer:**

```rust
let sealed = create(&data, "q3-results.pdf", &recipients,
    &CreateOptions { threshold: 2, ..Default::default() })?;  // Shamir, §7
```

## Decrypt

```rust
use cellular_defense::cell::{open, OpenOptions};

let key_doc: Value = serde_json::from_slice(&fs::read("me.cdkey")?)?;
let me = KeyRecord::from_cdkey(&key_doc)?;
let sealed: Value = serde_json::from_slice(&fs::read("q3-results.cell")?)?;

let result = open(&sealed, &OpenOptions {
    keys: vec![me],
    // Optional but recommended: a fingerprint you learned out of band. Without
    // it, "opened without error" is NOT evidence of who sealed the cell — a
    // signature can be stripped undetectably (§4.1).
    expected_signer: Some("aff6a52990ce2335".into()),
    ..Default::default()
})?;

fs::write(&result.filename, &result.data)?;
println!("{} {} {:?}", result.filename, result.content_type, result.meta);
println!("signed by {:?}", result.signer_fingerprint);
```

Set `passphrases` for a passphrase entry, and pass several keys at once for a
quorum — `open` collects shares until it has enough.

**Handling failure**, which is most of what an opener does:

```rust
use cellular_defense::error::Error;

match open(&sealed, &opts) {
    Ok(result) => { /* ... */ }
    Err(Error::Integrity(_))  => {} // header_hash/payload_hash mismatch — altered
    Err(Error::Signature(_))  => {} // signature invalid, or not the expected signer
    Err(Error::Decryption)    => {} // GCM tag failed — ciphertext or AAD tampered
    Err(Error::QuorumNotMet { needed, unlocked }) => {} // not enough shares
    Err(Error::NoMatchingKey) => {} // nothing supplied fits any access-map entry
    Err(Error::Lifetime(_))   => {} // advisory gate: expired, or still locked
    Err(e) => return Err(e.into()),
}
```

## Verify without any key

```rust
use cellular_defense::cell::verify;

let report = verify(&sealed, None)?;      // Err on tampering
println!("{} {:?}", report.signed, report.signer_fingerprint);
```

Any third party can confirm a cell has not been altered since it was sealed —
without being able to read it. That is the property the whole format rests on.

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
  `to_der()` call. Elsewhere it is either the default (OpenSSL,
  python-cryptography, Java's plain `SHA256withECDSA`) or one keystroke away:
  Go's `ecdsa.Sign` gives `r, s` directly, but `ecdsa.SignASN1` sits right next
  to it and gives DER.
