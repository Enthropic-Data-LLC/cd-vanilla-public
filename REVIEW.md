# Reviewing format v1.4

This is a request for review. The `.cell` format is published as a defensive
disclosure, so the specification is free for anyone to implement and criticise.
Version 1.4 is the newest and least examined revision. **It has not been
independently audited, and we have no budget for an audit.** If you know
applied cryptography, this is where we most want you to look.

## What changed in v1.4

Spec: [`docs/SPEC.md`](docs/SPEC.md) · tag `cell-format-v1.4-defensive-pub` ·
timestamp proofs in [`docs/defensive-pub/anchors/v1.4/`](docs/defensive-pub/anchors/v1.4).

| Mechanism | Spec | What it is |
|---|---|---|
| Blind access-map entries | §6 | No key fingerprint or label in the readable file; an opener finds its entry by **trial decryption**, relying on AES-KW's integrity check. Maps over 256 entries are refused before any key is tried. |
| Sender signature inside the ciphertext | §4.5 | ECDSA signature made before encryption, carried in the encrypted manifest; covers content, manifest, AAD, `doc_id`, `created_at`, and the sorted fingerprints of the intended ECDH recipients. |
| Padmé padding | §5.4 | The framed body is padded to a Padmé bucket with a 512-byte floor; padding must be all zero. |
| Argon2id passphrase method | §6.5 | RFC 9106, 64 MiB / 3 passes / 4 lanes by default, NFC-normalized passphrase, parameters bounded by the opener. Implemented in plain JavaScript in `cell-crypto.js` (the browser has no Argon2id). |
| Version in the AAD | §4.4 | `canonicalize({format, prev_hash, threshold, lifetime, policy})`, so relabelling a v1.4 cell as 1.3 fails the GCM tag. |

## What we most want attacked

1. **Trial decryption (§6).** Is "AES-KW rejects a wrong key with probability
   1 − 2⁻⁶⁴" the right argument? Any oracle, timing or key-confusion issue in
   trying every key against every entry? Is the 256-entry bound enough?
2. **The inner signature (§4.5).** Does the signed object cover enough? Is there
   a way to replay or re-bind a signature to a different cell, recipient set or
   manifest? Is the `to` list the right defence against re-encryption?
3. **Padmé framing and parsing (§5.4).** Length-frame and zero-padding checks;
   anything that makes a malformed body parse differently in two
   implementations.
4. **Argon2id in `cell-crypto.js`.** Hand-written Argon2id and BLAKE2b. We
   checked them against RFC 7693 / RFC 9106 vectors and the Argon2 reference
   implementation, but not beyond that. The refusal bounds in §6.5 (floor and
   ceiling) are also fair game.
5. **Version handling (§12).** Downgrade or relabelling paths that survive.

## Known gaps — please do not spend time rediscovering these

- No independent audit.
- The `yubikey-prf` entry's `credential_id` stays readable (the authenticator
  needs it), so cells addressed to the same security key are linkable.
- The entry count and each entry's method are readable; padding hides the size
  within a bucket, not the bucket.
- §4.1's envelope listing still shows `"version": "1.3"` and the three
  `header_sig*` fields. The sentence below it and the example in §15 are
  correct. It is left as anchored; fixing it changes the digest.
- The Go and Java ports now depend on `golang.org/x/crypto` + `x/text` and Bouncy
  Castle respectively (for Argon2id and NFC); Rust uses the `argon2` crate.

## Running everything

```bash
npm test                                                  # JS reference + 41 vectors
(cd impl/python && python3 -m unittest discover -s tests -t .)
(cd impl/go && go test ./...)
(cd impl/rust && cargo test --release)
(cd impl/java && mvn test)
python3 tools/interop-matrix.py                           # seal with each, open with every other
python3 tools/verify-cell.py conformance/vectors/open/v14-ecdh-signed.cell
```

The vectors are in [`conformance/vectors/`](conformance/vectors); `manifest.json`
says what each must do and why. The refusal vectors are the interesting ones.

## How to report

Open an issue on this repository, or email dbrown@enthropicdata.com. Findings
that affect the specification will be published as dated corrections, with the
mistake and the fix both visible, the way the changelog (§17) already does.
