# Cellular Defense — Cell Format Specification v1.3

**Enthropic Data LLC · enthropicdata.com · Weddington, NC**  
*Published as a defensive disclosure — freely implementable; no patent asserted.*

> **Licensing.** This specification is **not** covered by the AGPL in
> [`LICENSE`](../LICENSE), which applies to the source code in this repository.
> The format and every mechanism described here may be implemented by anyone,
> for any purpose including commercial, without licence, royalty, or permission.
> An independent implementation written from this document owes nothing to
> Enthropic Data. See [`LICENSING.md`](../LICENSING.md).

> **Since v1.3:** `lifetime` is **split by enforcer** (§8) — `advisory`, which
> conforming clients honour but which is *not* enforced against a keyholder, and
> `disposal`, which the storing operator performs and which *is*. `expires_at` is
> renamed `retain_until`, because the old name asserted a wall the mechanism
> never built.
>
> **Since v1.1/v1.2:** the advisory header metadata (threshold, lifetime, policy,
> lineage) is cryptographically bound to the ciphertext as AES-GCM *additional
> authenticated data* (§4.4), and all integrity hashes and signatures are
> computed over a **canonical JSON** serialization (§4.1.1) so that re-formatting
> the file (key order, whitespace) no longer breaks verification.
>
> Earlier `1.0`/`1.1`/`1.2` cells remain openable unchanged (§12).

---

## 1. Overview

Cellular Defense (CD) is a browser-native, zero-knowledge encrypted document platform. Documents are encrypted entirely within the sender's browser before leaving the device. The server stores only opaque ciphertext it cannot read under any circumstances. Recipients decrypt entirely within their own browser.

This document specifies the `.cell` file format, the cryptographic primitives, the access control architecture, and the security properties that can be independently verified. It is intended for security researchers, third-party implementers, and technical evaluators.

All cryptographic operations use the browser's **Web Crypto API** (W3C standard). No third-party cryptographic libraries are used.

---

## 2. Zero-Knowledge Architecture

Every `.cell` document is protected by two independent cryptographic layers.

| Layer | What It Protects | Algorithm | What an observer sees |
|-------|-----------------|-----------|----------------------|
| 1 | Document content | AES-256-GCM | Ciphertext only |
| 2 | Content Encryption Key (CEK) | ECDH P-256 + HKDF + AES-KW | Wrapped CEK only |

### 2.1 What the server/observer never holds

- ✗ Plaintext document content
- ✗ The Content Encryption Key (CEK)
- ✗ Any recipient private key
- ✗ Filename, MIME type, or file size
- ✗ Any key material sufficient to reconstruct a private key

### 2.2 What a `.cell` file exposes in plaintext

- ✓ Format version and document ID
- ✓ Cell creation timestamp
- ✓ Encrypted CEK shares (useless without the recipient's private key)
- ✓ Recipient method, label, and key fingerprint (public metadata only)
- ✓ Lifetime and policy settings
- ✓ Header hash and optional sender signature

---

## 3. File Formats

| Extension | Description |
|-----------|-------------|
| `.cell` | Plain JSON — human-readable, inspectable in any text editor |
| `.celz` | gzip-compressed `.cell` — same structure, ~30% smaller, binary |
| `.cdpub` | Public key export — share with others to receive encrypted cells |
| `.cdkey` | Full key export (private + public) — use on another device; store securely |

`.celz` files are produced by gzip-compressing the UTF-8 encoded JSON of the `.cell` document. The decompressed content is identical to the `.cell` format.

---

## 4. Cell Envelope — JSON Structure

### 4.0 Binary field encoding

Every binary field in a `.cell` — `iv`, `ciphertext`, `eph_spki`, `hkdf_salt`, `ct`, `salt`, `credential_id`, `prf_salt`, `spki`, `pkcs8`, `prev_hash`, `payload_hash`, `header_hash`, `header_sig`, `header_sig_key` — is **standard base64** (RFC 4648 §4): the `A–Z a–z 0–9 + /` alphabet, with `=` padding.

It is **not** base64url. There are no `-` or `_` characters and padding is not stripped. The reference implementation uses the browser's `btoa()`/`atob()`, and `atob()` raises `InvalidCharacterError` on a `-` or `_`, so a base64url-encoded cell is not merely non-canonical — it fails to parse.

> **Erratum.** Specification versions up to and including the anchored v1.2 text described these fields as "base64url" throughout. That was an error in the document, not in the format: no implementation has ever emitted base64url, and cells produced from 2026-06-08 onward are all standard base64. Corrected in v1.3. Implementers working from the anchored v1.2 text (`docs/defensive-pub/anchors/SPEC.md`) should read "base64url" as "base64" wherever it appears.

Decoders SHOULD accept the base64url alphabet on input for robustness. Encoders MUST emit standard base64.

### 4.1 Top-level fields

```json
{
  "version":    "1.3",
  "doc_id":     "<ULID>",
  "created_at": <unix timestamp — seconds since epoch>,
  "header":     { ... },
  "header_hash":    "<base64 SHA-256 of canonical header serialization>",
  "header_sig":     "<base64 ECDSA-SHA256 signature> | null",
  "header_sig_by":  "<self-asserted fingerprint label of signing key> | null",
  "header_sig_key": "<base64 SPKI of signing public key> | null",
  "payload":    { ... }
}
```

**`doc_id`** — ULID (Universally Unique Lexicographically Sortable Identifier). 26 characters, Crockford base32. First 10 characters encode 48-bit millisecond timestamp; last 16 characters are 80-bit cryptographic random. Lexicographically sortable by creation time.

**`header_hash`** — SHA-256 of the header serialization (§4.1.1). For v1.2 and v1.3 this is the **canonical** form; for v1.0/v1.1 it is `JSON.stringify(header)`. **Mandatory on every non-legacy cell**, and verified on open before any key material is touched (§10). An opener MUST reject a cell whose `header_hash` is absent rather than treat absence as licence to skip the check — otherwise deleting one field disables the header, ciphertext, and signature checks together. Note that `header_hash` is an **unkeyed** hash: it detects accidental corruption and benign re-formatting differences, but an attacker who edits the header can recompute it. Authenticity of the header against tampering comes from `header_sig` (sender identity) and the AES-GCM AAD binding (§4.4), not from `header_hash` alone.

**`header_sig`** — Optional ECDSA P-256 signature over the same header serialization bytes used for `header_hash` (§4.1.1). Provides sender authenticity. The signing key is the sender's ECDH P-256 key re-imported with ECDSA usage (same P-256 scalar, different algorithm label). If null, the cell is unsigned.

> **Signature encoding.** `header_sig` is the **raw 64-byte `r ‖ s` concatenation** (IEEE P1363 / the Web Crypto `ECDSA` output format), base64-encoded — **not** the DER `SEQUENCE { r, s }` that OpenSSL, Java, Go, and most general-purpose libraries produce and expect by default. An implementer using such a library must convert between the two forms. This is the single most likely point of failure when verifying a `.cell` outside a browser.

> **Signature absence is not detectable.** An attacker can delete `header_sig`, `header_sig_key`, and `header_sig_by` from a signed cell; the result is byte-indistinguishable from a cell that was never signed, because the signature is produced *after* the AAD is fixed and so nothing binds its presence. A verifier that requires an authenticated sender MUST compare the verified signing-key fingerprint against an expected value obtained out of band, and MUST NOT treat "opened without error" as evidence of authorship.

> **Trust note.** A valid `header_sig` only proves the holder of the private key matching `header_sig_key` produced it. `header_sig_by` is a self-asserted label and MUST NOT be trusted on its own. A verifier should anchor trust to the real fingerprint of `header_sig_key` (`SHA-256(SPKI)[:16]`) and resolve it against its own known keys/contacts before attributing identity.

### 4.1.1 Canonical serialization (v1.2+)

For v1.2 and v1.3, `header_hash`, `header_sig`, and the AAD (§4.4) are computed over a **deterministic** serialization so that re-ordering object keys or pretty-printing the JSON does not change the bytes (and therefore does not produce a false "tampered/forged" failure). The canonicalization is:

```
canonicalize(v):
  if v is null or not an object:   return JSON.stringify(v)
  if v is an array:                return "[" + join(",", canonicalize(e==undefined ? null : e) for e in v) + "]"
  otherwise (object):
     keys = sort(keys of v where v[k] != undefined)      // lexicographic
     return "{" + join(",", JSON.stringify(k) + ":" + canonicalize(v[k]) for k in keys) + "}"
```

This mirrors `JSON.stringify`'s primitive encoding and string escaping; the only differences are recursively sorted keys and no insignificant whitespace. v1.0/v1.1 cells continue to be verified with their original `JSON.stringify` serialization for backward compatibility (§12).

Deferring to `JSON.stringify` is exact but not self-contained, and the four rules it silently imports are where independent implementations diverge. They are stated here normatively, because each of them changes the hashed bytes and none of them is the default behaviour of a general-purpose JSON encoder outside JavaScript.

**Numbers.** JSON has no integer type: every number is an IEEE-754 binary64. A serializer MUST convert a value to binary64 *before* formatting it, and MUST then format it exactly as ECMA-262 6.1.6.1.20 (`Number::toString`, radix 10) specifies — the shortest decimal string that round-trips to the same binary64, with no trailing `.0`, positional form when the decimal exponent `n` satisfies `-6 < n ≤ 21` and exponential form otherwise, an explicit `+` on a non-negative exponent, and `-0` written as `0`. `NaN` and the infinities cannot appear, JSON having no literals for them.

| Value | Canonical form | A common wrong answer |
|-------|----------------|-----------------------|
| `1.0` | `1` | `1.0` |
| `-0` | `0` | `-0` |
| `1e20` | `100000000000000000000` | `1e+20`, `1.0E20` |
| `1e21` | `1e+21` | `1000000000000000000000` |
| `1e-6` | `0.000001` | `1e-06` |
| `1e-7` | `1e-7` | `1e-07`, `0.0000001` |
| `5e-324` | `5e-324` | `4.9e-324` |
| `9007199254740993` | `9007199254740992` | `9007199254740993` |

The last row is the rule's practical edge: a language with arbitrary-precision integers must round the literal through binary64 and emit the rounded value, because that is what a JavaScript reader will do with the same bytes. Emitting the exact integer produces a serialization no conforming reader can reproduce.

**Key ordering.** Keys sort by **UTF-16 code unit**, which is what `Array.prototype.sort` gives JavaScript — not by Unicode code point, and not by UTF-8 byte. The three orders agree throughout the Basic Multilingual Plane and disagree above it: a character outside the BMP is a surrogate pair in UTF-16 (`U+D800`–`U+DFFF`) and therefore sorts **below** `U+E000`–`U+FFFF`, where code-point and UTF-8 orders both place it above.

**String escaping.** Escape exactly six characters plus the remaining C0 controls: `"` as `\"`, `\` as `\\`, `U+0008` as `\b`, `U+0009` as `\t`, `U+000A` as `\n`, `U+000C` as `\f`, `U+000D` as `\r`, and every other code point below `U+0020` as `\u00xx` with lowercase hex. Everything from `U+0020` upward is emitted literally as UTF-8 — **including `/`, `<`, `>`, `&`, `U+2028` and `U+2029`**. Escaping any of those is a common default: Go's `encoding/json` escapes `<`, `>`, `&` for HTML safety and `U+2028`/`U+2029` even with HTML escaping disabled, and several encoders escape `/`. Every such escape changes the bytes and therefore the hash.

**Key order must survive parsing — v1.0/v1.1 only.** Because those versions serialize the header in its original insertion order (§12), an implementation whose JSON parser stores objects in an unordered or re-sorted map cannot reconstruct the bytes such a cell was signed over, and cannot verify it at all. Verifying v1.0/v1.1 therefore requires an order-preserving parse. v1.2+ sorts the keys itself and has no such requirement.

> **Conformance vectors.** `conformance/vectors/canonical.json` carries input/expected pairs for all of the above, generated from the reference implementation. They need no cryptography and fail loudly, which makes them the cheapest first test for a new implementation: a canonicalization that disagrees produces a `header_hash` that never matches, with nothing in the failure to indicate why.

### 4.2 Header

```json
"header": {
  "prev_hash":  "<base64 header_hash of predecessor cell> | null",
  "threshold":  { "required": <M>, "of_total": <N> },
  "lifetime":   { ... },
  "policy":     { ... },
  "access_map": [ ... ],
  "payload_hash": "<base64 SHA-256 of raw ciphertext bytes>"
}
```

**`prev_hash`** — Links this cell to a predecessor in a Mitosis chain (see §9). Null for original cells.

**`payload_hash`** — SHA-256 of the raw base64-decoded ciphertext bytes. Committed inside the header so it is covered by `header_hash` and `header_sig`. If the ciphertext is modified after sealing, this check fails on open.

**`threshold`** — Quorum requirement. `required` is M; `of_total` is N. For non-quorum cells: `required = 1`. See §6 for Shamir Secret Sharing.

### 4.3 Payload

```json
"payload": {
  "alg":      "AES-256-GCM",
  "encoding": "base64+gzip",
  "iv":       "<base64 12-byte IV>",
  "ciphertext": "<base64 — AES-256-GCM encrypted content>"
}
```

The ciphertext contains a manifest-prefixed gzip stream (see §5). The AES-GCM authentication tag is appended to the ciphertext by WebCrypto and verified automatically on decryption.

### 4.4 Additional Authenticated Data (AAD) — v1.1+

The advisory metadata that is fixed *before* encryption — `prev_hash`, `threshold`, `lifetime`, `policy` — is bound to the ciphertext as AES-GCM **additional authenticated data**. AES-GCM authenticates AAD without encrypting it: the recipient supplies the same AAD at decrypt time, and any mismatch fails the authentication tag.

**AAD construction:**

```
meta = [ header.prev_hash, header.threshold, header.lifetime, header.policy ]   // array, fixed order
AAD  = UTF-8 bytes of:
         canonicalize(meta)        for v1.2 and v1.3
         JSON.stringify(meta)      for v1.1
```

`access_map` and `payload_hash` are **not** in the AAD because they do not exist yet when the body is encrypted (the access map wraps the freshly generated CEK; `payload_hash` is derived from the resulting ciphertext). They are instead covered by `header_hash`/`header_sig`.

**Properties:**

- **Not strippable.** The recipient's decrypt always supplies the current header's metadata as AAD; there is no separate field an attacker can remove to disable the check.
- **Not downgradeable.** Decrypting a v1.2 cell *without* the AAD (e.g. by editing `version` to `1.0`) also fails the tag, since the ciphertext was produced *with* the AAD. An attacker cannot re-encrypt without the CEK.
- This binds metadata against third-party/storage/transit tampering. It does not (and cannot) prevent a legitimate recipient — who necessarily recovers the CEK — from ignoring `lifetime`/`policy`; those remain advisory toward authorized holders (§8, §9).

Cells without a `version` (legacy v2.x) and v1.0 cells carry no AAD; they decrypt with empty AAD.

---

## 5. Encrypted Payload Structure

The plaintext fed into AES-256-GCM is:

```
[ 4 bytes LE uint32 — manifest length ][ manifest JSON bytes ][ file bytes ]
```

This entire concatenation is gzip-compressed and then encrypted. The server and any observer see only ciphertext — filename, MIME type, and file size are invisible.

### 5.1 Manifest JSON

```json
{
  "filename":     "document.pdf",
  "content_type": "application/pdf",
  "size":         284921,
  "meta":         { "note": "Q3 escrow docs — call before opening", "case": "2026-0417" }
}
```

The manifest is recovered after successful decryption by reading the 4-byte length prefix, parsing that many bytes as UTF-8 JSON, then taking the remaining bytes as the file content.

`meta` (added 2026-07-18) is an **optional, sender-defined JSON object** carried inside the ciphertext — a note to the recipient, a case number, reply instructions, or any application-defined structure. Because it lives inside the encrypted manifest, it enjoys the same confidentiality and integrity as the file content: the server and any observer never see it, and tampering fails GCM authentication. Readers that predate this field ignore it; it requires no format-version bump.

### 5.2 Encoding stack (encrypt path)

```
original file bytes
  → prepend [4-byte manifest len][manifest JSON]
  → gzip compress entire buffer
  → AES-256-GCM encrypt with random 96-bit IV and 256-bit CEK
  → base64 encode
  → stored in payload.ciphertext
```

### 5.3 Decoding stack (decrypt path)

```
payload.ciphertext
  → base64 decode
  → AES-256-GCM decrypt (CEK + IV) — auth tag verified automatically
  → gzip decompress
  → read 4-byte LE length prefix
  → parse manifest JSON (that many bytes)
  → remaining bytes = original file content
```

---

## 6. Access Map

Each entry in `header.access_map` holds a wrapped copy of the CEK (or a Shamir share of the CEK for quorum cells) for one recipient.

### 6.1 ECDH P-256 entry

```json
{
  "method":      "ecdh-p256",
  "label":       "Alice",
  "fingerprint": "<16 hex chars — first 8 bytes of SHA-256(SPKI)>",
  "share_index": <integer 1..N> | null,
  "wrapped_cek": {
    "eph_spki":  "<base64 — ephemeral sender public key, SPKI format>",
    "hkdf_salt": "<base64 — 32 random bytes>",
    "ct":        "<base64 — AES-KW wrapped CEK or CEK share>"
  }
}
```

**CEK wrapping (per recipient):**

```
ephemeral_keypair   = ECDH P-256 (generated fresh per recipient)
shared_bits         = ECDH(ephemeral_privkey, recipient_pubkey)   → 256 bits
hkdf_salt           = 32 random bytes
hkdf_key            = HKDF-SHA256(shared_bits, salt, info="cellular-defense-cek-wrap-v1", 256 bits)
wrapped_cek         = AES-KW(cek_or_share, hkdf_key)
```

**CEK unwrapping (recipient):**

```
shared_bits         = ECDH(recipient_privkey, eph_spki)
hkdf_key            = HKDF-SHA256(shared_bits, hkdf_salt, info="cellular-defense-cek-wrap-v1", 256 bits)
cek_or_share        = AES-KW-unwrap(ct, hkdf_key)
```

### 6.2 PBKDF2 (passphrase) entry

```json
{
  "method":      "pbkdf2",
  "label":       "My passphrase",
  "fingerprint": "<16 hex chars — SHA-256 of PBKDF2 salt>",
  "share_index": <integer> | null,
  "wrapped_cek": {
    "salt":       "<base64 — 32 random bytes>",
    "iterations": 600000,
    "ct":         "<base64 — AES-KW wrapped CEK or CEK share>"
  }
}
```

**Key derivation:**

```
base_key   = PBKDF2-SHA256(passphrase, salt, 600000 iterations) → AES-KW 256-bit key
wrapped    = AES-KW(cek_or_share, base_key)
```

### 6.3 YubiKey PRF (FIDO2) entry

```json
{
  "method":        "yubikey-prf",
  "label":         "My YubiKey",
  "fingerprint":   "<16 hex chars — SHA-256 of credential_id>",
  "share_index":   <integer> | null,
  "wrapped_cek": {
    "credential_id": "<base64 — WebAuthn credential ID>",
    "prf_salt":      "<base64 — 32 random bytes, the PRF eval input>",
    "ct":            "<base64 — AES-KW wrapped CEK or CEK share>"
  }
}
```

The PRF output (32 bytes) is used directly as the AES-KW wrapping key. Requires HTTPS or localhost, Chrome or Chromium, and a FIDO2 key with the hmac-secret extension (YubiKey 5 series, firmware 5.2+).

### 6.4 `share_index`

For quorum cells (`threshold.required > 1`), each access map entry holds one Shamir share. `share_index` is the x-coordinate of that share (1-indexed, matching the share's polynomial evaluation point).

For non-quorum cells (`threshold.required = 1`) each entry holds the full CEK and the reference implementation **omits the `share_index` key entirely** rather than writing `null`. Both forms are accepted on read. Note that the choice is not cosmetic: `access_map` is covered by `header_hash`, and the canonical serialization of §4.1.1 drops `undefined` but preserves an explicit `null`, so a cell written with `"share_index": null` has a different `header_hash` from an otherwise identical cell written without the key. Each remains internally consistent and verifies correctly; they are simply not byte-identical. Writers SHOULD omit the key.

---

## 7. Quorum — Shamir Secret Sharing

When `threshold.required > 1`, the CEK is split into N shares using Shamir Secret Sharing over GF(256) before wrapping. Any M shares reconstruct the CEK; fewer than M shares reveal nothing.

### 7.1 Field arithmetic — GF(256)

Polynomial arithmetic over GF(2⁸) with irreducible polynomial `x⁸ + x⁴ + x³ + x + 1` (0x11b). Multiplication uses the Russian Peasant algorithm. Multiplicative inverse: `gfInv(x) = x^254 mod poly` (Fermat's little theorem in GF(2⁸)).

### 7.2 Share generation

For each byte position `b` of the CEK:

1. Build a degree-(k-1) polynomial `f` over GF(256) where `f(0) = secret[b]` and coefficients `f[1]..f[k-1]` are random.
2. Evaluate `f(i)` for `i = 1..N`. Each evaluation is one byte of share `i`.

### 7.3 Secret reconstruction (Lagrange interpolation at x=0)

Given M shares `(x₁, y₁)..(xₘ, yₘ)`, for each byte position:

```
secret[b] = Σᵢ yᵢ · Πⱼ≠ᵢ (xⱼ / (xᵢ ⊕ xⱼ))   (all operations in GF(256))
```

---

## 8. Lifetime Model — split by enforcer (v1.3)

`header.lifetime` describes a cell's intended lifetime. **As of v1.3 it is split
into two halves according to who enforces each, because they carry materially
different guarantees and must not be read as one.**

```json
"lifetime": {
  "type":     "<type string>",

  "advisory": {
    "retain_until": <unix timestamp> | null,
    "release_at":   <unix timestamp> | null,
    "single_use":   <boolean>,
    "minimum_atl":  <integer>
  },

  "disposal": {
    "at":     <unix timestamp> | null,
    "action": "none" | "delete" | "archive"
  }
}
```

| Type | Description | Typical `advisory.retain_until` | `disposal.action` |
|------|-------------|---------------------|-------------|
| `permanent` | No end date | `null` | `none` |
| `flash` | Single use, short-lived | `now + 1 hour` | `delete` |
| `session` | Hours to days | configurable | `delete` |
| `clinical` | Months (healthcare use) | configurable | `archive` |
| `record` | Years (compliance/legal) | configurable | `archive` |
| `timed_release` | Locked until `advisory.release_at` | configurable | configurable |

### 8.1 `lifetime.advisory` — conformance behaviour, NOT enforced

These values instruct conforming software. **They are not enforced against a
recipient who holds a qualifying key, and the specification does not claim they
are.** Such a recipient can modify their client, or write an independent opener
from this document, and recover the plaintext irrespective of every value in
this object. This is not an implementation weakness to be corrected in a later
version; it is a property of any scheme that hands a party both the ciphertext
and the means to decrypt it.

What the AAD binding of §4.4 provides here is narrower and worth stating
exactly: **a third party cannot alter, strip, or downgrade these values
undetected.** The recipient is therefore guaranteed to see the sender's true
instructions. Nothing obliges them to follow them. AES-GCM verifies byte
equality, not meaning — supplying a `retain_until` in the past as AAD
authenticates perfectly well.

Conforming clients MUST perform these checks before any cryptographic
operation:

1. **Timed release lock**: if `type = "timed_release"` and
   `advisory.release_at > now` → reject with "Timed release — unlocks `<date>`".
2. **Retention**: if `advisory.retain_until` is set and `< now` → reject with
   "Retention period ended `<date>`".

**`minimum_atl`** — minimum **Access Trust Level** required of a recipient
before the application should permit open: an integer tier reflecting how
strongly the recipient's identity was verified at enrollment (e.g. 1 =
email-verified, 2 = mailed-credential, 3 = in-person). Advisory in the sense
above; the cryptography does not evaluate it. Its real enforcement point is
fan-out (§6): a certificate below the floor is never wrapped a key in the first
place. *Naming note: earlier application code used the field name `minimum_etl`
("enrollment trust level") for the same concept — `minimum_atl` as specified
here is canonical for the `.cell` format.*

### 8.2 `lifetime.disposal` — operator-side, and genuinely enforced

`disposal` governs what the party **storing** the ciphertext does with it, and
is the half of the lifetime model that is actually enforced. A sweep deletes or
archives the stored bytes on schedule, without the operator reading or being
able to read anything. Against every party that has not already taken its own
copy, this is real: the object ceases to be retrievable.

- `disposal.at` — when the stored ciphertext becomes eligible for disposal.
- `disposal.action` — `delete` destroys it; `archive` withdraws it from
  circulation while its existence remains attested; `none` retains it.

`disposal.at` is deliberately independent of `advisory.retain_until`. They
frequently coincide, but they answer different questions and legitimately
differ — a `record` cell may remain readable by its recipients indefinitely
while the operator archives the stored copy after a statutory period.

Clients MUST NOT refuse to open a cell on the basis of `disposal`. A passed
disposal date is not a statement about the recipient's permission; it is a
statement about the operator's retention schedule.

### 8.3 Why the split

Until v1.2 both halves lived in one flat object (`expires_at`, `on_expiry`, …)
under a single "advisory" grade. That undersold `on_expiry`, which is enforced,
and oversold `expires_at`, which is not — and the field name "expires" asserted
a wall the mechanism never built. The rename to `retain_until` applies the same
vocabulary discipline the format already applies to `copy_protection`, which
*warns* and is forbidden from claiming to *prevent*.

v1.0–v1.2 cells retain the flat shape and are read under their own rules (§12).

---

## 9. Policy

`header.policy` carries distribution and presentation rules committed into the signed header.

```json
"policy": {
  "copy_protection":   "none" | "standard" | "strict",
  "watermark_mode":    "none" | "basic" | "full",
  "created_on_origin": "<URL of creating application>",
  "origin_sig":        "<CD server signature> | null"
}
```

| Field | Description |
|-------|-------------|
| `copy_protection` | Redistribution intent. `strict` triggers a visible warning to the recipient. |
| `watermark_mode` | Forensic watermarking intent. `basic` = recipient identity; `full` = forensic embedding. Actual rendering is application-layer. |
| `created_on_origin` | `window.location.origin` of the application that created the cell. |
| `origin_sig` | Reserved for CD server countersignature. `null` in standalone browser deployments. |

Policy is enforced by the application layer only; it is not a cryptographic access control mechanism. Since v1.1 it is bound to the ciphertext as AAD (§4.4), so its values are tamper-evident against third parties even though they are not enforced against an authorized recipient.

---

## 10. Audit Chain

The cell format provides a tamper-evident audit chain. Serialization below is the canonical form (§4.1.1) for v1.2 and v1.3, or `JSON.stringify` for v1.0/v1.1:

```
file bytes
  └─ encrypted in payload.ciphertext  (AES-256-GCM, with metadata bound as AAD — §4.4)
       └─ payload_hash = SHA-256(raw ciphertext bytes)
            └─ committed inside header (covered by header_hash)
                 └─ header_hash = SHA-256(serialize(header))
                      └─ header_sig = ECDSA-SHA256(serialize(header), sender_privkey)   [optional]
```

On open, the verifier checks in order:

0. Advisory lifetime gates (§8.1) — cheapest of all, and they need nothing but the clock.
1. `header_hash` is **present** (reject if absent, §4.1) and matches `SHA-256(serialize(cell.header))`. Benign reformatting is tolerated by canonicalization.
2. `payload_hash` (inside header) matches `SHA-256(base64decode(payload.ciphertext))`.
3. If `header_sig` present: ECDSA-SHA256 over `serialize(cell.header)` verifies against `header_sig_key`.
4. **On decrypt**, the AES-GCM tag verifies the ciphertext *and* the AAD-bound metadata (§4.4); a mismatch — including any edit to `threshold`/`lifetime`/`policy`/`prev_hash` that slipped past the unkeyed `header_hash` — fails here.

**Ordering is normative.** Steps 0–3 MUST complete before *any* key material is touched — before the access-map loop, before AES-KW unwrapping (itself a decryption), before a Shamir quorum is assembled, and before a passphrase entry runs its 600,000-iteration PBKDF2 derivation. An opener that unwraps first and verifies afterwards does expensive, interactive work on behalf of a cell it is about to reject, and performs a decryption under a header it has not authenticated. Step 4 is intrinsic to the body decryption and necessarily comes last.

**What this does and does not cover.** Together these detect tampering with the ciphertext, with the AAD-bound metadata, and — provided `header_hash` is present, which step 1 now enforces — with the rest of the header including `access_map`. They do **not** detect the *removal* of `header_sig` (§4.1): an attacker who strips the signature produces something indistinguishable from an unsigned cell. Sender authenticity must be established by checking the verified fingerprint against an expected value, not by the absence of an error.

---

## 11. Mitosis (Cell Lineage)

Mitosis is the operation of re-encrypting a cell to create a new version — changing recipients, rotating keys, or updating policy. The new cell references its predecessor via `header.prev_hash`.

```
cell₁: prev_hash = null
  └─ cell₂: prev_hash = cell₁.header_hash
       └─ cell₃: prev_hash = cell₂.header_hash
```

`prev_hash` equals the `header_hash` of the immediately preceding cell in the chain. This creates an auditable chain of custody for the document's access history.

`prev_hash` is included in the header and thus covered by `header_hash`, `header_sig`, and (since v1.1) the AES-GCM AAD (§4.4). Tampering with the lineage pointer is detected by the audit chain.

---

## 12. Format Versioning

The `version` field identifies the cell format version. The reference implementation supports exactly the versions listed in `SUPPORTED_VERSIONS = { "1.0", "1.1", "1.2", "1.3" }`. New cells are written as **`1.3`** (`CELL_FORMAT_VERSION`).

| Version | Status | Notes |
|---------|--------|-------|
| `1.0` | Supported (read) | Original format. `header_hash`/`header_sig` over `JSON.stringify(header)`; no AAD. |
| `1.1` | Supported (read) | Adds AES-GCM AAD over `JSON.stringify([prev_hash, threshold, lifetime, policy])`. Hash/sig still over `JSON.stringify(header)`. |
| `1.2` | Supported (read) | Canonical serialization (§4.1.1) for `header_hash`/`header_sig`/AAD. Flat `lifetime` (`expires_at`/`on_expiry`). |
| `1.3` | **Current (write)** | `lifetime` split by enforcer into `advisory` and `disposal`; `expires_at` renamed `retain_until` (§8). Serialization and AAD rules unchanged from 1.2. This specification. |

Open is version-gated: each cell is verified and AAD-bound using the serialization rules of *its own* `version`, so `1.0`/`1.1`/`1.2` cells continue to open unchanged, flat `lifetime` included.

Two sets govern that routing, and implementers should hold them as sets rather than as inline comparisons:

- **Canonical serialization** applies to `{ "1.2", "1.3" }`. Anything else uses `JSON.stringify`.
- **AAD binding** applies to `{ "1.1", "1.2", "1.3" }`. Anything else decrypts with empty AAD.

An implementation that adds a version to `SUPPORTED_VERSIONS` but leaves an inline `version === "1.2"` test elsewhere will silently drop canonical serialization, or decrypt new cells with no AAD, with no error raised at any point. The reference implementation keeps `CANONICAL_VERSIONS` and `AAD_VERSIONS` as explicit sets for exactly this reason.

**Unknown version behavior**: If `cell.version` is present but not in `SUPPORTED_VERSIONS`, the opener rejects the cell with a clear error: "Unsupported cell format version — update the app to open this cell."

**Legacy v2.0 detection**: If `cell.version` is absent and `cell.cd_version` is present, the cell is treated as legacy format. Legacy cells use `recipients` instead of `header.access_map` and `encrypted_body` instead of `payload`. The wrapped CEK in a legacy entry has no `hkdf_salt` field — the raw ECDH shared secret (first 32 bytes) is used directly as the AES-KW key without HKDF.

---

## 13. Key File Formats

### 13.1 `.cdpub` — Public key

Shared with others to receive encrypted cells. Contains no private key material.

```json
{
  "cd_pubkey":   "2.0",
  "label":       "Alice",
  "fingerprint": "<16 hex chars>",
  "method":      "ecdh-p256",
  "spki":        "<base64 — SubjectPublicKeyInfo, P-256>"
}
```

### 13.2 `.cdkey` — Private key export

Contains the full key record including private key. Must be stored securely.

```json
{
  "cd_key":      "2.0",
  "keyId":       "<UUID>",
  "label":       "My Key",
  "method":      "ecdh-p256",
  "fingerprint": "<16 hex chars>",
  "spki":        "<base64 — public key, SPKI format>",
  "pkcs8":       "<base64 — private key, PKCS#8 format>",
  "created_at":  <unix timestamp>,
  "exported_at": <unix timestamp>
}
```

### 13.3 Key fingerprint

`fingerprint = toHex(SHA-256(SPKI bytes)).slice(0, 16)`

16 lowercase hex characters (first 8 bytes of the SHA-256 of the SPKI-encoded public key). Used to match access map entries to available keys.

---

## 14. Cryptographic Primitive Reference

| Operation | Algorithm | Parameters |
|-----------|-----------|------------|
| Content encryption | AES-256-GCM | 256-bit random CEK, 96-bit random IV, 128-bit auth tag |
| CEK wrapping (ECDH) | AES-KW | 256-bit key derived via HKDF |
| ECDH key exchange | ECDH P-256 | Ephemeral sender keypair per recipient |
| Key derivation | HKDF-SHA256 | 256-bit output, 32-byte random salt, `info = "cellular-defense-cek-wrap-v1"` |
| CEK wrapping (passphrase) | AES-KW | 256-bit key via PBKDF2-SHA256, 600,000 iterations, 32-byte salt |
| CEK wrapping (YubiKey) | AES-KW | 256-bit key = PRF output (hmac-secret extension, 32 bytes) |
| GF(256) Shamir SSS | Over GF(2⁸) | Irreducible poly 0x11b (AES polynomial) |
| Metadata binding | AES-256-GCM AAD | `prev_hash`/`threshold`/`lifetime`/`policy` bound to ciphertext (v1.1+) |
| Header signing | ECDSA P-256 + SHA-256 | Signs canonical header bytes (§4.1.1) for v1.2+; `JSON.stringify(header)` for v1.0/v1.1. Raw 64-byte `r ‖ s` (IEEE P1363), **not** DER — see §4.1 |
| Audit hashes | SHA-256 | `header_hash`, `payload_hash`, fingerprints |
| Document ID | ULID | 48-bit ms timestamp + 80-bit CSPRNG, Crockford base32 |
| Randomness | `crypto.getRandomValues()` | Browser CSPRNG — never `Math.random()` |

All operations use the **Web Crypto API** (`crypto.subtle`). Requires a secure context — `https://`, `localhost`, or a `file://` document.

---

## 15. Complete Example

A minimal v1.3 cell encrypted for a single ECDH recipient, no quorum, permanent lifetime, unsigned. The `prev_hash`/`threshold`/`lifetime`/`policy` are additionally bound as AES-GCM AAD (§4.4), and `header_hash` is over the canonical serialization (§4.1.1):

```json
{
  "version": "1.3",
  "doc_id": "01JXXXXXXXXXXXXXXXXXXXXXXXXX",
  "created_at": 1780531200,
  "header": {
    "prev_hash": null,
    "threshold": { "required": 1, "of_total": 1 },
    "lifetime": {
      "type": "permanent",
      "advisory": {
        "retain_until": null,
        "release_at": null,
        "single_use": false,
        "minimum_atl": 1
      },
      "disposal": {
        "at": null,
        "action": "none"
      }
    },
    "policy": {
      "copy_protection": "standard",
      "watermark_mode": "none",
      "created_on_origin": "http://localhost:8080",
      "origin_sig": null
    },
    "access_map": [
      {
        "method": "ecdh-p256",
        "label": "Alice",
        "fingerprint": "a1b2c3d4e5f6a7b8",
        "wrapped_cek": {
          "eph_spki":  "<base64 — ephemeral public key>",
          "hkdf_salt": "<base64 — 32 random bytes>",
          "ct":        "<base64 — AES-KW wrapped 256-bit CEK>"
        }
      }
    ],
    "payload_hash": "<base64 — SHA-256 of raw ciphertext bytes>"
  },
  "header_hash":    "<base64 — SHA-256 of canonicalize(header)>",
  "header_sig":     null,
  "header_sig_by":  null,
  "header_sig_key": null,
  "payload": {
    "alg":        "AES-256-GCM",
    "encoding":   "base64+gzip",
    "iv":         "<base64 — 12-byte IV>",
    "ciphertext": "<base64 — gzip([4-byte len][manifest JSON][file bytes]) encrypted>"
  }
}
```

---

## 16. Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM — AEAD; IND-CCA2 secure under unique nonces |
| Authenticity (content) | AES-256-GCM auth tag — verified on decrypt |
| Authenticity (metadata) | AES-GCM AAD binds `threshold`/`lifetime`/`policy`/`prev_hash` — tamper-evident, not strippable/downgradeable (v1.1+) |
| Integrity (header) | SHA-256 `header_hash`, mandatory and checked before any key use (unkeyed — corruption/format check; authenticity from `header_sig` + AAD) |
| Integrity (ciphertext) | SHA-256 `payload_hash` committed in header |
| Sender authenticity | ECDSA P-256 `header_sig` — optional, per-cell; trust anchored to `header_sig_key` fingerprint, not the `header_sig_by` label |
| Reformat resilience | Canonical serialization — key-reorder/whitespace does not break hash/sig/AAD (v1.2+) |
| Forward secrecy (per-cell) | Fresh ephemeral ECDH keypair per recipient per cell |
| Key isolation | Each recipient's CEK copy uses independent ephemeral keypair |
| Metadata confidentiality | Filename, type, size encrypted inside payload (§5) |
| Threshold access | Shamir SSS — M shares required; **fewer than M** shares reveal nothing (information-theoretically) |
| Lineage integrity | `prev_hash` covered by `header_hash` and `header_sig` |
| Version safety | Unknown versions rejected with clear error |
| Disposal (`lifetime.disposal`) | **Enforced** — the operator's sweep deletes or archives the stored ciphertext on schedule, without reading it. Acts on every party that has not already taken a copy (§8.2) |
| Retention (`lifetime.advisory`) | **Not enforced against a keyholder.** Tamper-evident only: the AAD binding guarantees the recipient sees the sender's true values, and no third party can alter them. A recipient holding the CEK can disregard them entirely (§8.1) |

---

## 17. Changelog

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-06-08 | Initial published spec. ECDH+HKDF+AES-KW CEK wrapping; encrypted manifest; PBKDF2 and YubiKey PRF access methods; Shamir SSS quorum; full lifetime model; policy; header_hash/payload_hash audit chain; ECDSA header_sig; ULID doc_id; Mitosis prev_hash chain. |
| 1.1 | 2026-06-09 | Bind advisory metadata (`prev_hash`/`threshold`/`lifetime`/`policy`) to the ciphertext as AES-GCM AAD (§4.4) — tamper-evident, not strippable/downgradeable. AAD over `JSON.stringify([...])`; hash/sig still over `JSON.stringify(header)`. |
| 1.2 | 2026-06-09 | Canonical serialization (§4.1.1) for `header_hash`, `header_sig`, and AAD, so re-formatting (key order, whitespace) no longer breaks verification. Signature trust clarified to anchor on `header_sig_key`, not the `header_sig_by` label. v1.0/v1.1 cells remain openable. |
| 1.2 (editorial) | 2026-07-19 | Define `minimum_atl` (Access Trust Level, §8) and declare it canonical over the legacy `minimum_etl` field name. No format or wire change. |
| 1.3 | 2026-08-09 | Split `lifetime` by enforcer into `advisory` (conformance behaviour, not enforced against a keyholder) and `disposal` (operator-side, enforced against anyone without a copy), and rename `expires_at` to `advisory.retain_until` (§8). Motivated by a demonstration that an independent opener written from this specification recovers plaintext from a cell whose expiry has passed: the old flat shape graded an enforced field and an unenforced one identically, and the name "expires" claimed a guarantee the format does not provide. Serialization, AAD construction and all cryptographic primitives are unchanged; `1.0`/`1.1`/`1.2` cells are read under their own rules. See `docs/design/temporal-enforcement.md`. |
| 1.3 (corrections) | 2026-08-09 | Documentation corrections from an accuracy review that verified every claim against the reference implementation. **No format or wire change; no cell ever written is affected.** (a) Binary fields are **standard base64**, not base64url as stated since v1.0 — the document was wrong, the implementation was always right, and following the old text produced unparseable cells (§4.0). (b) `header_sig` is raw 64-byte `r ‖ s` (IEEE P1363), not DER — previously unstated, and the one gap that defeated an independent spec-only verification (§4.1). (c) `header_hash` is mandatory and its absence is a rejection; previously an opener could treat a missing hash as licence to skip the header, ciphertext and signature checks together (§4.1, §10). (d) Verification order is now normative: integrity precedes all key use (§10). (e) Signature *removal* is documented as undetectable (§4.1, §10). (f) §16 said "N-1 shares reveal nothing" where it meant fewer than M — N-1 is a quorum's worth. (g) `share_index` is omitted, not `null`, on non-quorum cells (§6.4). See `docs/REVIEW-2026-08-09.md`. |
| 1.3 (corrections 2) | 2026-08-23 | Three documentation corrections, found by a line-by-line review of the specification against itself and against the exposition built on it. **No format or wire change; no cell ever written is affected.** (a) §15's complete example wrote `"share_index": null` on a non-quorum cell, contradicting §6.4 and correction (g) above — the 2026-08-09 correction reached the normative text and missed the example, so the one artifact an implementer is most likely to copy still demonstrated the discouraged form. Example corrected to omit the key. (b) §10 gave the canonical serialization as applying to "v1.2", omitting v1.3, which §4.1.1 and §12 both place in `CANONICAL_VERSIONS`. (c) §14 gave the secure-context requirement as "HTTPS or localhost", omitting `file://` — a legitimate secure context and the one the offline, air-gapped sealing path depends on. |
| 1.3 (corrections 3) | 2026-08-23 | §4.1.1 made self-contained. **No format or wire change; no cell ever written is affected, and the reference implementation is unmodified.** The canonical serialization was defined by deferring to JavaScript's `JSON.stringify`, which is exact but silently imports four rules that are not the default behaviour of a JSON encoder in any other language: binary64 number formatting per ECMA-262 `Number::toString`, UTF-16 code-unit key ordering, the precise escape set (notably that `/`, `<`, `>`, `&`, `U+2028` and `U+2029` are **not** escaped), and — for v1.0/v1.1 only — the requirement that a parser preserve object key order at all. Each is now stated normatively with a worked table, because each independently produced a `header_hash` that never matched during the Python, Go, Rust and Java ports, and the failure carries no indication of its cause. Machine-checkable vectors accompany them at `conformance/vectors/canonical.json`. |

---

*Cellular Defense · Enthropic Data LLC · enthropicdata.com*
