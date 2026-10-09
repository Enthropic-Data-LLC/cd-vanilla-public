# Conformance fixtures

Shared test material for `.cell` implementations. Language-neutral on purpose —
all five implementations (the JavaScript reference and the Python, Go, Rust
and Java ports) consume exactly these files rather than minting their own.

## `keys/`

A fixed cast of five P-256 keypairs plus one passphrase. Every vector refers to
them by name, so "opens with carol, not with mallory" means the same thing in
any language.

| Key | Fingerprint | Role |
|---|---|---|
| alice | `97017b8bf3caab2d` | primary recipient |
| bob | `aff6a52990ce2335` | second recipient; the signer in signed-cell vectors |
| carol | `e3acafc957ac89fb` | third recipient (quorum) |
| dave | `6574194ee815c0f2` | fourth recipient (3-of-4 quorum) |
| mallory | `425f2c9a0c017fa6` | never a recipient — the wrong-key negative case |

Passphrase for every `pbkdf2` entry: `conformance-test-passphrase`.

These are published test keys. The private halves are in this repository and
protect nothing; they exist so failures are reproducible.

### Regenerating

```bash
python3 conformance/make-test-keys.py
```

The keys are **deterministic** — each private scalar is
`SHA-256("cellular-defense conformance key v1: " + label) mod n` — so the script
reproduces them byte-for-byte and an implementation in any language can derive
the same cast from the label alone, with nothing to download. A vector whose
keys drift is not a vector, which is why the fingerprints above are also pinned
in `impl/python/tests/test_conformance_keys.py`.

Both file formats are written (`.cdpub` per spec §13.1, `.cdkey` per §13.2), and
they are directly loadable by the reference implementation as well as by the
Python port — the field names are the spec's, not any one library's.

## `vectors/`

27 captured cells — 14 that must open, 13 that must be refused — indexed by
`vectors/manifest.json`, plus 225 canonical-serialization vectors. All five
implementations agree on all of them: every open vector opens in the JavaScript
reference and in the Python, Go, Rust and Java ports with byte-identical
plaintext, and every reject vector is refused by all five.

```
vectors/
  manifest.json      index — what each cell is, what opens it, what must not
  canonical.json     225 canonical serialization vectors (§4.1.1)
  open/              cells that must open
  reject/            cells that must be refused
  payloads/          the expected plaintext for each open vector
```

### `vectors/canonical.json`

Input/expected pairs for the canonical serialization that `header_hash`,
`header_sig` and the AES-GCM AAD are computed over. The expected strings come
from `cell-crypto.js` and nowhere else — §4.1.1 defines the canonical form by
deferring to JavaScript's `JSON.stringify`, so JavaScript is the authority on
the right answer and every other implementation checks itself against it.

Run these **first** in a new port. They need no crypto, they fail loudly, and
they catch the three divergences that otherwise surface as a `header_hash` that
never matches and no clue why: JavaScript's number formatting (`1.0` prints as
`1`, `1e-7` stays `1e-7`, integers round to float64 before printing), its
UTF-16 code-unit key ordering, and the five characters its `JSON.stringify`
does not escape but most other JSON encoders do (`<`, `>`, `&`, U+2028,
U+2029).

Regenerate with `./conformance/make-canonical-vectors.sh` (needs node and
python3). The corpus is fixed-seed, so it reproduces exactly.

### Coverage

**Versions** — 1.3, plus the read paths §12 requires to keep working: 1.2
(canonical serialization, flat lifetime), 1.1 (AAD over `JSON.stringify`), 1.0
(no AAD at all) and pre-spec legacy 2.0 (raw ECDH as the AES-KW key, no HKDF, no
header, no manifest prefix). Nothing writes those any more, which is exactly why
they need vectors — an untested read path is a read path that rots.

**Access methods** — `ecdh-p256` and `pbkdf2`, singly, mixed, and as Shamir
shares. `yubikey-prf` is deliberately absent: its key material comes from a
WebAuthn PRF evaluation that no file can carry and no headless runner can
perform, so a vector would have to ship the PRF output and would then be testing
AES-KW rather than the access method.

**Payload edges** — a zero-byte file, all 256 byte values, an astral-plane
filename and non-ASCII `meta` inside the encrypted manifest.

**Refusals** — the half that carries the weight:

| Vector | Caught at §10 step |
|---|---|
| `header-hash-missing`, `header-hash-mismatch` | 1 |
| `payload-hash-mismatch` | 2 |
| `signature-invalid`, `signature-der`, `forged-access-map` | 3 |
| `tampered-aad`, `version-downgrade` | 4 — GCM tag |
| `unsupported-version`, `retention-expired`, `timed-release-locked` | 0 |
| `quorum-short`, `wrong-key` | key recovery |

`reject-tampered-aad` is the one to check first in a new port. The cell is
internally consistent — the attacker edited AAD-bound metadata *and* recomputed
the unkeyed `header_hash`, so steps 1-3 all pass. Only the AES-GCM tag catches
it. An implementation that opens every positive vector and also opens this one
does not have a partial pass; it has no metadata authentication at all.

The manifest names a `reject_reason` for each, but **the refusal is normative
and the reason code is not**. The two implementations already differ on one:
`reject-signature-der` fails a length check in Python and fails verification in
WebCrypto. Both refuse, which is what conformance requires.

### Running them

```bash
cd impl/python && python3 -m unittest tests.test_conformance_vectors
```

A new port writes this runner first: read the manifest, open what must open and
compare against `payloads/`, attempt what must be refused and require an error.

### Regenerating

```bash
python3 conformance/make-vectors.py
```

Vectors are **captured, not reproduced**. Sealing is randomized — fresh
ephemeral keypair per recipient, fresh IV, fresh HKDF and PBKDF2 salts — and no
field commits to the gzip framing, so two conforming implementations sealing the
same file produce different bytes and both are correct. A vector asserts what
opens and what is refused, never byte-identical sealing. Re-running the
generator produces a new, equally valid set, which is a reason not to do it
casually: the value of a committed vector is that it stays put.
