# cellular-defense (Python)

A Python implementation of the Cellular Defense **`.cell`** encrypted document
format, written from [`docs/SPEC.md`](../../docs/SPEC.md) v1.3.

The format is a defensive disclosure (TDCommons No. 11391) and no patent is
asserted over it. This implementation is **Apache-2.0**, not AGPL: the reference
implementation in `cell-crypto.js` carries a copyleft licence that is a poison
pill for anyone who wants to embed a reader, and a format nobody can embed is a
library, not a format.

```bash
pip install -e .
```

Requires Python 3.10+ and [`cryptography`](https://cryptography.io). The test
suite uses only the standard library.

## Library

```python
from cellular_defense import KeyRecord, Recipient, cell_create, cell_open, verify_cell

alice = KeyRecord.generate("Alice")
bob   = KeyRecord.generate("Bob")

cell = cell_create(
    b"quarterly numbers",
    "q3.txt",
    [Recipient.for_key(alice), Recipient.for_key(bob), Recipient.passphrase_("break glass")],
    threshold=2,                 # 2-of-3 Shamir quorum
    sender=alice,                # adds an ECDSA header signature
    meta={"case": "2026-0417"},  # sender-defined, carried INSIDE the ciphertext
)

verify_cell(cell)                # audit chain — no key material needed
result = cell_open(cell, keys=[alice, bob])
result.data                      # b"quarterly numbers"
```

## CLI

```bash
cdcell keygen --label Alice --out alice
cdcell seal report.pdf --to alice.cdpub --sign alice.cdkey --out report.cell
cdcell verify report.cell            # audit chain, no key required
cdcell inspect report.cell           # exactly what an observer of the cell can see
cdcell open report.cell --key alice.cdkey --out ./
```

`verify` and `inspect` deliberately need no key. That a third party can confirm
a cell has not been altered — and enumerate precisely what it does and does not
leak — without being able to read it is the property the whole format rests on.

## What it implements

| Area | Status |
|---|---|
| Seal / open v1.3 | ✅ |
| Read v1.0, v1.1, v1.2 and legacy v2.x | ✅ version-gated per cell (§12) |
| ECDH P-256 → HKDF-SHA256 → AES-KW | ✅ |
| PBKDF2 (600k) access method | ✅ |
| WebAuthn PRF access method | ⚠️ wrap/unwrap only — the PRF output must be supplied by a CTAP2 layer; browser-only in practice |
| Shamir M-of-N quorum over GF(256) | ✅ |
| Canonical serialization, AAD binding, ECDSA `header_sig` | ✅ |
| `.cell` / `.celz` / `.cdpub` / `.cdkey` | ✅ |
| Mitosis lineage (`prev_hash`) | ✅ (pass `prev_hash=` to `cell_create`) |

## Tests

```bash
python3 -m unittest discover -s tests -t .     # 91 tests
```

The suite is in three parts, and the middle one is the one that matters:

- **Self-consistency** — round-trips, key files, GF(256) arithmetic.
- **Differential** (`tests/test_interop_js.py`) — seals in the JavaScript
  reference and opens here, seals here and opens in the reference, and compares
  the exact canonical bytes both implementations hash across 200 randomly
  generated JSON structures. A port can be perfectly self-consistent and
  interoperate with nothing; only cells that cross the boundary prove otherwise.
  Skipped automatically if Node or the reference tree is absent.
- **Negative cases** — tampered AAD, tampered ciphertext, a recomputed
  `header_hash` over an edited header, a downgraded `version`, a stripped
  signature, a DER-encoded signature, the wrong key, a short quorum, a gzip bomb.
  Refusals are the contract; a conformance suite that only tests success proves
  a library works, not that it is safe.

## Notes for other ports

Everything below cost real time to get right here and will cost it again in Go,
Rust, Java or C#. None of it is exotic — it is the gap between "the spec says
JSON" and "the bytes agree".

**Canonical JSON is where the hashes diverge.** §4.1.1 defines the canonical
form by deferring to `JSON.stringify`, which quietly imports three JavaScript
behaviours. Numbers are rendered with the shortest round-tripping decimal and
never a trailing `.0` (`1.0` → `1`, `1e-7` → `1e-7`); Python's `json` writes
`1.0` and `1e-07`, and both differences change the hash. Object keys sort by
UTF-16 code unit, not code point, so an astral character sorts *below*
U+E000..U+FFFF. And JSON has no integers, only float64 — an implementation with
real integers can serialize `2**60` exactly where JavaScript rounds it, so this
one refuses rather than emitting bytes no conforming reader can reproduce. See
`canonical.py`; the fuzz test against the reference is what proved it.

**AES-KW is not in every standard library.** Python has it
(`cryptography.hazmat.primitives.keywrap`); Go does not, and needs RFC 3394
implemented or vendored.

**`header_sig` is raw `r ‖ s`, never DER.** The spec already flags this as the
single most likely point of failure outside a browser, and it is: this library,
OpenSSL, Java and Go all produce DER by default. `crypto.der_to_p1363` and
`p1363_to_der` are the whole fix, and there is a negative test asserting a DER
signature is refused.

**The GCM tag is the trailing 16 bytes of `ciphertext`.** Python, Go and Rust
append it the same way WebCrypto does; Java will not unless `GCMParameterSpec`
is given a 128-bit tag length.

**Shamir has no interoperable standard.** Every implementation hand-rolls it and
round-trip tests pass regardless of which field or evaluation order was chosen.
The fixed vector in `tests/test_gf256.py`, plus the cross-implementation quorum
test, are the only things that actually pin it down. This module uses log tables
where the spec describes Russian-peasant multiplication; a test asserts the two
agree on all 65,536 products.

**gzip framing is not part of the format.** Two conforming implementations
sealing the same file produce different bytes, because the compressor's output
is decided before encryption and no field commits to it. Vectors must therefore
assert *open* determinism, not byte-identical sealing.

**`share_index` is omitted, not null, on non-quorum cells** (§6.4) — the two
forms hash differently, and both are internally valid.

**Binary fields are standard base64, not base64url** (§4.0). Decoders here
accept both; the encoder emits only standard, because `atob()` throws on `-`
and `_` and a base64url cell is unparseable rather than merely non-canonical.

## What this library does not claim

`enforce_advisory=False` is an honest parameter, not a backdoor. §8.1 states
that the advisory half of `lifetime` is not enforced against anyone holding a
qualifying key, and an independent opener written from the specification — which
is exactly what this is — can disregard it. The AAD binding guarantees the
recipient sees the sender's true instructions; nothing obliges them to follow
them. `lifetime.disposal` is the half that is genuinely enforced, and it is
enforced by whoever stores the ciphertext, not by any reader.

Likewise, a clean `verify_cell` establishes that a cell has not been altered —
not who wrote it. A signature can be stripped undetectably (§4.1), so pass
`expected_signer=` with a fingerprint you learned out of band whenever
authorship matters.
