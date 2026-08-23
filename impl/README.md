# Implementations

Five independent implementations of the `.cell` format, all checked against the
same [conformance vectors](../conformance). Cells sealed by any one of them open
in all the others with byte-identical plaintext.

| Language | Location | Licence | Dependencies | Encrypt / decrypt examples |
|---|---|---|---|---|
| **JavaScript** (reference) | [`../cell-crypto.js`](../cell-crypto.js) | AGPL-3.0 | none — Web Crypto | [root README](../README.md) |
| **Python** | [`python/`](python) | Apache-2.0 | `cryptography` | [README](python/README.md#encrypt) |
| **Go** | [`go/`](go) | Apache-2.0 | none | [README](go/README.md#encrypt) |
| **Rust** | [`rust/`](rust) | Apache-2.0 | RustCrypto, `serde_json`, `flate2` | [README](rust/README.md#encrypt) |
| **Java** | [`java/`](java) | Apache-2.0 | none at runtime | [README](java/README.md#encrypt) |

The JavaScript implementation lives at the repository root rather than under
`impl/`, because it is not only a port: `index.html` loads it directly, it is the
artifact the defensive publication anchors, and it is the one file here under the
AGPL. Everything under `impl/` is a port of it, and permissively licensed so it
can be embedded — see [`LICENSING.md`](../LICENSING.md) §3.

Each language README has the same four sections: **Encrypt**, **Decrypt**,
**Verify without any key**, and **Notes for the next port**. Every example in
them has been compiled and run verbatim.

## Choosing one

- **Python** — the widest audience for evaluation and scripting: compliance,
  forensics, data pipelines. One dependency, stdlib-only tests.
- **Go** — a single static binary that cross-compiles anywhere, which is what
  you hand an auditor who has no toolchain. Zero dependencies.
- **Rust** — the route to a second *browser* implementation via WASM, and an FFI
  core other languages can bind rather than each re-porting Shamir.
- **Java** — enterprise and Android integration. No runtime dependencies.

## What each language gives you, and what it costs

The format needs eight things: AES-256-GCM with AAD, ECDH P-256, HKDF-SHA256,
AES-KW, PBKDF2, ECDSA P-256 in IEEE P1363 form, gzip, and a JSON encoder that
matches JavaScript's `JSON.stringify` byte for byte. No language supplies all
eight, and they fail to supply *different* ones — which is the useful thing to
know before starting a sixth port.

| | Python | Go | Rust | Java |
|---|---|---|---|---|
| AES-KW | stdlib-ish (`cryptography`) | **write it** (RFC 3394) | crate (`aes-kw`) | stdlib (`AESWrap`) |
| HKDF | `cryptography` | stdlib (1.24+) | crate (`hkdf`) | **write it** (JDK 24+ only) |
| P1363 signatures | **convert** from DER | native (`ecdsa.Sign`) | native (`p256`) | stdlib (JDK 11+) |
| JSON parser | stdlib | stdlib | crate | **write it** (none, ever) |
| Order-preserving parse | free (dicts) | **write it** | feature flag | **write it** |
| UTF-16 key ordering | **custom comparator** | **custom comparator** | **custom comparator** | free (`String.compareTo`) |
| JS number formatting | **write it** | **write it** | **write it** | **write it** |

Two of those rows have a trap hidden inside a "native": Go's `ecdsa.Sign`
returns `r, s` as `*big.Int` and is P1363 already, but `ecdsa.SignASN1` right
next to it produces DER; Java's `SHA256withECDSAinP1363Format` is correct while
plain `SHA256withECDSA` is not. Reaching for the wrong one of a pair yields
signatures nothing else can verify.

The last row is unanimous, and it is the one that hurts: `1.0` must print as
`1`, `1e-7` must stay `1e-7`, and integers must round through binary64 first.
No language's default float formatting agrees with JavaScript's, and a
disagreement surfaces only as a `header_hash` that never matches, with nothing
in the failure to say why. Specification §4.1.1 states the rules; the vectors in
`conformance/vectors/canonical.json` check them without needing any crypto, and
are the cheapest first test for a new port.

Three findings worth carrying forward, each of which cost real time:

- **`serde_json` needs the `float_roundtrip` feature.** Its default float parser
  is not correctly rounded and lands one ULP off on large exponents.
- **Java's `Double.toString` is not shortest-round-trip for subnormals**, even
  on JDK 19+ where it is documented to be — `4.9E-324` where JavaScript prints
  `5e-324`.
- **Go's `encoding/json` escapes `<`, `>`, `&`, and escapes U+2028/U+2029 even
  with `SetEscapeHTML(false)`.** `JSON.stringify` escapes none of them.

## Running everything

```bash
npm test                                                    # JavaScript, 51 tests
cd impl/python && python3 -m unittest discover -s tests -t . # 106 tests
cd impl/go     && go test ./...
cd impl/rust   && cargo test --release                       # --release: PBKDF2 is 600k rounds
cd impl/java   && mvn test                                   # 39 tests
```
