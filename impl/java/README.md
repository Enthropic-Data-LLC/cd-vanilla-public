# cellular-defense (Java)

A Java implementation of the Cellular Defense **`.cell`** encrypted document
format, written from [`docs/SPEC.md`](../../docs/SPEC.md) v1.3.

**No runtime dependencies.** JUnit is test-scope only. Requires JDK 17+
(built and tested on 21).

Apache-2.0, like the rest of `impl/` — see [`LICENSING.md`](../../LICENSING.md) §3.

```xml
<dependency>
  <groupId>com.enthropicdata</groupId>
  <artifactId>cellular-defense</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Library

```java
KeyRecord alice = KeyRecord.generate("Alice");
KeyRecord bob   = KeyRecord.generate("Bob");

Cell.CreateOptions opts = new Cell.CreateOptions();
opts.threshold = 2;                       // 2-of-2 Shamir quorum
opts.sender = alice;                      // adds an ECDSA header signature
opts.meta = Json.of("case", "2026-0417"); // carried INSIDE the ciphertext

Map<String, Object> sealed = Cell.create(
        "quarterly numbers".getBytes(UTF_8), "q3.txt",
        List.of(Cell.Recipient.forKey(alice), Cell.Recipient.forKey(bob)), opts);

Cell.verify(sealed, null);                // audit chain — no key material needed

Cell.OpenOptions open = new Cell.OpenOptions();
open.keys = List.of(alice, bob);
open.expectedSigner = alice.fingerprint(); // authorship, against a known key
byte[] plaintext = Cell.open(sealed, open).data();
```

Failures are subclasses of `CellException`: `Integrity`, `Signature`,
`Decryption`, `NoMatchingKey`, `QuorumNotMet`, `Lifetime`, `UnsupportedVersion`,
`Malformed`, `Canonicalization`. Unchecked, deliberately — a cell that fails to
open is not something every layer should be forced to declare. The distinctions
matter: "this cell was tampered with" and "you gave me the wrong key" call for
different responses.

## CLI

```bash
mvn package
java -jar target/cellular-defense-0.1.0.jar keygen --label Alice --out alice
java -jar target/cellular-defense-0.1.0.jar seal report.pdf --to alice.cdpub --out report.cell
java -jar target/cellular-defense-0.1.0.jar verify report.cell    # no key required
java -jar target/cellular-defense-0.1.0.jar inspect report.cell   # what an observer sees
java -jar target/cellular-defense-0.1.0.jar open report.cell --key alice.cdkey --out ./
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
| Mitosis lineage (`prev_hash`) | ✅ via `CreateOptions.prevHash` |

## Tests

```bash
mvn test
```

The shared conformance vectors from [`conformance/`](../../conformance), the 225
canonical-serialization vectors, a deterministic Shamir share vector matching
the Python, Go and Rust ports byte for byte, and the negative cases — tampered
AAD, recomputed `header_hash` over an edited header, version downgrade,
DER-encoded signature, short quorum, expired retention.

Interoperability verified in every direction: cells sealed here open in
`cell-crypto.js`, Python, Go and Rust with byte-identical plaintext and verified
signatures, and vice versa.

## Notes for the next port

Java's profile is close to the inverse of Go's. The JDK supplies almost every
cryptographic primitive the format needs — including the two that gave other
ports the most trouble — and then omits the one thing everybody assumes is
present.

**What comes free here that did not elsewhere:**

- **`AESWrap`.** Go has no AES-KW in its standard library and has to implement
  RFC 3394; `Cipher.getInstance("AESWrap")` is right there.
- **IEEE P1363 signatures.** `SHA256withECDSAinP1363Format` (JDK 11+) produces
  and verifies the raw 64-byte `r ‖ s` the format requires. Go, Python and
  OpenSSL all default to DER and have to convert. But note that plain
  `"SHA256withECDSA"` still produces DER — swapping the two silently yields
  signatures nothing else can verify, which is §4.1's trap arriving by a
  different door.
- **UTF-16 key ordering.** `String.compareTo` compares UTF-16 code units, which
  is exactly JavaScript's string order. Go, Rust and Python all need a custom
  comparator so that astral characters sort below U+E000..U+FFFF; Java does not.

**What you have to write:**

- **HKDF.** Not in the JDK before 24 (`javax.crypto.KDF`). It is fifteen lines
  of `HmacSHA256` and RFC 5869 has test vectors.
- **JSON, entirely.** The JDK has never shipped a parser. `Json.java` here is a
  hundred lines and keeps key insertion order, which v1.0/v1.1 header hashing
  requires (§12) — a header parsed into a sorted or hashed map can never be
  re-serialized to the bytes it was signed over.

**Three traps specific to Java:**

- **`Double.toString` is not usable for canonicalization, even on JDK 19+ where
  it is documented to give the shortest round-tripping decimal.** For the
  subnormal minimum it returns `4.9E-324` where `5E-324` round-trips, is
  shorter, and is what JavaScript prints. `Canonical.jsNumber` searches for the
  shortest round-trip explicitly rather than trusting it — at most seventeen
  attempts, correct by construction.
- **`String.format` honours the default locale.** A German or French JVM
  formats `%e` with a comma decimal separator, producing a canonical string no
  other implementation can reproduce — a `header_hash` mismatch on some machines
  and not others. `Locale.ROOT` is load-bearing.
- **`GCMParameterSpec` needs the tag length stated explicitly.** 128 bits, to
  match WebCrypto's appended tag. Java will not default to it, and a shorter tag
  produces cells nothing else can open.

**One thing worth pinning rather than assuming:** `PBEKeySpec` takes a
`char[]`, and the specification says nothing about how a provider turns that
into the byte string PKCS#5 wants. SunJCE uses UTF-8 for the HMAC-SHA2
variants — which is what makes passphrase entries interoperate — but that is an
observation about the provider, not a guarantee. `ConformanceTest` pins it
against a value computed independently by the Python port, using a non-ASCII
passphrase where the encoding choice actually shows.
