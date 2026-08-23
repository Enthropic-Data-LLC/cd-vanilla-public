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

## Encrypt

```java
import com.enthropicdata.cell.*;
import java.nio.file.*;
import java.util.List;
import java.util.Map;

// The recipient's public key. They generated it with `cdcell keygen` and sent
// you the .cdpub; you never see their private key.
KeyRecord alice = KeyRecord.fromCdpub(
        Json.asObject(Json.parse(Files.readAllBytes(Path.of("alice.cdpub")))));

// Your own key, used to sign the header so Alice can confirm you sealed it.
KeyRecord me = KeyRecord.fromCdkey(
        Json.asObject(Json.parse(Files.readAllBytes(Path.of("me.cdkey")))));

Cell.CreateOptions opts = new Cell.CreateOptions();
opts.contentType = "application/pdf";
opts.sender = me;                              // optional ECDSA header signature
opts.meta = Json.of("case", "2026-0417");      // INSIDE the ciphertext

Map<String, Object> sealed = Cell.create(
        Files.readAllBytes(Path.of("q3-results.pdf")), "q3-results.pdf",
        List.of(Cell.Recipient.forKey(alice)), opts);

Files.writeString(Path.of("q3-results.cell"), Json.writePretty(sealed));
```

The filename, media type, size and `meta` are all encrypted: an observer of the
stored cell sees none of them (§5).

**Several recipients, any one of whom can open it:**

```java
List<Cell.Recipient> recipients = List.of(
        Cell.Recipient.forKey(alice),
        Cell.Recipient.forKey(bob),
        Cell.Recipient.passphrase("break glass in emergency", null));
Map<String, Object> sealed = Cell.create(data, "q3-results.pdf", recipients, null);
```

**A quorum — two of the three together, and no fewer:**

```java
Cell.CreateOptions quorum = new Cell.CreateOptions();
quorum.threshold = 2;                          // Shamir split over GF(256), §7
Map<String, Object> sealed = Cell.create(data, "q3-results.pdf", recipients, quorum);
```

## Decrypt

```java
KeyRecord me = KeyRecord.fromCdkey(
        Json.asObject(Json.parse(Files.readAllBytes(Path.of("me.cdkey")))));
Map<String, Object> sealed =
        Json.asObject(Json.parse(Files.readAllBytes(Path.of("q3-results.cell"))));

Cell.OpenOptions opts = new Cell.OpenOptions();
opts.keys = List.of(me);
// Optional but recommended: a fingerprint you learned out of band. Without it,
// "opened without error" is NOT evidence of who sealed the cell — a signature
// can be stripped undetectably (§4.1).
opts.expectedSigner = "aff6a52990ce2335";

Cell.OpenResult result = Cell.open(sealed, opts);

Files.write(Path.of(result.filename()), result.data());
System.out.println(result.filename() + " " + result.contentType() + " " + result.meta());
System.out.println("signed by " + result.signerFingerprint());
```

Set `opts.passphrases` for a passphrase entry, and pass several keys at once for
a quorum — `open` collects shares until it has enough.

**Handling failure**, which is most of what an opener does. Every failure is a
subclass of `CellException`, unchecked by design:

```java
try {
    Cell.OpenResult result = Cell.open(sealed, opts);
} catch (CellException.Integrity e) {
    // header_hash or payload_hash mismatch — the cell was altered
} catch (CellException.Signature e) {
    // header_sig present and invalid, or not the expected signer
} catch (CellException.Decryption e) {
    // AES-GCM tag failed — ciphertext or AAD-bound metadata was tampered
} catch (CellException.QuorumNotMet e) {
    // not enough shares
} catch (CellException.NoMatchingKey e) {
    // none of the supplied material fits any access-map entry
} catch (CellException.Lifetime e) {
    // advisory gate: retention expired, or a timed release is still locked
}
```

Note `QuorumNotMet` extends `NoMatchingKey`, so catch it first if you want to
distinguish them.

## Verify without any key

```java
Cell.VerifyResult report = Cell.verify(sealed, null);   // throws on tampering
System.out.println(report.signed() + " " + report.signerFingerprint());
```

Any third party can confirm a cell has not been altered since it was sealed —
without being able to read it. That is the property the whole format rests on.

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
