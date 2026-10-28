# Security Status

*Last updated: 2026-10-28. This page is a plain, current account of what has
been tested, by whom, what has not, and the limits that are true by design. It
is the transparency bridge until an independent audit exists, and it is meant to
be read alongside the [Security Policy](SECURITY.md). Where this page and the
normative specification disagree, the specification governs.*

## The one-paragraph version

The `.cell` format and the Cellular Defense system **have not had an independent
third-party cryptographic audit.** They have been tested by their authors, by
four independent implementations written to the same specification, and against
a shared conformance-vector suite; the design uses only standardized primitives
with no novel cryptography; the specification and reference implementation are
timestamped and Bitcoin-anchored; and every flaw found so far is on the public
record. The newest mechanisms have had the least scrutiny. Weigh all of this
accordingly, and have a qualified cryptographer review any deployment that
depends on it.

## At a glance

| Area | Status |
|---|---|
| Independent third-party crypto audit | **Not yet done** — planned; see [below](#the-audit) |
| Cryptographic primitives | Standardized only (NIST/IETF); no novel cryptography |
| Open source | Format, reference implementation, and broker are public |
| Independent implementations | Four (Python, Go, Rust, Java), checked against shared conformance vectors |
| Provenance | Specification + reference code OpenTimestamps-anchored in Bitcoin |
| Published flaw history | Yes — errata and revision history are public and kept |
| Coordinated disclosure / bounty | Open — see [SECURITY.md](SECURITY.md) |
| Hosted-service scanning (runtime) | Standard offensive tooling after each deploy; no critical/high *runtime* findings to date |
| Third-party dependency advisories | Tracked via GitHub Dependabot and triaged on an ongoing basis; the current open set is on the repository's advisories page |

## What has been tested — the scrutiny surface

These are the things anyone can check today. None of them is a substitute for an
independent audit; together they are the reason this project can be weighed with
real information rather than an adjective.

- **Open source, end to end.** The specification, the reference implementation
  (`cell-crypto.js` — a single dependency-free file), and this broker service
  are public and readable. Nothing in the trust path is hidden.
- **Four independent implementations + conformance vectors.** The format is
  implemented more than once (Python, Go, Rust, Java), all checked against a
  shared set of conformance vectors, so a deviation in any single implementation
  is detectable rather than silent.
- **Only standardized primitives.** AES-256-GCM, ECDH P-256, HKDF-SHA256,
  AES-KW, PBKDF2, SHA-256, ECDSA, Shamir's threshold scheme over GF(256), and
  (from v1.4) Argon2id with BLAKE2b and Padmé padding. No home-grown cipher. The
  reviewable risk is in the composition, which open review covers well.
- **Timestamped, Bitcoin-anchored provenance.** The specification and reference
  implementation are OpenTimestamps-anchored in the Bitcoin blockchain for each
  format revision (v1.2, v1.3, v1.4). The digests and their `.ots` proofs are
  published in the reference repository, so anyone can verify them offline. The
  current v1.4 `docs/SPEC.md` digest begins `35d2883e …` and is confirmed in
  Bitcoin block 972397 (2026-10-21).
- **A published flaw history.** Corrections are recorded, not curated away —
  for example, the earliest key-wrapping construction used the ECDH result too
  directly and was corrected to the HKDF construction within days, and an early
  encoding erratum (base64 vs base64url) is documented rather than quietly
  patched. The errata and revision history are public.
- **Author and automated testing.** The reference implementation and this broker
  service carry automated test suites, including backward-compatibility tests
  that prove documents sealed under older format versions still open.
- **Hosted-service security scanning.** The hosted directory-and-relay service
  is scanned with standard offensive tooling (port, TLS, and runtime
  vulnerability scanners, plus unauthenticated endpoint probes) after each
  production deploy. No critical or high runtime findings to date. This is
  distinct from third-party *dependency* advisories, which are tracked
  separately via Dependabot and may have open items at any given time — see the
  repository's advisories page for the current set.
- **Coordinated-disclosure program.** A credit-based vulnerability-disclosure
  program is open; see [SECURITY.md](SECURITY.md) for scope, reporting channels,
  and safe-harbor terms.

## What has not been done — the honest gaps

### The audit

There has been **no independent third-party cryptographic audit** of the format
or the implementation. This is the single most important thing this page says.
The oldest mechanisms have had the most time under public scrutiny; the v1.4
additions — blind access-map entries, the sender signature inside the encrypted
manifest, Padmé padding, the format version bound into the AAD, and the
hand-written Argon2id/BLAKE2b passphrase method — have had the least, and the
hand-written Argon2id/BLAKE2b is the first thing a reviewer auditing the format
should read.

A scoped, funded audit of the cryptographic core is a planned milestone. Until
it exists, the coordinated-disclosure program and open review are the best
scrutiny this project has.

### Still being verified

Some real-device and real-world behaviors are still being confirmed rather than
assumed, including: hardware-security-key flows on physical devices across
platforms; multi-device use across separate real browsers; email deliverability
of production notifications; and the printed recovery-kit QR on real paper and
scanners. These are integration and usability verifications, not open
cryptographic questions, but they are not all ticked off yet.

### Legal and compliance

The legal and compliance posture (retention, regulated-data handling, and
related questions) is under review by qualified counsel and is **not** finalized.
Nothing on this page or in the book is legal, security, or compliance advice;
whether any given deployment is secure or compliant with any legal regime is a
question for qualified professionals engaged for that purpose.

## Known limits — true by design, not bugs

These are properties of the architecture, stated plainly so they are not
mistaken for defects awaiting a patch. The specification states them in normative
language.

- **Metadata is not hidden, and is not claimed to be.** The server and a network
  observer can still see that an account exists, when encrypted blobs arrive and
  depart, roughly how large they are (v1.4 pads ciphertext to a coarse size
  bucket), which network addresses touch them, and how often. Zero-knowledge here
  is a precise claim about **content and keys**, not about traffic analysis. A
  deployment that must resist metadata analysis needs further measures of its own.
- **A declared lifetime is not self-enforcing against a keyholder.** Expiry,
  single-use, and release-date rules are cryptographically bound against
  third-party tampering — no one in storage or transit can alter or strip them
  undetected — but a recipient who already holds a qualifying key can ignore
  them (by running a patched client, setting the clock back, or writing an
  independent opener from the spec). The guarantee is that the recipient sees the
  true, unaltered terms; obedience belongs to honest software and the law, not to
  the ciphertext. Operator-side disposal of stored ciphertext **is** enforced.
- **Browser code-delivery is a residual trust.** A user who loads the sealing
  page fresh from a hostile operator's server every time, verifying nothing,
  still depends on that operator's honesty at serve time. This is mitigated — not
  erased — by the open format, an independent verifier, and (strongest) by
  self-hosting the dependency-free client so the storage operator serves no code
  at all.
- **Signature absence is not detectable.** A stripped signature is
  indistinguishable from a document that was never signed. A verifier that
  requires an authenticated sender must compare against an expected signer
  obtained out of band and must not treat "opened without error" as proof of
  authorship.
- **Key loss is data loss.** A server that never holds your keys cannot hand them
  back. This is the defining bargain of zero-knowledge, not a flaw; recovery,
  where used, is rebuilt deliberately (for example, split among parties you
  choose).
- **The endpoint is trusted by necessity.** Encryption and decryption happen on
  the user's device and browser; a compromised endpoint is outside what any
  document format can protect.

## How to verify, and how to help

- **Verify the anchors yourself:** the anchored bytes and their `.ots` proofs are
  in the reference repository (`docs/defensive-pub/anchors/`); hash the named
  file and confirm the proof commits into the stated Bitcoin block via any block
  explorer or your own node.
- **Run the conformance vectors** against any implementation, and read the
  specification and the independent verifier.
- **Report a vulnerability** privately through the channels in
  [SECURITY.md](SECURITY.md). Valid findings are credited publicly, in the
  Bitcoin-anchored errata when they change the format, via a CVE in your name
  where warranted, and in the book.

---

*This page changes as the work does; the version in the default branch is
current. If something here is out of date or overstated, that is a bug — please
say so.*
