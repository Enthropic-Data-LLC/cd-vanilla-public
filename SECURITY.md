# Security Policy

Cellular Defense makes a strong, falsifiable claim: **the server that stores
and relays a `.cell` document holds ciphertext, wrapped keys, and public
metadata only, and no server-side operation, credential, or administrative
privilege is sufficient to recover plaintext.** A claim like that is only worth
anything if anyone is invited to break it. This document is that invitation.

We would rather hear it from you than from an incident.

## The one question

Every report is measured against a single question:

> **Can you read, forge, or tamper with a document that the architecture says
> you cannot — or make the server able to recover plaintext it is supposed
> never to hold?**

If the answer is yes, by any path, we want it. A clean break of the central
claim is the most valuable thing you can send us, and it will be credited as
such (see [Recognition](#recognition)).

## Honest status

This format and this service **have not had an independent third-party
cryptographic audit.** We are not going to pretend otherwise, and you should
weigh any deployment accordingly.

What *does* exist, and what you can check today:

- **Open source.** The format, its reference implementation (`cell-crypto.js`),
  and this broker are public and readable end to end.
- **Multiple independent implementations.** The format is implemented more than
  once, checked against a **shared conformance-vector suite**, so a deviation in
  any single implementation is detectable rather than silent.
- **Timestamped provenance.** The specification and reference implementation are
  OpenTimestamps-anchored in the Bitcoin blockchain — the digests and their
  proofs are published and verifiable offline.
- **A published flaw history.** Every error we have found and corrected is on the
  record, in the specification's errata and revision history. We add to it; we
  do not quietly rewrite it.
- **Standardized primitives, no novel cryptography.** The construction composes
  AES-256-GCM, ECDH P-256, HKDF-SHA256, AES-KW, Shamir secret sharing over
  GF(256), ECDSA P-256, PBKDF2, Argon2id, and Padmé padding. Nothing here is a
  home-grown cipher. The interesting surface is almost entirely *composition* —
  which is exactly where open review is most effective.

A paid, scoped audit of the cryptographic core is a planned milestone. Until it
exists, adversarial review from people like you is the best scrutiny this
project has, and we treat it that way.

A fuller, current account — what has been tested and by whom, what has not, and
the limits that are true by design — is in
[SECURITY-STATUS.md](SECURITY-STATUS.md).

## Scope

The `.cell` format and its reference implementation live in
[`cd-vanilla`](https://github.com/sohocs509/cd-vanilla); this
repository, `cd-cert-broker`, is the zero-knowledge public-cert directory and
encrypted-object relay built on it. **Findings against either are in scope**,
and this is the right front door for both.

### In scope — the cryptographic core (highest value)

| Area | Examples of a valid finding |
|---|---|
| Confidentiality | Any path by which the server, an observer, or a non-recipient recovers plaintext or a content-encryption key |
| Integrity / authenticity | Undetectable tampering with content or governance metadata; forging a sender signature; defeating the AAD binding |
| Access control | Opening a document without satisfying its access map (OR / k-of-n quorum); defeating a required-recipient (AND) rule |
| Key handling | Any way a private key leaves the browser; a key backup or recovery flow that leaks the private half or the owner's identity |
| Canonicalization | Serialization ambiguities that let two different documents verify against one digest/signature, or that break cross-implementation agreement |
| Metadata leakage | The server learning materially more than it should (beyond the documented, inherent metadata — sizes-to-a-bucket, timestamps, counts) |

### In scope — the broker service (`cd-cert-broker`)

| Area | Examples of a valid finding |
|---|---|
| Directory integrity | Publishing or taking over a cert for an email address you do not control; defeating magic-link email-ownership proof |
| Relay | Reading, correlating, or tampering with parked ciphertext; defeating burn-after-read or TTL expiry |
| Auth / sessions | Publisher or admin session forgery, privilege escalation, the `X-Session-Token` surface |
| Server-side classics | Injection, SSRF, auth bypass, IDOR, rate-limit / enumeration bypass against the directory |
| Signed receipts | Forging a delivery receipt that verifies against the published `/.well-known` key |

### Out of scope

- **Anything touching other people's data on the live service
  (`app.cellulardefense.net`).** Do your testing against a **local or
  self-hosted instance** — setup is in the [README](README.md), and the format
  work needs no server at all. See [Rules of engagement](#rules-of-engagement).
- Denial of service, volumetric / stress testing, and anything that degrades the
  service for real users.
- Social engineering, physical attacks, and attacks on our staff or vendors.
- Spam or abuse of the real email / magic-link / verification-letter flows.
- Reports that reduce to "it isn't audited" (we know — see above) or "a user who
  installs malware / runs a backdoored client is compromised" (true of every
  system; the threat model assumes an honest client, which is why the client is
  open and verifiable).
- Missing security headers, best-practice nits, and automated-scanner output
  with no demonstrated impact. Show us a path.

## How to report

**Report privately. Do not open a public issue for a security finding.**

1. **Preferred — GitHub private advisory:** use *Report a vulnerability* under
   the **Security** tab of the relevant repo
   ([`cd-cert-broker`](https://github.com/sohocs509/cd-cert-broker/security/advisories/new)
   or `cd-vanilla`). No mailbox, encrypted in transit, and it threads the whole
   coordination in one place.
2. **Email:** `security@cellulardefense.net`. If the finding is sensitive and
   you want it encrypted, you can — fittingly — **encrypt it to us with the
   product itself**: look up that address on the directory and send a `.cell`.
   (If your finding is *in* the crypto, GitHub advisory is the safer channel.)

Please include: what you found, the impact against [the one
question](#the-one-question), and the shortest reproduction you can manage —
ideally a failing conformance vector or a minimal script against a local
instance.

**Coordinated disclosure.** We aim to acknowledge a report within **5 business
days** and to agree a fix-and-disclose timeline with you, defaulting to **90
days** or mutual agreement, whichever is sooner. We will not go public ahead of
you, and we would like to credit you when we do (see below). We will never
threaten a good-faith researcher — see [Safe harbor](#safe-harbor).

## Recognition

We do not have the budget for cash bounties, and we are not going to insult your
time by pretending a token reward is one. **We pay in the currency this field
actually runs on — durable, portable, public credit** — and we are generous and
scrupulous about it:

- **Public acknowledgment.** Every valid finding earns your name (or handle) in
  [`SECURITY-ACKNOWLEDGMENTS.md`](SECURITY-ACKNOWLEDGMENTS.md), with a link of
  your choosing. This is the record you can point an employer at.
- **A place in the anchored history.** A finding that changes the format or
  implementation is credited in the specification's **errata and revision
  history** — which is **OpenTimestamps-anchored in Bitcoin.** Your name goes
  into the permanent, independently-verifiable record of this format's
  development. As far as we know, that is a rarer thing to be able to offer than
  a bounty, and a better one.
- **CVE coordination.** Where a finding warrants it, we will help obtain and
  publish a CVE in your name.
- **Acknowledgment in the book.** Significant findings are credited in *Cellular
  Defense*, the book that documents this format.

You may of course decline credit or ask to be listed anonymously. If we ever
stand up a funded audit, past contributors of material findings are the first
people we will invite to scope it.

## Rules of engagement

Test in a way that cannot harm a real user:

- **Use your own instance.** Run `cd-cert-broker` locally or self-hosted (see
  the [README](README.md)), and attack the **format and conformance vectors**
  directly — most of the interesting work needs no server at all.
- **Only your own accounts and data** if you must touch a running service. Never
  access, modify, or retain data belonging to anyone else. If you encounter real
  user data, stop and tell us.
- **No DoS, no volumetric testing, no spam** of the live email, magic-link, or
  verification-letter flows.
- **Minimize blast radius.** Stop at proof-of-concept; you do not need to exfil a
  dataset to prove a point.

## Safe harbor

If you make a good-faith effort to follow this policy, we consider your research
**authorized**, we will not pursue or support legal action against you for it,
and we will work with you to understand and resolve the issue quickly. Good faith
means: you respect the scope and rules above, you avoid privacy violations and
service disruption, and you give us a reasonable chance to fix the issue before
disclosing it. If in doubt about whether something is in bounds, ask first via
one of the private channels — we would much rather have the conversation.

## Testing resources

- **Run it:** [README.md](README.md) — local setup and the test suite.
- **The format & reference implementation:**
  [`cd-vanilla`](https://github.com/sohocs509/cd-vanilla), including the
  specification, the conformance vectors, and the OpenTimestamps anchors.
- **Known unverified items:** [VERIFICATION-NEEDED.md](VERIFICATION-NEEDED.md) —
  an honest standing list of what rests on a claim we have not yet checked.

---

*This policy may change; the version in the default branch governs. Thank you for
spending your time making this safer for the people who rely on it.*
