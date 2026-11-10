# Design note: temporal enforcement — what `lifetime` can and cannot be

**Status as of 2026-11-10.** Recommendations 1–3 **implemented in v1.3**; see
the closing section. Recommendation 4 is **half done**: the quorum-escrow
pattern of §4.3 is now a supported method,
[`docs/methods/escrowed-release.md`](../methods/escrowed-release.md), with the
enforced alternatives (§4.1, §4.2, a time-gate service, and others) logged
there as possible extensions. Making the bare field real remains open — and
`extension-profiles.md` §4 proposes a different shape for it than §4.1 below
assumes: a beacon-gated *access-map entry* rather than a lifetime field, so
that quorum supplies the enforcement. Read that before acting on this.
First note in `docs/design/`.

The question that prompted this: *should `lifetime` be removed from the format
unless expiry can be made mathematically enforced?*

The short answer is that the question contains two different problems wearing
one name, and they have opposite answers. Expiry cannot be enforced, by anyone,
ever. Timed release can be — genuinely, and with deployed technology. The
current specification treats them as siblings, which is the actual defect.

---

## 1. What is true today, demonstrated rather than asserted

`cellOpen` refuses an expired cell:

```js
if (lt.expires_at && lt.expires_at < now)
  throw new Error(`Cell expired ${fmtDate(lt.expires_at)}`);
```

That check is ordinary application logic. It runs *before any cryptographic
work*, and nothing cryptographic depends on it.

This was tested on 2026-08-09 rather than reasoned about. A cell was minted with
`expires_at = 1704067200` (2024-01-01, long past) and a recipient key retained.
The reference implementation refused it:

```
REFUSED: Cell expired Dec 31, 2023, 7:00 PM
```

An independent opener — roughly forty lines of Python written from `SPEC.md`
alone, using a general-purpose cryptographic library and no code from this
project — recovered the plaintext:

```
CEK recovered: 32 bytes
AAD rebuilt: 231 bytes — including the expiry that says 'expired'
GCM tag: VALID — the cipher raised no objection
PLAINTEXT RECOVERED: SETTLEMENT TERMS — this document was marked to
                     expire on 2024-01-01.
```

**The AAD binding does not help here, and it is worth being explicit about why,
because this is the most common misreading of the mechanism.** Binding
`lifetime` as additional authenticated data prevents a third party *changing*
the date. It does nothing to prevent a keyholder *ignoring* it. The independent
opener supplied the true, unmodified, expired lifetime as AAD and GCM accepted
it — AES-GCM verifies byte equality, not meaning. The cipher has no concept of
"expired." A bound field is a field nobody can forge; it is not a field anybody
must obey.

Nothing here is a vulnerability. It is the `advisory` grade behaving exactly as
graded. The value of running the test is that a documented claim is now a
demonstrated one.

---

## 2. The asymmetry

**Expiry — "cannot open *after* T" — is impossible to enforce.** Not difficult;
impossible. A recipient who could legitimately open the document at T−1 simply
keeps the plaintext. No clock, no beacon, no chain, and no cryptography changes
this, because the clock was never the weak link — possession of recovered
plaintext is. Every scheme that has claimed otherwise has been a
rights-management scheme, and the analog hole applies to all of them.

**Timed release — "cannot open *before* T" — is enforceable.** Here the secret
has not been released yet, so there is still something to protect. This is a
different problem with a real solution space.

The specification currently places both in `lifetime` under the same grade. That
conflation is what should change, more than the field itself.

---

## 3. Why binding to a chain does not solve expiry

The suggestion that prompted this note was to bind time to Bitcoin rather than
to a local clock, since a local clock can be set backwards by whoever owns the
machine. That reasoning is correct about local clocks and points at the right
family of solutions, but it targets the wrong direction.

A block height proves **that time has passed**. It does not publish **a
decryption key that becomes available later**. For expiry you would need the
inverse — something that renders decryption *impossible* after a moment — and no
construction can do that once the key and the ciphertext are both in a
recipient's hands. For timed release you need a key that *appears* on schedule,
which is precisely what a chain height does not give you.

So: chain-anchored time is genuinely useful for *proving when something existed*
(the project already uses OpenTimestamps for exactly this), and useless for
enforcing either direction of `lifetime` on its own.

---

## 4. Options for making timed release real

Evaluated against the project's existing construction rules.

### 4.1 Threshold beacon / timelock encryption (drand `tlock`) — recommended

The drand network (League of Entropy) publishes threshold BLS signatures on a
fixed round schedule. Timelock encryption treats a future round number as an
identity in an identity-based encryption scheme; the round's signature, once
published, *is* the decryption key. Before that round, no party holding the
ciphertext can decrypt. After it, anyone can fetch the beacon and decrypt.

- **Enforced by:** a threshold of independent operators, not the recipient's
  clock. The recipient cannot advance it by lying about the time.
- **Trust assumption:** a threshold of drand nodes do not collude to publish a
  round early. Distributed, but not zero-trust.
- **Connectivity:** required at *decrypt* time to fetch the beacon. Not required
  at seal time beyond knowing the round schedule.
- **Cost:** BLS12-381 pairings. **The Web Crypto API provides none.** Adopting
  this breaks the project's "download nothing" rule, and by a wider margin than
  the Argon2id trade already documented in the credo — a pairing library is far
  more code than a KDF. This is the real decision, and it should be made
  deliberately rather than absorbed quietly.

### 4.2 Timelock puzzles / VDFs — no network, but imprecise

Sequential-squaring puzzles (Rivest–Shamir–Wagner, 1996) and modern verifiable
delay functions require a quantity of inherently serial work to solve.

- **Enforced by:** physics and the absence of parallel shortcuts.
- **Trust assumption:** none. No third party, no network, no clock.
- **Cost:** wall-clock accuracy depends entirely on the solver's hardware, so
  the achievable precision is a factor of several, not minutes. Suitable for
  "not for about a week," useless for "opens 10:00 Monday." The recipient also
  burns continuous CPU.

### 4.3 Quorum escrow — available today, zero new cryptography

Worth stating because it is already possible with the format as specified, and
is currently underused: put a share behind a party who will not participate
before the date. Under a 2-of-3 quorum where one share is held by an escrow
agent, timed release is enforced not by a clock but by the *absence of a
sufficient key* until that agent acts.

- **Enforced by:** the same information-theoretic property as any quorum — below
  the threshold the key does not exist.
- **Trust assumption:** the escrow party behaves. Human, nameable, auditable.
- **Cost:** none technically; it requires a real counterparty and a ceremony.

This is the honest recommendation for deployments that need enforced timed
release *now*, and the book already gestures at it in the lifetime chapter. It
should be promoted from an aside to the documented pattern.

---

## 5. The part that is already enforced, and is being undersold

`lifetime` currently has two consumers with completely different guarantees, and
the specification grades them as one:

| Consumer | Behaviour | Actually enforced? |
|---|---|---|
| Server sweep (`on_expiry: delete` / `archive`) | Operator deletes or archives ciphertext on schedule | **Yes** — against everyone who has not already taken a copy. The operator never reads anything to do it. |
| Client check on open | Refuses to decrypt past `expires_at` | **No** — conformance behaviour only, as §1 demonstrates |

The first is real data minimisation and is the strongest practical argument
*against* deleting the field. Remove `lifetime` and the deletion trigger goes
with it: documents accumulate indefinitely, which is the failure mode the whole
apoptosis idea exists to prevent. The advisory client check is the weak half;
the disposal schedule is not.

---

## 6. Recommendation

1. **Do not remove `lifetime`.** Removing it to correct a misperception about the
   client check would sacrifice the server-side disposal trigger, which is
   genuinely enforced and is the feature's main value.

2. **Split the field by enforcer in the specification.** State that `on_expiry`
   governs operator-side disposal (enforced) while the client-side refusal is a
   conformance behaviour (not enforced against a keyholder). One grade covering
   both simultaneously undersells the first and oversells the second.

3. **Rename the client-facing concept.** "Expiry" imports a promise the mechanism
   does not make. `retention`, `disposal_schedule`, or `handling` conveys the
   same information without implying a wall. This is the existing vocabulary
   policy applied consistently — the same policy already forbids "prevent" for
   `copy_protection`, and "expires" is the identical category of error.

4. **Decide `timed_release` deliberately.** It is currently the least defensible
   field in the format: it *sounds* enforced, it is widely assumed to be
   enforced, and it is the same ignorable `if` as expiry. Either
   - make it real (§4.1, accepting the pairing dependency), or
   - document the quorum-escrow pattern (§4.3) as the supported way to get
     enforced timed release, and grade the bare field as bluntly as
     `copy_protection` is graded.

   The present middle position — an unenforced field with an enforced-sounding
   name and no documented alternative — is the one option with nothing to
   recommend it.

---

## 7. Open decisions

- Does the project accept a pairing-curve dependency for `tlock`, given the
  "download nothing" rule? This is a philosophy decision, not a technical one,
  and it should be recorded either way.
- If `lifetime` is renamed, v1.2 cells in the wild carry the old field names.
  Any rename is a format change requiring a version bump and a gated read path
  (§12), not an editorial correction.
- Should the demonstration in §1 be published — in the disclosure's scope
  limitations and the book's lifetime chapter? Publishing a working bypass of
  one's own advisory field is unusual, but it is trivially derivable from the
  specification already, and demonstrating a stated limit is more credible than
  restating it.

## Reproducing §1

The demonstration used only `cell-crypto.js` (to mint the expired cell) and a
standalone Python opener with no project code. The opener performs, in order:
ECDH P-256 against `eph_spki`, HKDF-SHA256 with the entry's `hkdf_salt` and
`info = "cellular-defense-cek-wrap-v1"`, AES-KW unwrap, then AES-256-GCM decrypt
supplying `canonicalize([prev_hash, threshold, lifetime, policy])` as AAD, then
gunzip and strip the 4-byte manifest prefix. It contains no expiry check because
nothing in the format requires one.


---

## 8. Implemented — v1.3, 2026-08-09

Recommendations 1, 2 and 3 are done. `lifetime` was kept, split by enforcer,
and the client-facing field renamed:

```json
"lifetime": {
  "type": "record",
  "advisory": { "retain_until": …, "release_at": …, "single_use": …, "minimum_atl": … },
  "disposal": { "at": …, "action": "none" | "delete" | "archive" }
}
```

Changed: `docs/SPEC.md` §8 (rewritten and split into §8.1 advisory / §8.2
disposal / §8.3 rationale), §12 (version table and routing sets), §15 (worked
example), §16 (the two halves now carry separate grades), and the changelog;
`cell-crypto.js` (v1.3 write, `normalizeLifetime`/`readLifetime`, renamed
rejection message); `index.html` (display and lifetime builders); `tests/`.

Two things worth recording for whoever touches versioning next:

- **A third hardcoded version gate was found during implementation.** Alongside
  `serializeHeader`'s `version === '1.2'`, the open path carried
  `(fmtVersion === '1.1' || fmtVersion === '1.2')` when deciding whether to
  supply AAD. Adding 1.3 to `SUPPORTED_VERSIONS` without finding that line
  produced cells that decrypted with **no AAD at all**, silently losing the
  binding — no error, no failed test until the round-trip broke. Both gates are
  now sets (`CANONICAL_VERSIONS`, `AAD_VERSIONS`) and §12 documents them.
- **Backward compatibility is two-directional and both directions are tested.**
  v1.0–1.2 cells are read under their own flat-shape rules, and callers still
  *passing* a flat lifetime object to `cellCreate` have it normalised into the
  split shape rather than rejected.

Test suite: 49/49 (was 45/45; four added covering the split, legacy-input
normalisation, disposal never blocking a client open, and v1.2 version
routing). v1.3 cells verified independently from the specification text alone —
`header_hash`, `payload_hash`, fingerprint and ECDSA `header_sig` all reproduce.

**Not changed, deliberately:** the book and `docs/DEFENSIVE-DISCLOSURE.md` still
describe v1.2. The disclosure reproduces the *Bitcoin-anchored* v1.2 text and
must continue to; the book's Appendix A is pinned to the same. Bringing the
book's prose chapters to v1.3 is follow-up work, and note that v1.3 is not
itself timestamped — only v1.2 carries a priority anchor today.
