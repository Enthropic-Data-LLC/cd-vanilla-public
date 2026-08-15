# Defensive Publication Register — Cellular Defense

**Enthropic Data LLC** · Strategy: pure defensive publishing — no patent sought or asserted.
Guide: `docs/DEFENSIVE-PUBLISHING-GUIDE.md` · Spec: `docs/SPEC.md`

Status values: `draft` → `review` → `submitted` → **`published`**.
Only `published` establishes prior art. Everything else protects nothing.

## Published / in flight

| ID | Mechanism | Priority | Status | Venue | Pub #/DOI | Date | Timestamp anchor | Evidence |
|----|-----------|----------|--------|-------|-----------|------|------------------|----------|
| DP-001 | Metadata-as-AAD binding (non-strippable, non-downgradeable) | ★ | **submitted** | TDCommons — Defensive Publications Series | MS **#12742** (submission no.; DOI pending) | submitted 2026-08-15 | `docs/defensive-pub/anchors/SPEC.md.ots` — **Bitcoin-confirmed** (blocks 958650, 958690) | `evidence/dp-001/` |

## Backlog — drafted from the guide's §6 inventory

| ID | Mechanism | Priority | Notes |
|----|-----------|----------|-------|
| DP-009 | Full-format master disclosure — all `.cell` **v1.3** mechanisms consolidated | ★ | `docs/DEFENSIVE-DISCLOSURE.md` — reproduces `docs/SPEC.md` in §5 plus design rationale (§6), variations (§7), scope limitations (§8), figures (§9); drafted for Research Disclosure journal submission, 43pp letter/12pt. Rebuilt on v1.3 2026-08-09. Not yet submitted or timestamped in its own right — see anchors below for the priority date it corroborates. |
| DP-002 | Canonical-serialization audit chain, version-gated | ★ | Partly covered inside DP-001; may warrant its own disclosure for the hash/sig application. |
| DP-003 | Shamir-split CEK across a multi-method access map (`share_index`) | ★ | Split the *content key*, wrap each share to a different access method. |
| DP-004 | WebAuthn-PRF-derived keypair — token *is* the key, never stored | ★ | P-256 scalar = PRF output mod n; portable public stub. Physical touch-test still pending. |
| DP-005 | Encrypted manifest prefix — filename/MIME/size inside the ciphertext | | `[4-byte LE len][manifest JSON][file bytes]`, gzip-then-encrypt. |
| DP-006 | Mitosis lineage chain (`prev_hash` = predecessor `header_hash`) | | Auditable chain of custody across re-encryptions. |
| DP-007 | Email-keyed cert directory + burn-after-read encrypted relay | ★ | cd-cert-broker as a system composition. |
| DP-008 | Per-recipient ephemeral ECDH → HKDF → AES-KW wrapping | | Per-cell forward secrecy / key isolation. |

## Anchored artifacts

| Artifact | SHA-256 | Anchored |
|---|---|---|
| `docs/SPEC.md` (as disclosed 7/18; pinned by tag `cell-format-v1.2-defensive-pub`) | `2e1ac039bfb1920bc5ba848f2bfdf904e0c9ccfe0443c016034a6eb5bc7c6c41` | 2026-07-18, OTS — **Bitcoin-confirmed 2026-07-19** (proof at the tag) |
| ~~`docs/SPEC.md`~~ (7/19 editorial: `minimum_atl`) — **superseded, never confirmed** | `68434edf42c598e1e7c9962a80455e225eba302a50fd2461470560a912ca2415` | 2026-07-19, OTS — left pending and overtaken by the licensing note and then v1.3. No longer matches any file in the tree; the proof is recoverable from git history. |
| `cell-crypto.js` | `11ce4b07f2459ea1b4677d98e864a424849afd7080cafdfdff60ca7b81decae5` | 2026-07-18, OTS — **Bitcoin-confirmed 2026-07-19** |
| `docs/DEFENSIVE-PUBLISHING-GUIDE.md` | `6d97cc4e048b6710969b5116ea774bc9b63c57969aedc4eb20d130f07dd95ee0` | 2026-07-18, OTS — **Bitcoin-confirmed 2026-07-19** |

### v1.3 anchor — Bitcoin-confirmed 2026-08-10

The lifetime split (`advisory`/`disposal`, `expires_at` → `retain_until`) is a
**new mechanism and is not covered by the v1.2 anchor**. Stamped separately on
2026-08-09, after the accuracy-review corrections
(`docs/REVIEW-2026-08-09.md`) had settled both files, and upgraded to full
Bitcoin attestation on 2026-08-10:

| Artifact | SHA-256 | Anchored |
|---|---|---|
| `docs/SPEC.md` (v1.3 + corrections) | `870a5ea00846b5e0be810adb7e6c5e63dbe0a7e1d41a9ebcafdfba25d8d20c0d` | 2026-08-09 20:15 ET — **Bitcoin-confirmed** (961803, 961805, 961836) |
| `cell-crypto.js` (v1.3 + integrity fixes) | `277cbcfe784fb8503c9b259af5ffa8719d521ab2c482e8595bbb1eef8e7537bb` | 2026-08-09 20:15 ET — **Bitcoin-confirmed** (961803, 961805, 961836) |

| Block | Merkle root | Mined (UTC) |
|---|---|---|
| 961803 | `cba3701df17c2c9db621d859289c37879b83856e55c7529cd1c207edd14041f6` | 2026-08-10 00:35:00 |
| 961805 | `7edb17cfcb5971918699e5f8d2dcd4d243fa5d1edbc2dbdc14f0639db2f3cb17` | 2026-08-10 00:41:25 |
| 961836 | `f7128ba0009ca2e1c744b5bcc463a5980dad035e27b644a91c66b8eaf07e34bf` | 2026-08-10 04:42:43 |

Both live files are **byte-identical to their anchors** — `sha256sum docs/SPEC.md
cell-crypto.js` reproduces the digests above. Frozen copies with their upgraded
proofs are in `docs/defensive-pub/anchors/v1.3/`. Keep it that way: any edit to
either file, however editorial, breaks that identity and needs a fresh stamp.

Superseded v1.3 stamps, left pending and overtaken the same day — do not cite:
`9e119336…` (SPEC.md, pre-corrections) and `69c2a89d…` (cell-crypto.js,
pre-corrections).

> **The workflow that failed once, written down.** `ots stamp` produces a
> *pending* proof committing only to a calendar server. It becomes prior-art
> evidence only after `ots upgrade` folds in a mined Bitcoin attestation. The
> v1.2 proofs sat pending and uncommitted-upgraded for three weeks while the
> book and the disclosure both claimed they were confirmed — true, but
> unverifiable by any reader. **After every stamp: `ots upgrade`, confirm with
> `ots info` that a `BitcoinBlockHeaderAttestation` is present, commit the
> upgraded proof, and only then write a block height into a table.**
>
> Timing, for expectations: v1.3 was stamped 20:15 ET, mined into 961803 twenty
> minutes later at 20:35 ET, but the calendars did not serve a complete proof
> until the small hours. Pending at the one-hour mark is normal.

The v1.2 proofs are unaffected and remain Bitcoin-confirmed. They no longer
require a tag checkout: the anchored bytes and their **upgraded** proofs sit
together at the root of **`docs/defensive-pub/anchors/`**, verifiable with one
`sha256sum` and one `ots info`. See the anchors README for both revisions, the
merkle roots, and the errata carried by the frozen v1.2 text.

Repo tag: `cell-format-v1.2-defensive-pub` (commit `62a8143`).
Bitcoin anchor: block **958650** (merkle root `cd57b1c2…3aead6`) and block **958690** (merkle root `d3619eda…a44858`).
Verify (needs a Bitcoin node, or use a block explorer for the merkle roots): `ots verify docs/defensive-pub/anchors/SPEC.md.ots` · Inspect the proof offline: `ots info docs/defensive-pub/anchors/SPEC.md.ots`

> Note the path. `docs/SPEC.md.ots` is the **v1.3** proof and commits to blocks 961803/961805/961836; the v1.2 proof for the digests above lives only in `docs/defensive-pub/anchors/`.

> **Status of the v1.2 anchor: block-anchored and permanent.** Those `.ots` proofs were upgraded to full Bitcoin attestation on 2026-07-19 and committed. The v1.2 priority date is independently verifiable by anyone against the Bitcoin blockchain, with no dependence on the OpenTimestamps calendars remaining online.
>
> **v1.3 is separately anchored and also confirmed.** The proofs stamped 2026-08-09 were upgraded on 2026-08-10 and carry Bitcoin attestations for blocks 961803, 961805 and 961836 — see the v1.3 section above. The two anchors cover different bytes, so cite whichever revision you are actually relying on; neither paragraph covers the repository as a whole.

## History rewrite, 2026-08-14 — and why it does not touch the anchors

A pre-publication secret scan over the working tree and all 87 commits of the private
source repository found no keys, tokens or credentials, but did find that a book screenshot
(`64-audit.png`) was redacted only at the tip. The unredacted image — internal LAN addresses
in the audit-log IP column — survived at two earlier revisions and would have become public
along with the repository. That history was rewritten so every revision of the image carries
the redacted bytes.

**This public repository does not carry that history at all.** It was exported as a fresh
tree containing only the files published here; the companion book and the private working
notes it was separated from are not present in any revision. The OpenTimestamps proofs are
unaffected either way — they attest to file bytes, not to git history, and the anchored
bytes in `anchors/` are byte-identical to the ones anchored on chain.
The old blobs `29ba87dc…` and `6063b7c6…` no longer exist.

**No timestamp proof is affected, and this is the general rule, not a lucky escape.**
OpenTimestamps commits to the SHA-256 of *file content*; it knows nothing about commit
hashes, so rewriting history cannot invalidate a proof. All five anchored digests were
re-verified after the rewrite and are unchanged, and all five `.ots` files still carry
their Bitcoin attestations.

What did change: every commit from 2026-07-20 onward has a new hash, and
`cell-format-v1.3-defensive-pub` was re-pointed (`971b7a1` → `565e052`) and force-pushed.
`cell-format-v1.2-defensive-pub` (`62a8143`) predates the screenshot and is **untouched**,
so the citations to that commit in this file, in DP-001, in the disclosure and in the
book's Appendix E all remain correct.

> Any clone made before 2026-08-14 still contains the unredacted blobs. Re-clone rather
> than pull, and do not push from an old working copy — doing so would restore the very
> objects this removed.

## Public availability — CLOSED 2026-08-15

**The code and specification are public: `github.com/Enthropic-Data-LLC/cd-vanilla-public`.**
Verified reachable anonymously (HTTP 200, no account), and both anchored files re-hashed
from the published copies to their recorded digests — `docs/SPEC.md` to `870a5ea0…d8d20c0d`
and `cell-crypto.js` to `277cbcfe…8e7537bb`. The verification procedure in the disclosure's
§10 can now be carried out by anyone, which was the whole of what was missing.

This repository is a **clean-room export** of the private `sohocs509/cd-vanilla`, with fresh
history, carrying the code, the specification and the anchored bytes but not the companion
book. Two consequences worth stating rather than leaving to be discovered:

- **The commits and tags cited in these documents live in the private source repository.**
  `cell-format-v1.2-defensive-pub` (`62a8143`) and `cell-format-v1.3-defensive-pub` are not
  present here. Nothing is lost by that: OpenTimestamps commits to *file content*, never to
  git history, so every anchor verifies against the published files directly. That is
  precisely what `docs/defensive-pub/anchors/` exists for.
- **Accessibility dates from 2026-08-15, not from the anchors.** Existence is proven from
  2026-07-18 (v1.2) and 2026-08-09 (v1.3); public availability begins the day this repository
  was published. The two are separate requirements and carry separate dates.

**Independently archived the same day**, so availability does not depend on this repository
staying online — identifiers and caveats in [`evidence/README.md`](evidence/README.md):

| Archive | Identifier |
|---|---|
| Software Heritage snapshot | `swh:1:snp:41977f6b7b27ab1a29ae27fd5889b358f5834f36` |
| `docs/SPEC.md` content | `swh:1:cnt:08626ba292a3adf59290e4335af02074e48941c0` |
| `cell-crypto.js` content | `swh:1:cnt:9ca50b405ce218a158d2ce7f2ec517bfc331389f` |
| Wayback Machine | snapshots `20260815124807` / `…4813` / `…4819` — the stored `SPEC.md` and `cell-crypto.js` were re-downloaded and **hash to their anchored digests** |

> **Still outstanding — a date is not a filing.** No venue submission has been made; DP-001
> remains `draft`. Steps 1–3 of the publishing guide's §5 anchoring stack are complete
> (timestamp, signed tag, independent archive); **step 4 is not**. Publishing and archiving
> closed the availability gap; neither places the disclosure where an examiner searches.
> See §4 of `docs/DEFENSIVE-PUBLISHING-GUIDE.md` for the venue ranking — TDCommons is the
> recommended free primary, and DP-001 is already drafted for it.
