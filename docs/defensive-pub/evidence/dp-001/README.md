# DP-001 — submitted to Technical Disclosure Commons, 2026-08-15

**Submission number: MS #12742.** Status page:
`https://www.tdcommons.org/cgi/preview.cgi?article=12742&context=dpubs_series`

**Status: submitted and revised, awaiting editorial approval.** Not yet published.
TDCommons states submissions are "typically approved and posted within one business day";
their Author FAQ gives up to 72 hours where revisions are requested.

> **#12742 is a submission number, not a publication identifier.** Cite it for
> correspondence with the editors. The citable publication number / DOI is assigned when
> the disclosure actually posts, and only that belongs in a prior-art citation.

## Revision history

| When | Event |
|---|---|
| 2026-08-15 | Initial submission. The file uploaded was the repository's working copy, which still carried the internal pre-filing checklist — including a heading reading "remove before filing", an unticked "Submission date — fill in", and internal process notes. |
| 2026-08-15 | **Replaced**, reason given to the editors: *"Removed internal use checklist."* The file now on record is the clean 8-page PDF whose digest is below. |

The underlying cause is fixed rather than papered over: the checklist no longer lives in
the submission document at all. It moved to `../DP-001-prefiling-checklist.md`, and
`../DP-001-tdcommons-submission.md` is byte-identical to the filed artifact — so uploading
straight from the repository can no longer reproduce this.

| Field | Value as submitted |
|---|---|
| Title | Tamper-Evident, Non-Downgradeable Binding of Advisory Header Metadata to Ciphertext in Client-Side-Encrypted Document Envelopes via AES-GCM Additional Authenticated Data |
| Inventor | David Lee Brown (`dbrown@enthropicdata.com`) |
| Assignee | Enthropic Data LLC, Weddington, North Carolina, USA |
| Venue | Technical Disclosure Commons — Defensive Publications Series |
| Licence | **Creative Commons Attribution 4.0** (TDCommons default, mandatory) |
| Submission type | Initial Submission |
| Cost | None — TDCommons is free |

## Exactly what was filed

The uploaded PDF is preserved here verbatim, with its digest, so the filed artifact can be
compared against any later revision:

| File | SHA-256 |
|---|---|
| `DP-001-as-submitted-2026-08-15.pdf` (8 pp, US Letter) | `c0ad820b7adb804d669f1ccec5a5b44bc34587107e098219b9a5d303d8d919ce` |
| `DP-001-as-submitted-2026-08-15.md` (source) | `e009eff6e872d76ca42fc3b7b54951ad1a0c5174de8c53ffc013e5451b1ea678` |

This copy differs from `../DP-001-tdcommons-submission.md` in **presentation only**: the
internal pre-filing checklist is removed, the submission date is stamped, the anchor table
is set as labelled blocks so the 64-character digests render unbroken, and the
`canonicalize` pseudocode is wrapped to the page. No technical claim, digest, or block
height differs.

## What this does and does not establish

Filing places the disclosure where patent examiners search, which is the thing neither the
timestamps nor the public repository could do. It does **not** move the priority date:
existence is still dated from the OpenTimestamps anchors (2026-07-18 for v1.2), and public
availability from 2026-08-15. This is a third, independent witness to the same design.

## On acceptance — do this

1. Record the publication number / DOI in `../REGISTER.md` (replacing the MS #12742
   placeholder), and change DP-001's status there from `submitted` to `published`.
2. Save the confirmation e-mail and the published URL into this directory.
3. Only then is DP-001 prior art in the form an examiner encounters. Until the approval
   lands, this directory records a **submission**, not a publication — the distinction the
   rest of these documents are careful about.
