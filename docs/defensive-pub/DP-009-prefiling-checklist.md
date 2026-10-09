# DP-009 — pre-filing checklist (internal)

This checklist is kept out of `docs/DEFENSIVE-DISCLOSURE.md` on purpose. That file is the
document that gets uploaded, and a filed disclosure with a section headed "remove before
filing" says it was filed carelessly. DP-001 learned this the hard way (see
`DP-001-prefiling-checklist.md`). The list was split out of the disclosure on 2026-10-09.

**Venue decided 2026-10-09: TDCommons**, the same venue as DP-001 (Defensive Publications
Series No. 11391). It is free and indexed, and CC BY 4.0 is its mandatory licence, which
the disclosure's header now states. Research Disclosure, the paid journal the document
was originally drafted for, is not being used.

## Before filing

- [x] **Venue** — TDCommons, decided 2026-10-09.
- [x] **Reference repository is public** — since 2026-08-15:
      `github.com/Enthropic-Data-LLC/cd-vanilla-public`, reachable anonymously.
- [x] **§5 matches the current specification** — 2026-10-09. A token-level diff against
      `docs/SPEC.md` (`0412968e…`) differs only in heading levels, the preamble and the
      omitted licensing note. **Re-run the diff if the spec changes again before filing.**
- [x] **Every anchor cited in §10 is Bitcoin-confirmed.** The v1.3 proofs were upgraded
      2026-08-10 and the corrections-3 proof 2026-10-08. §10 must never say "confirmed"
      about a pending proof.
- [x] **Figures** — `python3 tools/verify-cell.py docs/figure-data/*.cell` reports 3/3
      (2026-10-09). Do **not** run `tools/make-figure-cells.mjs` casually: it regenerates
      the cells (it ignores `--help`), and every value §9 quotes would then be stale.
- [x] **No secrets** — re-checked 2026-10-09 (no key blocks or tokens). The only contact
      detail is the deliberate `dbrown@enthropicdata.com`.
- [x] **Confidentiality** — checked 2026-10-09. Nothing touches the withheld DNA Key
      construction. The only "enrollment" mentions are the published `minimum_atl`
      definition in §5. Re-check after any edit to §6–§8.
- [ ] **Build** — `./docs/build-disclosure.sh` (US Letter, 12pt). Its two sparse-page
      warnings (pages of whole code listings) were inspected 2026-10-09 and are false
      positives.
- [ ] **Upload** — the PDF, plus the Markdown source if the form allows it. Freeze both
      into `evidence/dp-009/` with their SHA-256 digests, as was done for DP-001.

## After acceptance

- [ ] Record the series number in `REGISTER.md` (TDCommons mints no DOI; the series number
      is the citable id, and the MS number is for correspondence only). Flip DP-009 to
      `published` and save the confirmation into `evidence/dp-009/`.
- [ ] Add DP-009 to `WORKS` in `scripts/citation-monitor.py`.
