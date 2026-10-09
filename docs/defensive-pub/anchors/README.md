# Anchored artifacts — Bitcoin timestamp proofs

These are the **exact bytes** whose SHA-256 digests are timestamped into the Bitcoin
blockchain, together with their OpenTimestamps proofs. They are frozen historical
artifacts, kept here so that the priority claims in the defensive disclosure and in the
book can be verified **from this directory alone** — no git archaeology, no network, no
trust in Enthropic Data.

Several revisions are anchored, and they cover different things:

| Location | Revision | Covers |
|---|---|---|
| this directory | v1.2, 2026-07-18 | The envelope, AAD binding, canonical serialization, ECDH→HKDF→AES-KW fan-out, Shamir quorum, audit chain, version gating |
| [`v1.3/`](v1.3/) | v1.3, 2026-08-09 | The above **plus** the lifetime split by enforcer (`advisory`/`disposal`, `expires_at` → `retain_until`) and the accuracy-review corrections |
| [`v1.3-corrections-2/`](v1.3-corrections-2/) | v1.3 + corrections 2, 2026-08-23 | Documentation only — no format or wire change. The specification text reproduced in the companion book's Appendix A |
| [`v1.3-corrections-3/`](v1.3-corrections-3/) | v1.3 + corrections 2 and 3, 2026-08-23 | Documentation only — §4.1.1 canonical serialization made self-contained (numbers, key order, escaping) |

The v1.2 files sit at this directory's root rather than in a `v1.2/` subdirectory for
one specific reason: the anchored v1.2 text is referenced by path from the current
specification's erratum note, and that reference cannot be corrected later without
altering a file whose digest is itself anchored. The frozen bytes therefore keep the
path they were given. Later revisions get subdirectories.

> ⚠️ **Do not implement from the v1.2 files at this root** — they contain known errata,
> listed at the end of this document. Implement from
> [`../../SPEC.md`](../../SPEC.md), which is byte-identical to `v1.3/SPEC.md` as of
> 2026-08-10 and will move ahead of it over time. When it does, hash it and compare:
> if it no longer matches any anchor here, it is a later revision awaiting its own stamp.

## v1.2 — anchored 2026-07-18

| File | SHA-256 | Bitcoin |
|---|---|---|
| `SPEC.md` | `2e1ac039 bfb1920b c5ba848f 2bfdf904 e0c9ccfe 0443c016 034a6eb5 bc7c6c41` | 958650, 958690 |
| `cell-crypto.js` | `11ce4b07 f2459ea1 b4677d98 e864a424 849afd70 80cafdfd ff60ca7b 81decae5` | 958650, 958690 |
| `DEFENSIVE-PUBLISHING-GUIDE.md` | `6d97cc4e 048b6710 969b5116 ea774bc9 b63c5796 9aedc4eb 20d130f0 7dd95ee0` | 958650, 958690 |

Source revision: tag `cell-format-v1.2-defensive-pub`, commit `62a8143`.

| Block | Merkle root | Mined (UTC) |
|---|---|---|
| 958650 | `cd57b1c229d489b8ed0a04adf73339517d82e1586fa26dca0ec2085da03aead6` | 2026-07-19 03:36:41 |
| 958690 | `d3619eda7f45881bf02d08b03faa0fa5f679458d33da22846a20dedd53a44858` | 2026-07-19 07:14:39 |

## v1.3 — anchored 2026-08-09

| File | SHA-256 | Bitcoin |
|---|---|---|
| `SPEC.md` | `870a5ea0 0846b5e0 be810adb 7e6c5e63 dbe0a7e1 d41a9ebc afdfba25 d8d20c0d` | 961803, 961805, 961836 |
| `cell-crypto.js` | `277cbcfe 784fb850 3c9b259a f5ffa871 9d521ab2 c482e859 5bbb1eef 8e7537bb` | 961803, 961805, 961836 |

Source revision: tag `cell-format-v1.3-defensive-pub`.

| Block | Merkle root | Mined (UTC) |
|---|---|---|
| 961803 | `cba3701df17c2c9db621d859289c37879b83856e55c7529cd1c207edd14041f6` | 2026-08-10 00:35:00 |
| 961805 | `7edb17cfcb5971918699e5f8d2dcd4d243fa5d1edbc2dbdc14f0639db2f3cb17` | 2026-08-10 00:41:25 |
| 961836 | `f7128ba0009ca2e1c744b5bcc463a5980dad035e27b644a91c66b8eaf07e34bf` | 2026-08-10 04:42:43 |

## v1.3 + corrections 2 — anchored 2026-08-23

| File | SHA-256 | Bitcoin |
|---|---|---|
| `SPEC.md` | `19a16a2e 4827ae03 75499e25 d68275c5 3910a098 c47cebaf 144e219c 569917f5` | 963744, 963750, 963751, 963764 |

`cell-crypto.js` is unchanged from the v1.3 anchor and was not re-stamped.

| Block | Merkle root | Mined (UTC) |
|---|---|---|
| 963744 | `600d120fe8c75b486e950b7aa3711d18bc4e35a399b603f41987ab11dd37e695` | 2026-08-23 15:43:56 |
| 963750 | `48d6ccdff76231ae33ee9272726ae3f2b2b6fe5bd993aa7957ac30009908c644` | 2026-08-23 17:16:04 |
| 963751 | `8156c9d5e64fc9cfa17b9c4778688479a31599b55c87cd9d823a5ab23e90e453` | 2026-08-23 17:11:58 |
| 963764 | `daf695f183cc09dbf778fa16a0c525b3d93f68e7491deee0a85f4f908d20bb9b` | 2026-08-23 20:32:26 |

## v1.3 + corrections 2 and 3 — anchored 2026-08-23

| File | SHA-256 | Bitcoin |
|---|---|---|
| `SPEC.md` | `0412968e ed2d6e16 831a8fa4 130eaf1a 9fedaad3 8fa3fceb 56aa12dd 0aad9e0b` | 963756, 963764, 963794 |

| Block | Merkle root | Mined (UTC) |
|---|---|---|
| 963756 | `264fb5ee12aef7eccf1d789a64e19d4f43877a94327c66e811e9aa26031ea95c` | 2026-08-23 18:03:58 |
| 963764 | `daf695f183cc09dbf778fa16a0c525b3d93f68e7491deee0a85f4f908d20bb9b` | 2026-08-23 20:32:26 |
| 963794 | `d89b49d0e6e24238ecfdf19bf9d0d9ff252980b11cc23f30a434a5d3c61927f5` | 2026-08-24 01:46:42 |

## Verify it yourself

```bash
cd v1.3                       # or stay here for v1.2

# 1. Confirm the bytes hash to the published digests
sha256sum SPEC.md cell-crypto.js

# 2. Confirm each proof commits into the stated Bitcoin blocks
ots info SPEC.md.ots | grep BitcoinBlockHeaderAttestation

# 3. Full verification against a Bitcoin node (authoritative)
ots verify SPEC.md.ots

# 3b. Without a node: check the merkle roots above against any block explorer,
#     e.g. https://blockstream.info/block-height/961803
```

Step 2 needs no node and no network — the proof is self-contained once upgraded. Step 3
is the authoritative check and is what an evaluator should perform.

## Note on proof upgrading

An OpenTimestamps proof is created *pending*: it commits to a calendar server, and the
Bitcoin attestation only becomes part of the proof file after `ots upgrade` is run, once
the calendar's commitment has been mined and aggregated.

The v1.2 proofs committed on 2026-07-18 were pending-only stubs and were not upgraded
until 2026-08-09. For three weeks the repository asserted a Bitcoin anchor that a reader
could not confirm from the committed files. The anchor was real the whole time — but
"true" and "verifiable by a stranger" are different properties, and only the second one
is worth anything in a defensive publication.

**So: after every `ots stamp`, come back and `ots upgrade`.** Expect a few hours;
v1.3 was mined 20 minutes after stamping but took several more before the calendars
would serve the completed proof. Verify with `ots info` that a
`BitcoinBlockHeaderAttestation` is actually present before recording a block height
anywhere, and commit the upgraded file.

Never overwrite an upgraded `.ots` with a fresh pending stamp of a newer file — that
silently destroys the evidence for the older one. Give each revision its own home here,
the way `v1.3/` has one.

## Known errata in the v1.2 text

The anchored bytes cannot be corrected — that is the point of anchoring them. Two errors
in the frozen v1.2 text are fixed in v1.3:

1. **`base64url` should read `base64`.** The v1.2 spec specifies `base64url` for the
   binary fields. The implementation uses, and has always used, standard base64
   (`btoa`/`atob`, with `+`, `/` and `=`). An implementer following the v1.2 text
   literally will produce cells the reference implementation cannot parse.
2. **"N-1 shares reveal nothing"** in §16 should read "fewer than M shares reveal
   nothing". §7 of the same document states it correctly.

Neither affects the priority claim, which is about what existed on 2026-07-18, not about
whether it was free of errors. The full list of corrections is the `1.3 (corrections)`
row of the v1.3 changelog, and the reasoning is in `../../REVIEW-2026-08-09.md`.
