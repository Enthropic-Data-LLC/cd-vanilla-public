# Method: escrowed release — no opening before a date, by quorum

**Status: supported method, adopted 2026-11-10.** Built entirely from format
v1.4 mechanisms: an ECDH entry (SPEC §6.1), an Argon2id passphrase entry
(§6.5), a 2-of-2 quorum (§7) and, optionally, the advisory release date
(§8.1). **No format change.** `docs/SPEC.md` and the anchored bytes are
untouched.

This is the documented answer to recommendation 4 of
[`docs/design/temporal-enforcement.md`](../design/temporal-enforcement.md): the
bare `advisory.release_at` field asks a client not to open early, and an
independent opener ignores it. This method makes early opening *impossible* for
the recipient, by withholding part of the key until a nameable person releases
it. The enforcement is a missing share, not a clock.

---

## 1. What it guarantees, and what it does not

| Property | Status | Enforced by |
|---|---|---|
| The recipient cannot open before the escrow agent releases the passphrase | **Enforced** | Quorum (§7): below the threshold the key does not exist |
| The escrow agent cannot open the cell | **Enforced** | The agent holds only a passphrase, never the cell or the recipient's private key |
| The release happens on the agreed date | **Trust in the agent** | The agent's conduct, not cryptography |
| Optional close: a recipient who has not received the passphrase by a second date never can | **Trust in the agent** | The agent destroying every copy of the passphrase at that date, unreleased |
| A recipient who has opened cannot open again later | **Not enforced, ever** | Nothing can; they keep the plaintext (temporal-enforcement §2) |
| The recipient cannot guess the passphrase | **Only as strong as the passphrase** | Argon2id cost × passphrase randomness (§4) |

---

## 2. Roles

- **Sender.** Seals the cell and writes the escrow instruction (§6).
- **Recipient.** Holds an ECDH key pair and receives the cell at any time,
  including immediately.
- **Escrow agent.** A person or firm the sender trusts to release on the date:
  a lawyer, CPA, executor or trustee. Holds the passphrase and the instruction.
  Never receives the cell.
- **Backup agent** (optional). Holds the *same* passphrase in case the first
  agent is unavailable. See §7 for why it must be the same passphrase and not a
  second entry.

---

## 3. Construction

```
access_map: [
  { method: "ecdh-p256", share_index: 1, ... },   // the recipient's key
  { method: "argon2id",  share_index: 2, ... }    // the escrowed passphrase
]
threshold: { required: 2, of_total: 2 }
lifetime:  { type: "timed_release",
             advisory: { release_at: <T1>, retain_until: null | <T2>, ... },
             disposal: { ... } }
```

- **Exactly two entries.** The threshold is flat across the whole access map,
  so every extra entry creates a new pair that can open without the agent.
  Adding the sender's own key at 2-of-3 lets sender and recipient open together
  before the date; adding a second recipient at 2-of-3 lets the two recipients
  do the same.
- **Several recipients:** seal **one cell per recipient**, each 2-of-2. They may
  share one escrow passphrase, which the agent then releases to all of them at
  once. (A nested alternative also works: an outer passphrase-only cell whose
  content is an inner cell addressed to all recipients. One cell per recipient
  is simpler to reason about.)
- **`release_at` is optional and advisory.** Set it to T1 when the tool allows.
  Conforming clients then show "unlocks <date>", and the AAD binding (§4.4)
  guarantees the recipient sees the sender's true date. It enforces nothing;
  the passphrase does. If T1 is set and the agent releases early, conforming
  clients still wait for T1; independent openers do not.
- **`retain_until` (T2) is advisory too.** The enforced close, if wanted, is the
  agent destroying the passphrase (§6).

---

## 4. The passphrase

**It must be generated, never chosen.** The recipient holds both the cell and
their own key for as long as they like, so the passphrase is the only thing
between them and the content, and they can guess offline with no limit on time.
Argon2id at the v1.4 defaults (64 MiB, 3 passes) makes each guess expensive. It
does not rescue a phrase a person made up.

Use **at least 128 bits of randomness**. Either of these is enough:

```sh
# 6 groups of 5 random letters (~141 bits); easy to read aloud
python3 -c "import secrets,string as s; print('-'.join(''.join(secrets.choice(s.ascii_lowercase) for _ in range(5)) for _ in range(6)))"

# 10 words from the EFF large diceware list (~129 bits), rolled with real dice
```

- **The sender should not keep a copy.** They do not need it: they have the
  plaintext.
- **The release channel does not need to be secret.** The passphrase opens
  nothing without the recipient's private key, so the agent can release it by
  phone, letter or email. The only party it must be kept from before the date
  is the recipient.

---

## 5. Steps

### 5.1 Recipient (once)

Generate a key pair and send the public half to the sender.

```sh
cdcell keygen -label "Recipient Name" -out recipient
# send recipient.cdpub; keep recipient.cdkey
```

The browser app's keychain works too; export the `.cdpub` from it.

### 5.2 Sender — Go CLI

```sh
cdcell seal letter.pdf -to recipient.cdpub -passphrase -threshold 2 -out letter.cell
```

Paste the generated passphrase at both prompts. The Go CLI cannot set a
lifetime yet (gap G3), so the cell carries no advisory release date; put the
date in the escrow instruction.

### 5.3 Sender — browser app

1. Choose the file.
2. **+ From keychain** (or **+ Paste pubkey**) → the recipient's public key.
3. **+ Passphrase** → paste the generated passphrase.
4. **Quorum threshold** → `2` of 2.
5. **Lifetime** → *Timed release — unlocks at date*, set **Unlock at** to T1.
6. Encrypt and send the cell to the recipient.

### 5.4 Sender → agent

Give the agent the passphrase and the signed escrow instruction (§6). Not the
cell.

### 5.5 Recipient — opening, after release

```sh
cdcell open letter.cell -key recipient.cdkey -passphrase -out .
```

**The browser app cannot open this cell yet** (gap G1): each open button
supplies one kind of credential, so a key-plus-passphrase quorum is never met.
Until G1 is fixed, recipients open with the Go CLI.

---

## 6. Escrow instruction (template)

```
ESCROW INSTRUCTION — sealed document, escrowed release

Document:        <description; NOT the content>
Recipient:       <name, and how the agent will confirm their identity>
Release on:      <T1, with time zone>
Release by:      <phone / letter / email to a confirmed address>
Close (optional):If not released to the recipient by <T2>, destroy every copy
                 of the passphrase and confirm destruction to <sender/estate>.
If unreachable:  <what to do if the recipient cannot be found by T1>
Backup agent:    <name, or "none"> — holds the same passphrase under the same terms
Storage:         <sealed envelope in the firm's safe / password manager entry>

The passphrase opens nothing on its own. Do not release it before the date
above, to the recipient or anyone else.

Signed: <sender>   Accepted: <agent>   Date: <date>
```

---

## 7. Failure modes

| What goes wrong | Result | Mitigation |
|---|---|---|
| Agent loses the passphrase | The cell can never be opened | A backup agent holding the **same** passphrase. Trust then becomes "either agent could release early" |
| A second passphrase *entry* is added for the backup agent instead | At 2-of-3, the two agents together open it without the recipient | Never do this. Same passphrase, not a second entry |
| Recipient loses their private key | The cell can never be opened | As for any cell; the sender may still hold the plaintext and re-seal |
| Agent releases early | Recipient opens early | Choice of agent; the written instruction |
| Recipient's clock is wrong and T1 is set | Conforming clients refuse until their own clock passes T1 | Correct the clock, or `cdcell open … -ignore-advisory` |
| Weak passphrase | Recipient guesses it offline | §4: generate, ≥ 128 bits |

---

## 8. Verified

**2026-11-10**, with the Go CLI (`impl/go/cmd/cdcell`), on a v1.4 cell sealed
`-to recipient.cdpub -passphrase -threshold 2`:

| Opened with | Result |
|---|---|
| Recipient key only | `quorum not met: need 2, unlocked 1` |
| Passphrase only | `quorum not met: need 2, unlocked 1` |
| Recipient key + wrong passphrase | `quorum not met: need 2, unlocked 1` |
| Recipient key + correct passphrase | Opened; plaintext matched |

Conformance vector `v13-quorum-2of3-mixed` (ECDH shares with a passphrase
share) exercises the same mixed-quorum path in the JS library.

---

## 9. Known gaps

| ID | Gap | Fix |
|---|---|---|
| **G1** | The browser app cannot open a key-plus-passphrase quorum: **Use keychain key** tries only ECDH entries and **Enter passphrase** only passphrase entries. The library (`cellOpen`) already supports it | One open flow that collects a keychain key *and* a passphrase before calling `cellOpen`, offered when the threshold is above 1 |
| **G2** | Go CLI `seal -passphrase` reads each prompt with a fresh buffered reader, so piped input loses the second line (`error: EOF`). Interactive use is unaffected | One shared `bufio.Reader` for stdin |
| **G3** | Go CLI `seal` has no lifetime flag, so CLI-sealed cells carry no advisory release date | `-release-at` (and `-retain-until`) flags |
| **G4** | The app's passphrase dialog has no generator, so users will type weak passphrases for exactly the case where it matters most | A **Generate** button, ≥ 128 bits |

---

## 10. Possible extensions — logged, not adopted

Considered on 2026-11-10 and kept for later. None is part of the supported
method; each would need its own decision.

| ID | Extension | Adds | Trust | Cost / blocker | Where it is discussed |
|---|---|---|---|---|---|
| **X1** | **Escrow share hand-off** | The agent holds an ECDH key instead of a passphrase; at release they unwrap their share and hand the raw share to the recipient. Removes the weak-passphrase risk entirely | The agent | A share export/import format in clients (today `cellOpen` must unlock every share in one session). No change to the cell format | — |
| **X2** | **Time-gate escrow service** | An online service holds a per-cell key, answers only inside [T1, T2] on its own clock, deletes the key at T2. Also turns `single_use` and `retain_until` into enforced properties for anyone who has not yet opened | The operator (could release early under compromise or compulsion) | New access-map method → spec revision + fresh anchor. Keys must live **outside** routine backups (a backed-up key is not deleted) — crypto-shred by encrypting each key under a per-day key. Downtime across the whole window loses the cell | — |
| **X3** | **drand `tlock` access-map entry** | Start enforced by a threshold of independent beacon operators; no party we run can release early | drand threshold | A BLS12-381 pairing library, which the Web Crypto API lacks — conflicts with the "download nothing" rule. Decision open | `extension-profiles.md` §4, `temporal-enforcement.md` §4.1 |
| **X4** | **3-of-3: recipient + `tlock` + time-gate** | The closest thing to a time window: the beacon opens it, the service's deletion closes it | drand for the start; the operator for the close | X2 and X3 | — |
| **X5** | **Cloud KMS escrow** | A provider key whose policy allows decryption only between T1 and T2 (e.g. AWS KMS with an `aws:CurrentTime` condition), disabled at T2 | The provider, and whoever administers the account (they can edit the policy) | A vendor dependency; deletion waits at least 7 days after disabling; roughly $1 per key per month | — |
| **X6** | **Self-hosted time-gate** | X2 run by the firm itself, for customers who will not trust us | The firm | X2, packaged | — |
| **X7** | **Time-lock puzzles / VDFs** | No third party at all | None | Precision is a factor of several (solver hardware), and the recipient burns CPU throughout. "Not for roughly a week", never "opens 10:00 Monday" | `temporal-enforcement.md` §4.2 |
| **X8** | **Witness encryption to a blockchain height** | Start enforced by accumulated proof of work | The chain's honest majority | Research only; witness encryption is not practical today | `temporal-enforcement.md` §3 (chain-anchored time) |

**Not an extension, and never will be:** stopping a recipient who has already
opened the cell from opening it again after a date. No cipher can do it. A
recipient who could open at one moment can copy everything they used and repeat
the calculation later (`temporal-enforcement.md` §2). Every extension above
closes a window only against someone who has not yet opened.
