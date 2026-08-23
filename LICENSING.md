# Licensing

Cellular Defense is deliberately split in two. The **format** is given away
permanently; the **code** is licensed. Read the distinction carefully before
assuming either half constrains the other.

---

## 1. The `.cell` format specification — free, forever, to everyone

`docs/SPEC.md` and every cryptographic construction and technical mechanism it
describes are published as a **defensive disclosure**. No patent is sought or
asserted over them. They are contributed to the public prior art and are
**freely implementable by anyone, for any purpose, commercial or otherwise,
without license, royalty, or permission.**

This is not a courtesy; it is the point. A format whose security claims rest on
being inspectable cannot also be a secret. If you write your own implementation
of `.cell` from the specification — a clean-room implementation that copies no
code from this repository — **you owe Enthropic Data nothing**, and nothing in
this document or the `LICENSE` file changes that.

The specification is therefore **not** licensed under the AGPL. The AGPL applies
to source code in this repository, not to the ideas the specification describes.

## 2. The reference implementation — AGPL-3.0, or a commercial license

The source code in this repository (`cell-crypto.js`, the client, the CLI, the
tooling — everything that is not the specification) is licensed under the
**GNU Affero General Public License, version 3**. The full text is in
[`LICENSE`](LICENSE).

**Personal, educational, research, and non-profit use is free** under the AGPL.
So is commercial use, *provided you comply with the AGPL* — which for most
commercial deployments is the sticking point, because the AGPL requires that:

- if you convey the software, you provide **complete corresponding source** to
  your recipients, under the AGPL (§4–§6); and
- if you let users interact with a **modified** version **over a network**, you
  must offer those users the modified source (§13) — the "Affero clause," which
  closes the hosted-service loophole in the ordinary GPL.

If you cannot or will not publish your modifications under those terms — the
usual case for a proprietary product or a closed hosted service — you need a
**commercial license**.

## 3. The Python and Go implementations, and the conformance suite — Apache-2.0

`impl/` and `conformance/` are licensed under the **Apache License 2.0**
([`impl/python/LICENSE`](impl/python/LICENSE), [`impl/go/LICENSE`](impl/go/LICENSE),
[`conformance/LICENSE`](conformance/LICENSE)) — **not** the AGPL that covers the
rest of this repository.

This is deliberate, and it follows directly from §1. A format that is free to
implement is not actually free to implement if the only way to check your
implementation is against copyleft code. The conformance vectors have to be
usable inside a proprietary product, or they test nothing that matters; and a
reader library nobody can embed is a library, not a format.

So these two directories are permissive on purpose:

- **`conformance/`** — shared test keys and captured `.cell` vectors, with the
  generators that produced them. Use them to validate any implementation, in any
  language, under any license.
- **`impl/python/`** and **`impl/go/`** — independent implementations written
  from `docs/SPEC.md`. Embed them, fork them, ship them in a closed product; the
  Apache license asks only for attribution and the patent grant it carries.

The AGPL in [`LICENSE`](LICENSE) continues to cover `cell-crypto.js`,
`index.html`, `server.js` and the rest of the reference implementation. Two
licenses in one repository is a thing to be explicit about rather than clever
about: **if a file is under `impl/` or `conformance/`, it is Apache-2.0;
otherwise it is AGPL-3.0.** Every source file carries an `SPDX-License-Identifier`
line stating which, and **where a file's SPDX line differs from the positional
rule, the SPDX line governs.**

There is exactly one such file today:
[`impl/python/tests/interop/js_bridge.mjs`](impl/python/tests/interop/js_bridge.mjs)
is **AGPL-3.0-only**, because it loads `cell-crypto.js` in order to run cells
through the reference implementation. It is a test harness, it is needed only to
run the differential tests, and nothing in the Python library imports it — so the
Apache grant over `impl/` is unaffected by it. It is called out here
rather than quietly filed under the directory rule, because a licence you have
to infer from a directory path is a licence somebody gets wrong.

## 4. Commercial licensing

A commercial license removes the AGPL's source-disclosure obligations for your
product, on negotiated terms.

**Contact:** dbrown@enthropicdata.com — Enthropic Data LLC, Weddington, NC.

As sole copyright holder, Enthropic Data can license the same code under other
terms; the AGPL grant here does not restrict that.

## 5. Improvements

The intent of this project is that improvements to the reference implementation
come back to it, so that everyone relying on the format benefits from review of
the same code.

Be aware of what the license does and does not compel, because the difference
matters:

- The AGPL **requires** you to offer corresponding source **to the users of your
  modified version**. It does **not**, by itself, require you to send patches
  upstream to this repository. A user who complies fully with the AGPL and never
  contacts us has done nothing wrong.
- Contributions to *this* repository are accepted under the same AGPL terms,
  and by opening a pull request you license your contribution accordingly.

If upstream contribution is to be a hard requirement rather than an expectation,
that belongs in a commercial agreement or a contributor license agreement, not
in the AGPL. **No CLA is in force today.**

## 6. Related repositories

`cd-cert-broker` and the server-backed `cellular-defense` application are
separate works under separate terms; neither carries a license file at the time
of writing, which under copyright default means all rights reserved. The cert
broker is operated as a hosted service and its implementation is not
open-sourced. Consult each repository — do not assume this file governs them.

---

*This file describes licensing intent in plain language. Where it and the
`LICENSE` text disagree, `LICENSE` governs. It is not legal advice, and the
arrangement above — particularly the spec/code split and the dual-licensing
posture — is worth review by counsel before it is relied on commercially.*
