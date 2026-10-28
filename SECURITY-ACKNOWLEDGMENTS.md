# Security Acknowledgments

The people below found and responsibly reported security issues in the
Cellular Defense `.cell` format, its reference implementation, or the
`cd-cert-broker` service. We are grateful to every one of them.

This is the public half of our [Security Policy](SECURITY.md). A finding that
changes the format or implementation is *also* credited in the specification's
errata and revision history — which is OpenTimestamps-anchored in Bitcoin, so
the credit is part of the permanent, independently-verifiable record.

Credit is given as the reporter wishes: real name or handle, with an optional
link. Reporters may decline credit or ask to be listed anonymously.

---

## Hall of fame

*No findings have been published yet. Yours could be the first —
see [SECURITY.md](SECURITY.md).*

<!--
Add newest first. Keep one row per finding. Suggested format:

| Date (report) | Researcher | Finding (one line, no exploit detail until fixed) | Severity | References |
|---|---|---|---|---|
| 2026-11-14 | Jane Doe ([@janedoe](https://example.com)) | Canonicalization ambiguity allowing two documents to share one signature | High | errata §N · [advisory](…) · CVE-2026-XXXXX |

Severity guide: Critical = breaks the central confidentiality/integrity claim;
High = significant access-control or authenticity bypass; Medium = meaningful
leakage or service-level bypass; Low = limited impact with a real path.
Link the anchored errata entry and/or advisory once disclosure is coordinated.
-->

## How to join this list

Read the [Security Policy](SECURITY.md), test against a local or self-hosted
instance (or the format directly), and report privately. Valid findings are
credited here, in the anchored errata when they change the format, via a CVE in
your name where warranted, and in the book *Cellular Defense* for significant
work.
