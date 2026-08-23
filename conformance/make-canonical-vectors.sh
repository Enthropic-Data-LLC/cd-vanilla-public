#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate conformance/vectors/canonical.json from the reference implementation.
#
# The expected strings come from cell-crypto.js and nowhere else. Canonical
# serialization is defined by deferring to JavaScript's JSON.stringify (spec
# §4.1.1), so JavaScript is the authority on what the right answer is; every
# other implementation is checking itself against it, not the other way round.
#
# Requires node and python3. Run from the repository root:
#     ./conformance/make-canonical-vectors.sh
set -euo pipefail
cd "$(dirname "$0")/.."
python3 conformance/_canonical_corpus.py > /tmp/cd-canonical-corpus.json
node conformance/_canonical_expected.mjs /tmp/cd-canonical-corpus.json conformance/vectors/canonical.json
rm -f /tmp/cd-canonical-corpus.json
echo "wrote conformance/vectors/canonical.json"
