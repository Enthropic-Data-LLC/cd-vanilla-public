// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: AGPL-3.0-only
//
// Runs the corpus through the reference implementation's canonicalize() to
// produce the expected strings. AGPL because it loads cell-crypto.js; it is a
// generator, not part of any shipped library. See make-canonical-vectors.sh.
import { readFileSync, writeFileSync } from 'node:fs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
globalThis.window = { location: { origin: 'test://x' }, CompressionStream };
globalThis.location = { hostname: 'localhost', origin: 'test://x' };
globalThis.navigator = { userAgent: 'node' };
globalThis.document = { addEventListener() {}, getElementById() { return null; } };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.indexedDB = {};

const w = new Function(readFileSync(`${ROOT}/cell-crypto.js`, 'utf8') + '\n;return { canonicalize };')();
const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));

writeFileSync(process.argv[3], JSON.stringify({
  note: 'Canonical serialization vectors (spec §4.1.1). expected[] is what the reference '
      + 'implementation cell-crypto.js produces, which is what header_hash, header_sig and '
      + 'the AES-GCM AAD are computed over. Regenerate with conformance/make-canonical-vectors.sh.',
  spec_section: '4.1.1',
  generated_from: 'cell-crypto.js canonicalize()',
  cases: cases.map(c => ({ name: c.name, input: c.input, expected: w.canonicalize(c.input) })),
}, null, 2) + '\n');
console.log(`wrote ${cases.length} canonical vectors from the reference`);
