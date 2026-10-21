// Headless runner for cd-vanilla's browser test suite.
// Loads the real function definitions from index.html and executes the real
// test definitions from tests/test.html against them — no reimplementation.
import { readFileSync } from 'node:fs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

function biggestScript(html) {
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  return blocks.sort((a, b) => b.length - a.length)[0];
}

// --- browser global stubs sufficient for the pure-crypto/format code paths ---
globalThis.window = { location: { origin: 'test://x' }, CompressionStream };
globalThis.location = { hostname: 'localhost', origin: 'test://x' };
globalThis.navigator = { userAgent: 'node' };
globalThis.document = { addEventListener() {}, getElementById() { return null; } };
const _ls = {};
globalThis.localStorage = {
  getItem: k => (k in _ls ? _ls[k] : null),
  setItem: (k, v) => { _ls[k] = String(v); },
  removeItem: k => { delete _ls[k]; },
};
globalThis.indexedDB = {};

// --- load cell-crypto.js functions (extracted from index.html for reuse) ---
const indexJs = readFileSync(`${ROOT}/cell-crypto.js`, 'utf8');
const appExports =
  'return { toB64, fromB64, sha256, toHex, ulid, gfMul, gfInv, shamirSplit, ' +
  'shamirCombine, cellCreate, cellOpen, ecdhWrapCek, ecdhUnwrapCek, ' +
  'pbkdf2WrapCek, pbkdf2UnwrapCek, gzip, gunzip, canonicalize, serializeHeader, ' +
  'blake2b, argon2id, argon2Params, argon2idWrapCek, argon2idUnwrapCek, padmeLength, padBody, unpadBody, ' +
  'crypto: globalThis.crypto };';
const w = new Function(indexJs + '\n;' + appExports)();

// --- load test definitions (trim the DOM runner; we iterate ourselves) ---
let testJs = biggestScript(readFileSync(`${ROOT}/tests/test.html`, 'utf8'));
testJs = testJs.slice(0, testJs.indexOf('// ─── Runner'));
const testApi = new Function(testJs + '\n;return { tests, _setW: (x) => { w = x; } };')();
testApi._setW(w);

// --- run ---
let pass = 0, fail = 0, skipped = 0;
const failures = [];
let section = '';
for (const t of testApi.tests) {
  if (t.section !== section) { section = t.section; console.log(`\n── ${section}`); }
  if (t.skip) { console.log(`  ○ ${t.name} (${t.reason})`); skipped++; continue; }
  const t0 = performance.now();
  try {
    await t.fn();
    console.log(`  ✓ ${t.name} (${(performance.now() - t0).toFixed(0)}ms)`);
    pass++;
  } catch (e) {
    console.log(`  ✗ ${t.name}\n      ${e.message}`);
    failures.push(`${t.section} › ${t.name}: ${e.message}`);
    fail++;
  }
}

const total = pass + fail;
console.log(`\n${'═'.repeat(50)}`);
console.log(`${pass}/${total} passed` + (fail ? ` · ${fail} FAILED` : ' · all pass') +
            (skipped ? ` · ${skipped} skipped (hardware)` : ''));
if (fail) { console.log('\nFailures:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
