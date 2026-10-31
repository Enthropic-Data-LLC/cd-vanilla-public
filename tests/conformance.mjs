// Runs the reference implementation against the shared conformance vectors
// (conformance/vectors/manifest.json) — the same files every port consumes.
// Open vectors must open with the listed keys/passphrases to the exact
// plaintext, filename and signer, and must NOT open with must_not_open_with;
// reject vectors must be refused. Error types are not compared across
// languages: the reasons are the portable part.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
globalThis.window = { location: { origin: 'test://x' }, CompressionStream };
globalThis.location = { hostname: 'localhost', origin: 'test://x' };
globalThis.navigator = { userAgent: 'node' };
globalThis.document = { addEventListener() {}, getElementById() { return null; } };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.indexedDB = {};

const w = new Function(readFileSync(`${ROOT}/cell-crypto.js`, 'utf8') +
  '\n;return { cellOpen, ecdhUnwrapCek, pbkdf2UnwrapCek, argon2idUnwrapCek, fromB64, fp };')();

const VEC = `${ROOT}/conformance/vectors`;
const manifest = JSON.parse(readFileSync(`${VEC}/manifest.json`, 'utf8'));
const keys = {};
async function key(name) {
  if (!keys[name]) {
    const k = JSON.parse(readFileSync(`${ROOT}/conformance/keys/${name}.cdkey`, 'utf8'));
    keys[name] = {
      fingerprint: await w.fp(k.spki),
      priv: await crypto.subtle.importKey('pkcs8', w.fromB64(k.pkcs8), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']),
    };
  }
  return keys[name];
}

async function open(cell, spec) {
  const privs = await Promise.all((spec.keys || []).map(key));
  const passes = spec.passphrases || [];
  return w.cellOpen(cell, async (e) => {
    if (e.method === 'ecdh-p256') {
      for (const k of privs) { try { return await w.ecdhUnwrapCek(e.wrapped_cek, k.priv); } catch { } }
    } else if (e.method === 'pbkdf2' || e.method === 'argon2id') {
      const unwrap = e.method === 'pbkdf2' ? w.pbkdf2UnwrapCek : w.argon2idUnwrapCek;
      for (const p of passes) { try { return await unwrap(e.wrapped_cek, p); } catch { } }
    }
    return null;
  });
}

let pass = 0, fail = 0;
const failures = [];
for (const v of manifest.vectors) {
  const cell = JSON.parse(readFileSync(`${VEC}/${v.file}`, 'utf8'));
  try {
    if (v.expect === 'open') {
      const r = await open(cell, v.open_with);
      const sha = createHash('sha256').update(r.bytes).digest('hex');
      if (sha !== v.plaintext.sha256) throw new Error('plaintext mismatch');
      if (r.filename !== v.filename) throw new Error(`filename ${r.filename}`);
      if (v.signer && r.sigVerified !== (await key(v.signer)).fingerprint) throw new Error(`signer ${r.sigVerified}`);
      if (!v.signer && r.sigVerified) throw new Error('unexpected signature');
      if (v.must_not_open_with) {
        let opened = false;
        try { await open(cell, v.must_not_open_with); opened = true; } catch { }
        if (opened) throw new Error('opened with must_not_open_with');
      }
    } else {
      let refused = false;
      try { await open(cell, v.open_with); } catch { refused = true; }
      if (!refused) throw new Error(`accepted a vector that must be refused (${v.reject_reason})`);
    }
    pass++;
  } catch (e) {
    fail++; failures.push(`${v.id}: ${e.message}`);
  }
}
console.log(`conformance: ${pass}/${pass + fail} vectors` + (fail ? ` · ${fail} FAILED` : ' · all pass'));
if (fail) { failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
