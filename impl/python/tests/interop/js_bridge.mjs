// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: AGPL-3.0-only
//
// Bridge to the AGPL reference implementation, for differential testing only.
// Loads the real cell-crypto.js the same way tests/run.mjs does — no
// reimplementation — and exposes seal/open/canonicalize over argv + JSON files
// so the Python suite can drive it.
//
//   node js_bridge.mjs keypair <out.json>
//   node js_bridge.mjs seal <spec.json> <out.cell>
//   node js_bridge.mjs open <in.cell> <spec.json> <out.json>
//   node js_bridge.mjs canonicalize <in.json> <out.txt>
import { readFileSync, writeFileSync } from 'node:fs';

const ROOT = new URL('../../../..', import.meta.url).pathname.replace(/\/$/, '');

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

const src = readFileSync(`${ROOT}/cell-crypto.js`, 'utf8');
const exportsList =
  'return { toB64, fromB64, sha256, toHex, canonicalize, serializeHeader, cellAad, ' +
  'cellCreate, cellOpen, ecdhUnwrapCek, pbkdf2UnwrapCek };';
const w = new Function(src + '\n;' + exportsList)();

// A minimal stand-in for the browser File the reference expects.
function fileOf(bytes, name, type) {
  return { name, type, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
}

async function genKeypair(label) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const spki = w.toB64(new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey)));
  const pkcs8 = w.toB64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)));
  return { label, method: 'ecdh-p256', spki, pkcs8, fingerprint: w.toHex(await w.sha256(w.fromB64(spki))).slice(0, 16) };
}

async function privFrom(pkcs8B64) {
  return crypto.subtle.importKey('pkcs8', w.fromB64(pkcs8B64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}

const [, , cmd, a, b, c] = process.argv;

if (cmd === 'keypair') {
  writeFileSync(a, JSON.stringify(await genKeypair(b || 'Key'), null, 2));

} else if (cmd === 'canonicalize') {
  // Read as text and parse ourselves so key order survives exactly as written.
  writeFileSync(b, w.canonicalize(JSON.parse(readFileSync(a, 'utf8'))));

} else if (cmd === 'seal') {
  const spec = JSON.parse(readFileSync(a, 'utf8'));
  const bytes = Uint8Array.from(Buffer.from(spec.data_b64, 'base64'));
  const cell = await w.cellCreate(
    fileOf(bytes, spec.filename, spec.content_type || ''),
    spec.recipients,
    {
      threshold: spec.threshold || 1,
      lifetime: spec.lifetime || null,
      policy: spec.policy || undefined,
      prevHash: spec.prev_hash || null,
      meta: spec.meta || undefined,
      senderRec: spec.sender || undefined,
    },
  );
  writeFileSync(b, JSON.stringify(cell, null, 2));

} else if (cmd === 'open') {
  const cell = JSON.parse(readFileSync(a, 'utf8'));
  const spec = JSON.parse(readFileSync(b, 'utf8'));
  const privs = await Promise.all((spec.keys || []).map(async k => ({ fp: k.fingerprint, key: await privFrom(k.pkcs8) })));
  const result = await w.cellOpen(cell, async (entry) => {
    if (entry.method === 'ecdh-p256') {
      for (const p of privs) {
        try { return await w.ecdhUnwrapCek(entry.wrapped_cek, p.key); } catch { /* next */ }
      }
      return null;
    }
    if (entry.method === 'pbkdf2') {
      for (const pass of spec.passphrases || []) {
        try { return await w.pbkdf2UnwrapCek(entry.wrapped_cek, pass); } catch { /* next */ }
      }
      return null;
    }
    return null;
  });
  writeFileSync(c, JSON.stringify({
    data_b64: Buffer.from(result.bytes).toString('base64'),
    filename: result.filename,
    content_type: result.contentType,
    meta: result.meta,
    sig_verified: result.sigVerified,
  }, null, 2));

} else {
  console.error(`unknown command ${cmd}`);
  process.exit(2);
}
