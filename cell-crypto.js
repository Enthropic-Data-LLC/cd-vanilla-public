// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: AGPL-3.0-only
//
// Licensed under the GNU Affero General Public License v3 (see LICENSE).
// A commercial licence is available from Enthropic Data LLC — see LICENSING.md.
// The .cell FORMAT itself is a defensive disclosure and is not covered by the
// AGPL: an independent implementation written from docs/SPEC.md owes nothing.
//
// Cell Format crypto library — reusable across Enthropic projects.
// Requires: WebCrypto API, CompressionStream/DecompressionStream, IndexedDB, localStorage.
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════════════════════════

function toB64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str);
}
function fromB64(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function parsePemKey(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return fromB64(b64);
}
function toHex(buf) {
  return Array.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha256(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data)
              : data instanceof Uint8Array ? data : new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
async function fp(spkiB64) {
  return toHex(await sha256(fromB64(spkiB64))).slice(0, 16);
}
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(1) + ' MB';
}
function fmtDate(ts) {
  return new Date(ts * 1000).toLocaleString('en-US',
    { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
// Escape for a single-quoted JS string embedded in a double-quoted HTML attribute (e.g. onclick="fn('${jsq(x)}')").
// JS-string escaping first, then HTML-attribute escaping, so neither layer can be broken out of.
function jsq(s) {
  return String(s == null ? '' : s)
    .replace(/\\/g, '\\\\').replace(/'/g, "\\'")
    .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
// Sanitise attacker-supplied identifiers from imported .cdkey/.cdpub files so
// they can never carry HTML/JS into the DOM. keyId → safe charset (else fresh
// UUID); fingerprint → lowercase hex (else dropped and recomputed from SPKI).
function safeKeyId(id) {
  return (typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id)) ? id : crypto.randomUUID();
}
function safeFingerprint(fpr) {
  return (typeof fpr === 'string' && /^[0-9a-f]{1,64}$/.test(fpr)) ? fpr : null;
}
async function assertValidSpki(spkiB64) {
  try {
    await crypto.subtle.importKey('spki', fromB64(spkiB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  } catch { throw new Error('Invalid SPKI public key'); }
}
function ulid() {
  const E = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let t = Date.now(), s = new Array(26);
  for (let i = 9; i >= 0; i--) { s[i] = E[t & 31]; t = Math.floor(t / 32); }
  const r = crypto.getRandomValues(new Uint8Array(10));
  let bits = 0, avail = 0, ri = 0;
  for (let i = 10; i < 26; i++) {
    if (avail < 5) { bits = (bits << 8) | r[ri++]; avail += 8; }
    avail -= 5; s[i] = E[(bits >> avail) & 31];
  }
  return s.join('');
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPRESSION / DECOMPRESSION
// ═══════════════════════════════════════════════════════════════════════════

async function gzip(bytes) {
  const cs = new CompressionStream('gzip');
  const w = cs.writable.getWriter(); w.write(bytes); w.close();
  return collectStream(cs.readable);
}
async function gunzip(bytes) {
  const ds = new DecompressionStream('gzip');
  const w = ds.writable.getWriter(); w.write(bytes); w.close();
  return collectStream(ds.readable);
}
// Guard against gzip bombs: a few KB can decompress to many GB and OOM the tab.
const MAX_DECOMPRESSED = 2 * 1024 * 1024 * 1024; // 2 GiB
async function collectStream(readable, maxBytes = MAX_DECOMPRESSED) {
  const chunks = []; const r = readable.getReader(); let total = 0;
  for (;;) {
    const {done, value} = await r.read(); if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { try { await r.cancel(); } catch {} throw new Error('Decompressed size exceeds safety limit'); }
    chunks.push(value);
  }
  const out = new Uint8Array(total); let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — CEK (Content Encryption Key, 256-bit AES-GCM)
// ═══════════════════════════════════════════════════════════════════════════

async function cekGenerate() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function cekExportRaw(cek) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', cek));
}
async function cekEncrypt(cek, plainBytes, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  const ct = await crypto.subtle.encrypt(params, cek, plainBytes);
  return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}
async function cekDecrypt(cekRaw, ivB64, ctB64, aad) {
  const cek = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['decrypt']);
  const params = { name: 'AES-GCM', iv: fromB64(ivB64) };
  if (aad) params.additionalData = aad;
  return new Uint8Array(await crypto.subtle.decrypt(params, cek, fromB64(ctB64)));
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — ECDH P-256 KEY WRAP / UNWRAP
// Per spec §4.1: ECDH shared secret → HKDF-SHA256 → AES-KW (not raw ECDH).
// hkdf_salt is 32 random bytes stored alongside the wrapped CEK.
// ═══════════════════════════════════════════════════════════════════════════

// Format version constants — checked on open to give clear errors on unknown versions
const CELL_FORMAT_VERSION = '1.4';
const SUPPORTED_VERSIONS  = new Set(['1.0', '1.1', '1.2', '1.3', '1.4']);

// Versions whose hash/signature/AAD are computed over the CANONICAL
// serialization (§4.1.1) rather than insertion-ordered JSON.stringify.
// Adding a version without adding it here silently downgrades it to the
// v1.0 serialization — the exact class of mistake §12 exists to prevent.
const CANONICAL_VERSIONS = new Set(['1.2', '1.3', '1.4']);

// Versions that bind advisory metadata to the ciphertext as AES-GCM AAD
// (§4.4). Kept as a set for the same reason: adding 1.3 to SUPPORTED_VERSIONS
// while leaving an inline `v === '1.1' || v === '1.2'` test elsewhere silently
// decrypts new cells with no AAD, losing the binding without any error.
const AAD_VERSIONS = new Set(['1.1', '1.2', '1.3', '1.4']);

// v1.4 (§4.4, §5.4, §6, §4.5) — each feature gated by its own set, for the
// same reason as above:
//   VERSIONED_AAD  the format version itself is part of the AAD
//   PADDED         payload body is length-framed and Padmé-padded
//   INNER_SIG      sender signature lives inside the encrypted manifest;
//                  header_sig / header_sig_by / header_sig_key must be absent
//   BLIND_ENTRIES  access-map entries carry no fingerprint or label;
//                  openers find their entry by trial decryption
const VERSIONED_AAD_VERSIONS = new Set(['1.4']);
const PADDED_VERSIONS        = new Set(['1.4']);
const INNER_SIG_VERSIONS     = new Set(['1.4']);
const BLIND_ENTRY_VERSIONS   = new Set(['1.4']);

// Trial decryption costs one ECDH per (entry × local key); bound the map so a
// hostile cell cannot make opening it arbitrarily expensive.
const MAX_ACCESS_ENTRIES = 256;

const HKDF_INFO = new TextEncoder().encode('cellular-defense-cek-wrap-v1');

async function _hkdfWrapKey(sharedBits, salt, usage) {
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: HKDF_INFO },
    hkdfKey,
    { name: 'AES-KW', length: 256 },
    false,
    [usage]
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — SHAMIR SECRET SHARING OVER GF(256) (spec §5.2 threshold/quorum)
// ═══════════════════════════════════════════════════════════════════════════

function gfMul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}
function gfInv(x) {
  let r = 1, base = x, e = 254;
  while (e) { if (e & 1) r = gfMul(r, base); base = gfMul(base, base); e >>= 1; }
  return r;
}
function shamirSplit(secret, n, k) {
  const shares = Array.from({length: n}, (_, i) => ({ x: i + 1, data: new Uint8Array(secret.length) }));
  for (let bi = 0; bi < secret.length; bi++) {
    const c = new Uint8Array(k);
    c[0] = secret[bi];
    crypto.getRandomValues(c.subarray(1));
    for (const {x, data} of shares) {
      let y = c[k - 1];
      for (let i = k - 2; i >= 0; i--) y = gfMul(y, x) ^ c[i];
      data[bi] = y;
    }
  }
  return shares;
}
function shamirCombine(shares) {
  if (!shares.length) throw new Error('No shares to combine');
  const xs = shares.map(s => s.x);
  if (xs.some(x => !Number.isInteger(x) || x < 1 || x > 255))
    throw new Error('Invalid share index — must be 1..255');
  if (new Set(xs).size !== xs.length)
    throw new Error('Duplicate share indices — cannot reconstruct secret');
  const out = new Uint8Array(shares[0].data.length);
  for (let bi = 0; bi < out.length; bi++) {
    let s = 0;
    for (let i = 0; i < shares.length; i++) {
      let num = 1, den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        num = gfMul(num, shares[j].x);
        den = gfMul(den, shares[i].x ^ shares[j].x);
      }
      s ^= gfMul(shares[i].data[bi], gfMul(num, gfInv(den)));
    }
    out[bi] = s;
  }
  return out;
}

async function ecdhWrapCek(cekRaw, recipientSpkiB64) {
  const recipPub = await crypto.subtle.importKey(
    'spki', fromB64(recipientSpkiB64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const eph = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: recipPub }, eph.privateKey, 256
  );
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const wrapKey = await _hkdfWrapKey(sharedBits, salt, 'wrapKey');
  const cekKey = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', true, ['encrypt']);
  const wrapped = await crypto.subtle.wrapKey('raw', cekKey, wrapKey, 'AES-KW');
  const ephSpki = await crypto.subtle.exportKey('spki', eph.publicKey);
  return {
    eph_spki:  toB64(new Uint8Array(ephSpki)),
    hkdf_salt: toB64(salt),
    ct:        toB64(new Uint8Array(wrapped)),
  };
}

async function ecdhUnwrapCek(wrappedCek, privateKey) {
  const ephPub = await crypto.subtle.importKey(
    'spki', fromB64(wrappedCek.eph_spki),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: ephPub }, privateKey, 256
  );
  let wrapKey;
  if (wrappedCek.hkdf_salt) {
    // v1.0 / v2.1+: ECDH → HKDF-SHA256 → AES-KW  (spec §4.1)
    wrapKey = await _hkdfWrapKey(sharedBits, fromB64(wrappedCek.hkdf_salt), 'unwrapKey');
  } else {
    // legacy v2.0: ECDH shared bits used directly as AES-KW key (pre-spec)
    wrapKey = await crypto.subtle.importKey(
      'raw', new Uint8Array(sharedBits).slice(0, 32), 'AES-KW', false, ['unwrapKey']
    );
  }
  const cekKey = await crypto.subtle.unwrapKey(
    'raw', fromB64(wrappedCek.ct), wrapKey, 'AES-KW',
    { name: 'AES-GCM' }, true, ['decrypt']
  );
  return new Uint8Array(await crypto.subtle.exportKey('raw', cekKey));
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — PBKDF2 KEY WRAP / UNWRAP
// ═══════════════════════════════════════════════════════════════════════════

async function pbkdf2WrapCek(cekRaw, passphrase, saltIn) {
  const salt = saltIn || crypto.getRandomValues(new Uint8Array(32));
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const wrap = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    base, { name: 'AES-KW', length: 256 }, false, ['wrapKey']
  );
  const cekKey = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', true, ['encrypt']);
  const wrapped = await crypto.subtle.wrapKey('raw', cekKey, wrap, 'AES-KW');
  return { salt: toB64(salt), iterations: 600000, ct: toB64(new Uint8Array(wrapped)) };
}

async function pbkdf2UnwrapCek(wrappedCek, passphrase) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const wrap = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromB64(wrappedCek.salt), iterations: wrappedCek.iterations || 600000, hash: 'SHA-256' },
    base, { name: 'AES-KW', length: 256 }, false, ['unwrapKey']
  );
  const cekKey = await crypto.subtle.unwrapKey(
    'raw', fromB64(wrappedCek.ct), wrap, 'AES-KW', { name: 'AES-GCM' }, true, ['decrypt']
  );
  return new Uint8Array(await crypto.subtle.exportKey('raw', cekKey));
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — BLAKE2b (RFC 7693) and Argon2id (RFC 9106), plain JavaScript
//
// WebCrypto has neither, and this file deliberately has no dependencies, so
// both are implemented here. 64-bit words are held as pairs of 32-bit halves
// (low, high) in Uint32Arrays. Checked against RFC 9106 §5.3 and the reference
// implementation (argon2-cffi) in tests/run.mjs and the Python port.
// ═══════════════════════════════════════════════════════════════════════════

const B2B_IV32 = new Uint32Array([
  0xF3BCC908, 0x6A09E667, 0x84CAA73B, 0xBB67AE85, 0xFE94F82B, 0x3C6EF372, 0x5F1D36F1, 0xA54FF53A,
  0xADE682D1, 0x510E527F, 0x2B3E6C1F, 0x9B05688C, 0xFB41BD6B, 0x1F83D9AB, 0x137E2179, 0x5BE0CD19,
]);
const B2B_SIGMA = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
].map(x => x * 2);

// v, m: Uint32Array(32). a..d, ix, iy: indices of 64-bit words ×2.
function _b2bG(v, m, a, b, c, d, ix, iy) {
  let o0, o1, x0, x1;
  // v[a] += v[b] + m[ix]
  o0 = v[a] + v[b]; o1 = v[a + 1] + v[b + 1]; if (o0 >= 0x100000000) o1++;
  o0 = (o0 >>> 0) + m[ix]; o1 += m[ix + 1]; if (o0 >= 0x100000000) o1++;
  v[a] = o0; v[a + 1] = o1;
  // v[d] = rotr64(v[d] ^ v[a], 32)
  x0 = v[d] ^ v[a]; x1 = v[d + 1] ^ v[a + 1]; v[d] = x1; v[d + 1] = x0;
  // v[c] += v[d]
  o0 = v[c] + v[d]; o1 = v[c + 1] + v[d + 1]; if (o0 >= 0x100000000) o1++; v[c] = o0; v[c + 1] = o1;
  // v[b] = rotr64(v[b] ^ v[c], 24)
  x0 = v[b] ^ v[c]; x1 = v[b + 1] ^ v[c + 1];
  v[b] = (x0 >>> 24) ^ (x1 << 8); v[b + 1] = (x1 >>> 24) ^ (x0 << 8);
  // v[a] += v[b] + m[iy]
  o0 = v[a] + v[b]; o1 = v[a + 1] + v[b + 1]; if (o0 >= 0x100000000) o1++;
  o0 = (o0 >>> 0) + m[iy]; o1 += m[iy + 1]; if (o0 >= 0x100000000) o1++;
  v[a] = o0; v[a + 1] = o1;
  // v[d] = rotr64(v[d] ^ v[a], 16)
  x0 = v[d] ^ v[a]; x1 = v[d + 1] ^ v[a + 1];
  v[d] = (x0 >>> 16) ^ (x1 << 16); v[d + 1] = (x1 >>> 16) ^ (x0 << 16);
  // v[c] += v[d]
  o0 = v[c] + v[d]; o1 = v[c + 1] + v[d + 1]; if (o0 >= 0x100000000) o1++; v[c] = o0; v[c + 1] = o1;
  // v[b] = rotr64(v[b] ^ v[c], 63)
  x0 = v[b] ^ v[c]; x1 = v[b + 1] ^ v[c + 1];
  v[b] = (x1 >>> 31) ^ (x0 << 1); v[b + 1] = (x0 >>> 31) ^ (x1 << 1);
}

function _b2bCompress(h, block, t, last) {
  const v = new Uint32Array(32), m = new Uint32Array(32);
  for (let i = 0; i < 16; i++) { v[i] = h[i]; v[i + 16] = B2B_IV32[i]; }
  v[24] ^= t >>> 0; v[25] ^= Math.floor(t / 0x100000000);   // counter, low 64 bits
  if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
  for (let i = 0; i < 32; i++)
    m[i] = block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
  for (let r = 0; r < 12; r++) {
    const s = r * 16;
    _b2bG(v, m, 0, 8, 16, 24, B2B_SIGMA[s], B2B_SIGMA[s + 1]);
    _b2bG(v, m, 2, 10, 18, 26, B2B_SIGMA[s + 2], B2B_SIGMA[s + 3]);
    _b2bG(v, m, 4, 12, 20, 28, B2B_SIGMA[s + 4], B2B_SIGMA[s + 5]);
    _b2bG(v, m, 6, 14, 22, 30, B2B_SIGMA[s + 6], B2B_SIGMA[s + 7]);
    _b2bG(v, m, 0, 10, 20, 30, B2B_SIGMA[s + 8], B2B_SIGMA[s + 9]);
    _b2bG(v, m, 2, 12, 22, 24, B2B_SIGMA[s + 10], B2B_SIGMA[s + 11]);
    _b2bG(v, m, 4, 14, 16, 26, B2B_SIGMA[s + 12], B2B_SIGMA[s + 13]);
    _b2bG(v, m, 6, 8, 18, 28, B2B_SIGMA[s + 14], B2B_SIGMA[s + 15]);
  }
  for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i + 16];
}

// One-shot unkeyed BLAKE2b; outlen 1..64 bytes.
function blake2b(input, outlen = 64) {
  if (!(outlen >= 1 && outlen <= 64)) throw new Error('blake2b: outlen must be 1..64');
  const h = new Uint32Array(B2B_IV32);
  h[0] ^= 0x01010000 ^ outlen;
  const block = new Uint8Array(128);
  let t = 0, off = 0;
  // every full block except the last is compressed as non-final
  while (input.length - off > 128) {
    block.set(input.subarray(off, off + 128));
    t += 128; _b2bCompress(h, block, t, false); off += 128;
  }
  block.fill(0); block.set(input.subarray(off));
  t += input.length - off;
  _b2bCompress(h, block, t, true);
  const out = new Uint8Array(outlen);
  for (let i = 0; i < outlen; i++) out[i] = h[i >> 2] >>> (8 * (i & 3));
  return out;
}

const _le32 = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
function _concat(...parts) {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// H' — Argon2's variable-length hash (RFC 9106 §3.3).
function _argon2Hprime(input, T) {
  const x = _concat(_le32(T), input);
  if (T <= 64) return blake2b(x, T);
  const out = new Uint8Array(T);
  const r = Math.ceil(T / 32) - 2;
  let v = blake2b(x, 64);
  out.set(v.subarray(0, 32), 0);
  for (let i = 1; i < r; i++) { v = blake2b(v, 64); out.set(v.subarray(0, 32), i * 32); }
  out.set(blake2b(v, T - 32 * r), 32 * r);
  return out;
}

// fBlaMka + G over 64-bit words at word indices a,b,c,d of Uint32Array B.
// fBlaMka(x, y) = x + y + 2 * lo32(x) * lo32(y)  (mod 2^64)
function _bla(B, a, b) {
  const xa = B[a], ya = B[b];
  // 32×32 → 64-bit product of the low halves, split into 16-bit limbs
  const a0 = xa & 0xffff, a1 = xa >>> 16, b0 = ya & 0xffff, b1 = ya >>> 16;
  const p00 = a0 * b0, cross = a0 * b1 + a1 * b0 + (p00 >>> 16);
  let plo = (((cross & 0xffff) * 0x10000) + (p00 & 0xffff)) >>> 0;
  let phi = (a1 * b1 + Math.floor(cross / 0x10000)) >>> 0;
  // ×2
  phi = ((phi << 1) | (plo >>> 31)) >>> 0; plo = (plo << 1) >>> 0;
  // x + y + 2xy
  let lo = B[a] + B[b], hi = B[a + 1] + B[b + 1]; if (lo >= 0x100000000) hi++;
  lo = (lo >>> 0) + plo; hi += phi; if (lo >= 0x100000000) hi++;
  B[a] = lo; B[a + 1] = hi;
}
function _argonG(B, a, b, c, d) {
  let x0, x1;
  _bla(B, a, b);
  x0 = B[d] ^ B[a]; x1 = B[d + 1] ^ B[a + 1]; B[d] = x1; B[d + 1] = x0;                       // rotr 32
  _bla(B, c, d);
  x0 = B[b] ^ B[c]; x1 = B[b + 1] ^ B[c + 1];
  B[b] = (x0 >>> 24) ^ (x1 << 8); B[b + 1] = (x1 >>> 24) ^ (x0 << 8);                       // rotr 24
  _bla(B, a, b);
  x0 = B[d] ^ B[a]; x1 = B[d + 1] ^ B[a + 1];
  B[d] = (x0 >>> 16) ^ (x1 << 16); B[d + 1] = (x1 >>> 16) ^ (x0 << 16);                     // rotr 16
  _bla(B, c, d);
  x0 = B[b] ^ B[c]; x1 = B[b + 1] ^ B[c + 1];
  B[b] = (x1 >>> 31) ^ (x0 << 1); B[b + 1] = (x0 >>> 31) ^ (x1 << 1);                       // rotr 63
}
// BLAKE2 round without message over 16 words given by word indices w[0..15].
function _argonP(B, w) {
  _argonG(B, w[0], w[4], w[8], w[12]);  _argonG(B, w[1], w[5], w[9], w[13]);
  _argonG(B, w[2], w[6], w[10], w[14]); _argonG(B, w[3], w[7], w[11], w[15]);
  _argonG(B, w[0], w[5], w[10], w[15]); _argonG(B, w[1], w[6], w[11], w[12]);
  _argonG(B, w[2], w[7], w[8], w[13]);  _argonG(B, w[3], w[4], w[9], w[14]);
}
// Precomputed Uint32 offsets (word index × 2) for the 8 row and 8 column rounds.
const _ARGON_ROWS = Array.from({ length: 8 }, (_, i) => Array.from({ length: 16 }, (_, j) => (16 * i + j) * 2));
const _ARGON_COLS = Array.from({ length: 8 }, (_, i) => Array.from({ length: 16 }, (_, j) =>
  (2 * i + (j & 1) + 16 * (j >> 1)) * 2));

// G compression (RFC 9106 §3.5): next = P(prev ^ ref) ^ (prev ^ ref) [^ next if xor]
// mem: Uint32Array; offsets are Uint32 indices of 1024-byte blocks (256 words).
const _R = new Uint32Array(256), _Z = new Uint32Array(256);
function _fillBlock(mem, prevOff, refOff, nextOff, withXor, R = _R, Z = _Z) {
  for (let i = 0; i < 256; i++) R[i] = mem[prevOff + i] ^ mem[refOff + i];
  if (withXor) for (let i = 0; i < 256; i++) Z[i] = R[i] ^ mem[nextOff + i];
  else Z.set(R);
  for (let i = 0; i < 8; i++) _argonP(R, _ARGON_ROWS[i]);
  for (let i = 0; i < 8; i++) _argonP(R, _ARGON_COLS[i]);
  for (let i = 0; i < 256; i++) mem[nextOff + i] = Z[i] ^ R[i];
}

// Argon2id, version 0x13. password/salt: Uint8Array; m in KiB; returns Uint8Array(tagLen).
// secret/ad are Argon2's optional K and X inputs; the format uses neither (they
// exist so RFC 9106's own test vector can be run).
function argon2id(password, salt, { t, m, p, tagLen = 32, secret = new Uint8Array(0), ad = new Uint8Array(0) }) {
  if (!(Number.isInteger(t) && t >= 1)) throw new Error('argon2id: t must be ≥ 1');
  if (!(Number.isInteger(p) && p >= 1 && p <= 0xffffff)) throw new Error('argon2id: bad p');
  if (!(Number.isInteger(m) && m >= 8 * p)) throw new Error('argon2id: m must be ≥ 8p');
  if (!(salt.length >= 8)) throw new Error('argon2id: salt must be ≥ 8 bytes');
  const TYPE = 2, VERSION = 0x13, SL = 4;
  const H0 = blake2b(_concat(
    _le32(p), _le32(tagLen), _le32(m), _le32(t), _le32(VERSION), _le32(TYPE),
    _le32(password.length), password, _le32(salt.length), salt,
    _le32(secret.length), secret, _le32(ad.length), ad), 64);
  const mPrime = 4 * p * Math.floor(m / (4 * p));
  const q = mPrime / p, segLen = q / SL;
  const mem = new Uint32Array(mPrime * 256);
  const blk = (lane, idx) => (lane * q + idx) * 256;
  const toWords = (bytes, off) => {
    for (let i = 0; i < 256; i++)
      mem[off + i] = bytes[4 * i] | (bytes[4 * i + 1] << 8) | (bytes[4 * i + 2] << 16) | (bytes[4 * i + 3] << 24);
  };
  for (let l = 0; l < p; l++) {
    toWords(_argon2Hprime(_concat(H0, _le32(0), _le32(l)), 1024), blk(l, 0));
    toWords(_argon2Hprime(_concat(H0, _le32(1), _le32(l)), 1024), blk(l, 1));
  }
  const addr = new Uint32Array(256), input = new Uint32Array(256), zero = new Uint32Array(256);
  const scratch = new Uint32Array(256 * 3);      // zero | input | addr, for _fillBlock on a local buffer
  const nextAddresses = () => {
    input[12]++;                                  // word 6: counter (low half)
    scratch.fill(0, 0, 256); scratch.set(input, 256);
    _fillBlock(scratch, 0, 256, 512, false);      // addr = G(0, input)
    _fillBlock(scratch, 0, 512, 512, false);      // addr = G(0, addr)
    addr.set(scratch.subarray(512, 768));
  };
  for (let pass = 0; pass < t; pass++) {
    for (let slice = 0; slice < SL; slice++) {
      for (let lane = 0; lane < p; lane++) {
        const indep = pass === 0 && slice < SL / 2;
        if (indep) {
          input.fill(0);
          input[0] = pass; input[2] = lane; input[4] = slice;
          input[6] = mPrime; input[8] = t; input[10] = TYPE;
        }
        let start = 0;
        if (pass === 0 && slice === 0) { start = 2; if (indep) nextAddresses(); }
        let cur = lane * q + slice * segLen + start;
        let prev = cur % q === 0 ? cur + q - 1 : cur - 1;
        for (let i = start; i < segLen; i++, cur++, prev++) {
          if (cur % q === 1) prev = cur - 1;
          let j1, j2;
          if (indep) {
            if (i % 128 === 0) nextAddresses();
            j1 = addr[2 * (i % 128)]; j2 = addr[2 * (i % 128) + 1];
          } else {
            j1 = mem[prev * 256]; j2 = mem[prev * 256 + 1];
          }
          const refLane = (pass === 0 && slice === 0) ? lane : j2 % p;
          const same = refLane === lane;
          let area;
          if (pass === 0) {
            if (slice === 0) area = i - 1;
            else area = same ? slice * segLen + i - 1 : slice * segLen + (i === 0 ? -1 : 0);
          } else {
            area = same ? q - segLen + i - 1 : q - segLen + (i === 0 ? -1 : 0);
          }
          // relative = area - 1 - (area * (j1² >> 32) >> 32), exact with 16-bit limbs
          const x = _mulHi32(j1, j1);
          const rel = area - 1 - _mulHi32(area, x);
          const startPos = (pass !== 0 && slice !== SL - 1) ? (slice + 1) * segLen : 0;
          const refIdx = (startPos + rel) % q;
          _fillBlock(mem, prev * 256, blk(refLane, refIdx), cur * 256, pass !== 0);
        }
      }
    }
  }
  const C = new Uint32Array(256);
  for (let l = 0; l < p; l++) { const o = blk(l, q - 1); for (let i = 0; i < 256; i++) C[i] ^= mem[o + i]; }
  const cb = new Uint8Array(1024);
  for (let i = 0; i < 256; i++) { cb[4 * i] = C[i]; cb[4 * i + 1] = C[i] >>> 8; cb[4 * i + 2] = C[i] >>> 16; cb[4 * i + 3] = C[i] >>> 24; }
  mem.fill(0);
  return _argon2Hprime(cb, tagLen);
}
// High 32 bits of the 64-bit product of two unsigned 32-bit integers.
function _mulHi32(a, b) {
  const a0 = a & 0xffff, a1 = a >>> 16, b0 = b & 0xffff, b1 = b >>> 16;
  const cross = a0 * b1 + a1 * b0 + ((a0 * b0) >>> 16);
  return (a1 * b1 + Math.floor(cross / 0x10000)) >>> 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — ARGON2ID KEY WRAP / UNWRAP (v1.4, §6.5)
// Passphrase (UTF-8 of its NFC form) → Argon2id → 32-byte AES-KW key → wrap CEK.
// Parameters travel in the entry. Writers use RFC 9106's second recommended
// option; openers refuse anything weaker than OWASP's floor (a cell that
// claims t=1, m=8 protects nothing) or large enough to exhaust the device.
// ═══════════════════════════════════════════════════════════════════════════

const ARGON2_DEFAULTS = { m: 65536, t: 3, p: 4 };          // 64 MiB, 3 passes, 4 lanes
const ARGON2_LIMITS   = { mMin: 19456, mMax: 1048576, tMin: 1, tMax: 16, pMin: 1, pMax: 16 };

// Public: callers (e.g. a key-backup restore) can refuse bad parameters up front
// with a clear reason, rather than see a failed unwrap as "no matching key".
function argon2Params(w) {
  const { m, t, p } = w || {};
  const L = ARGON2_LIMITS;
  if (![m, t, p].every(Number.isInteger) || m < L.mMin || m > L.mMax ||
      t < L.tMin || t > L.tMax || p < L.pMin || p > L.pMax)
    throw new Error('Argon2id parameters out of range — refusing (§6.5)');
  if (t === 1 && m < 47104)
    throw new Error('Argon2id with one pass needs at least 46 MiB — refusing (§6.5)');
  return { m, t, p };
}
function _argon2Key(passphrase, salt, params) {
  return argon2id(new TextEncoder().encode(String(passphrase).normalize('NFC')), salt,
                  { ...params, tagLen: 32 });
}

async function argon2idWrapCek(cekRaw, passphrase, params = ARGON2_DEFAULTS) {
  const { m, t, p } = argon2Params(params);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = _argon2Key(passphrase, salt, { m, t, p });
  const wrap = await crypto.subtle.importKey('raw', kek, 'AES-KW', false, ['wrapKey']);
  kek.fill(0);
  const cekKey = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', true, ['encrypt']);
  const wrapped = await crypto.subtle.wrapKey('raw', cekKey, wrap, 'AES-KW');
  return { salt: toB64(salt), m, t, p, ct: toB64(new Uint8Array(wrapped)) };
}

async function argon2idUnwrapCek(wrappedCek, passphrase) {
  const params = argon2Params(wrappedCek);
  const salt = fromB64(wrappedCek.salt);
  if (salt.length < 16) throw new Error('Argon2id salt shorter than 16 bytes — refusing (§6.5)');
  const kek = _argon2Key(passphrase, salt, params);
  const wrap = await crypto.subtle.importKey('raw', kek, 'AES-KW', false, ['unwrapKey']);
  kek.fill(0);
  const cekKey = await crypto.subtle.unwrapKey(
    'raw', fromB64(wrappedCek.ct), wrap, 'AES-KW', { name: 'AES-GCM' }, true, ['decrypt']
  );
  return new Uint8Array(await crypto.subtle.exportKey('raw', cekKey));
}

// ═══════════════════════════════════════════════════════════════════════════
// PADDING — Padmé (v1.4, §5.4)
// Pads the compressed body so the ciphertext length reveals only O(log log L)
// bits about it (Nikitin et al., "Reducing Metadata Leakage from Encrypted
// Files and Communication with PURBs", PETS 2019). Overhead ≤ 12 %, plus a
// 512-byte floor so short messages share one size.
// ═══════════════════════════════════════════════════════════════════════════

const PAD_FLOOR = 512;
function padmeLength(L) {
  if (L <= PAD_FLOOR) return PAD_FLOOR;
  if (!(L < 2 ** 32)) throw new Error('padmeLength: body too large');
  const E = 31 - Math.clz32(L);          // floor(log2 L), exact on integers
  const S = 32 - Math.clz32(E);          // floor(log2 E) + 1
  const step = 2 ** (E - S);
  return Math.ceil(L / step) * step;
}
// body = LE32(len(gz)) || gz || zero bytes up to padmeLength(4 + len(gz))
function padBody(gz) {
  const out = new Uint8Array(padmeLength(4 + gz.length));
  new DataView(out.buffer).setUint32(0, gz.length, true);
  out.set(gz, 4);
  return out;
}
function unpadBody(body) {
  if (body.length < 4) throw new Error('Malformed padded body');
  const n = new DataView(body.buffer, body.byteOffset, 4).getUint32(0, true);
  if (4 + n > body.length) throw new Error('Malformed padded body — length exceeds body');
  for (let i = 4 + n; i < body.length; i++)
    if (body[i] !== 0) throw new Error('Malformed padded body — non-zero padding');
  return body.subarray(4, 4 + n);
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO — YUBIKEY PRF WRAP / UNWRAP
// PRF output is 32 bytes → used directly as AES-KW wrapping key.
// Only works over HTTPS or localhost (WebAuthn requirement).
// ═══════════════════════════════════════════════════════════════════════════

async function prfGet(credentialIdB64, prfSaltB64) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      userVerification: 'required',
      allowCredentials: [{ id: fromB64(credentialIdB64), type: 'public-key' }],
      extensions: { prf: { eval: { first: fromB64(prfSaltB64) } } },
    }
  });
  const extResults = assertion.getClientExtensionResults();
  console.debug('[PRF get] extension results:', JSON.stringify(extResults));
  const prf = extResults?.prf?.results?.first;
  if (!prf) {
    console.warn('[PRF get] prf.results.first is missing. Full ext:', extResults);
    const err = new Error('PRF output not returned by this authenticator.');
    err.extResults = extResults;
    throw err;
  }
  return new Uint8Array(prf);
}

async function prfWrapCek(cekRaw, credentialIdB64, prfSaltB64) {
  const prfOut = await prfGet(credentialIdB64, prfSaltB64);
  const wrap = await crypto.subtle.importKey('raw', prfOut, 'AES-KW', false, ['wrapKey']);
  const cekKey = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', true, ['encrypt']);
  const wrapped = await crypto.subtle.wrapKey('raw', cekKey, wrap, 'AES-KW');
  return { credential_id: credentialIdB64, prf_salt: prfSaltB64, ct: toB64(new Uint8Array(wrapped)) };
}

async function prfUnwrapCek(wrappedCek) {
  const prfOut = await prfGet(wrappedCek.credential_id, wrappedCek.prf_salt);
  const wrap = await crypto.subtle.importKey('raw', prfOut, 'AES-KW', false, ['unwrapKey']);
  const cekKey = await crypto.subtle.unwrapKey(
    'raw', fromB64(wrappedCek.ct), wrap, 'AES-KW', { name: 'AES-GCM' }, true, ['decrypt']
  );
  return new Uint8Array(await crypto.subtle.exportKey('raw', cekKey));
}

async function registerYubiKey(label) {
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Cell Format', id: location.hostname || 'localhost' },
      user: { id: userId, name: label, displayName: label },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required', authenticatorAttachment: 'cross-platform' },
      extensions: { prf: { eval: { first: prfSalt } } },
    }
  });
  const ext = cred.getClientExtensionResults();
  console.debug('[PRF register] extension results:', JSON.stringify(ext));
  // prf.enabled = true  → CTAP 2.1 PRF or hmac-secret translation confirmed
  // prf.results.first   → some browsers return the first eval inline during create
  if (!ext?.prf?.enabled && !ext?.prf?.results?.first) {
    console.warn('[PRF register] ext.prf:', ext?.prf);
    throw new Error(
      'This authenticator does not support the PRF extension.\n\n' +
      'Required: YubiKey 5 series (firmware 5.2+) or another FIDO2 key with hmac-secret.\n' +
      'The Yubico Security Key (blue, ~$25) does NOT support PRF — you need the YubiKey 5 series.'
    );
  }
  const credId = toB64(new Uint8Array(cred.rawId));
  const prfSaltB64 = toB64(prfSalt);
  // Verify PRF actually works before storing — some browser/key combos report
  // prf.enabled:true during create() but fail to return output during get().
  // If prf.results.first was returned inline we already know it works; otherwise test now.
  if (!ext?.prf?.results?.first) {
    try {
      await prfGet(credId, prfSaltB64);
    } catch (e) {
      const isFirefoxLinux = /Firefox/.test(navigator.userAgent) && /Linux/.test(navigator.userAgent);
      throw new Error(
        'PRF registration succeeded but PRF output was not returned on first use.\n\n' +
        (isFirefoxLinux
          ? '⚠️ Firefox on Linux does not support YubiKey PRF — use Chrome or Chromium instead.\n\n'
          : 'This may be a browser or firmware issue. Try Chrome/Chromium if you are not already using it.\n\n') +
        'Diagnostic:\n' +
        'browser: ' + navigator.userAgent + '\n' +
        'create() ext: ' + JSON.stringify(ext) + '\n' +
        'get() ext: ' + JSON.stringify(e.extResults ?? null)
      );
    }
  }
  return {
    keyId: crypto.randomUUID(), label, method: 'yubikey-prf',
    fingerprint: toHex(await sha256(fromB64(credId))).slice(0, 16),
    credential_id: credId, prf_salt: prfSaltB64,
    created_at: Math.floor(Date.now() / 1000),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC KEY CONTACTS — localStorage  (public metadata only, no private keys)
// Safe to store: no secrets, survives IDB clears, shareable fingerprints.
// ═══════════════════════════════════════════════════════════════════════════

const LS_PUB = 'cd-vanilla-pubkeys';

function lsPubAll() {
  try { return JSON.parse(localStorage.getItem(LS_PUB) || '[]'); } catch { return []; }
}
function lsPubSave(rec) {
  const pub = {
    keyId: rec.keyId, label: rec.label, method: rec.method,
    fingerprint: rec.fingerprint || null,
    spki: rec.spki || null,
    credential_id: rec.credential_id || null,
    prf_salt: rec.prf_salt || null,
    saved_at: Math.floor(Date.now() / 1000),
  };
  const rest = lsPubAll().filter(r => r.keyId !== pub.keyId);
  localStorage.setItem(LS_PUB, JSON.stringify([...rest, pub]));
}
function lsPubDel(keyId) {
  localStorage.setItem(LS_PUB, JSON.stringify(lsPubAll().filter(r => r.keyId !== keyId)));
}
// Returns localStorage entries that are NOT already in IDB (contacts only).
function lsPubContacts(idbKeys) {
  const idbIds = new Set(idbKeys.map(k => k.keyId));
  return lsPubAll().filter(r => !idbIds.has(r.keyId));
}

// ═══════════════════════════════════════════════════════════════════════════
// KEYCHAIN — IndexedDB  (stores key metadata + private keys for this device)
// ═══════════════════════════════════════════════════════════════════════════

const KC = { DB: 'cd-vanilla', VER: 1, STORE: 'keys' };

function kcOpen() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(KC.DB, KC.VER);
    req.onupgradeneeded = e => e.target.result.createObjectStore(KC.STORE, { keyPath: 'keyId' });
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  });
}
async function kcAll() {
  const db = await kcOpen();
  return new Promise((res, rej) => {
    const req = db.transaction(KC.STORE).objectStore(KC.STORE).getAll();
    req.onsuccess = e => res(e.target.result); req.onerror = e => rej(e.target.error);
  });
}
async function kcGet(id) {
  const db = await kcOpen();
  return new Promise((res, rej) => {
    const req = db.transaction(KC.STORE).objectStore(KC.STORE).get(id);
    req.onsuccess = e => res(e.target.result); req.onerror = e => rej(e.target.error);
  });
}
async function kcSave(rec) {
  const db = await kcOpen();
  await new Promise((res, rej) => {
    const tx = db.transaction(KC.STORE, 'readwrite');
    tx.objectStore(KC.STORE).put(rec);
    tx.oncomplete = res; tx.onerror = e => rej(e.target.error);
  });
  // Mirror public fields to localStorage — no secrets stored there.
  if (rec.spki || rec.credential_id) lsPubSave(rec);
}
async function kcDel(id) {
  const db = await kcOpen();
  await new Promise((res, rej) => {
    const tx = db.transaction(KC.STORE, 'readwrite');
    tx.objectStore(KC.STORE).delete(id);
    tx.oncomplete = res; tx.onerror = e => rej(e.target.error);
  });
  lsPubDel(id);
}

async function kcGenEcdh(label) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const spki  = toB64(new Uint8Array(await crypto.subtle.exportKey('spki',  pair.publicKey)));
  const pkcs8 = toB64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)));
  const rec = { keyId: crypto.randomUUID(), label, method: 'ecdh-p256',
    fingerprint: await fp(spki), spki, pkcs8, created_at: Math.floor(Date.now()/1000) };
  await kcSave(rec);
  return rec;
}

async function kcLoadPrivKey(rec) {
  if (!rec.pkcs8) throw new Error('No private key stored for this record');
  return crypto.subtle.importKey('pkcs8', fromB64(rec.pkcs8),
    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}

// ═══════════════════════════════════════════════════════════════════════════
// CELL FORMAT — CREATE  (spec v1.2)
// options: { threshold, lifetime, policy, senderRec }
// ═══════════════════════════════════════════════════════════════════════════

// Deterministic JSON serialization (recursively sorted keys, no insignificant
// whitespace) so that header_hash / header_sig / AAD depend only on the *values*,
// not on how the .cell JSON happens to be formatted. A tool that re-orders keys
// or pretty-prints the file no longer causes a false "tampered/forged" failure.
// Mirrors JSON.stringify's primitive/escape handling; undefined is dropped from
// objects and becomes null in arrays, as JSON.stringify does.
function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(x => canonicalize(x === undefined ? null : x)).join(',') + ']';
  const keys = Object.keys(v).filter(k => v[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}
// Bytes that header_hash and header_sig are computed over. v1.2+ uses the
// canonical form; v1.0/v1.1 keep the legacy JSON.stringify form for compat.
function serializeHeader(header, version) {
  return new TextEncoder().encode(
    CANONICAL_VERSIONS.has(version) ? canonicalize(header) : JSON.stringify(header));
}

// Additional authenticated data (v1.1+): binds the advisory metadata that is
// decided before encryption (prev_hash/threshold/lifetime/policy) to the
// AES-GCM ciphertext. Any post-hoc edit to these header fields makes the GCM
// tag fail on open — not strippable and not downgradeable (decrypting without
// the AAD also fails the tag). v1.2 canonicalizes so reformatting the JSON does
// not break the binding; v1.1 keeps its original array-of-JSON.stringify form.
function cellAad(header, version) {
  const meta = [
    header.prev_hash ?? null,
    header.threshold ?? null,
    header.lifetime  ?? null,
    header.policy    ?? null,
  ];
  if (VERSIONED_AAD_VERSIONS.has(version)) {
    // v1.4: an object, so the format version is authenticated alongside the
    // metadata — relabelling a cell's version fails the GCM tag.
    return new TextEncoder().encode(canonicalize({
      format: version, prev_hash: meta[0], threshold: meta[1], lifetime: meta[2], policy: meta[3],
    }));
  }
  return new TextEncoder().encode(version === '1.1' ? JSON.stringify(meta) : canonicalize(meta));
}

// ═══════════════════════════════════════════════════════════════════════════
// LIFETIME — split by enforcer (v1.3)
//
// Up to v1.2 the lifetime object mixed two things with different guarantees
// under one flat shape, and graded them as one:
//
//   expires_at / release_at   a check a conforming client performs. NOT
//                             enforced: a recipient holding the CEK can open
//                             the cell regardless, by editing the client or
//                             writing forty lines from the specification. The
//                             AAD binding stops a third party ALTERING these
//                             values; it does not oblige a keyholder to OBEY
//                             them.
//   on_expiry                 what the operator's sweep does to the stored
//                             ciphertext. Genuinely enforced against everyone
//                             who has not already taken a copy, and performed
//                             without the operator reading anything.
//
// v1.3 separates them so the artifact states its own grades:
//
//   lifetime: {
//     type: "record",
//     advisory: { retain_until, release_at, single_use, minimum_atl },
//     disposal: { at, action }
//   }
//
// "expires_at" is renamed "retain_until" because the old name promised a wall
// the mechanism never built — the same category of error the vocabulary policy
// already catches for copy_protection ("warns", never "prevents").
// ═══════════════════════════════════════════════════════════════════════════

// Accept either shape and return the v1.3 shape. Callers that still pass the
// flat v1.0–1.2 object keep working; their values land in the right halves.
function normalizeLifetime(lt) {
  if (!lt) return null;
  if (lt.advisory || lt.disposal) {
    return {
      type: lt.type ?? 'permanent',
      advisory: {
        retain_until: lt.advisory?.retain_until ?? null,
        release_at:   lt.advisory?.release_at   ?? null,
        single_use:   lt.advisory?.single_use   ?? false,
        minimum_atl:  lt.advisory?.minimum_atl  ?? 1,
      },
      disposal: {
        at:     lt.disposal?.at     ?? null,
        action: lt.disposal?.action ?? 'none',
      },
    };
  }
  // Legacy flat shape. expires_at served both roles; carry it into both so a
  // migrated cell keeps the behaviour its author intended.
  return {
    type: lt.type ?? 'permanent',
    advisory: {
      retain_until: lt.expires_at ?? null,
      release_at:   lt.release_at ?? null,
      single_use:   lt.single_use ?? false,
      minimum_atl:  lt.minimum_atl ?? 1,
    },
    disposal: {
      at:     lt.expires_at ?? null,
      action: lt.on_expiry  ?? 'none',
    },
  };
}

// Read either shape uniformly, so open-path logic is version-agnostic.
function readLifetime(lt) {
  if (!lt) return null;
  const n = normalizeLifetime(lt);
  return {
    type: n.type,
    retainUntil: n.advisory.retain_until,
    releaseAt:   n.advisory.release_at,
    singleUse:   n.advisory.single_use,
    minimumAtl:  n.advisory.minimum_atl,
    disposalAt:     n.disposal.at,
    disposalAction: n.disposal.action,
  };
}

async function _wrapEntry(r, keyMat, shareIdx, version = CELL_FORMAT_VERSION) {
  // v1.4 entries are blind: no fingerprint, no label. The header is readable
  // by anyone holding the file, and those fields named the recipients.
  const blind = BLIND_ENTRY_VERSIONS.has(version);
  const base = blind ? { method: r.method } : { label: r.label, method: r.method, fingerprint: r.fingerprint };
  if (shareIdx !== null) base.share_index = shareIdx;
  if (r.method === 'ecdh-p256') {
    return { ...base, wrapped_cek: await ecdhWrapCek(keyMat, r.spki) };
  } else if (r.method === 'argon2id') {
    if (!blind) throw new Error('argon2id entries need format v1.4');
    return { ...base, wrapped_cek: await argon2idWrapCek(keyMat, r.passphrase, r.argon2 || ARGON2_DEFAULTS) };
  } else if (r.method === 'pbkdf2') {
    const wk = await pbkdf2WrapCek(keyMat, r.passphrase);
    if (blind) return { ...base, wrapped_cek: wk };
    return { ...base, fingerprint: toHex(await sha256(fromB64(wk.salt))).slice(0, 16),
             label: r.label || 'Passphrase', wrapped_cek: wk };
  } else if (r.method === 'yubikey-prf') {
    // credential_id stays (WebAuthn needs it to ask the right authenticator),
    // so cells for the same security key remain linkable — see §6.3.
    return { ...base, wrapped_cek: await prfWrapCek(keyMat, r.credential_id, r.prf_salt) };
  }
  return null;
}

/* Sender signature, v1.4 (§4.5). Signed BEFORE encryption and carried inside
   the encrypted manifest, so only recipients learn who signed. It covers the
   content, the manifest, the authenticated metadata (with the version), the
   cell's identity and the intended key recipients, so a recipient cannot
   re-encrypt the file to someone else with the signature still attesting to it
   without the new holder seeing that they are not in `to`. */
function _senderSigInput(fields) {
  return new TextEncoder().encode(canonicalize({ purpose: 'cell-sender-signature', ...fields }));
}
async function _senderSigKey(sr) {
  if (sr?.sig && typeof sr.sig === 'object' && sr.sig.type === 'private') return sr.sig;   // CryptoKey (ECDSA)
  if (sr?.pkcs8)
    return crypto.subtle.importKey('pkcs8', fromB64(sr.pkcs8), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return null;
}

async function cellCreate(file, recipients, options = {}) {
  const version = options.version || CELL_FORMAT_VERSION;
  if (!SUPPORTED_VERSIONS.has(version) || !CANONICAL_VERSIONS.has(version))
    throw new Error(`cellCreate writes v1.2 and later only, not "${version}"`);
  const threshold = Math.max(1, Math.min(options.threshold || 1, Math.max(recipients.length, 1)));
  const raw  = new Uint8Array(await file.arrayBuffer());
  const docId = ulid(), createdAt = Math.floor(Date.now() / 1000);

  // Manifest encrypted inside the payload — filename/type/size invisible to observers (spec §3.3).
  // options.meta: optional sender-defined object (note, case number, reply
  // instructions, …) carried INSIDE the ciphertext — metadata the server and
  // any observer never see. Additive and ignored by older readers.
  const manifest = { filename: file.name, content_type: file.type || 'application/octet-stream', size: raw.byteLength };
  if (options.meta && typeof options.meta === 'object') manifest.meta = options.meta;

  // Advisory metadata is fixed before encryption so it can be authenticated as
  // AES-GCM AAD (spec v1.2). These exact values are reused in the header below.
  const meta = {
    prev_hash: options.prevHash || null,
    threshold: { required: threshold, of_total: recipients.length },
    lifetime:  normalizeLifetime(options.lifetime) || {
                 type: 'permanent',
                 advisory: { retain_until: null, release_at: null, single_use: false, minimum_atl: 1 },
                 disposal: { at: null, action: 'none' },
               },
    policy:    options.policy   || { copy_protection: 'standard', watermark_mode: 'none', created_on_origin: null, origin_sig: null },
  };
  const aad = cellAad(meta, version);

  const innerSig = INNER_SIG_VERSIONS.has(version);
  const sigKey = await _senderSigKey(options.senderRec);
  if (innerSig && sigKey) {
    const senderSpki = options.senderRec.spki;
    const to = (await Promise.all(recipients.filter(r => r.method === 'ecdh-p256' && r.spki)
      .map(r => fp(r.spki)))).sort();
    const sigInput = _senderSigInput({
      version, doc_id: docId, created_at: createdAt,
      aad: new TextDecoder().decode(aad), manifest: { ...manifest },
      content_sha256: toB64(await sha256(raw)), sender_spki: senderSpki, to,
    });
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sigKey, sigInput);
    manifest.sender = { spki: senderSpki, to, sig: toB64(new Uint8Array(sig)) };
  }
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, manifestBytes.length, true);
  const plaintext = new Uint8Array(4 + manifestBytes.length + raw.byteLength);
  plaintext.set(lenBuf); plaintext.set(manifestBytes, 4); plaintext.set(raw, 4 + manifestBytes.length);

  const gz = await gzip(plaintext);
  const body = PADDED_VERSIONS.has(version) ? padBody(gz) : gz;
  const cek    = await cekGenerate();
  const cekRaw = await cekExportRaw(cek);
  const enc = await cekEncrypt(cek, body, aad);

  let accessMap;
  if (threshold > 1) {
    const rawShares = shamirSplit(cekRaw, recipients.length, threshold);
    accessMap = (await Promise.all(recipients.map((r, i) => _wrapEntry(r, rawShares[i].data, i + 1, version)))).filter(Boolean);
  } else {
    accessMap = (await Promise.all(recipients.map(r => _wrapEntry(r, cekRaw, null, version)))).filter(Boolean);
  }
  cekRaw.fill(0);

  // payload_hash binds ciphertext into the header — tamper-evident commitment
  const payloadHash = toB64(await sha256(fromB64(enc.ct)));

  // Same metadata that was bound as AAD, plus the post-encryption fields.
  const header = { ...meta, access_map: accessMap, payload_hash: payloadHash };
  const headerBytes = serializeHeader(header, version);
  const header_hash = toB64(await sha256(headerBytes));

  const cell = { version, doc_id: docId, created_at: createdAt, header, header_hash };
  if (!innerSig) {
    // ≤ v1.3: ECDSA over the header, in the clear — names the sender to anyone.
    let header_sig = null, header_sig_by = null, header_sig_key = null;
    const sr = options.senderRec;
    if (sigKey && sr?.spki) {
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sigKey, headerBytes);
      header_sig     = toB64(new Uint8Array(sig));
      header_sig_by  = sr.fingerprint;
      header_sig_key = sr.spki;
    }
    Object.assign(cell, { header_sig, header_sig_by, header_sig_key });
  }
  cell.payload = { alg: 'AES-256-GCM', encoding: PADDED_VERSIONS.has(version) ? 'base64+gzip+padme' : 'base64+gzip',
                   iv: enc.iv, ciphertext: enc.ct };
  return cell;
}

// ═══════════════════════════════════════════════════════════════════════════
// CELL FORMAT — OPEN  (supports v1.0 and legacy v2.x)
// tryDecryptFn: (entry) => Promise<Uint8Array|null>  (null = not my key)
// ═══════════════════════════════════════════════════════════════════════════

async function cellOpen(cell, tryDecryptFn) {
  // Version gate — warn on unknown versions rather than silently misbehaving
  const fmtVersion = cell.version ?? cell.cd_version ?? 'unknown';
  const isLegacy   = !cell.version && cell.cd_version;
  if (!isLegacy && !SUPPORTED_VERSIONS.has(fmtVersion))
    throw new Error(`Unsupported cell format version "${fmtVersion}" — update the app to open this cell`);

  // Advisory lifetime checks (spec §8) — before any crypto work.
  //
  // These are CONFORMANCE behaviour, not enforcement. A recipient who holds a
  // qualifying key can remove these lines, or write their own opener from the
  // specification, and recover the plaintext regardless; the AAD binding
  // guarantees only that the values below are the ones the sender set, not
  // that anyone honours them. Honest software refuses; the format cannot
  // compel it to. See docs/design/temporal-enforcement.md.
  //
  // What IS enforced is lifetime.disposal, and not here: the operator's sweep
  // deletes or archives the stored ciphertext on schedule, without reading it.
  // That acts on everyone who has not already taken a copy.
  const lt  = readLifetime(cell.header?.lifetime);
  const now = Math.floor(Date.now() / 1000);
  if (lt) {
    if (lt.type === 'timed_release' && lt.releaseAt && lt.releaseAt > now)
      throw new Error(`Timed release — unlocks ${fmtDate(lt.releaseAt)}`);
    if (lt.retainUntil && lt.retainUntil < now)
      throw new Error(`Retention period ended ${fmtDate(lt.retainUntil)}`);
  }

  // Normalise field names — support v1.0 and legacy v2.x
  const accessMap   = cell.header?.access_map ?? cell.recipients ?? [];
  const payloadInfo = cell.payload ?? cell.encrypted_body ?? {};
  const ivField     = payloadInfo.iv;
  const ctField     = payloadInfo.ciphertext ?? payloadInfo.ct;
  const threshold   = cell.header?.threshold?.required ?? 1;
  if (accessMap.length > MAX_ACCESS_ENTRIES)
    throw new Error(`Too many access-map entries (${accessMap.length} > ${MAX_ACCESS_ENTRIES})`);
  if (INNER_SIG_VERSIONS.has(fmtVersion) && (cell.header_sig || cell.header_sig_key || cell.header_sig_by))
    throw new Error(`A v${fmtVersion} cell carries its signature inside the payload — a header signature here is malformed`);

  // ── Tamper detection + authenticity — BEFORE any key material is touched ──
  //
  // Order matters (spec §10). These are cheap, structural, and need no key, so
  // they run ahead of the access-map loop: a corrupted cell must not cost the
  // user a 600,000-iteration PBKDF2 derivation, a YubiKey touch, or the
  // assembly of a quorum before it is refused. AES-KW unwrapping is itself a
  // decryption; nothing may be decrypted under a header that has not verified.
  //
  // header_hash is MANDATORY for every non-legacy cell. It was previously
  // guarded on its own presence, which meant deleting the field skipped this
  // whole block — header_hash, payload_hash and header_sig alike — and a cell
  // with a forged access_map or a stripped signature opened without complaint.
  // Absence is now a rejection, not a licence to skip the checks.
  let sigVerified = null; // null = unsigned, string = verified fp, throws on invalid
  if (!isLegacy) {
    if (!cell.header)      throw new Error('Malformed cell — missing header');
    if (!cell.header_hash) throw new Error('Integrity check failed — header_hash is missing');

    const headerBytes = serializeHeader(cell.header, fmtVersion);
    const computed = toB64(await sha256(headerBytes));
    if (computed !== cell.header_hash)
      throw new Error('Integrity check failed — header may be tampered');

    if (cell.header.payload_hash) {
      const ctHash = toB64(await sha256(fromB64(ctField)));
      if (ctHash !== cell.header.payload_hash)
        throw new Error('Integrity check failed — ciphertext may be tampered');
    }

    // A signature is verified when present. Note that its ABSENCE is not
    // detectable from the cell alone — an attacker can strip header_sig and
    // the result is byte-indistinguishable from a cell that was never signed
    // (header_sig is not covered by the AAD, which is fixed before signing).
    // Callers that require authenticated senders must check sigVerified
    // against an expected fingerprint; see spec §4.1.
    if (cell.header_sig && cell.header_sig_key) {
      const ecdsaPub = await crypto.subtle.importKey(
        'spki', fromB64(cell.header_sig_key),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
      );
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, ecdsaPub, fromB64(cell.header_sig), headerBytes
      );
      if (!valid) throw new Error('Header signature invalid — cell may be forged');
      sigVerified = cell.header_sig_by || '(unknown)';
    }
  }

  let cekRaw = null, usedRecipient = null;

  if (threshold > 1) {
    const shares = [];
    for (const r of accessMap) {
      try {
        const share = await tryDecryptFn(r);
        if (share) {
          shares.push({ x: r.share_index ?? (accessMap.indexOf(r) + 1), data: share });
          if (shares.length >= threshold) break;
        }
      } catch { /* try next */ }
    }
    if (shares.length < threshold)
      throw new Error(`Quorum not met — need ${threshold}, unlocked ${shares.length}`);
    cekRaw = shamirCombine(shares);
    for (const s of shares) s.data.fill(0); // wipe individual share material
    usedRecipient = { label: `${shares.length}-of-${accessMap.length} quorum` };
  } else {
    for (const r of accessMap) {
      try {
        const result = await tryDecryptFn(r);
        if (result) { cekRaw = result; usedRecipient = r; break; }
      } catch { /* try next */ }
    }
  }
  if (!cekRaw) throw new Error('No matching key — check your key method and try again');

  // v1.1+ binds metadata as AAD; tampering with threshold/lifetime/policy/prev_hash
  // (or stripping the AAD by downgrading the version) fails the GCM tag here.
  const aad = AAD_VERSIONS.has(fmtVersion) ? cellAad(cell.header, fmtVersion) : undefined;
  const decrypted = await cekDecrypt(cekRaw, ivField, ctField, aad);
  cekRaw.fill(0);
  const compressed = PADDED_VERSIONS.has(fmtVersion) ? unpadBody(decrypted) : decrypted;
  const plain = await gunzip(compressed);

  // Manifest-prefixed payload (v1.0) vs legacy cells that had plaintext metadata
  let filename, contentType, fileBytes, meta = null;
  if (cell.original_filename !== undefined) {
    filename    = cell.original_filename ?? cell.doc_id ?? 'decrypted';
    contentType = cell.content_type ?? 'application/octet-stream';
    fileBytes   = plain;
  } else {
    const manifestLen = new DataView(plain.buffer, plain.byteOffset, 4).getUint32(0, true);
    const mf = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + manifestLen)));
    filename    = mf.filename     ?? cell.doc_id ?? 'decrypted';
    contentType = mf.content_type ?? 'application/octet-stream';
    meta        = mf.meta         ?? null;
    fileBytes   = plain.slice(4 + manifestLen);
    if (INNER_SIG_VERSIONS.has(fmtVersion) && mf.sender) {
      // v1.4 inner signature (§4.5). The signer's fingerprint is recomputed
      // from the key, never taken from the file.
      const s = mf.sender;
      if (typeof s.spki !== 'string' || typeof s.sig !== 'string' || !Array.isArray(s.to))
        throw new Error('Malformed sender signature');
      const { sender, ...unsigned } = mf;
      const sigInput = _senderSigInput({
        version: fmtVersion, doc_id: cell.doc_id, created_at: cell.created_at,
        aad: new TextDecoder().decode(aad), manifest: unsigned,
        content_sha256: toB64(await sha256(fileBytes)), sender_spki: s.spki, to: s.to,
      });
      const pub = await crypto.subtle.importKey('spki', fromB64(s.spki),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, fromB64(s.sig), sigInput);
      if (!ok) throw new Error('Sender signature invalid — cell may be forged');
      sigVerified = await fp(s.spki);
      return { bytes: fileBytes, filename, contentType, meta, usedRecipient, sigVerified,
               sigKey: s.spki, signedTo: s.to.slice() };
    }
  }
  return { bytes: fileBytes, filename, contentType, meta, usedRecipient, sigVerified,
           sigKey: INNER_SIG_VERSIONS.has(fmtVersion) ? null : (cell.header_sig_key || null), signedTo: null };
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE I/O
// ═══════════════════════════════════════════════════════════════════════════

function dlBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 15000);
}

async function dlCell(cell, baseName, format) {
  const json = JSON.stringify(cell, null, 2);
  if (format === 'celz') {
    const compressed = await gzip(new TextEncoder().encode(json));
    dlBlob(new Blob([compressed], { type: 'application/octet-stream' }), baseName + '.celz');
  } else {
    dlBlob(new Blob([json], { type: 'application/json' }), baseName + '.cell');
  }
}

function dlBytes(bytes, filename, type) {
  dlBlob(new Blob([bytes], { type: type || 'application/octet-stream' }), filename);
}

function dlText(text, filename) {
  dlBlob(new Blob([text], { type: 'text/plain' }), filename);
}

// Parse a .cell or .celz file
async function parseCell(file) {
  if (file.name.endsWith('.celz')) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const json = new TextDecoder().decode(await gunzip(bytes));
    return JSON.parse(json);
  }
  return JSON.parse(await file.text());
}
