// Render test for the demo app (index.html): every field a .cell file carries
// is shown escaped. The Open view renders the moment a file is dropped in,
// before any key is used and before header_hash is checked, so anyone who can
// hand someone a .cell controls these strings.
//
// Loads the real cell-crypto.js and the real app script (app.js),
// renders into a stub element, and inspects the HTML string.
import { readFileSync } from 'node:fs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

const stubEl = () => ({
  style: {}, innerHTML: '', textContent: '', value: '', checked: false,
  classList: { add() {}, remove() {}, toggle() {} },
  addEventListener() {}, appendChild() {}, setAttribute() {},
  querySelector() { return null; }, querySelectorAll() { return []; },
});
globalThis.window = { location: { origin: 'test://x' }, CompressionStream };
globalThis.location = { hostname: 'localhost', origin: 'test://x' };
globalThis.navigator = { userAgent: 'node' };
globalThis.document = { addEventListener() {}, getElementById: stubEl, createElement: stubEl };
const _ls = {};
globalThis.localStorage = {
  getItem: k => (k in _ls ? _ls[k] : null),
  setItem: (k, v) => { _ls[k] = String(v); },
  removeItem: k => { delete _ls[k]; },
};
globalThis.indexedDB = {};

// The app script is a separate file (app.js) so the page can run under script-src 'self'.
const html = readFileSync(`${ROOT}/index.html`, 'utf8');
const appJs = readFileSync(`${ROOT}/app.js`, 'utf8');
const cryptoJs = readFileSync(`${ROOT}/cell-crypto.js`, 'utf8');
const app = new Function(cryptoJs + '\n;' + appJs + `
;kcAll = async () => [];
return {
  renderOpen, renderEncrypt,
  setCell: (c) => { _openCell = c; },
  setFile: (f) => { _encFile = f; },
};`)();

// Breaks out of an element, and out of a double-quoted attribute.
const P = '"><img src=x onerror=PWNED>';
const Q = 'x" autofocus onfocus="PWNED';

function hostileCell(legacy) {
  const c = {
    doc_id: P + Q,
    created_at: P,
    header: {
      prev_hash: Q + P,
      threshold: { required: P, of_total: 2 },
      lifetime: { type: P },
      policy: { copy_protection: P, watermark_mode: P, created_on_origin: P + Q },
      access_map: [
        { method: P, label: P, fingerprint: P, share_index: P },
        { method: 'ecdh-p256', share_index: '1' + P },
        { method: 'pbkdf2', share_index: Q },
      ],
    },
    header_hash: P,
    header_sig: P, header_sig_by: P + Q,
    payload: { alg: P },
    original_filename: P + Q, content_type: P + Q, original_size: P,
  };
  if (legacy) c.cd_version = '2.0' + P; else c.version = '1.4';
  return c;
}

function unsafe(out) {
  const problems = [];
  if (out.includes('<img')) problems.push('an <img> element from the file');
  if (/["']\s*(autofocus|onfocus)/.test(out)) problems.push('an attribute added from the file');
  return problems;
}

let pass = 0, fail = 0;
async function check(name, fn) {
  try {
    const out = await fn();
    const problems = unsafe(out);
    if (problems.length) throw new Error(problems.join('; '));
    console.log(`  ✓ ${name}`); pass++;
  } catch (e) {
    console.log(`  ✗ ${name}\n      ${e.message}`); fail++;
  }
}

console.log('── Render (index.html)');
for (const legacy of [false, true]) {
  await check(`Open view escapes every field of a hostile ${legacy ? 'legacy v2.0' : 'v1.4'} cell`, async () => {
    app.setCell(hostileCell(legacy));
    const el = stubEl();
    await app.renderOpen(el);
    return el.innerHTML;
  });
}
await check('Open view escapes a quorum cell with markup in share_index', async () => {
  const c = hostileCell(false);
  c.header.threshold.required = 2;
  app.setCell(c);
  const el = stubEl();
  await app.renderOpen(el);
  if (!el.innerHTML.includes('2-of-3')) throw new Error('quorum row missing');
  return el.innerHTML;
});
await check('Encrypt view escapes a file name and type carried over by Mitosis', async () => {
  app.setFile({ name: P + Q, size: 10, type: P + Q });
  const el = stubEl();
  await app.renderEncrypt(el);
  return el.innerHTML;
});

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
