// server.js serves the demo and its browser test page, and nothing else.
//
// Runs a copy from a temporary directory holding files it must never hand out,
// including a TLS key. Serving anything under this directory once made such a
// key downloadable.
import { spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const dir = mkdtempSync(path.join(os.tmpdir(), 'cd-server-test-'));
const SERVED = ['index.html', 'app.js', 'app.css', 'cell-crypto.js', 'tests/test.html'];
const PLANTED = ['certs/localhost.key', 'certs/localhost.crt', 'docs/notes.md', 'real.cell', 'me.cdkey',
                 'README.md', '.env', '.git/HEAD'];

for (const f of ['server.js', ...SERVED]) {
  mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
  copyFileSync(path.join(ROOT, f), path.join(dir, f));
}
for (const f of PLANTED) {
  mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
  writeFileSync(path.join(dir, f), 'must not be served');
}
writeFileSync(path.join(dir, 'package.json'), '{"type":"module"}');

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const port = await freePort();
const get = (p) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path: p }, (res) => {
    const chunks = [];
    res.on('data', c => chunks.push(c));
    res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
  }).on('error', reject);
});

// No certificate, so it takes its plain-HTTP path.
const child = spawn(process.execPath, ['server.js'], {
  cwd: dir, stdio: 'ignore',
  env: { ...process.env, PORT: String(port), HPORT: '0', CERT: '/nonexistent', KEY: '/nonexistent' },
});

let pass = 0, fail = 0;
const check = (name, ok, detail = '') => {
  if (ok) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`); fail++; }
};

try {
  let up = false;
  for (let i = 0; i < 100 && !up; i++) {
    try { await get('/'); up = true; } catch { await new Promise(r => setTimeout(r, 50)); }
  }
  if (!up) throw new Error('server.js did not start');

  console.log('── Static server (server.js)');
  for (const f of SERVED) {
    const r = await get('/' + f);
    check(`serves /${f}`, r.status === 200 && r.body.equals(readFileSync(path.join(dir, f))), `status ${r.status}`);
  }
  check('/ is index.html', (await get('/')).body.equals(readFileSync(path.join(dir, 'index.html'))));
  check('a query string does not change what is served', (await get('/app.js?v=1')).status === 200);

  const refused = [...PLANTED.map(f => '/' + f), '/server.js', '/package.json',
    '/certs/', '/docs/', '/tests/', '/certs%2flocalhost.key', '/./certs/localhost.key',
    '/tests/../certs/localhost.key', '/%2e%2e/%2e%2e/etc/passwd', '/index.html%00.key', '/app.js/'];
  for (const p of refused) {
    const r = await get(p);
    check(`refuses ${p}`, r.status === 404 && !r.body.includes('must not be served'), `status ${r.status}`);
  }
  check('still running after every refused request', (await get('/')).status === 200);
} catch (e) {
  check('server test ran', false, e.message);
} finally {
  child.kill();
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
