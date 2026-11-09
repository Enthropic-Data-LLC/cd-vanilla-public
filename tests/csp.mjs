// CSP guard for the demo (index.html + app.js + app.css).
//
// The page is meant to run under `script-src 'self'` with no 'unsafe-inline'. That only
// holds while no markup carries an inline handler or inline script, and every data-act
// the markup can emit is one the dispatcher in app.js knows. This test fails the moment
// either stops being true, long before a browser would show a dead button.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const html = readFileSync(`${ROOT}/index.html`, 'utf8');
const app = readFileSync(`${ROOT}/app.js`, 'utf8');
const css = readFileSync(`${ROOT}/app.css`, 'utf8');

let pass = 0, fail = 0;
function check(name, ok, detail = '') {
  if (ok) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name}${detail ? '\n      ' + detail : ''}`); fail++; }
}

console.log('── CSP guard (index.html, app.js, app.css)');

const inlineHandler = /\son[a-z]+\s*=\s*["'`]/i;
check('index.html has no inline event handlers', !inlineHandler.test(html));
check('app.js templates have no inline event handlers',
  !inlineHandler.test(app.replace(/\.on[a-z]+\s*=/g, '')),   // el.onclick = fn is fine, an attribute is not
  (app.match(inlineHandler) || [''])[0]);
check('index.html has no inline <script>', ![...html.matchAll(/<script\b([^>]*)>/gi)].some(m => !/\bsrc=/.test(m[1])));
check('index.html has no inline <style> element', !/<style\b/i.test(html));
check('index.html has no javascript: URLs', !/javascript:/i.test(html) && !/javascript:/i.test(app));
check('app.js does not use eval or new Function', !/\beval\s*\(|new\s+Function\s*\(/.test(app));
check('app.js has no string-form setTimeout/setInterval', !/set(Timeout|Interval)\s*\(\s*["'`]/.test(app));
check('app.css has no @import or external url()', !/@import|url\(\s*["']?https?:/i.test(css));
check('index.html loads app.js and app.css from this origin',
  /<script src="app\.js"><\/script>/.test(html) && /<link rel="stylesheet" href="app\.css">/.test(html));

// Every data-act / data-change the templates can emit must be in the dispatcher.
const actionsBody = app.match(/const ACTIONS = \{([\s\S]*?)\n\};/)?.[1] ?? '';
const changeBody = app.match(/const CHANGE_ACTIONS = \{([\s\S]*?)\};/)?.[1] ?? '';
const known = new Set([...actionsBody.matchAll(/^\s{2}(\w+):/gm)].map(m => m[1]));
const knownChange = new Set([...changeBody.matchAll(/(\w+):/g)].map(m => m[1]));
const used = new Set([...app.matchAll(/data-act="(\w+)"/g)].map(m => m[1]));
const usedChange = new Set([...app.matchAll(/data-change="(\w+)"/g)].map(m => m[1]));
check(`dispatcher defined (${known.size} actions)`, known.size > 0);
const missing = [...used].filter(n => !known.has(n));
check(`every data-act in the markup has a handler (${used.size} used)`, missing.length === 0, 'missing: ' + missing.join(', '));
const missingC = [...usedChange].filter(n => !knownChange.has(n));
check(`every data-change has a handler (${usedChange.size} used)`, missingC.length === 0, 'missing: ' + missingC.join(', '));
// Each dispatcher entry must point at a real function in app.js or cell-crypto.js.
const cryptoJs = readFileSync(`${ROOT}/cell-crypto.js`, 'utf8');
const defined = new Set([...(app + cryptoJs).matchAll(/(?:async\s+)?function\s+(\w+)/g)].map(m => m[1]));
const callTargets = new Set();
for (const m of actionsBody.matchAll(/=>\s*(?:\{([^}]*)\}|(\w+)\()/g)) {
  for (const c of (m[1] || m[2] + '(').matchAll(/\b([A-Za-z_]\w*)\s*\(/g)) callTargets.add(c[1]);
}
const builtins = new Set(['Number', 'if', 'then', 'select', 'writeText', 'getElementById']);
const undefinedFns = [...callTargets].filter(n => !defined.has(n) && !builtins.has(n));
check('every function the dispatcher calls exists', undefinedFns.length === 0, 'undefined: ' + undefinedFns.join(', '));
// The dispatcher refuses names that are not own properties (no 'constructor', '__proto__', ...).
check('dispatcher guards against prototype names', /hasOwnProperty\.call\(ACTIONS/.test(app) && /hasOwnProperty\.call\(CHANGE_ACTIONS/.test(app));

// Load app.js the way a browser does (a classic script at top level) and check the
// dispatcher is really there: ACTIONS must be a global, and the delegated click and
// change listeners must be attached at load, not deferred into some later call.
{
  const listeners = {};
  const stub = () => ({ style: {}, classList: { add() {}, remove() {}, toggle() {} }, addEventListener() {}, appendChild() {}, setAttribute() {} });
  const ctx = vm.createContext({
    window: {}, location: { hostname: 'localhost', origin: 'test://x' }, navigator: { userAgent: 'node' },
    document: { addEventListener: (t, f) => { (listeners[t] ||= []).push(f); }, getElementById: stub, createElement: stub },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} }, indexedDB: {},
    CompressionStream, DecompressionStream, TextEncoder, TextDecoder, crypto: globalThis.crypto, console,
    setTimeout, clearTimeout, URL, Blob, File, atob, btoa,
  });
  let loadErr = '';
  try { vm.runInContext(cryptoJs + '\n;' + app, ctx, { filename: 'app.js' }); } catch (e) { loadErr = String(e); }
  check('app.js loads as a classic script', !loadErr, loadErr);
  check('ACTIONS is a top-level binding (not buried in a function)', vm.runInContext("typeof ACTIONS === 'object' && Object.keys(ACTIONS).length > 30", ctx));
  check('click and change listeners are attached at load', (listeners.click?.length ?? 0) >= 1 && (listeners.change?.length ?? 0) >= 1,
    `click=${listeners.click?.length ?? 0} change=${listeners.change?.length ?? 0}`);
  // Drive the click listener with a fake element: a known action runs, prototype names do not.
  const click = listeners.click?.[0];
  const hit = []; vm.runInContext("closeModal = () => { globalThis.__hit = (globalThis.__hit||0) + 1; }", ctx);
  const el = (act) => ({ dataset: { act }, closest() { return this; } });
  click?.({ target: el('closeModal') });
  check('a known data-act dispatches', vm.runInContext('globalThis.__hit', ctx) === 1);
  let threw = false;
  try { for (const n of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'nope']) click?.({ target: el(n) }); } catch { threw = true; }
  check('prototype names and unknown actions are ignored without error', !threw && vm.runInContext('globalThis.__hit', ctx) === 1);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
