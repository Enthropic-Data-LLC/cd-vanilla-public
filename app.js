'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// APP STATE
// ═══════════════════════════════════════════════════════════════════════════

let _view = 'home';
let _encFile = null;
let _encRecipients = [];
let _openCell = null;
let _prevHash = null;       // set when doing Mitosis re-encrypt
let _mitosisSource = null;  // { bytes, filename, contentType } from last successful decrypt

// ═══════════════════════════════════════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function showAlert(id, msg, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'alert alert-' + (type || 'info');
  el.textContent = msg;
  el.style.display = 'block';
}
function hideAlert(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

function showModal(html) {
  const ov = document.getElementById('modal-overlay');
  ov.innerHTML = `<div class="modal-box">${html}</div>`;
  ov.style.display = 'flex';
  ov.onclick = e => { if (e.target === ov) closeModal(); };
}
function closeModal() { document.getElementById('modal-overlay').style.display = 'none'; }

function methodIcon(m) {
  return { 'ecdh-p256': '🔑', 'pbkdf2': '💬', 'argon2id': '💬', 'yubikey-prf': '🔐' }[m] || '🗝️';
}
function methodLabel(m) {
  return { 'ecdh-p256': 'ECDH P-256', 'pbkdf2': 'Passphrase (PBKDF2)', 'argon2id': 'Passphrase (Argon2id)', 'yubikey-prf': 'YubiKey PRF' }[m] || m;
}
function fileIcon(type) {
  if (!type) return '📄';
  if (type.startsWith('image/')) return '🖼️';
  if (type.startsWith('video/')) return '🎬';
  if (type.startsWith('audio/')) return '🎵';
  if (type.includes('pdf')) return '📕';
  if (type.includes('zip') || type.includes('archive') || type.includes('octet-stream')) return '📦';
  if (type.startsWith('text/')) return '📝';
  return '📄';
}
function navActive(v) {
  ['nav-home','nav-keychain','nav-about'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('active', false);
    el.removeAttribute('aria-current');
  });
  let activeId = null;
  if (v === 'home' || v === 'encrypt' || v === 'open') activeId = 'nav-home';
  if (v === 'keychain') activeId = 'nav-keychain';
  if (v === 'about')    activeId = 'nav-about';
  if (activeId) {
    document.getElementById(activeId)?.classList.add('active');
    document.getElementById(activeId)?.setAttribute('aria-current', 'page');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RENDER DISPATCH
// ═══════════════════════════════════════════════════════════════════════════

async function render() {
  navActive(_view);
  const app = document.getElementById('app');
  if (_view === 'home')     renderHome(app);
  else if (_view === 'encrypt') await renderEncrypt(app);
  else if (_view === 'open')    await renderOpen(app);
  else if (_view === 'keychain') await renderKeychain(app);
  else if (_view === 'about')    renderAbout(app);
}
function go(v) { _view = v; render(); }

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: HOME
// ═══════════════════════════════════════════════════════════════════════════

function renderHome(app) {
  app.innerHTML = `
    <div class="hero">
      <h1>Cell <span>Format</span></h1>
      <p class="hero-sub">Encrypt any file into a self-contained <code>.cell</code> or <code>.celz</code> —
        AES-256-GCM encrypted, zero server dependency, keys stay in your browser.</p>
      <div class="home-actions">
        <div class="drop-card" id="drop-enc">
          <div class="drop-icon">🔐</div>
          <div class="drop-title">Encrypt a file</div>
          <div class="drop-sub">Drop any file or click to browse</div>
          <input type="file" id="inp-enc" style="display:none">
        </div>
        <div class="drop-card" id="drop-open">
          <div class="drop-icon">🔓</div>
          <div class="drop-title">Open a .cell / .celz</div>
          <div class="drop-sub">Drop an encrypted cell or click to browse</div>
          <input type="file" id="inp-open" accept=".cell,.celz,.json" style="display:none">
        </div>
      </div>
    </div>`;

  function setupDrop(cardId, inputId, onFile) {
    const card = document.getElementById(cardId);
    const input = document.getElementById(inputId);
    card.onclick = () => input.click();
    card.ondragover = e => { e.preventDefault(); card.classList.add('drag-over'); };
    card.ondragleave = () => card.classList.remove('drag-over');
    card.ondrop = e => { e.preventDefault(); card.classList.remove('drag-over'); onFile(e.dataTransfer.files[0]); };
    input.onchange = () => onFile(input.files[0]);
  }

  setupDrop('drop-enc', 'inp-enc', file => {
    _encFile = file; _encRecipients = []; go('encrypt');
  });

  setupDrop('drop-open', 'inp-open', async file => {
    try {
      _openCell = await parseCell(file);
      if (!(_openCell.version || _openCell.cd_version) || !(_openCell.payload || _openCell.encrypted_body))
        throw new Error('Not a valid cell file');
      go('open');
    } catch (e) { alert('Invalid cell file: ' + e.message); }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// LIFETIME HELPERS  (spec §6)
// ═══════════════════════════════════════════════════════════════════════════

function formatLifetime(lt) {
  if (!lt) return '—';
  // readLifetime() reads both the v1.3 split shape and the flat v1.0-1.2 one,
  // so this renders cells of any supported version. Reading lt.expires_at
  // directly would show nothing at all for a v1.3 cell.
  const L = readLifetime(lt);
  const ret = L.retainUntil ? fmtDate(L.retainUntil) : null;
  const rel = L.releaseAt   ? fmtDate(L.releaseAt)   : null;
  const now = Math.floor(Date.now() / 1000);
  // "Retention ended" is deliberately not "EXPIRED": the document is not gone
  // and the holder is not locked out — a conforming client declines to open it.
  const ended = L.retainUntil && L.retainUntil < now;
  const tail  = `${ret ? ` · retain to ${ret}` : ''}${ended ? ' · retention ended' : ''}`;
  switch (L.type) {
    case 'flash':         return `Flash · single use${tail}`;
    case 'session':       return `Session${tail}`;
    case 'clinical':      return `Clinical${tail}`;
    case 'record':        return `Record${tail}`;
    case 'permanent':     return 'Permanent · no retention limit';
    case 'timed_release': {
      const locked = rel && L.releaseAt > now;
      return `Timed release · ${locked ? `🔒 unlocks ${rel}` : `unlocked ${rel}`}${tail}`;
    }
    default: return esc(L.type || '—');
  }
}

function getLifetimeOption() {
  const type = document.getElementById('enc-lifetime-type')?.value || 'permanent';
  const now  = Math.floor(Date.now() / 1000);
  switch (type) {
    case 'flash':
      return { type, advisory: { retain_until: now + 3600, release_at: null, single_use: true, minimum_atl: 1 }, disposal: { at: now + 3600, action: 'delete' } };
    case 'session': {
      const h = parseInt(document.getElementById('enc-lt-val')?.value || '24');
      return { type, advisory: { retain_until: now + h * 3600, release_at: null, single_use: false, minimum_atl: 1 }, disposal: { at: now + h * 3600, action: 'delete' } };
    }
    case 'clinical': {
      const m = parseInt(document.getElementById('enc-lt-val')?.value || '6');
      return { type, advisory: { retain_until: now + m * 30 * 86400, release_at: null, single_use: false, minimum_atl: 1 }, disposal: { at: now + m * 30 * 86400, action: 'archive' } };
    }
    case 'record': {
      const y = parseInt(document.getElementById('enc-lt-val')?.value || '7');
      return { type, advisory: { retain_until: now + y * 365 * 86400, release_at: null, single_use: false, minimum_atl: 1 }, disposal: { at: now + y * 365 * 86400, action: 'archive' } };
    }
    case 'timed_release': {
      const s = document.getElementById('enc-lt-release')?.value;
      const release_at = s ? Math.floor(new Date(s).getTime() / 1000) : now + 3600;
      return { type, advisory: { retain_until: null, release_at, single_use: false, minimum_atl: 1 }, disposal: { at: null, action: 'archive' } };
    }
    default:
      return { type: 'permanent', advisory: { retain_until: null, release_at: null, single_use: false, minimum_atl: 1 }, disposal: { at: null, action: 'none' } };
  }
}

function renderLifetimeOptions() {
  const type = document.getElementById('enc-lifetime-type')?.value || 'permanent';
  const div  = document.getElementById('enc-lifetime-opts');
  if (!div) return;
  const rel = new Date(Date.now() + 3600000).toISOString().slice(0, 16);
  const opts = {
    flash:    `<p class="hint" style="margin-top:0.25rem">Expires in 1 hour. Marked single-use.</p>`,
    session:  `<div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.25rem"><input type="number" id="enc-lt-val" min="1" max="168" value="24" style="width:70px"><span style="color:#666;font-size:0.88rem">hours</span></div>`,
    clinical: `<div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.25rem"><input type="number" id="enc-lt-val" min="1" max="72" value="6" style="width:70px"><span style="color:#666;font-size:0.88rem">months · archived on expiry</span></div>`,
    record:   `<div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.25rem"><input type="number" id="enc-lt-val" min="1" max="25" value="7" style="width:70px"><span style="color:#666;font-size:0.88rem">years · archived on expiry</span></div>`,
    timed_release: `<div class="field" style="margin-top:0.25rem"><label style="font-size:0.82rem">Unlock at</label><input type="datetime-local" id="enc-lt-release" value="${rel}" style="width:100%"></div>`,
    permanent: ``,
  };
  div.innerHTML = opts[type] ?? '';
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: ENCRYPT
// ═══════════════════════════════════════════════════════════════════════════

async function renderEncrypt(app) {
  const signerKeys = (await kcAll()).filter(k => k.method === 'ecdh-p256' && k.pkcs8 && k.spki);
  app.innerHTML = `
    <div class="page-header">
      <button class="btn btn-secondary btn-sm" data-act="go" data-a="home">← Back</button>
      <h2>Encrypt file</h2>
    </div>
    <div class="two-col">
      <div>
        <div class="card">
          <h3>File</h3>
          <div class="file-info">
            <div class="file-icon">${fileIcon(_encFile.type)}</div>
            <div>
              <div class="file-name">${esc(_encFile.name)}</div>
              <div class="file-meta">${fmtBytes(_encFile.size)} · ${esc(_encFile.type || 'unknown type')}</div>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>Recipients <span class="count-badge" id="rec-count">0</span></h3>
          <p class="hint" style="margin-bottom:1rem">Anyone with a matching key can decrypt this cell.</p>
          <div id="rec-list"></div>
          <div class="btn-group" style="margin-top:1rem">
            <button class="btn btn-secondary btn-sm" data-act="encAddFromKeychain">+ From keychain</button>
            <button class="btn btn-secondary btn-sm" data-act="encAddPassphrase">+ Passphrase</button>
            <button class="btn btn-secondary btn-sm" data-act="encAddYubikey">+ YubiKey</button>
            <button class="btn btn-secondary btn-sm" data-act="encAddPubkeyPaste">+ Paste pubkey</button>
          </div>
        </div>
      </div>

      <div>
        <div class="card">
          <h3>Options</h3>
          <div class="field">
            <label>Lifetime</label>
            <select id="enc-lifetime-type" data-change="renderLifetimeOptions">
              <option value="permanent">Permanent — no expiry</option>
              <option value="flash">Flash — single use, &lt;1 hour</option>
              <option value="session">Session — hours to days</option>
              <option value="clinical">Clinical — days to months</option>
              <option value="record">Record — months to years</option>
              <option value="timed_release">Timed release — unlocks at date</option>
            </select>
            <div id="enc-lifetime-opts"></div>
          </div>
          <div class="field">
            <label>Quorum threshold</label>
            <div style="display:flex;align-items:center;gap:0.5rem">
              <input type="number" id="enc-thresh" min="1" max="1" value="1" style="width:64px">
              <span id="enc-thresh-of" style="color:#666;font-size:0.88rem">of 0 recipients</span>
            </div>
            <p class="hint" style="margin-top:0.25rem">1 = standard. &gt;1 requires M keys simultaneously.</p>
          </div>
          <div class="field">
            <label>Sign as (optional)</label>
            <select id="enc-signer">
              <option value="">— Unsigned —</option>
              ${signerKeys.map(k => `<option value="${k.keyId}">${esc(k.label)} · ${k.fingerprint}</option>`).join('')}
            </select>
            <p class="hint" style="margin-top:0.25rem">ECDSA, sealed inside the encryption: only a recipient can see who signed, and the signature covers the content and the intended recipients.</p>
          </div>
          <div class="field">
            <label>Copy protection</label>
            <select id="enc-copy-prot">
              <option value="none">None</option>
              <option value="standard" selected>Standard</option>
              <option value="strict">Strict — no redistribution</option>
            </select>
          </div>
          <div class="field">
            <label>Watermark mode</label>
            <select id="enc-watermark">
              <option value="none" selected>None</option>
              <option value="basic">Basic — recipient identity</option>
              <option value="full">Full — forensic</option>
            </select>
          </div>
          <div class="field">
            <label>Output format</label>
          </div>
          <div class="format-toggle">
            <input type="radio" name="fmt" id="fmt-cell" value="cell" checked>
            <label for="fmt-cell">.cell (JSON)</label>
            <input type="radio" name="fmt" id="fmt-celz" value="celz">
            <label for="fmt-celz">.celz (gzip)</label>
          </div>
          <p class="hint"><strong>.cell</strong> — human-readable JSON, inspect in any text editor.<br>
          <strong>.celz</strong> — gzip-compressed .cell, ~30% smaller, binary.</p>
        </div>

        <div class="card">
          ${_prevHash ? `<div class="alert alert-info" style="display:block;margin-bottom:1rem">🔄 <strong>Mitosis</strong> — linked to previous cell.<br><span style="font-family:monospace;font-size:0.78rem">prev_hash: ${esc(_prevHash.slice(0,24))}…</span></div>` : ''}
          <div id="enc-status" class="alert" style="display:none"></div>
          <button class="btn btn-primary btn-block" id="btn-encrypt" data-act="doEncrypt">🔐 Encrypt &amp; Download</button>
          <p class="hint" style="text-align:center;margin-top:0.75rem">Share the output file any way you like — it is fully self-contained.</p>
        </div>
      </div>
    </div>`;
  renderRecList();
}

function renderRecList() {
  const list = document.getElementById('rec-list');
  const count = document.getElementById('rec-count');
  if (count) count.textContent = _encRecipients.length;
  const n = _encRecipients.length;
  const tInp = document.getElementById('enc-thresh');
  const tOf  = document.getElementById('enc-thresh-of');
  if (tInp) {
    tInp.max = n || 1;
    if (parseInt(tInp.value) > n) tInp.value = n || 1;
    if (tOf) tOf.textContent = `of ${n} recipient${n === 1 ? '' : 's'}`;
  }
  if (!list) return;
  if (!n) {
    list.innerHTML = '<p style="color:#aaa;font-size:0.85rem">No recipients yet.</p>'; return;
  }
  list.innerHTML = _encRecipients.map((r, i) => `
    <div class="recipient-row">
      <span class="recipient-icon">${methodIcon(r.method)}</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:0.9rem">${esc(r.label)}</div>
        <div style="font-size:0.75rem;color:#888;font-family:monospace">${esc(methodLabel(r.method))}${r.fingerprint ? ' · ' + esc(r.fingerprint) : ''}</div>
      </div>
      <button class="btn-icon" data-act="encRemove" data-a="${i}">✕</button>
    </div>`).join('');
}

function encRemove(i) { _encRecipients.splice(i, 1); renderRecList(); }

async function encAddFromKeychain() {
  const keys     = await kcAll();
  const contacts = lsPubContacts(keys);
  const allRows  = [
    ...keys.map(k => ({ ...k, _src: 'keychain' })),
    ...contacts.map(c => ({ ...c, _src: 'contact' })),
  ];
  showModal(`
    <h3>Add recipient</h3>
    ${allRows.length ? `<div class="modal-list">
      ${allRows.map(k => `
        <div class="modal-key-row" data-act="encSelectKey" data-a="${esc(k.keyId)}" data-b="${esc(k._src)}">
          ${methodIcon(k.method)} <strong>${esc(k.label)}</strong>
          <span style="font-size:0.75rem;color:#888"> · <code>${esc(k.fingerprint)}</code></span>
          ${k._src === 'contact' ? '<span style="font-size:0.72rem;color:#1565c0;margin-left:4px">contact</span>' : ''}
          ${!k.spki && k.method === 'ecdh-p256' ? '<span style="color:#c62828;font-size:0.75rem"> (no public key)</span>' : ''}
        </div>`).join('')}
    </div>` : `<p style="color:#aaa;font-size:0.9rem;margin-bottom:1rem">No keys yet.</p>`}
    <div class="btn-group" style="margin-top:1rem;flex-wrap:wrap">
      <button class="btn btn-primary btn-sm" data-act="encInlineGenKey">+ Generate ECDH key</button>
      <button class="btn btn-secondary btn-sm" data-act="closeModal">Cancel</button>
    </div>`);
}

function encInlineGenKey() {
  showModal(`
    <h3>Generate ECDH P-256 key</h3>
    <p class="hint" style="margin-bottom:1rem">Creates a new key in your keychain and adds it as a recipient.</p>
    <div class="field"><label>Label</label><input id="ig-lbl" placeholder="e.g. My Key" style="width:100%" autofocus></div>
    <div id="ig-err" class="alert alert-error" style="display:none"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="encInlineGenConfirm">Generate &amp; add</button>
      <button class="btn btn-secondary" data-act="encAddFromKeychain">Back</button>
    </div>`);
  setTimeout(() => document.getElementById('ig-lbl')?.focus(), 80);
}

async function encInlineGenConfirm() {
  const lbl = document.getElementById('ig-lbl').value.trim();
  const err = document.getElementById('ig-err');
  if (!lbl) { err.textContent = 'Enter a label'; err.style.display = 'block'; return; }
  try {
    const k = await kcGenEcdh(lbl);
    _encRecipients.push({ keyId: k.keyId, method: k.method, label: k.label,
      fingerprint: k.fingerprint, spki: k.spki });
    closeModal();
    renderRecList();
  } catch (e) { err.textContent = e.message; err.style.display = 'block'; }
}

async function encSelectKey(keyId, src) {
  const k = src === 'contact'
    ? lsPubAll().find(r => r.keyId === keyId)
    : await kcGet(keyId);
  if (!k) return;
  if (_encRecipients.find(r => r.keyId === keyId)) { closeModal(); return; }
  _encRecipients.push({ keyId: k.keyId, method: k.method, label: k.label,
    fingerprint: k.fingerprint, spki: k.spki,
    credential_id: k.credential_id, prf_salt: k.prf_salt });
  closeModal(); renderRecList();
}

function encAddPassphrase() {
  showModal(`
    <h3>Passphrase recipient</h3>
    <div class="field"><label>Label</label><input id="mp-lbl" placeholder="e.g. My passphrase" style="width:100%"></div>
    <div class="field"><label>Passphrase</label><input type="password" id="mp-p1" style="width:100%" autofocus></div>
    <div class="field"><label>Confirm</label><input type="password" id="mp-p2" style="width:100%"></div>
    <div id="mp-err" class="alert alert-error" style="display:none"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="encConfirmPass">Add</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
}

function encConfirmPass() {
  const p1 = document.getElementById('mp-p1').value;
  const p2 = document.getElementById('mp-p2').value;
  const lbl = document.getElementById('mp-lbl').value || 'Passphrase';
  const err = document.getElementById('mp-err');
  if (!p1) { err.textContent='Passphrase required'; err.style.display='block'; return; }
  if (p1 !== p2) { err.textContent='Passphrases do not match'; err.style.display='block'; return; }
  // v1.4 writes Argon2id (§6.5); the label stays in this UI only — v1.4 entries are blind
  _encRecipients.push({ method: 'argon2id', label: lbl, passphrase: p1 });
  closeModal(); renderRecList();
}

async function encAddYubikey() {
  const keys = (await kcAll()).filter(k => k.method === 'yubikey-prf');
  if (!keys.length) {
    if (!confirm('No YubiKey registered. Register one now?\n(Key must be present for both encryption and decryption.)')) return;
    await kcAddYubikey(); return;
  }
  showYubikeyPicker(keys);
}

function showYubikeyPicker(keys) {
  showModal(`
    <h3>YubiKey keys</h3>
    <div class="modal-list" id="yk-picker-list">
      ${keys.map(k => `
        <div class="modal-key-row" style="justify-content:space-between">
          <span data-act="encSelectKeyClose" data-a="${esc(k.keyId)}" style="flex:1;cursor:pointer">
            🔐 <strong>${esc(k.label)}</strong>
            <span style="font-size:0.75rem;color:#888"> · <code>${esc(k.fingerprint)}</code></span>
          </span>
          <button class="btn btn-danger btn-sm" style="margin-left:0.75rem;flex-shrink:0"
            data-act="ykPickerRemove" data-a="${esc(k.keyId)}">Remove</button>
        </div>`).join('')}
    </div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-secondary btn-sm" data-act="kcAddYubikey">+ Register new key</button>
      <button class="btn btn-secondary btn-sm" data-act="closeModal">Cancel</button>
    </div>`);
}

async function ykPickerRemove(keyId) {
  const k = await kcGet(keyId);
  if (!k) return;
  if (!confirm(`Remove "${k.label}" from this device?\n\nThe credential stays on your YubiKey. You can re-register it at any time.`)) return;
  await kcDel(keyId);
  const remaining = (await kcAll()).filter(k => k.method === 'yubikey-prf');
  if (!remaining.length) { closeModal(); return; }
  showYubikeyPicker(remaining);
}

function encAddPubkeyPaste() {
  showModal(`
    <h3>Paste public key</h3>
    <p class="hint" style="margin-bottom:1rem">Paste a .cdpub JSON (from someone's exported public key) to encrypt a cell they can open.</p>
    <div class="field"><label>Label</label><input id="mpk-lbl" placeholder="e.g. Alice" style="width:100%"></div>
    <div class="field"><label>Public key (JSON or raw SPKI base64)</label>
      <textarea id="mpk-data" rows="5" placeholder='{"cd_pubkey":"2.0","spki":"..."}' style="width:100%;font-family:monospace;font-size:0.75rem"></textarea>
    </div>
    <div id="mpk-err" class="alert alert-error" style="display:none"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="encConfirmPubkey">Add</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
}

async function encConfirmPubkey() {
  const lbl  = document.getElementById('mpk-lbl').value || 'Recipient';
  const data = document.getElementById('mpk-data').value.trim();
  const err  = document.getElementById('mpk-err');
  try {
    const parsed = JSON.parse(data);
    const spki = parsed.spki;
    await assertValidSpki(spki);
    const fingerprint = safeFingerprint(parsed.fingerprint) || await fp(spki);
    _encRecipients.push({ method: 'ecdh-p256', label: lbl, fingerprint, spki });
    closeModal(); renderRecList();
  } catch (e) { err.textContent = 'Invalid key: ' + e.message; err.style.display = 'block'; }
}

async function doEncrypt() {
  if (!_encRecipients.length) {
    showAlert('enc-status', 'Add at least one recipient.', 'error'); return;
  }
  const btn = document.getElementById('btn-encrypt');
  btn.textContent = '⏳ Encrypting…'; btn.disabled = true;
  hideAlert('enc-status');
  try {
    const fmt         = document.querySelector('input[name="fmt"]:checked')?.value || 'cell';
    const threshold   = parseInt(document.getElementById('enc-thresh')?.value || '1');
    const signerKeyId = document.getElementById('enc-signer')?.value;
    const senderRec   = signerKeyId ? await kcGet(signerKeyId) : null;
    const lifetime    = getLifetimeOption();
    const policy      = {
      copy_protection:   document.getElementById('enc-copy-prot')?.value  || 'standard',
      watermark_mode:    document.getElementById('enc-watermark')?.value   || 'none',
      created_on_origin: window.location.origin || null,
      origin_sig:        null,
    };
    const cell = await cellCreate(_encFile, _encRecipients, { threshold, senderRec, lifetime, policy, prevHash: _prevHash });
    _prevHash = null;
    await dlCell(cell, _encFile.name, fmt);
    const n = cell.header.access_map.length;
    const t = cell.header.threshold.required;
    const threshNote = t > 1 ? ` (${t}-of-${n} quorum)` : '';
    const sigNote    = (cell.header_sig || senderRec) ? ` · signed` : '';
    showAlert('enc-status',
      `✅ Saved as ${_encFile.name}.${fmt} — ${n} recipient(s)${threshNote}${sigNote}, AES-256-GCM`, 'success');
  } catch (e) {
    showAlert('enc-status', '❌ ' + e.message, 'error');
    console.error(e);
  }
  btn.textContent = '🔐 Encrypt & Download'; btn.disabled = false;
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: OPEN
// ═══════════════════════════════════════════════════════════════════════════

async function renderOpen(app) {
  const c = _openCell;
  const accessMap  = c.header?.access_map ?? c.recipients ?? [];
  // Everything below comes from the file, before any check: anyone who can hand
  // the user a .cell controls it. Escape every string; numbers must be numbers.
  const thrReq     = c.header?.threshold?.required;
  const threshold  = Number.isInteger(thrReq) && thrReq > 0 ? thrReq : 1;
  const docId      = String(c.doc_id || c.cell_id || '');
  const fmtVersion = c.version ?? c.cd_version ?? 'unknown';
  const isLegacy   = !c.version && c.cd_version;
  const policy     = c.header?.policy;
  // original_filename / content_type / original_size are legacy v2.0 fields,
  // authenticated by nothing. On a supported version the real values are inside
  // the ciphertext, so anything found here is someone else's edit: never show it.
  app.innerHTML = `
    <div class="page-header">
      <button class="btn btn-secondary btn-sm" data-act="go" data-a="home">← Back</button>
      <h2>Open cell</h2>
    </div>
    <div class="two-col">
      <div>
        <div class="card">
          <h3>Cell metadata</h3>
          <table class="meta-table">
            <tr><td>File</td><td><strong>${isLegacy && c.original_filename ? esc(c.original_filename) : '<span style="color:#aaa;font-style:italic">🔒 encrypted</span>'}</strong></td></tr>
            <tr><td>Type</td><td>${isLegacy && c.content_type ? esc(c.content_type) : '<span style="color:#aaa;font-style:italic">🔒 encrypted</span>'}</td></tr>
            <tr><td>Size</td><td>${isLegacy && c.original_size ? esc(fmtBytes(Number(c.original_size))) : '<span style="color:#aaa;font-style:italic">🔒 encrypted</span>'}</td></tr>
            <tr><td>Lifetime</td><td>${formatLifetime(c.header?.lifetime)}</td></tr>
            <tr><td>Encryption</td><td>${esc(c.payload?.alg || c.encrypted_body?.alg || 'AES-256-GCM')}</td></tr>
            <tr><td>Created</td><td>${c.created_at ? fmtDate(c.created_at) : '—'}</td></tr>
            ${threshold > 1 ? `<tr><td>Quorum</td><td><strong>${threshold}-of-${accessMap.length}</strong> keys required</td></tr>` : ''}
            ${policy ? `<tr><td>Copy protection</td><td>${esc(policy.copy_protection || 'none')}${policy.copy_protection === 'strict' ? ' 🔒' : ''}</td></tr>` : ''}
            ${policy?.watermark_mode && policy.watermark_mode !== 'none' ? `<tr><td>Watermark</td><td>${esc(policy.watermark_mode)}</td></tr>` : ''}
            ${policy?.created_on_origin ? `<tr><td>Origin</td><td style="font-size:0.8rem">${esc(policy.created_on_origin)}</td></tr>` : ''}
            <tr><td>Integrity</td><td>${c.header_hash ? '✅ hash chain' : '⚠️ no hash (legacy)'}</td></tr>
            <tr><td>Signed by</td><td>${c.header_sig ? `<span style="font-family:monospace;font-size:0.78rem">${esc(c.header_sig_by || '?')}</span>` : (c.version === '1.4' ? '<span style="color:#aaa;font-style:italic">🔒 inside the ciphertext, if signed</span>' : '—')}</td></tr>
            ${c.header?.prev_hash ? `<tr><td>Prev cell</td><td style="font-family:monospace;font-size:0.72rem" title="${esc(c.header.prev_hash)}">🔗 ${esc(String(c.header.prev_hash).slice(0,24))}…</td></tr>` : ''}
            <tr><td>Doc ID</td><td style="font-family:monospace;font-size:0.72rem">${esc(docId.slice(0,18))}…</td></tr>
            <tr><td>Version</td><td>${esc(c.version || c.cd_version || '—')}</td></tr>
          </table>
        </div>

        <div class="card">
          <h3>Access map (${accessMap.length})</h3>
          ${accessMap.map(r => `
            <div class="recipient-row">
              <span class="recipient-icon">${methodIcon(r.method)}</span>
              <div>
                <div style="font-weight:600;font-size:0.9rem">${esc(r.label || methodLabel(r.method))}</div>
                <div style="font-size:0.75rem;color:#888;font-family:monospace">${r.fingerprint ? esc(methodLabel(r.method)) + ' · ' + esc(r.fingerprint) : 'no fingerprint, no label — found by trial decryption'}${Number.isInteger(r.share_index) ? ' · share #' + r.share_index : ''}</div>
              </div>
            </div>`).join('')}
        </div>
      </div>

      <div>
        <div class="card">
          <h3>Decrypt</h3>
          ${isLegacy ? `<div class="alert" style="display:block;margin-bottom:1rem;background:#fff8e1;border-color:#f9a825;color:#5d4037">⚠️ Legacy format (${esc(fmtVersion)}) — decryption supported but re-encrypt to upgrade.</div>` : ''}
          ${!isLegacy && !SUPPORTED_VERSIONS.has(fmtVersion) ? `<div class="alert alert-error" style="display:block;margin-bottom:1rem">Unknown format version "${esc(fmtVersion)}" — this cell may not decrypt correctly.</div>` : ''}
          ${policy?.copy_protection === 'strict' ? `<div class="alert" style="display:block;margin-bottom:1rem;background:#fff3e0;border-color:#e65100;color:#bf360c">🔒 Strict copy protection — authorized recipients only. Do not redistribute.</div>` : ''}
          ${threshold > 1 ? `<div class="alert alert-info" style="display:block;margin-bottom:1rem">Quorum: provide ${threshold} of ${accessMap.length} keys to open.</div>` : ''}
          <div id="open-status" class="alert" style="display:none"></div>
          <div class="btn-group-vert">
            <button class="btn btn-primary" data-act="openWithKeychain">🔑 Use keychain key</button>
            <button class="btn btn-secondary" data-act="openWithPassphrase">💬 Enter passphrase</button>
            <button class="btn btn-secondary" data-act="openWithYubikey">🔐 Use YubiKey</button>
            <button class="btn btn-secondary" data-act="openWithKeyFile">📂 Use .cdkey / .pem file</button>
          </div>
          <div id="open-reencrypt" style="display:none;margin-top:1rem;border-top:1px solid #f0f0f0;padding-top:1rem"></div>
        </div>
      </div>
    </div>`;
}

// A valid ECDSA signature only proves the signer held the private key matching
// header_sig_key. Trust must be anchored to THAT key (its real fingerprint /
// SPKI), never to the self-asserted header_sig_by label — otherwise an attacker
// signs with their own key but claims a victim's fingerprint. Resolve the actual
// signing key against the opener's keychain/contacts.
async function resolveSigner(spki) {
  if (!spki) return null;
  const all = [...(await kcAll()), ...lsPubAll()];
  return all.find(k => k.spki && k.spki === spki) || null;
}
async function sigNoteFor(result) {
  if (!result.sigVerified) return '';
  const realFp = result.sigKey ? await fp(result.sigKey) : null;
  const signer = await resolveSigner(result.sigKey);
  // Shown with showAlert(), i.e. textContent: plain text, nothing to escape.
  if (signer) return ` · ✍️ signed by ${signer.label} (${realFp || ''})`;
  return ` · ⚠️ signed by UNKNOWN key ${realFp || '?'} — not in your keychain/contacts`;
}

async function openWithKeychain() {
  const keys = (await kcAll()).filter(k => k.method === 'ecdh-p256' && k.pkcs8);
  if (!keys.length) { showAlert('open-status', 'No ECDH private keys in keychain.', 'error'); return; }
  showAlert('open-status', '🔑 Trying keychain keys…', 'info');
  let usedKey = null;  // v1.4 entries carry no label, so remember which of our keys unwrapped
  try {
    const result = await cellOpen(_openCell, async (r) => {
      if (r.method !== 'ecdh-p256') return null;
      for (const key of keys) {
        if (r.fingerprint && r.fingerprint !== key.fingerprint) continue;
        try {
          const priv = await kcLoadPrivKey(key);
          const cek = await ecdhUnwrapCek(r.wrapped_cek, priv);
          usedKey = key;
          return cek;
        } catch { continue; }
      }
      return null;
    });
    const sigNote = await sigNoteFor(result);
    showAlert('open-status', `✅ Decrypted with "${result.usedRecipient?.label || usedKey?.label || 'keychain key'}"${sigNote}`, 'success');
    dlBytes(result.bytes, result.filename, result.contentType);
    _showReencrypt(result);
  } catch (e) { showAlert('open-status', '❌ ' + e.message, 'error'); }
}

let _passOpen = null;  // AbortController of the passphrase open in progress

function openWithPassphrase() {
  showModal(`
    <h3>Enter passphrase</h3>
    <div class="field"><input type="password" id="odec-pass" placeholder="Passphrase" style="width:100%" autofocus></div>
    <p id="odec-progress" class="hint" style="display:none" aria-live="polite"></p>
    <div id="odec-err" class="alert alert-error" style="display:none"></div>
    <div class="btn-group" style="margin-top:0.75rem">
      <button class="btn btn-primary" id="odec-go" data-act="openConfirmPass">Decrypt</button>
      <button class="btn btn-secondary" data-act="cancelPassOpen">Cancel</button>
    </div>`);
  setTimeout(() => document.getElementById('odec-pass')?.focus(), 80);
  document.getElementById('odec-pass').onkeydown = e => { if (e.key==='Enter') openConfirmPass(); };
}

// Stops before the next entry. A derivation already running finishes first:
// key derivation runs on the page and cannot be interrupted part-way.
function cancelPassOpen() {
  _passOpen?.abort();
  closeModal();
}

async function openConfirmPass() {
  const pass = document.getElementById('odec-pass').value;
  const err  = document.getElementById('odec-err');
  const prog = document.getElementById('odec-progress');
  const go   = document.getElementById('odec-go');
  if (!pass) { err.textContent='Enter a passphrase'; err.style.display='block'; return; }
  if (_passOpen) return;
  const ac = _passOpen = new AbortController();
  const map = _openCell.header?.access_map ?? _openCell.recipients ?? [];
  const total = map.filter(r => r?.method === 'pbkdf2' || r?.method === 'argon2id').length;
  let n = 0;
  go.disabled = true; err.style.display = 'none';
  try {
    const result = await cellOpen(_openCell, async (r) => {
      if (r.method === 'argon2id') return argon2idUnwrapCek(r.wrapped_cek, pass);
      if (r.method !== 'pbkdf2') return null;
      return pbkdf2UnwrapCek(r.wrapped_cek, pass);
    }, {
      signal: ac.signal,
      onAttempt: async ({ kdf }) => {
        if (!kdf) return;
        prog.textContent = `Trying the passphrase on entry ${++n} of ${total}… this can take a while.`;
        prog.style.display = 'block';
        await new Promise(r => setTimeout(r, 30));   // repaint before the derivation holds the page
      },
    });
    if (ac.signal.aborted) return;
    closeModal();
    const sigNote = await sigNoteFor(result);
    showAlert('open-status', `✅ Decrypted successfully${sigNote}`, 'success');
    dlBytes(result.bytes, result.filename, result.contentType);
    _showReencrypt(result);
  } catch (e) {
    if (ac.signal.aborted) return;
    prog.style.display = 'none';
    err.textContent = /not tried/.test(e.message) ? e.message : 'Wrong passphrase or corrupted cell';
    err.style.display = 'block';
  } finally {
    _passOpen = null;
    go.disabled = false;
  }
}

async function openWithYubikey() {
  showAlert('open-status','🔐 Touch your YubiKey…','info');
  try {
    const result = await cellOpen(_openCell, async (r) => {
      if (r.method !== 'yubikey-prf') return null;
      return prfUnwrapCek(r.wrapped_cek);
    });
    const sigNote = await sigNoteFor(result);
    showAlert('open-status', `✅ Decrypted with YubiKey${sigNote}`, 'success');
    dlBytes(result.bytes, result.filename, result.contentType);
    _showReencrypt(result);
  } catch (e) { showAlert('open-status','❌ YubiKey: ' + e.message,'error'); }
}

function openWithKeyFile() {
  showModal(`
    <h3>Use key file</h3>
    <p class="hint" style="margin-bottom:1rem">Select a <strong>.cdkey</strong> (exported from keychain) or a PKCS8 <strong>.pem</strong> private key. Used only in memory — never saved to this browser.</p>
    <input type="file" id="okf-inp" accept=".cdkey,.pem,.json">
    <div id="okf-err" class="alert alert-error" style="display:none;margin-top:0.75rem"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="openConfirmKeyFile">Decrypt</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
}

async function openConfirmKeyFile() {
  const inp = document.getElementById('okf-inp');
  const err = document.getElementById('okf-err');
  if (!inp.files[0]) { err.textContent='Select a key file'; err.style.display='block'; return; }
  try {
    const file = inp.files[0];
    const isPem = file.name.toLowerCase().endsWith('.pem');
    let priv, label, fp_key;
    if (isPem) {
      const text = await file.text();
      if (!text.includes('-----BEGIN')) throw new Error('Not a valid PEM file');
      priv = await crypto.subtle.importKey('pkcs8', parsePemKey(text),
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      label = file.name;
    } else {
      const data = JSON.parse(await file.text());
      if (!data.pkcs8) throw new Error('No private key in this file');
      priv = await crypto.subtle.importKey('pkcs8', fromB64(data.pkcs8),
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      label = data.label || 'key file';
      fp_key = data.fingerprint;
    }
    const result = await cellOpen(_openCell, async (r) => {
      if (r.method !== 'ecdh-p256') return null;
      if (fp_key && r.fingerprint && r.fingerprint !== fp_key) return null;
      return ecdhUnwrapCek(r.wrapped_cek, priv);
    });
    closeModal();
    const sigNote = await sigNoteFor(result);
    showAlert('open-status', `✅ Decrypted with "${label}"${sigNote}`, 'success');
    dlBytes(result.bytes, result.filename, result.contentType);
    _showReencrypt(result);
  } catch (e) { err.textContent='Failed: ' + e.message; err.style.display='block'; }
}

// ═══════════════════════════════════════════════════════════════════════════
// MITOSIS — re-encrypt an opened cell with new recipients / keys
// ═══════════════════════════════════════════════════════════════════════════

function _showReencrypt(result) {
  _mitosisSource = { bytes: result.bytes, filename: result.filename, contentType: result.contentType };
  const div = document.getElementById('open-reencrypt');
  if (!div) return;
  div.style.display = 'block';
  div.innerHTML = `
    <button class="btn btn-secondary btn-block" data-act="doMitosis">🔄 Re-encrypt (Mitosis)</button>
    <p class="hint" style="text-align:center;margin-top:0.5rem">Create a new cell linked to this one — change recipients or rotate keys.</p>`;
}

function doMitosis() {
  if (!_mitosisSource) return;
  _encFile = new File([_mitosisSource.bytes], _mitosisSource.filename, { type: _mitosisSource.contentType });
  _prevHash = _openCell?.header_hash || null;
  _encRecipients = [];
  _mitosisSource = null;
  go('encrypt');
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: KEYCHAIN
// ═══════════════════════════════════════════════════════════════════════════

async function renderKeychain(app) {
  const keys     = await kcAll();
  const contacts = lsPubContacts(keys);
  app.innerHTML = `
    <div class="page-header">
      <h2>Keychain</h2>
    </div>
    <div class="card" style="margin-bottom:1.5rem">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;margin-bottom:1.25rem">
        <div>
          <p class="hint" style="max-width:480px;margin-bottom:0.25rem">Private keys are stored in IndexedDB. Public key metadata is also mirrored to <strong>localStorage</strong> so your fingerprints survive an IDB clear.</p>
          <p class="hint" style="max-width:480px">Private keys never leave this device unless you explicitly export them with <strong>Export .cdkey</strong>.</p>
        </div>
        <div class="btn-group">
          <button class="btn btn-primary btn-sm" data-act="kcGenKey">+ Generate key</button>
          <button class="btn btn-secondary btn-sm" data-act="kcAddYubikey">+ Register YubiKey</button>
          <button class="btn btn-secondary btn-sm" data-act="kcImport">+ Import</button>
        </div>
      </div>
      ${keys.length === 0 ? `
        <div style="text-align:center;padding:2.5rem;color:#aaa">
          <div style="font-size:2rem;margin-bottom:0.75rem">🔑</div>
          No keys yet. Generate an ECDH key to get started.
        </div>` : `
        <div>${keys.map(k => `
          <div class="key-row">
            <span style="font-size:1.5rem;flex-shrink:0">${methodIcon(k.method)}</span>
            <div style="flex:1;min-width:0">
              <div style="font-weight:600">${esc(k.label)}</div>
              <div style="font-size:0.78rem;color:#888">
                ${esc(methodLabel(k.method))} ·
                <span style="font-family:monospace">${esc(k.fingerprint)}</span>
                ${k.method === 'yubikey-prf' ? ' · <span style="color:#1565c0">WebAuthn credential</span>' : k.pkcs8 ? ' · <span style="color:#2e7d32">has private key</span>' : ' · <span style="color:#888">public key only</span>'}
                ${lsPubAll().find(r => r.keyId === k.keyId) ? ' · <span style="color:#1565c0" title="Public key mirrored to localStorage">📋 in localStorage</span>' : ''}
                · added ${k.created_at ? fmtDate(k.created_at) : '?'}
              </div>
            </div>
            <div class="btn-group">
              ${k.spki ? `<button class="btn btn-secondary btn-sm" data-act="kcSharePub" data-a="${esc(k.keyId)}">Share pubkey</button>` : ''}
              ${k.pkcs8 ? `<button class="btn btn-secondary btn-sm" data-act="kcExportKey" data-a="${esc(k.keyId)}">Export .cdkey</button>` : ''}
              <button class="btn btn-danger btn-sm" data-act="kcDeleteKey" data-a="${esc(k.keyId)}">Delete</button>
            </div>
          </div>`).join('')}
        </div>`}
    </div>

    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
        <div>
          <strong>Saved contacts</strong>
          <p class="hint" style="margin:0.25rem 0 0">Public keys stored in localStorage — for encrypting to others. No private key required.</p>
        </div>
        <button class="btn btn-secondary btn-sm" data-act="kcSaveContact">+ Save contact</button>
      </div>
      ${contacts.length === 0 ? `
        <div style="text-align:center;padding:1.5rem;color:#aaa;font-size:0.9rem">
          No contacts yet. Paste a .cdpub from someone to add them.
        </div>` : `
        <div>${contacts.map(c => `
          <div class="key-row">
            <span style="font-size:1.5rem;flex-shrink:0">${methodIcon(c.method)}</span>
            <div style="flex:1;min-width:0">
              <div style="font-weight:600">${esc(c.label)} <span style="font-size:0.72rem;color:#1565c0;font-weight:400">contact</span></div>
              <div style="font-size:0.78rem;color:#888">
                ${esc(methodLabel(c.method))} ·
                <span style="font-family:monospace">${esc(c.fingerprint)}</span>
                · saved ${c.saved_at ? fmtDate(c.saved_at) : '?'}
              </div>
            </div>
            <div class="btn-group">
              <button class="btn btn-danger btn-sm" data-act="kcDeleteContact" data-a="${esc(c.keyId)}">Remove</button>
            </div>
          </div>`).join('')}
        </div>`}
    </div>`;
}

async function kcGenKey() {
  showModal(`
    <h3>Generate ECDH P-256 key</h3>
    <div class="field"><label>Label</label><input id="gk-lbl" placeholder="e.g. My Key" style="width:100%" autofocus></div>
    <div id="gk-err" class="alert alert-error" style="display:none"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="kcConfirmGenKey">Generate</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
  setTimeout(() => document.getElementById('gk-lbl')?.focus(), 80);
}

async function kcConfirmGenKey() {
  const lbl = document.getElementById('gk-lbl').value.trim();
  const err = document.getElementById('gk-err');
  if (!lbl) { err.textContent='Enter a label'; err.style.display='block'; return; }
  try {
    const k = await kcGenEcdh(lbl);
    closeModal();
    showModal(`
      <h3>✅ Key generated</h3>
      <p style="margin-bottom:1rem">Your new ECDH P-256 key "<strong>${esc(k.label)}</strong>" is ready.</p>
      <table class="meta-table" style="margin-bottom:1rem">
        <tr><td>Fingerprint</td><td style="font-family:monospace">${esc(k.fingerprint)}</td></tr>
        <tr><td>Method</td><td>${esc(methodLabel(k.method))}</td></tr>
      </table>
      <p class="hint" style="margin-bottom:1rem">Share your <strong>public key</strong> with others so they can encrypt cells for you. Export a <strong>.cdkey</strong> to use on another device.</p>
      <div class="btn-group">
        <button class="btn btn-primary" data-act="closeSharePub" data-a="${esc(k.keyId)}">Share pubkey</button>
        <button class="btn btn-secondary" data-act="closeRenderKeychain">Done</button>
      </div>`);
  } catch (e) {
    document.getElementById('gk-err').textContent = e.message;
    document.getElementById('gk-err').style.display = 'block';
  }
}

async function kcAddYubikey() {
  showModal(`
    <h3>Register YubiKey</h3>
    <p class="hint" style="margin-bottom:1rem">Requires HTTPS or localhost and <strong>Chrome or Chromium</strong> (Firefox on Linux does not support YubiKey PRF). Requires a <strong>YubiKey 5 series</strong> (firmware 5.2+) or any FIDO2 key with hmac-secret.<br><span style="color:#c62828">⚠ The Yubico Security Key (solid blue or black, ~$25) does <u>not</u> support PRF — it lacks hmac-secret at the hardware level.</span></p>
    <div class="field"><label>Label</label><input id="yk-lbl" placeholder="e.g. My YubiKey" style="width:100%" autofocus></div>
    <div id="yk-err" class="alert alert-error" style="display:none"></div>
    <div id="yk-info" class="alert alert-info" style="display:none">Touch your YubiKey when it flashes…</div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" id="btn-yk-reg" data-act="kcConfirmYubikey">Register</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
  setTimeout(() => document.getElementById('yk-lbl')?.focus(), 80);
}

async function kcConfirmYubikey() {
  const lbl = document.getElementById('yk-lbl').value.trim();
  const err = document.getElementById('yk-err');
  const info = document.getElementById('yk-info');
  if (!lbl) { err.textContent='Enter a label'; err.style.display='block'; return; }
  document.getElementById('btn-yk-reg').disabled = true;
  info.style.display='block'; err.style.display='none';
  try {
    const rec = await registerYubiKey(lbl);
    await kcSave(rec);
    closeModal();
    alert(`YubiKey "${lbl}" registered.\nFingerprint: ${rec.fingerprint}`);
    if (_view === 'keychain') renderKeychain(document.getElementById('app'));
    return rec;
  } catch (e) {
    info.style.display='none';
    err.textContent = e.message; err.style.display='block';
    document.getElementById('btn-yk-reg').disabled = false;
  }
}

async function kcSharePub(keyId) {
  const k = await kcGet(keyId);
  if (!k || !k.spki) return;
  const json = JSON.stringify({ cd_pubkey: '2.0', label: k.label, fingerprint: k.fingerprint, method: k.method, spki: k.spki }, null, 2);
  showModal(`
    <h3>Share public key — ${esc(k.label)}</h3>
    <p class="hint" style="margin-bottom:0.75rem">Give this to anyone who wants to encrypt a cell you can open.</p>
    <textarea readonly rows="8" data-act="selectAll" style="width:100%;font-family:monospace;font-size:0.75rem;padding:0.5rem">${esc(json)}</textarea>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="dlText" data-a="${esc(json)}" data-b="${esc(k.fingerprint)}.cdpub">⬇ Download .cdpub</button>
      <button class="btn btn-secondary" data-act="copyText" data-a="${esc(json)}">Copy</button>
      <button class="btn btn-secondary" data-act="closeModal">Close</button>
    </div>`);
}

async function kcExportKey(keyId) {
  const k = await kcGet(keyId);
  if (!k || !k.pkcs8) return;
  if (!confirm(`Export private key for "${k.label}"?\n\nThis exports your PRIVATE KEY. Store it securely.`)) return;
  dlText(JSON.stringify({ cd_key: '2.0', ...k, exported_at: Math.floor(Date.now()/1000) }, null, 2), `${k.fingerprint}.cdkey`);
}

async function kcDeleteKey(keyId) {
  const k = await kcGet(keyId);
  if (!k) return;
  if (!confirm(`Delete "${k.label}"?\n\nYou will not be able to decrypt cells encrypted for this key.`)) return;
  await kcDel(keyId);
  renderKeychain(document.getElementById('app'));
}

function kcImport() {
  showModal(`
    <h3>Import key</h3>
    <p class="hint" style="margin-bottom:1rem">Import a <strong>.cdkey</strong> (private key) or <strong>.cdpub</strong> (public key only — for encrypting to someone else).</p>
    <input type="file" id="ki-inp" accept=".cdkey,.cdpub,.json">
    <div id="ki-err" class="alert alert-error" style="display:none;margin-top:0.75rem"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="kcConfirmImport">Import</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
}

async function kcConfirmImport() {
  const inp = document.getElementById('ki-inp');
  const err = document.getElementById('ki-err');
  if (!inp.files[0]) { err.textContent='Select a file'; err.style.display='block'; return; }
  try {
    const data = JSON.parse(await inp.files[0].text());
    if (!data.cd_key && !data.cd_pubkey) throw new Error('Not a .cdkey or .cdpub file');
    const rec = {
      keyId:       safeKeyId(data.keyId),
      label:       data.label || 'Imported Key',
      method:      data.method || 'ecdh-p256',
      fingerprint: safeFingerprint(data.fingerprint),
      spki:        data.spki || null,
      pkcs8:       data.cd_key ? (data.pkcs8 || null) : null,
      credential_id: data.credential_id || null,
      prf_salt:    data.prf_salt || null,
      created_at:  Math.floor(Date.now()/1000),
    };
    if (rec.method === 'ecdh-p256' && rec.spki) await assertValidSpki(rec.spki);
    if (!rec.fingerprint && rec.spki) rec.fingerprint = await fp(rec.spki);
    await kcSave(rec);
    closeModal();
    renderKeychain(document.getElementById('app'));
  } catch (e) { err.textContent = 'Import failed: ' + e.message; err.style.display = 'block'; }
}

function kcSaveContact() {
  showModal(`
    <h3>Save contact public key</h3>
    <p class="hint" style="margin-bottom:1rem">Paste a <strong>.cdpub</strong> JSON from someone else. Their public key is saved to localStorage so you can encrypt cells for them.</p>
    <div class="field"><label>Display name (optional override)</label><input id="sc-lbl" placeholder="Leave blank to use name from file" style="width:100%"></div>
    <div class="field"><label>Public key JSON (.cdpub)</label>
      <textarea id="sc-data" rows="6" placeholder='{"cd_pubkey":"2.0","label":"Alice","spki":"..."}' style="width:100%;font-family:monospace;font-size:0.75rem" autofocus></textarea>
    </div>
    <div id="sc-err" class="alert alert-error" style="display:none"></div>
    <div class="btn-group" style="margin-top:1rem">
      <button class="btn btn-primary" data-act="kcConfirmSaveContact">Save</button>
      <button class="btn btn-secondary" data-act="closeModal">Cancel</button>
    </div>`);
  setTimeout(() => document.getElementById('sc-data')?.focus(), 80);
}

async function kcConfirmSaveContact() {
  const raw = document.getElementById('sc-data').value.trim();
  const lbl = document.getElementById('sc-lbl').value.trim();
  const err = document.getElementById('sc-err');
  try {
    const data = JSON.parse(raw);
    if (!data.cd_pubkey && !data.spki) throw new Error('Not a valid .cdpub file');
    const method = data.method || 'ecdh-p256';
    if (method === 'ecdh-p256' && data.spki) await assertValidSpki(data.spki);
    let fingerprint = safeFingerprint(data.fingerprint);
    if (!fingerprint && data.spki) fingerprint = await fp(data.spki);
    const rec = {
      keyId:       safeKeyId(data.keyId),
      label:       lbl || data.label || 'Contact',
      method,
      fingerprint,
      spki:        data.spki || null,
      credential_id: data.credential_id || null,
      prf_salt:    data.prf_salt || null,
    };
    lsPubSave(rec);
    closeModal();
    renderKeychain(document.getElementById('app'));
  } catch (e) { err.textContent = 'Invalid: ' + e.message; err.style.display = 'block'; }
}

function kcDeleteContact(keyId) {
  const c = lsPubAll().find(r => r.keyId === keyId);
  if (!c) return;
  if (!confirm(`Remove contact "${c.label}"?`)) return;
  lsPubDel(keyId);
  renderKeychain(document.getElementById('app'));
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW: ABOUT
// ═══════════════════════════════════════════════════════════════════════════

function renderAbout(app) {
  app.innerHTML = `
    <div class="page-header"><h2>About Cell Format</h2></div>
    <div class="card" style="max-width:680px">
      <h3>What is a .cell file?</h3>
      <p style="margin-bottom:1rem;line-height:1.7">A <strong>.cell</strong> file is a self-contained encrypted envelope. Any file type can be encrypted into one — the original file is gzip-compressed then AES-256-GCM encrypted client-side. The server (if any) stores only ciphertext.</p>

      <h3>File formats</h3>
      <table class="meta-table" style="margin-bottom:1.5rem">
        <tr><td><code>.cell</code></td><td>Plain JSON — human-readable structure, inspect in any text editor.</td></tr>
        <tr><td><code>.celz</code></td><td>gzip-compressed JSON — same format, ~30% smaller. Binary.</td></tr>
        <tr><td><code>.cdpub</code></td><td>Public key export — share with others to receive encrypted cells.</td></tr>
        <tr><td><code>.cdkey</code></td><td>Full key export (private + public) — use on another device. Keep safe.</td></tr>
      </table>

      <h3>Cell envelope (JSON)</h3>
      <p style="color:#555;font-size:0.88rem;margin-bottom:0.75rem">Filename, MIME type, and size are inside the encrypted payload (spec §5.1) — invisible to any observer, server, or transit node. From v1.4 the access map names no one: an entry has no fingerprint or label, and you find yours by trial decryption (spec §6). A signature, if any, is inside the ciphertext (spec §4.5).</p>
      <pre style="background:#f5f5f5;padding:1rem;border-radius:8px;font-size:0.78rem;overflow-x:auto;margin-bottom:1.5rem">{
  "version": "1.4",
  "doc_id": "&lt;ULID e.g. 01JXXXXXXXXXXXXXXXXXXXXXXXXX&gt;",
  "created_at": 1780531200,
  "header": {
    "prev_hash": null,
    "threshold": { "required": 1, "of_total": 1 },
    "lifetime":  { "type": "permanent", "advisory": { "retain_until": null, "release_at": null, "single_use": false, "minimum_atl": 1 }, "disposal": { "at": null, "action": "none" } },
    "policy":    { "copy_protection": "standard", "watermark_mode": "none", "created_on_origin": "...", "origin_sig": null },
    "access_map": [
      {
        "method": "ecdh-p256",
        "wrapped_cek": { "eph_spki": "...", "hkdf_salt": "...", "ct": "..." }
      }
    ],
    "payload_hash": "&lt;base64 SHA-256 of ciphertext&gt;"
  },
  "header_hash": "&lt;base64 SHA-256 of canonical header JSON&gt;",
  "payload": {
    "alg": "AES-256-GCM",
    "encoding": "base64+gzip+padme",
    "iv":  "&lt;base64 12-byte IV&gt;",
    "ciphertext": "&lt;base64 — [LE32 len][gzip([4-byte len][manifest JSON][file bytes])][zero pad], encrypted&gt;"
  }
}</pre>

      <h3>Key methods</h3>
      <table class="meta-table" style="margin-bottom:1.5rem">
        <tr><td>🔑 ECDH P-256</td><td>Generate a keypair in the browser. Private key stays in IndexedDB. Share your public key (.cdpub) with others.</td></tr>
        <tr><td>💬 Argon2id</td><td>Derive a key from a passphrase (RFC 9106; 64 MiB, 3 passes, 4 lanes). Share the passphrase out-of-band. Older PBKDF2 cells still open.</td></tr>
        <tr><td>🔐 YubiKey PRF</td><td>FIDO2 PRF extension — the key evaluates a fresh random 32-byte salt for every cell, so each cell has its own 32-byte wrapping key. Requires HTTPS + YubiKey 5 series.</td></tr>
      </table>

      <h3>Crypto stack</h3>
      <p style="line-height:1.7;color:#555">Content: <strong>AES-256-GCM</strong> with random 96-bit IV per cell. The format version and the header's advisory metadata (threshold, lifetime, policy, lineage) are bound to the ciphertext as GCM <strong>additional authenticated data</strong> — tampering with them, or relabelling the version, fails the auth tag on open. Integrity hashes and signatures are computed over a <strong>canonical JSON</strong> form, so re-formatting the file (key order, whitespace) does not break verification.
      CEK wrapping: ECDH P-256 ephemeral keypair → <strong>HKDF-SHA256</strong> (256-bit, random 32-byte salt, info <code>cellular-defense-cek-wrap-v1</code>) → <strong>AES-KW</strong>.
      Passphrases: <strong>Argon2id</strong> (RFC 9106, 16-byte salt, NFC-normalised passphrase) → AES-KW; PBKDF2-SHA256 (600,000 iterations) is still accepted on open, up to 10,000,000. Because the header hash is unkeyed, an opener bounds its work: passphrase entries are tried cheapest first, and one open never does more key derivation than a single maximum-parameter entry. A slow open shows progress and can be cancelled.
      M-of-N quorum: <strong>Shamir Secret Sharing</strong> over GF(256) — CEK split into N shares; M shares required to reconstruct.
      Size: the decrypted body is <strong>Padmé-padded</strong> (512-byte floor), so the ciphertext length shows a size bucket, not the exact size. An opener refuses a body that is not exactly one gzip member with nothing after it, or whose padded length is not exactly the Padmé length, so one file cannot open as two different documents.
      Tamper detection: <strong>payload_hash</strong> (SHA-256 of ciphertext) committed inside the header; <strong>header_hash</strong> (SHA-256 of canonical header JSON) verified on open; optional <strong>ECDSA P-256</strong> sender signature inside the encrypted manifest, covering the content, the cell's identity and the intended recipients.
      Lineage: <strong>prev_hash</strong> links a re-encrypted cell (Mitosis) back to its predecessor — creating an auditable chain of custody.
      Everything except Argon2id and BLAKE2b uses the browser's <strong>WebCrypto API</strong>; those two are plain JavaScript in <code>cell-crypto.js</code>, checked against the RFC test vectors. No server round-trips.</p>
    </div>

    <div class="card" style="max-width:680px">
      <h3>License &amp; Copyright</h3>
      <p style="line-height:1.7;margin-bottom:1rem">Copyright &copy; 2026 <strong>Enthropic Data LLC</strong>.</p>
      <p style="line-height:1.7;margin-bottom:1rem;color:#555"><strong>The format</strong> (<code>docs/SPEC.md</code>) is a defensive publication: anyone may implement it, for any purpose, without licence or royalty. No patent is sought or asserted.<br>
      <strong>This code</strong> is licensed under the GNU AGPL-3.0; a commercial licence is available for products that cannot meet its terms. The ports in <code>impl/</code> and the conformance suite are Apache-2.0. See <code>LICENSING.md</code>.</p>
      <p style="line-height:1.7;color:#555"><strong>Third-party components:</strong> None. Cell Format uses the browser's built-in WebCrypto API (W3C Web Cryptography API, <a href="https://www.w3.org/TR/WebCryptoAPI/" target="_blank" rel="noopener noreferrer">W3C Recommendation</a>) and standard browser APIs. No external libraries are bundled or loaded.</p>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════════

// ── Event delegation ─────────────────────────────────────────────────────────
// The markup carries data-act (plus data-a / data-b arguments) and never an inline
// handler, so the page runs under script-src 'self' with no 'unsafe-inline'. Only
// names in ACTIONS can be invoked; anything else in a data-act is ignored.
const ACTIONS = {
  // markup with arguments carry them in data-a / data-b (decoded text, never JS source)
  go:                 el => go(el.dataset.a),
  encRemove:          el => encRemove(Number(el.dataset.a)),
  encSelectKey:       el => encSelectKey(el.dataset.a, el.dataset.b),
  encSelectKeyClose:  el => { encSelectKey(el.dataset.a); closeModal(); renderRecList(); },
  ykPickerRemove:     el => ykPickerRemove(el.dataset.a),
  kcSharePub:         el => kcSharePub(el.dataset.a),
  kcExportKey:        el => kcExportKey(el.dataset.a),
  kcDeleteKey:        el => kcDeleteKey(el.dataset.a),
  kcDeleteContact:    el => kcDeleteContact(el.dataset.a),
  closeSharePub:      el => { closeModal(); kcSharePub(el.dataset.a); },
  closeRenderKeychain: () => { closeModal(); renderKeychain(document.getElementById('app')); },
  selectAll:          el => el.select(),
  dlText:             el => dlText(el.dataset.a, el.dataset.b),
  copyText:           el => { if (navigator.clipboard) navigator.clipboard.writeText(el.dataset.a).then(() => { el.textContent = 'Copied!'; }, () => { el.textContent = 'Copy failed — select the text and copy it'; }); },
  // no-argument actions
  cancelPassOpen: () => cancelPassOpen(),
  closeModal: () => closeModal(),
  doEncrypt: () => doEncrypt(),
  doMitosis: () => doMitosis(),
  encAddFromKeychain: () => encAddFromKeychain(),
  encAddPassphrase: () => encAddPassphrase(),
  encAddPubkeyPaste: () => encAddPubkeyPaste(),
  encAddYubikey: () => encAddYubikey(),
  encConfirmPass: () => encConfirmPass(),
  encConfirmPubkey: () => encConfirmPubkey(),
  encInlineGenConfirm: () => encInlineGenConfirm(),
  encInlineGenKey: () => encInlineGenKey(),
  kcAddYubikey: () => kcAddYubikey(),
  kcConfirmGenKey: () => kcConfirmGenKey(),
  kcConfirmImport: () => kcConfirmImport(),
  kcConfirmSaveContact: () => kcConfirmSaveContact(),
  kcConfirmYubikey: () => kcConfirmYubikey(),
  kcGenKey: () => kcGenKey(),
  kcImport: () => kcImport(),
  kcSaveContact: () => kcSaveContact(),
  openConfirmKeyFile: () => openConfirmKeyFile(),
  openConfirmPass: () => openConfirmPass(),
  openWithKeyFile: () => openWithKeyFile(),
  openWithKeychain: () => openWithKeychain(),
  openWithPassphrase: () => openWithPassphrase(),
  openWithYubikey: () => openWithYubikey(),
};
const CHANGE_ACTIONS = { renderLifetimeOptions: () => renderLifetimeOptions() };
document.addEventListener('click', (e) => {
  const el = e.target.closest ? e.target.closest('[data-act]') : null;
  if (!el) return;
  const f = Object.prototype.hasOwnProperty.call(ACTIONS, el.dataset.act) ? ACTIONS[el.dataset.act] : null;
  if (f) f(el);
});
document.addEventListener('change', (e) => {
  const el = e.target.closest ? e.target.closest('[data-change]') : null;
  if (!el) return;
  const f = Object.prototype.hasOwnProperty.call(CHANGE_ACTIONS, el.dataset.change) ? CHANGE_ACTIONS[el.dataset.change] : null;
  if (f) f(el);
});

document.addEventListener('DOMContentLoaded', () => {
  if (!window.CompressionStream) {
    document.getElementById('app').innerHTML = `<div class="card"><div class="alert alert-error">
      Your browser does not support CompressionStream (required for gzip).<br>
      Please use Chrome 80+, Firefox 113+, or Safari 16.4+.
    </div></div>`;
    return;
  }

  document.getElementById('nav-home').onclick     = () => go('home');
  document.getElementById('nav-keychain').onclick  = () => go('keychain');
  document.getElementById('nav-about').onclick     = () => go('about');

  render();
});
