'use strict';
/* Vault — vault.js v1.4.0
   AES-256-GCM + PBKDF2-SHA256 (new) / Argon2id (legacy compat)
   Backward compatible: old Argon2id backups are auto-migrated to
   PBKDF2 on restore/unlock. KDF is stored in meta + backup JSON. */

const VERSION     = 'v1.4.0';
const DB_NAME     = 'vault_db';
const STORE       = 'entries';
const LOCK_MS     = 5 * 60 * 1000;
const KDF_PBKDF2  = 'pbkdf2';
const KDF_ARGON2  = 'argon2id';
// CDN URL for Argon2 — only injected when an old backup/vault needs it
const ARGON2_CDN = 'https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js';
// SRI hash for the above file. Compute with:
//   curl -sL <ARGON2_CDN> | openssl dgst -sha256 -binary | openssl base64
// Then prefix with 'sha256-'. Leave empty to skip SRI (NOT recommended for production).
const ARGON2_SRI = '';

/* ── State ─────────────────────────────────────────── */
let CK            = null;
let SALT          = null;
let CUR_KDF       = KDF_PBKDF2; // always in sync with CK/SALT
let DB            = null;
let lockTimer     = null;
let lockEnd       = 0;
let curTab        = 'passwords';
let pendingBackup = null;
let newEnvVars    = null;
const envCache    = new Map();
let lastSyncTime  = null;  // Date of last successful backup export

/* ── Codec helpers ─────────────────────────────────── */
const te    = new TextEncoder();
const td    = new TextDecoder();
const b64e  = buf => {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
};
const b64d  = s   => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rnd   = n   => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };

/* ── DOM helpers ───────────────────────────────────── */
const $   = id => document.getElementById(id);
const esc = s  => String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');

function toast(msg, type = 'ok') {
  const col = { ok: 'var(--green)', err: 'var(--red)', info: 'var(--accent-bright)' }[type];
  const el  = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = `position:fixed;top:16px;right:16px;z-index:9999;padding:10px 16px;
    background:var(--surface2);border:1px solid var(--border);border-radius:8px;
    font-size:.82rem;color:${col};box-shadow:0 4px 24px rgba(0,0,0,.35);
    animation:fadeIn .15s ease;pointer-events:none;`;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2800);
}

/* ── KDF — PBKDF2-SHA256 (current, no deps) ────────── */
async function deriveKeyPbkdf2(pass, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 600_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/* ── KDF — Argon2id (legacy compat, lazy CDN load) ── */
let argon2LoadPromise = null;
function loadArgon2() {
  if (window.argon2) return Promise.resolve();
  if (argon2LoadPromise) return argon2LoadPromise;
  argon2LoadPromise = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = ARGON2_CDN;
    s.crossOrigin = 'anonymous';
    if (ARGON2_SRI) s.integrity = ARGON2_SRI; // SRI verification when hash is provided
    s.onload  = () => window.argon2 ? resolve() : reject(new Error('argon2 not exposed after load'));
    s.onerror = () => {
      argon2LoadPromise = null; // reset so caller can retry
      reject(new Error(
        'Could not load Argon2 library from CDN. ' +
        'Check your internet connection, or serve argon2-bundled.min.js locally as a fallback.'
      ));
    };
    document.head.appendChild(s);
  });
  return argon2LoadPromise;
}

async function deriveKeyArgon2(pass, saltBytes) {
  await loadArgon2();
  // argon2-browser API — parameter names differ from other argon2 libs:
  //   pass (not password), time (not iterations), mem (not memorySize),
  //   hashLen (not hashLength), type enum (not outputType: 'binary').
  // Wrong names cause silent fallback to library defaults → wrong key → wrong backup decryption.
  const result = await window.argon2.hash({
    pass       : pass,
    salt       : saltBytes,
    parallelism: 1,
    time       : 3,
    mem        : 65536,
    hashLen    : 32,
    type       : window.argon2.ArgonType.Argon2id,
  });
  // result.hash is a Uint8Array of the derived key bytes
  return crypto.subtle.importKey(
    'raw', result.hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
  );
}

/* ── KDF dispatcher ─────────────────────────────────── */
async function deriveKey(pass, saltBytes, kdf = KDF_PBKDF2) {
  return kdf === KDF_ARGON2
    ? deriveKeyArgon2(pass, saltBytes)
    : deriveKeyPbkdf2(pass, saltBytes);
}

/* ── Re-encrypt all entries under a new key ─────────── */
async function reEncryptAll(entries, oldKey, newKey) {
  return Promise.all(entries.map(async e => {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(e.encrypted.iv) }, oldKey, b64d(e.encrypted.ct)
    );
    const iv = rnd(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, newKey, pt);
    return { ...e, encrypted: { iv: b64e(iv), ct: b64e(ct) } };
  }));
}

/* ── Background migration: Argon2 → PBKDF2 ──────────── */
// Called after a successful Argon2 unlock with CK already set.
async function migrateToPbkdf2(pass) {
  try {
    const entries = await dbGetAll();
    const ns  = rnd(16);
    const nk  = await deriveKeyPbkdf2(pass, ns);
    const re  = await reEncryptAll(entries, CK, nk);
    await dbClear();
    for (const e of re) { const { id, ...rest } = e; await dbAdd(rest); }
    CK = nk; SALT = ns; CUR_KDF = KDF_PBKDF2;
    await metaPut('salt', b64e(ns));
    await metaPut('kdf',  KDF_PBKDF2);
    envCache.clear();
    markUnsaved();
    updateSidebarMeta();
    toast('Vault migrated from Argon2id → PBKDF2', 'info');
  } catch (err) {
    console.warn('KDF migration failed (non-fatal):', err);
  }
}

/* ── Crypto ─────────────────────────────────────────── */
async function aesEncrypt(plain) {
  const iv = rnd(12);
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, CK, te.encode(plain));
  return { iv: b64e(iv), ct: b64e(ct) };
}

async function aesDecrypt({ iv, ct }) {
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv: b64d(iv) }, CK, b64d(ct));
  return td.decode(pt);
}

/* ── IndexedDB ──────────────────────────────────────── */
function openDB() {
  return new Promise((ok, fail) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = e => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains(STORE))
        d.createObjectStore(STORE, { keyPath: 'id', autoIncrement: true });
      if (!d.objectStoreNames.contains('meta'))
        d.createObjectStore('meta');
    };
    r.onsuccess = e => ok(e.target.result);
    r.onerror   = e => fail(e.target.error);
  });
}

const wrap  = r     => new Promise((ok, fail) => { r.onsuccess = () => ok(r.result); r.onerror = () => fail(r.error); });
const txS   = rw    => DB.transaction(STORE, rw ? 'readwrite' : 'readonly').objectStore(STORE);
const txM   = rw    => DB.transaction('meta',  rw ? 'readwrite' : 'readonly').objectStore('meta');

const dbGetAll = ()     => wrap(txS().getAll());
const dbGet    = id     => wrap(txS().get(id));
const dbAdd    = obj    => wrap(txS(true).add(obj));
const dbPut    = obj    => wrap(txS(true).put(obj));
const dbDel    = id     => wrap(txS(true).delete(id));
const dbClear  = ()     => wrap(txS(true).clear());
const metaGet  = k      => wrap(txM().get(k));
const metaPut  = (k, v) => wrap(txM(true).put(v, k));
const metaClr  = ()     => wrap(txM(true).clear());

/* ── Entry helpers ──────────────────────────────────── */
async function addEntry(name, content, tag, type) {
  const encrypted = await aesEncrypt(content);
  return dbAdd({ name, tag: tag || '', type, encrypted, created: Date.now() });
}

/* ── .env parsing / formatting ──────────────────────── */
function parseDotEnv(text) {
  const vars = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let   val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'")))
      val = val.slice(1, -1);
    if (key) vars[key] = val;
  }
  return vars;
}

function formatDotEnv(vars) {
  return Object.entries(vars).map(([k, v]) =>
    /[\s#"'\\]/.test(v) || v === ''
      ? `${k}="${v.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`
      : `${k}=${v}`
  ).join('\n') + '\n';
}

/* ── Env cache ──────────────────────────────────────── */
async function getEnvVars(envId) {
  if (envCache.has(envId)) return envCache.get(envId);
  const entry = await dbGet(envId);
  if (!entry) return {};
  const vars = JSON.parse(await aesDecrypt(entry.encrypted));
  envCache.set(envId, vars);
  return vars;
}

async function saveEnvVars(envId, vars) {
  const entry = await dbGet(envId);
  if (!entry) return;
  entry.encrypted = await aesEncrypt(JSON.stringify(vars));
  entry.updated   = Date.now();
  envCache.set(envId, vars);
  await dbPut(entry);
}

/* ── Auto-lock ──────────────────────────────────────── */
const resetLock = () => { lockEnd = Date.now() + LOCK_MS; };
const stopLock  = () => clearInterval(lockTimer);

function startLock() {
  stopLock();
  lockEnd   = Date.now() + LOCK_MS;
  lockTimer = setInterval(() => {
    const rem = Math.max(0, lockEnd - Date.now());
    if (rem === 0) { lockVault(); return; }
    const m = Math.floor(rem / 60000);
    const s = Math.floor((rem % 60000) / 1000);
    $('lock-countdown').textContent = `${m}:${String(s).padStart(2, '0')}`;
  }, 1000);
}

/* ── Lock / unlock ──────────────────────────────────── */
function lockVault() {
  CK = null; SALT = null; CUR_KDF = KDF_PBKDF2;
  envCache.clear();
  stopLock();
  $('vault-view').style.display    = 'none';
  $('auth-view').style.display     = '';
  $('sidebar-meta').style.display  = 'none';
  $('sync-banner').style.display   = 'none';
  setAuthMode('unlock');
}

function unlockUI() {
  $('auth-view').style.display    = 'none';
  $('vault-view').style.display   = '';
  $('sidebar-meta').style.display = 'block';
  $('tab-unlock').style.display   = '';
  $('unlock-key').value = '';
  updateSidebarMeta();
  updateCounts();
  startLock();
  switchTab('passwords');
}

/* ── Auth mode ──────────────────────────────────────── */
function setAuthMode(mode) {
  ['unlock','new','restore'].forEach(m =>
    $(`auth-${m}`).style.display = m === mode ? '' : 'none'
  );
  document.querySelectorAll('#auth-view .tab').forEach(t =>
    t.classList.toggle('active', t.dataset.mode === mode)
  );
}

/* ── Sidebar counts + meta ──────────────────────────── */
async function updateCounts(all) {
  if (!all) all = await dbGetAll();
  $('count-pw').textContent   = all.filter(e => e.type === 'pw').length;
  $('count-keys').textContent = all.filter(e => e.type === 'key').length;
  $('count-cert').textContent = all.filter(e => e.type === 'cert').length;
  $('count-env').textContent  = all.filter(e => e.type === 'env').length;
  // entry-count intentionally not shown (not in sidebar design)
}

function updateSidebarMeta() {
  const el = $('last-update');
  if (!el) return;
  if (lastSyncTime) {
    el.textContent = `Synced ${lastSyncTime.toLocaleTimeString()}`;
    el.style.display = '';
  } else {
    el.style.display = 'none';
  }
}

/* ── Tab switching ──────────────────────────────────── */
function switchTab(tab) {
  curTab = tab;
  document.querySelectorAll('#main-tabs .tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === tab)
  );
  $('vault-content-section').style.display = ['passwords','keys','certs'].includes(tab) ? '' : 'none';
  $('security-section').style.display      = tab === 'security' ? '' : 'none';
  $('envs-section').style.display          = tab === 'envs'     ? '' : 'none';

  if (['passwords','keys','certs'].includes(tab)) {
    $('importer-ui').style.display = tab !== 'passwords' ? '' : 'none';
    renderEntryList();
  } else if (tab === 'envs') {
    renderEnvList();
  }
  resetLock();
}

/* ── Entry list ─────────────────────────────────────── */
async function renderEntryList() {
  const q    = $('v-search').value.toLowerCase();
  const type = { passwords:'pw', keys:'key', certs:'cert' }[curTab];
  const all  = await dbGetAll();
  const rows = all.filter(e => e.type === type &&
    (!q || e.name.toLowerCase().includes(q) || (e.tag || '').toLowerCase().includes(q))
  );
  updateCounts(all);
  const c = $('list-container');
  if (!rows.length) {
    c.innerHTML = `<div class="empty-state">No ${curTab} stored yet.</div>`;
    return;
  }
  c.innerHTML = rows.map(e => `
    <div class="entry-item">
      <div class="entry-row">
        <div>
          <span class="entry-name">${esc(e.name)}</span>
          ${e.tag ? `<span class="entry-tag">${esc(e.tag)}</span>` : ''}
        </div>
        <div class="entry-actions">
          <button class="btn btn-view"  data-action="view"   data-id="${e.id}">View</button>
          <button class="btn btn-copy"  data-action="copy"   data-id="${e.id}">Copy</button>
          <button class="btn btn-del"   data-action="delete" data-id="${e.id}" title="Delete">×</button>
        </div>
      </div>
      <div class="secret-area" id="sec-${e.id}"></div>
    </div>`).join('');
}

/* ── Entry actions (delegated) ──────────────────────── */
async function handleEntryAction(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  resetLock();
  const id     = parseInt(btn.dataset.id, 10);
  const action = btn.dataset.action;

  if (action === 'view') {
    const area = $(`sec-${id}`);
    const open = area.classList.contains('active');
    if (!open) {
      const all   = await dbGetAll();
      const entry = all.find(e => e.id === id);
      area.textContent = await aesDecrypt(entry.encrypted);
      btn.classList.add('btn-view-active');
    } else {
      area.textContent = '';
      btn.classList.remove('btn-view-active');
    }
    area.classList.toggle('active');
  }

  if (action === 'copy') {
    const all   = await dbGetAll();
    const entry = all.find(e => e.id === id);
    const secret = await aesDecrypt(entry.encrypted);
    await navigator.clipboard.writeText(secret);
    btn.textContent = '✓ Copied';
    btn.classList.add('btn-copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('btn-copied'); }, 1500);
    // Clear clipboard after 30s
    setTimeout(() => navigator.clipboard.readText().then(t => { if (t === secret) navigator.clipboard.writeText(''); }).catch(() => {}), 30000);
  }

  if (action === 'delete') {
    if (!confirm('Delete this entry?')) return;
    await dbDel(id);
    markUnsaved();
    renderEntryList();
  }
}

/* ── Env list ───────────────────────────────────────── */
async function renderEnvList() {
  const q    = ($('env-search')?.value || '').toLowerCase();
  const all  = await dbGetAll();
  const envs = all.filter(e => e.type === 'env' && (!q || e.name.toLowerCase().includes(q)));
  updateCounts(all);

  const c = $('env-list-container');
  if (!c) return;
  if (!envs.length) {
    c.innerHTML = `<div class="empty-state">No environments yet — create one or import a .env file.</div>`;
    return;
  }

  c.innerHTML = `<div class="empty-state" style="padding:8px 0;font-size:.8rem">Decrypting…</div>`;

  const resolved = await Promise.all(envs.map(async e => {
    let vars = {};
    try { vars = JSON.parse(await aesDecrypt(e.encrypted)); envCache.set(e.id, vars); } catch {}
    return { e, vars };
  }));

  c.innerHTML = resolved.map(({ e, vars }) => {
    const keys    = Object.keys(vars);
    const count   = keys.length;
    const preview = keys.slice(0, 3).join(', ') + (keys.length > 3 ? '…' : '');
    return `
    <div class="env-item" data-id="${e.id}">
      <div class="env-info-row">
        <span class="env-name">${esc(e.name)}</span>
        <span class="env-badge">${count} var${count !== 1 ? 's' : ''}</span>
        ${preview ? `<span class="env-preview">${esc(preview)}</span>` : ''}
      </div>
      <div class="env-action-row">
        <button class="btn btn-ghost" data-action="env-import" data-id="${e.id}">&#8593; Import</button>
        <input type="file" accept=".env,text/plain"
          class="env-file-input" data-id="${e.id}" style="display:none">
        <button class="btn btn-ghost" data-action="env-export" data-id="${e.id}">&#8595; Export</button>
        <button class="btn btn-view"  data-action="env-toggle" data-id="${e.id}">&#9660;</button>
        <button class="btn btn-x"     data-action="env-delete" data-id="${e.id}" title="Delete">&times;</button>
      </div>
      <div class="env-body" id="env-body-${e.id}" style="display:none">
        ${renderVarTable(e.id, vars)}
        <div class="env-add-row">
          <input type="text"     id="ekey-${e.id}" class="env-add-key"
            placeholder="VARIABLE_NAME" autocomplete="off" spellcheck="false">
          <div class="input-with-toggle" style="flex:1;position:relative">
            <input type="password" id="eval-${e.id}" class="env-add-val"
              placeholder="value" autocomplete="off">
            <button class="toggle-btn" data-target="eval-${e.id}" aria-label="Toggle">👁</button>
          </div>
          <button class="btn btn-primary" data-action="var-add" data-id="${e.id}"
            style="padding:9px 14px;white-space:nowrap;width:auto">+ Add</button>
        </div>
      </div>
    </div>`;
  }).join('');

  c.querySelectorAll('.env-file-input').forEach(inp =>
    inp.addEventListener('change', handleEnvFileInput)
  );
}

function renderVarTable(envId, vars) {
  const entries = Object.entries(vars);
  if (!entries.length)
    return `<div class="env-empty">No variables yet — add one below or import a .env file.</div>`;
  return `<table class="env-table">
    <thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>
    <tbody>${entries.map(([k, v]) => `
      <tr>
        <td>${esc(k)}</td>
        <td>
          <span class="env-val-masked">••••••••</span>
          <span class="env-val-plain" style="display:none">${esc(v)}</span>
        </td>
        <td>
          <button class="btn btn-view" data-action="var-toggle"
            style="font-size:.72rem;padding:3px 8px">View</button>
          <button class="btn btn-copy" data-action="var-copy"
            data-env-id="${envId}" data-key="${esc(k)}"
            style="font-size:.72rem;padding:3px 8px">Copy</button>
          <button class="btn btn-del" data-action="var-delete"
            data-env-id="${envId}" data-key="${esc(k)}">×</button>
        </td>
      </tr>`).join('')}
    </tbody>
  </table>`;
}

/* ── Env actions (delegated) ────────────────────────── */
async function handleEnvAction(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  resetLock();
  const action = btn.dataset.action;
  const envId  = parseInt(btn.dataset.id ?? btn.dataset.envId, 10);

  if (action === 'env-toggle') {
    const body = $(`env-body-${envId}`);
    if (!body) return;
    const open = body.style.display !== 'none';
    body.style.display = open ? 'none' : '';
    btn.textContent = open ? '▼' : '▲';
    return;
  }
  if (action === 'env-import') {
    btn.closest('.env-item').querySelector('.env-file-input')?.click();
    return;
  }
  if (action === 'env-export') {
    const all   = await dbGetAll();
    const entry = all.find(x => x.id === envId);
    const vars  = await getEnvVars(envId);
    const a     = document.createElement('a');
    a.href     = URL.createObjectURL(new Blob([formatDotEnv(vars)], { type: 'text/plain' }));
    a.download = `${entry?.name || 'environment'}.env`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 100);
    return;
  }
  if (action === 'env-delete') {
    if (!confirm('Delete this environment and all its variables?')) return;
    await dbDel(envId);
    envCache.delete(envId);
    markUnsaved();
    renderEnvList();
    return;
  }
  if (action === 'var-toggle') {
    const row    = btn.closest('tr');
    const masked = row.querySelector('.env-val-masked');
    const plain  = row.querySelector('.env-val-plain');
    const show   = plain.style.display !== 'none';
    masked.style.display = show ? '' : 'none';
    plain.style.display  = show ? 'none' : '';
    btn.textContent = show ? 'View' : 'Hide';
    return;
  }
  if (action === 'var-copy') {
    const key  = btn.dataset.key;
    const vars = await getEnvVars(envId);
    const val = vars[key] ?? '';
    await navigator.clipboard.writeText(val);
    btn.textContent = '✓';
    btn.classList.add('btn-copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('btn-copied'); }, 1500);
    setTimeout(() => navigator.clipboard.readText().then(t => { if (t === val) navigator.clipboard.writeText(''); }).catch(() => {}), 30000);
    return;
  }
  if (action === 'var-delete') {
    const key = btn.dataset.key;
    if (!confirm(`Delete "${key}"?`)) return;
    const vars = await getEnvVars(envId);
    delete vars[key];
    await saveEnvVars(envId, vars);
    markUnsaved();
    await renderEnvList();
    reopenBody(envId);
    return;
  }
  if (action === 'var-add') {
    const keyEl = $(`ekey-${envId}`);
    const valEl = $(`eval-${envId}`);
    const key   = keyEl.value.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    if (!key) { toast('Key name is required', 'err'); return; }
    const vars  = await getEnvVars(envId);
    vars[key]   = valEl.value;
    await saveEnvVars(envId, vars);
    keyEl.value = ''; valEl.value = '';
    markUnsaved();
    toast(`${key} saved`, 'ok');
    await renderEnvList();
    reopenBody(envId);
    return;
  }
}

async function handleEnvFileInput(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  const envId   = parseInt(e.target.dataset.id, 10);
  const newVars = parseDotEnv(await file.text());
  const count   = Object.keys(newVars).length;
  if (!count) { toast('No variables found in file', 'err'); return; }
  const existing = await getEnvVars(envId);
  await saveEnvVars(envId, { ...existing, ...newVars });
  e.target.value = '';
  markUnsaved();
  toast(`Imported ${count} variable${count !== 1 ? 's' : ''}`, 'ok');
  await renderEnvList();
  reopenBody(envId);
}

function reopenBody(envId) {
  const body = $(`env-body-${envId}`);
  const btn  = document.querySelector(`[data-action="env-toggle"][data-id="${envId}"]`);
  if (body) body.style.display = '';
  if (btn)  btn.textContent = '▲';
}

/* ── New env panel ──────────────────────────────────── */
function showNewEnvPanel(show) {
  const p = $('new-env-panel');
  if (!p) return;
  p.style.display = show ? '' : 'none';
  if (show) {
    newEnvVars = null;
    $('new-env-name').value = '';
    updateNewEnvFileLabel();
    $('new-env-name').focus();
  }
}

function updateNewEnvFileLabel() {
  const lbl   = $('new-env-file-label');
  if (!lbl) return;
  const count = newEnvVars ? Object.keys(newEnvVars).length : 0;
  lbl.textContent = count
    ? `✓ ${count} variable${count !== 1 ? 's' : ''} ready to import`
    : 'Click or drop a .env file to pre-populate (optional)';
  lbl.style.color = count ? 'var(--green)' : '';
}

async function createEnv() {
  const name = $('new-env-name').value.trim();
  if (!name) { toast('Environment name is required', 'err'); return; }
  await addEntry(name, JSON.stringify(newEnvVars || {}), 'env', 'env');
  markUnsaved();
  showNewEnvPanel(false);
  toast(`"${name}" created`, 'ok');
  renderEnvList();
}

/* ── Misc UI ────────────────────────────────────────── */
function markUnsaved() { $('sync-banner').style.display = 'flex'; }

async function exportBackup() {
  const all = await dbGetAll();
  const data = { version: VERSION, kdf: CUR_KDF, salt: b64e(SALT), entries: all, ts: Date.now() };
  const a   = document.createElement('a');
  a.href    = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type:'application/json' }));
  a.download = `vault_backup_${VERSION}_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 100);
  lastSyncTime = new Date();
  updateSidebarMeta();
  $('sync-banner').style.display = 'none';
}

/* ── Change password — always upgrades to PBKDF2 ───── */
async function changePassword() {
  const np  = $('change-pass-new').value;
  const nc  = $('change-pass-confirm').value;
  if (np.length < 10) { toast('Min. 10 characters required', 'err'); return; }
  if (np !== nc)       { toast('Keys do not match', 'err'); return; }
  const btn = $('change-pass-btn');
  btn.disabled = true; btn.textContent = 'Re-encrypting…';
  try {
    const entries = await dbGetAll();
    const ns  = rnd(16);
    const nk  = await deriveKeyPbkdf2(np, ns);
    const re  = await reEncryptAll(entries, CK, nk);
    await dbClear();
    for (const e of re) { const { id, ...rest } = e; await dbAdd(rest); }
    CK = nk; SALT = ns; CUR_KDF = KDF_PBKDF2;
    await metaPut('salt', b64e(ns));
    await metaPut('kdf',  KDF_PBKDF2);
    envCache.clear();
    $('change-pass-new').value = ''; $('change-pass-confirm').value = '';
    markUnsaved();
    toast('Master key updated', 'ok');
  } catch (err) {
    toast('Re-encryption failed: ' + err.message, 'err');
  } finally {
    btn.disabled = false; btn.textContent = 'Update & re-encrypt';
  }
}

/* ── Wipe ───────────────────────────────────────────── */
async function wipeVault() {
  if (!confirm('Permanently delete ALL vault data? This cannot be undone.')) return;
  await dbClear(); await metaClr();
  CK = null; SALT = null; CUR_KDF = KDF_PBKDF2; envCache.clear(); stopLock();
  $('vault-view').style.display   = 'none';
  $('auth-view').style.display    = '';
  $('sidebar-meta').style.display = 'none';
  $('sync-banner').style.display  = 'none';
  $('tab-unlock').style.display   = 'none';
  setAuthMode('new');
  toast('Vault wiped', 'info');
}

/* ── Init ───────────────────────────────────────────── */
async function init() {
  DB = await openDB();
  $('app-version').textContent = VERSION;

  const hasSalt = !!(await metaGet('salt'));
  document.querySelectorAll('#auth-view .tab').forEach(t =>
    t.addEventListener('click', () => setAuthMode(t.dataset.mode))
  );
  if (hasSalt) {
    $('tab-unlock').style.display = '';
    setAuthMode('unlock');
    $('unlock-key').focus();
  } else {
    setAuthMode('new');
    $('new-key').focus();
  }

  /* Create new vault (always PBKDF2) */
  $('create-btn').addEventListener('click', async () => {
    const key  = $('new-key').value;
    const conf = $('new-confirm').value;
    if (key.length < 10) { toast('Min. 10 characters required', 'err'); return; }
    if (key !== conf)     { toast('Keys do not match', 'err'); return; }
    const btn = $('create-btn');
    btn.disabled = true; btn.textContent = 'Initialising…';
    try {
      const s = rnd(16);
      CK = await deriveKeyPbkdf2(key, s);
      SALT = s;
      CUR_KDF = KDF_PBKDF2;
      await metaPut('salt', b64e(s));
      await metaPut('kdf',  KDF_PBKDF2);
      $('new-key').value = ''; $('new-confirm').value = '';
      unlockUI();
    } catch (err) { toast('Failed: ' + err.message, 'err'); }
    finally { btn.disabled = false; btn.textContent = 'Initialize encrypted storage'; }
  });

  /* Unlock — detect KDF, auto-migrate Argon2 vaults in background */
  $('unlock-btn').addEventListener('click', async () => {
    const key = $('unlock-key').value;
    if (!key) { toast('Enter your master key', 'err'); return; }
    const btn = $('unlock-btn');
    btn.disabled = true; btn.textContent = 'Unlocking…';
    try {
      const saltStr = await metaGet('salt');
      if (!saltStr) throw new Error('No vault found');
      // No kdf in meta → old vault → Argon2id
      const kdf = (await metaGet('kdf')) || KDF_ARGON2;
      const s   = b64d(saltStr);
      if (kdf === KDF_ARGON2) btn.textContent = 'Loading Argon2…';
      const k = await deriveKey(key, s, kdf);
      // Verify against first entry
      const entries = await dbGetAll();
      if (entries.length) {
        await crypto.subtle.decrypt(
          { name:'AES-GCM', iv: b64d(entries[0].encrypted.iv) }, k, b64d(entries[0].encrypted.ct)
        );
      }
      CK = k; SALT = s; CUR_KDF = kdf;
      unlockUI();
      // Background migrate if Argon2 — migrateToPbkdf2 updates CUR_KDF when done
      if (kdf === KDF_ARGON2) migrateToPbkdf2(key);
    } catch (err) {
      const msg = err.message?.includes('Argon2') || err.message?.includes('argon2')
        ? err.message : 'Incorrect master key';
      toast(msg, 'err');
    } finally { btn.disabled = false; btn.textContent = 'Unlock vault'; $('unlock-key').value = ''; }
  });

  /* Restore backup — detect KDF, decrypt, immediately migrate if Argon2 */
  $('restore-zone').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = ev => {
      try {
        pendingBackup = JSON.parse(ev.target.result);
        $('file-label').textContent = `✓ ${f.name}`;
        $('file-label').classList.add('staged');
      } catch { toast('Invalid backup file', 'err'); }
    };
    r.readAsText(f);
  });

  $('restore-btn').addEventListener('click', async () => {
    if (!pendingBackup) { toast('Upload a backup file first', 'err'); return; }
    const key = $('restore-key').value;
    if (!key) { toast('Enter the master key', 'err'); return; }
    const btn = $('restore-btn');
    btn.disabled = true; btn.textContent = 'Restoring…';
    try {
      // No kdf field in backup → old backup → Argon2id
      const backupKdf = pendingBackup.kdf || KDF_ARGON2;
      const s = b64d(pendingBackup.salt);
      if (backupKdf === KDF_ARGON2) btn.textContent = 'Loading Argon2…';
      const k = await deriveKey(key, s, backupKdf);
      // Verify
      if (pendingBackup.entries?.length) {
        const e0 = pendingBackup.entries[0];
        await crypto.subtle.decrypt(
          { name:'AES-GCM', iv: b64d(e0.encrypted.iv) }, k, b64d(e0.encrypted.ct)
        );
      }
      // Write entries
      await dbClear();
      for (const e of (pendingBackup.entries || [])) { const { id, ...rest } = e; await dbAdd(rest); }
      await metaPut('salt', pendingBackup.salt);
      await metaPut('kdf',  backupKdf);
      CK = k; SALT = s; CUR_KDF = backupKdf;

      // Immediately re-encrypt under PBKDF2 if backup was Argon2
      if (backupKdf === KDF_ARGON2) {
        btn.textContent = 'Migrating to PBKDF2…';
        const entries = await dbGetAll();
        const ns = rnd(16);
        const nk = await deriveKeyPbkdf2(key, ns);
        const re = await reEncryptAll(entries, CK, nk);
        await dbClear();
        for (const e of re) { const { id, ...rest } = e; await dbAdd(rest); }
        CK = nk; SALT = ns;
        await metaPut('salt', b64e(ns));
        await metaPut('kdf',  KDF_PBKDF2);
        CUR_KDF = KDF_PBKDF2;
        toast('Backup restored & migrated to PBKDF2', 'info');
      }

      $('restore-key').value = '';
      markUnsaved();
      unlockUI();
    } catch (err) {
      const msg = err.message?.includes('Argon2') || err.message?.includes('argon2')
        ? err.message : 'Wrong key or corrupt backup';
      toast(msg, 'err');
    } finally { btn.disabled = false; btn.textContent = 'Restore & decrypt'; }
  });

  document.querySelectorAll('#main-tabs .tab').forEach(t =>
    t.addEventListener('click', () => switchTab(t.dataset.tab))
  );

  document.addEventListener('click', e => {
    const btn = e.target.closest('.toggle-btn');
    if (!btn) return;
    const inp = $(btn.dataset.target);
    if (!inp) return;
    inp.type = inp.type === 'password' ? 'text' : 'password';
    btn.textContent = inp.type === 'password' ? '👁' : '🙈';
  });

  $('list-container').addEventListener('click', handleEntryAction);
  $('env-list-container').addEventListener('click', handleEnvAction);

  $('add-btn').addEventListener('click', async () => {
    const name    = $('n-name').value.trim();
    const content = $('n-content').value.trim();
    const tag     = $('n-tag').value.trim();
    if (!name || !content) { toast('Name and content are required', 'err'); return; }
    const type = { passwords:'pw', keys:'key', certs:'cert' }[curTab] || 'pw';
    await addEntry(name, content, tag, type);
    $('n-name').value = ''; $('n-content').value = ''; $('n-tag').value = '';
    markUnsaved();
    renderEntryList();
  });

  $('v-search').addEventListener('input', renderEntryList);
  $('env-search').addEventListener('input', renderEnvList);

  $('content-zone').addEventListener('click', () => $('content-uploader').click());
  $('content-uploader').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = ev => {
      $('n-content').value = ev.target.result;
      if (!$('n-name').value) $('n-name').value = f.name;
    };
    r.readAsText(f);
  });

  $('new-env-btn').addEventListener('click', () => showNewEnvPanel(true));
  $('cancel-env-btn').addEventListener('click', () => showNewEnvPanel(false));
  $('create-env-btn').addEventListener('click', createEnv);
  $('new-env-import-zone').addEventListener('click', () => $('new-env-file-input').click());
  $('new-env-file-input').addEventListener('change', async e => {
    const f = e.target.files[0];
    if (!f) return;
    newEnvVars = parseDotEnv(await f.text());
    updateNewEnvFileLabel();
  });

  $('change-pass-btn').addEventListener('click', changePassword);
  $('wipe-btn').addEventListener('click', wipeVault);
  $('lock-btn').addEventListener('click', lockVault);
  $('export-btn').addEventListener('click', exportBackup);

  document.addEventListener('keydown', resetLock);
  document.addEventListener('click',   resetLock);

  $('unlock-key').addEventListener('keydown',   e => { if (e.key === 'Enter') $('unlock-btn').click(); });
  $('new-confirm').addEventListener('keydown',  e => { if (e.key === 'Enter') $('create-btn').click(); });
  $('new-env-name').addEventListener('keydown', e => { if (e.key === 'Enter') $('create-env-btn').click(); });
}

document.addEventListener('DOMContentLoaded', init);