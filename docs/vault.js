'use strict';
/* Vault — vault.js v2.0.0
   AES-256-GCM + PBKDF2-SHA256 (new) / Argon2id (legacy compat)
   Backward compatible: old Argon2id backups are auto-migrated to
   PBKDF2 on restore/unlock. KDF is stored in meta + backup JSON.

   v2.0.0 — Tabs redesign: secrets no longer live in fixed
   Passwords/Keys/Certs/Envs tabs. Instead the user creates their own
   named tabs; each tab holds a mixed list of secrets of any type
   (password / key / cert / env). Existing vaults are migrated
   automatically: the old fixed categories become tabs of the same
   name, and every entry is assigned to the tab matching its type. */

const APP         = 'keys';
const VERSION     = 'v2.1.0';
const DB_NAME     = 'vault_db';
const DB_VERSION  = 2;           // bumped to add the 'tabs' store
const STORE       = 'entries';
const STORE_TABS  = 'tabs';
const LOCK_MS     = 5 * 60 * 1000;
const KDF_PBKDF2  = 'pbkdf2';
const KDF_ARGON2  = 'argon2id';
// PBKDF2 iteration count is stored per-vault (meta key 'iterations') so it can
// be raised over time without breaking vaults/backups created before the
// change. A vault/backup with no stored count predates this field entirely —
// it was always derived at PBKDF2_ITERATIONS_LEGACY, so that's the fallback.
const PBKDF2_ITERATIONS_LEGACY  = 600_000;
const PBKDF2_ITERATIONS_CURRENT = 1_200_000;
// CDN URL for Argon2 — only injected when an old backup/vault needs it
const ARGON2_CDN = 'https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js';
// SRI hash for the above file, computed from argon2-browser@1.18.0's
// dist/argon2-bundled.min.js (jsDelivr serves npm packages verbatim, so
// this matches the CDN file byte-for-byte). Re-derive if ARGON2_CDN's
// version ever changes:
//   curl -sL <ARGON2_CDN> | openssl dgst -sha256 -binary | openssl base64
const ARGON2_SRI = 'sha256-d8ZLlGuvGlEW3FkfS5ll1jaxtFX3Xt0tSlh8t14BaHs=';

// Default names used when migrating a legacy (pre-tabs) vault/backup.
const TYPE_TAB_DEFAULTS = { pw: 'Passwords', key: 'Keys', cert: 'Certs', env: 'Envs' };
const TYPE_LABELS = { pw: 'PW', key: 'KEY', cert: 'CERT', env: 'ENV', file: 'FILE', billing: 'BILL', crypto: 'CRYPTO' };
const TYPE_COLORS = { pw: 'var(--accent-bright)', key: 'var(--purple)', cert: 'var(--amber)', env: 'var(--green)', file: 'var(--cyan)', billing: 'var(--rose)', crypto: 'var(--teal)' };

// Default lead time, in days, for the "renewal coming up" reminder — used
// whenever a billing entry doesn't specify its own reminderDays.
const BILLING_REMINDER_DAYS_DEFAULT = 7;

// Supported coins for the 'crypto' entry type. `pattern` is a lenient
// sanity check against the address format that coin's mainnet actually
// uses (not a full checksum/validity proof — that would need per-chain
// crypto libraries) — it catches pasted-wrong-coin and typo mistakes
// without false-rejecting a technically-valid address this regex doesn't
// anticipate. `memoField`, where present, is a SEPARATE piece of data a
// receiving address needs beyond the address itself (XRP's destination
// tag, Monero's payment ID) — mixing it into the address field is a classic
// way to send funds that an exchange then can't credit to the right account.
const CRYPTO_COINS = {
  btc: {
    label: 'Bitcoin (BTC)',
    pattern: /^(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})$/,
  },
  ethereum: {
    label: 'Ethereum (ETH)',
    pattern: /^0x[a-fA-F0-9]{40}$/,
  },
  xrp: {
    label: 'XRP',
    pattern: /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/,
    memoField: {
      label: 'Destination tag (optional)',
      hint: 'Numeric tag some exchanges need to credit a deposit — a separate field from the address itself.',
      validate: v => v === '' || /^\d{1,10}$/.test(v),
    },
  },
  usdt: {
    label: 'USDT (Tether)',
    pattern: /^(0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|[1-9A-HJ-NP-Za-km-z]{32,44})$/,
    hint: 'USDT runs on several networks — accepts an ERC-20 (0x…), TRC-20 (T…), or Solana-style address. Make sure it matches the network you intend to use.',
  },
  monero: {
    label: 'Monero (XMR)',
    pattern: /^[48][0-9A-Za-z]{94}$/,
    memoField: {
      label: 'Payment ID (optional)',
      hint: '16 or 64 hex characters — a separate field from the address itself, used to identify a specific payment.',
      validate: v => v === '' || /^[0-9a-fA-F]{16}$/.test(v) || /^[0-9a-fA-F]{64}$/.test(v),
    },
  },
  bnb: {
    label: 'BNB',
    pattern: /^(0x[a-fA-F0-9]{40}|bnb1[a-z0-9]{38})$/,
    hint: 'Accepts a BNB Smart Chain (0x…) or legacy Beacon Chain (bnb1…) address.',
  },
  tron: {
    label: 'Tron (TRX)',
    pattern: /^T[1-9A-HJ-NP-Za-km-z]{33}$/,
  },
  solana: {
    label: 'Solana (SOL)',
    pattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  },
};

function cryptoCoinOptionsHTML(selected) {
  return Object.entries(CRYPTO_COINS)
    .map(([key, c]) => `<option value="${key}" ${key === selected ? 'selected' : ''}>${esc(c.label)}</option>`)
    .join('');
}

// Returns an error string, or null if the address passes this coin's
// lenient format check.
function validateCryptoAddress(coinKey, address) {
  const coin = CRYPTO_COINS[coinKey];
  if (!coin) return 'Unknown cryptocurrency';
  if (!address) return 'Wallet address is required';
  if (!coin.pattern.test(address.trim())) return `That doesn't look like a valid ${coin.label} address`;
  return null;
}

// Shows/hides and relabels the memo/tag field for whichever coin is
// currently selected — only XRP and Monero define one for now.
function updateCryptoMemoField(coinKey, wrapEl, labelEl) {
  const memoField = CRYPTO_COINS[coinKey]?.memoField;
  if (!wrapEl || !labelEl) return;
  if (memoField) {
    wrapEl.style.display = '';
    labelEl.textContent = memoField.label;
  } else {
    wrapEl.style.display = 'none';
  }
}

function updateCryptoHint(coinKey, hintEl) {
  if (!hintEl) return;
  const hint = CRYPTO_COINS[coinKey]?.hint;
  if (hint) { hintEl.textContent = hint; hintEl.style.display = ''; }
  else hintEl.style.display = 'none';
}

// Local upload cap for attachments — generous for documents/small media,
// but keeps a single entry from freezing the tab (base64 encode is O(n)
// char-by-char) or blowing past IndexedDB's per-value comfort zone.
const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024; // 10 MB
function formatBytes(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// Palette + deterministic hash used for tab/entry avatar chips
const AVATAR_COLORS = ['#6366f1','#059669','#d97706','#dc2626','#2563eb','#7c3aed','#0891b2','#db2777','#65a30d','#ea580c'];
function avatarColor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}
function avatarInitials(name) {
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

/* ── State ─────────────────────────────────────────── */
let CK            = null;
let SALT          = null;
let CUR_KDF       = KDF_PBKDF2; // always in sync with CK/SALT
let CUR_ITER      = PBKDF2_ITERATIONS_CURRENT; // PBKDF2 iteration count in effect for CK (meaningless when CUR_KDF is argon2id)
let DB            = null;
let lockTimer     = null;
let lockEnd       = 0;
let curTabId      = null;   // numeric tab id, or the string 'security'
let curAddType    = 'pw';   // which secret type the add-form is set to
let addPanelOpen  = false;  // whether the "+ Add" panel is expanded
let viewMode      = 'grid'; // 'grid' | 'list'
let TABS          = [];     // in-memory cache of tabs, always kept sorted per TAB_SORT_MODE
let TAB_SORT_MODE = 'alpha'; // 'alpha' (default) | 'manual' (drag-reordered — persisted in meta.tabSortMode)
let searchAllTabs = false;  // when true + a query is typed, search spans every tab instead of just curTabId
let pendingBackup = null;
let newEnvVars    = null;
let newAttachmentFile = null; // { name, mimeType, size, buffer } staged for the add-entry form
const envCache    = new Map();
let lastSyncTime  = null;  // Date of last successful backup export
let lastCopied    = null;  // { value, timer } — last secret written to the clipboard by this app

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
const genHex       = bytes => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
const genBase64Url = bytes => b64e(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/* ── Value generator — standalone, never writes into the add-entry form.
   Generate, then Copy if you want it; nothing here touches the vault or
   any entry until the user pastes it somewhere themselves. ──────────── */
// Unbiased random integer in [0, maxExclusive) via rejection sampling —
// a plain `rnd(n) % maxExclusive` would slightly favor low values for any
// maxExclusive that doesn't evenly divide 256^n.
function genRandomInt(maxExclusive) {
  if (maxExclusive <= 1) return 0;
  const bytesNeeded = Math.max(1, Math.ceil(Math.log2(maxExclusive) / 8));
  const ceiling = 256 ** bytesNeeded;
  const maxUnbiased = Math.floor(ceiling / maxExclusive) * maxExclusive;
  let val;
  do {
    val = rnd(bytesNeeded).reduce((acc, b) => acc * 256 + b, 0);
  } while (val >= maxUnbiased);
  return val % maxExclusive;
}

function genRandomString(charset, length) {
  let s = '';
  for (let i = 0; i < length; i++) s += charset[genRandomInt(charset.length)];
  return s;
}

function genPickWord(list) { return list[genRandomInt(list.length)]; }

const GEN_CHARSET_LOWER   = 'abcdefghijklmnopqrstuvwxyz';
const GEN_CHARSET_UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const GEN_CHARSET_DIGITS  = '0123456789';
const GEN_CHARSET_SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';

function genCharsetFor(complexity) {
  if (complexity === 'simple') return GEN_CHARSET_LOWER + GEN_CHARSET_DIGITS;
  if (complexity === 'good')   return GEN_CHARSET_LOWER + GEN_CHARSET_UPPER + GEN_CHARSET_DIGITS;
  return GEN_CHARSET_LOWER + GEN_CHARSET_UPPER + GEN_CHARSET_DIGITS + GEN_CHARSET_SYMBOLS; // strong / verystrong
}

const GEN_PW_WORDCOUNT = { simple: 3, good: 4, strong: 5, verystrong: 7 };
const GEN_PW_CHARLEN   = { simple: 8, good: 12, strong: 16, verystrong: 24 };
const GEN_PW_PINLEN    = { simple: 4, good: 6, strong: 8, verystrong: 10 };
const GEN_PW_HEXBYTES  = { simple: 8, good: 16, strong: 32, verystrong: 64 };

// Short, ordinary, easy-to-type words (not a cryptographic Diceware list —
// this generator is a convenience helper, not the vault's own KDF/key
// material). ~140 words gives ~7.1 bits/word; complexity scales the word
// count to compensate (7 words ≈ 50 bits at "very strong").
const GEN_WORDLIST = [
  'alpha','amber','anchor','apple','arrow','autumn','azure','badge','basil','beacon',
  'birch','blossom','brave','bridge','bright','bronze','canyon','captain','cedar','chrome',
  'clever','cloud','comet','coral','crimson','crystal','dawn','delta','desert','diamond',
  'dragon','dune','eagle','ember','emerald','falcon','feather','fern','flame','forest',
  'fox','garden','glacier','gold','granite','grove','harbor','hazel','hollow','honey',
  'horizon','ivory','ivy','jade','jasper','jungle','lagoon','lantern','laurel','lily',
  'lotus','lunar','maple','marble','maroon','meadow','mint','misty','mountain','nectar',
  'nova','oak','ocean','olive','onyx','opal','orbit','orchid','otter','panther',
  'pearl','pebble','phoenix','pine','planet','plum','polar','prairie','quartz','quiet',
  'rapid','raven','reef','river','rocket','rose','ruby','sage','sandalwood','sapphire',
  'scarlet','shadow','silver','sky','slate','solar','spruce','star','storm','summit',
  'sunny','swan','tempest','thunder','tide','timber','topaz','trail','tulip','tundra',
  'twilight','valley','velvet','violet','vivid','walnut','willow','winter','wolf','zephyr',
];

function genPassphrase(complexity, separatorKey, digitMode) {
  const words = Array.from({ length: GEN_PW_WORDCOUNT[complexity] }, () => genPickWord(GEN_WORDLIST));
  const cased = separatorKey === 'camel' ? words.map(w => w[0].toUpperCase() + w.slice(1)) : words;
  const joinChar = { space: ' ', hyphen: '-', dot: '.', camel: '' }[separatorKey] ?? ' ';
  let phrase = cased.join(joinChar);
  const digit = () => String(genRandomInt(90) + 10); // a 2-digit number, 10-99
  const glue = separatorKey === 'camel' ? '' : joinChar;
  if (digitMode === 'prefix' || digitMode === 'both') phrase = digit() + glue + phrase;
  if (digitMode === 'suffix' || digitMode === 'both') phrase = phrase + glue + digit();
  return phrase;
}

function genEncodedBytes(byteLen, encoding) {
  const bytes = rnd(byteLen);
  if (encoding === 'hex') return genHex(bytes);
  if (encoding === 'base64url') return genBase64Url(bytes);
  return b64e(bytes); // 'base64'
}

function genOpensslPreview(sizeBytes, encoding) {
  if (encoding === 'hex') return `$ openssl rand -hex ${sizeBytes}`;
  if (encoding === 'base64') return `$ openssl rand -base64 ${sizeBytes}`;
  return `$ openssl rand -base64 ${sizeBytes} | tr '+/' '-_' | tr -d '='`; // base64url has no native openssl flag
}

function genPemBlock(buf, label) {
  const b64 = b64e(buf);
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

async function genRsaKeyPair(bits) {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
  const [pub, priv] = await Promise.all([
    crypto.subtle.exportKey('spki',  keyPair.publicKey),
    crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
  ]);
  return { publicPem: genPemBlock(pub, 'PUBLIC KEY'), privatePem: genPemBlock(priv, 'PRIVATE KEY') };
}

/* ── Lock-state guard ─────────────────────────────────
   These functions are reachable two ways: through the sidebar UI
   (hidden via .locked-hidden while locked) and directly, since every
   top-level function here is a global in a classic <script> — anyone
   with the page open in a locked state could call e.g. addTab() or
   renderTabsBar() from the console. The UI hiding alone is therefore
   not enough; every function that reads or renders tab/entry data
   also checks isUnlocked() itself before doing anything. ── */
const isUnlocked = () => CK !== null;

/* ── Cross-tab lock sync ───────────────────────────────
   Without this, unlocking the vault in two tabs and then changing the
   master key (or migrating KDF) in one leaves the other tab holding a
   stale in-memory key — any edit it then makes gets encrypted under a
   key that no longer matches meta.salt, silently and permanently
   corrupting that entry. BroadcastChannel never delivers a tab's own
   messages back to itself, so this can't self-trigger or loop. */
const lockChannel = ('BroadcastChannel' in window) ? new BroadcastChannel('vault-lock-sync') : null;
function broadcastLock() {
  try { lockChannel?.postMessage({ type: 'lock' }); } catch {}
}
if (lockChannel) {
  lockChannel.onmessage = e => {
    if (e.data?.type === 'lock' && isUnlocked()) {
      lockVault();
      toast('Locked — the vault changed in another tab', 'info');
    }
  };
}

/* ── Failed-attempt backoff (unlock / restore) ────────
   PBKDF2 at 600k+ iterations already costs real time per guess, but this
   adds an explicit, visible lockout on top so a script or rogue extension
   can't just hammer the unlock/restore flow. State is persisted to the
   (unencrypted) IndexedDB 'meta' store — reachable before unlock, same as
   'salt'/'kdf' — so it survives a page reload instead of resetting it;
   this is still an in-browser speed-bump, not a durable server-side
   lockout, but it can no longer be defeated by simply reloading the page. */
const FREE_ATTEMPTS    = 2;      // first couple of typos cost nothing
const BASE_DELAY_MS    = 1000;
const MAX_DELAY_MS     = 30000;
const attemptState = { unlock: { count: 0, lockUntil: 0 }, restore: { count: 0, lockUntil: 0 }, export: { count: 0, lockUntil: 0 } };

async function loadAttemptState() {
  for (const key of Object.keys(attemptState)) {
    const saved = await metaGet(`attempts_${key}`);
    if (saved && typeof saved.count === 'number') attemptState[key] = saved;
  }
}

function persistAttemptState(key) {
  metaPut(`attempts_${key}`, attemptState[key]).catch(() => {});
}

function cooldownRemaining(key) {
  return Math.max(0, attemptState[key].lockUntil - Date.now());
}

function registerFailedAttempt(key) {
  const s = attemptState[key];
  s.count++;
  if (s.count > FREE_ATTEMPTS) {
    const delay = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** (s.count - FREE_ATTEMPTS - 1));
    s.lockUntil = Date.now() + delay;
  }
  persistAttemptState(key);
}

function registerSuccess(key) {
  attemptState[key] = { count: 0, lockUntil: 0 };
  persistAttemptState(key);
}

// Disables btn and shows a live countdown for as long as the cooldown
// lasts; a no-op (just re-enables) once the cooldown has already elapsed.
function applyCooldownUI(key, btn, defaultText) {
  const tick = () => {
    const rem = cooldownRemaining(key);
    if (rem <= 0) { btn.disabled = false; btn.textContent = defaultText; return; }
    btn.disabled = true;
    btn.textContent = `Wait ${Math.ceil(rem / 1000)}s…`;
    setTimeout(tick, 250);
  };
  tick();
}

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
async function deriveKeyPbkdf2(pass, saltBytes, iterations = PBKDF2_ITERATIONS_CURRENT) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
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
async function deriveKey(pass, saltBytes, kdf = KDF_PBKDF2, iterations = PBKDF2_ITERATIONS_CURRENT) {
  return kdf === KDF_ARGON2
    ? deriveKeyArgon2(pass, saltBytes)
    : deriveKeyPbkdf2(pass, saltBytes, iterations);
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

/* ── Background upgrade: Argon2id → PBKDF2, or low-iteration
   PBKDF2 → current iteration count ──────────────────────────
   Called after a successful unlock with CK already set, whenever the
   vault's on-disk KDF params are weaker than PBKDF2_ITERATIONS_CURRENT. */
async function migrateToPbkdf2(pass) {
  const fromArgon2 = CUR_KDF === KDF_ARGON2;
  try {
    const entries = await dbGetAll();
    const ns  = rnd(16);
    const nk  = await deriveKeyPbkdf2(pass, ns); // uses PBKDF2_ITERATIONS_CURRENT
    const re  = await reEncryptAll(entries, CK, nk);
    await dbClear();
    for (const e of re) { const { id, ...rest } = e; await dbAdd(rest); }
    CK = nk; SALT = ns; CUR_KDF = KDF_PBKDF2; CUR_ITER = PBKDF2_ITERATIONS_CURRENT;
    await metaPut('salt', b64e(ns));
    await metaPut('kdf',  KDF_PBKDF2);
    await metaPut('iterations', PBKDF2_ITERATIONS_CURRENT);
    envCache.clear();
    markUnsaved();
    updateSidebarMeta();
    broadcastLock(); // any other open tab is now holding a stale key — force it to relock
    toast(fromArgon2
      ? 'Vault migrated from Argon2id → PBKDF2'
      : 'Vault upgraded to current PBKDF2 iteration count', 'info');
  } catch (err) {
    console.warn('KDF upgrade failed (non-fatal):', err);
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

// Binary variants for file attachments — same cipher, no text (de)coding
// so arbitrary file bytes round-trip exactly. reEncryptAll() below already
// works on raw ArrayBuffers so KDF migration / master-key changes cover
// attachments transparently, no separate handling needed there.
async function aesEncryptBytes(buf) {
  const iv = rnd(12);
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, CK, buf);
  return { iv: b64e(iv), ct: b64e(ct) };
}

async function aesDecryptBytes({ iv, ct }) {
  return crypto.subtle.decrypt({ name:'AES-GCM', iv: b64d(iv) }, CK, b64d(ct)); // ArrayBuffer
}

/* ── IndexedDB ──────────────────────────────────────── */
function openDB() {
  return new Promise((ok, fail) => {
    const r = indexedDB.open(DB_NAME, DB_VERSION);
    r.onupgradeneeded = e => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains(STORE))
        d.createObjectStore(STORE, { keyPath: 'id', autoIncrement: true });
      if (!d.objectStoreNames.contains('meta'))
        d.createObjectStore('meta');
      if (!d.objectStoreNames.contains(STORE_TABS))
        d.createObjectStore(STORE_TABS, { keyPath: 'id', autoIncrement: true });
    };
    r.onsuccess = e => ok(e.target.result);
    r.onerror   = e => fail(e.target.error);
  });
}

const wrap  = r     => new Promise((ok, fail) => { r.onsuccess = () => ok(r.result); r.onerror = () => fail(r.error); });
const txS   = rw    => DB.transaction(STORE, rw ? 'readwrite' : 'readonly').objectStore(STORE);
const txM   = rw    => DB.transaction('meta',  rw ? 'readwrite' : 'readonly').objectStore('meta');
const txT   = rw    => DB.transaction(STORE_TABS, rw ? 'readwrite' : 'readonly').objectStore(STORE_TABS);

const dbGetAll = ()     => wrap(txS().getAll());
const dbGet    = id     => wrap(txS().get(id));
const dbAdd    = obj    => wrap(txS(true).add(obj));
const dbPut    = obj    => wrap(txS(true).put(obj));
const dbDel    = id     => wrap(txS(true).delete(id));
const dbClear  = ()     => wrap(txS(true).clear());
const metaGet  = k      => wrap(txM().get(k));
const metaPut  = (k, v) => wrap(txM(true).put(v, k));
const metaClr  = ()     => wrap(txM(true).clear());

const tabGetAll = ()    => wrap(txT().getAll());
const tabAdd    = obj   => wrap(txT(true).add(obj));
const tabPut    = obj   => wrap(txT(true).put(obj));
const tabDel    = id    => wrap(txT(true).delete(id));
const tabsClear = ()    => wrap(txT(true).clear());

/* ── Tabs — creation, migration, rendering ──────────── */
// Tab sort order: 'alpha' (default) sorts by name regardless of any stored
// `order` field; 'manual' (entered by dragging a tab in the sidebar) sorts
// by that `order` field, falling back to creation time for tabs that
// predate it. The mode itself is persisted in meta.tabSortMode so it
// survives a reload; TAB_SORT_MODE is loaded once at init(). Favorited
// tabs (tab.favorite) are always pinned ahead of the rest, each group
// sorted independently by the same mode.
function sortTabsGroup(tabs) {
  const list = [...tabs];
  return TAB_SORT_MODE === 'manual'
    ? list.sort((a, b) => (a.order ?? a.created ?? 0) - (b.order ?? b.created ?? 0))
    : list.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }));
}

function sortTabs(tabs) {
  const favs = sortTabsGroup(tabs.filter(t => t.favorite));
  const rest = sortTabsGroup(tabs.filter(t => !t.favorite));
  return [...favs, ...rest];
}

async function toggleTabFavorite(id) {
  if (!isUnlocked()) return;
  const tab = TABS.find(t => t.id === id);
  if (!tab) return;
  await tabPut({ ...tab, favorite: !tab.favorite });
  await renderTabsBar();
}

async function setTabSortAlphabetical() {
  TAB_SORT_MODE = 'alpha';
  await metaPut('tabSortMode', 'alpha');
  await renderTabsBar();
  toast('Tabs sorted A–Z', 'info');
}

// Drag-and-drop a tab before/onto another one — switches to 'manual' mode
// and persists a sequential `order` on every tab so the new arrangement
// sticks (rather than only reordering the in-memory TABS array for this
// render).
async function reorderTabs(draggedId, targetId) {
  if (draggedId === targetId) return;
  const current = TABS.slice();
  const fromIdx = current.findIndex(t => t.id === draggedId);
  const toIdx   = current.findIndex(t => t.id === targetId);
  if (fromIdx === -1 || toIdx === -1) return;
  const [moved] = current.splice(fromIdx, 1);
  current.splice(toIdx, 0, moved);
  TAB_SORT_MODE = 'manual';
  await metaPut('tabSortMode', 'manual');
  for (let i = 0; i < current.length; i++) await tabPut({ ...current[i], order: i });
  await renderTabsBar();
}

// Ensures at least one tab exists. On a fresh vault, creates a single
// "General" tab. On a vault upgraded from the old fixed-category
// layout (entries exist but no tabs do — or a legacy backup with no
// `tabs` array), recreates those categories as tabs and backfills
// every entry's tabId to match its type.
async function ensureTabsReady() {
  let tabs = await tabGetAll();
  if (tabs.length) { TABS = sortTabs(tabs); return TABS; }

  const entries = await dbGetAll();
  if (!entries.length) {
    const id = await tabAdd({ name: 'General', created: Date.now() });
    TABS = [{ id, name: 'General', created: Date.now() }];
    return TABS;
  }

  const madeIds = {};
  for (const type of Object.keys(TYPE_TAB_DEFAULTS)) {
    if (entries.some(e => e.type === type)) {
      madeIds[type] = await tabAdd({ name: TYPE_TAB_DEFAULTS[type], created: Date.now() });
    }
  }
  const fallbackId = Object.values(madeIds)[0];
  for (const e of entries) {
    const tabId = madeIds[e.type] ?? fallbackId;
    if (tabId !== undefined && e.tabId !== tabId) await dbPut({ ...e, tabId });
  }
  TABS = sortTabs(await tabGetAll());
  return TABS;
}

async function loadTabs() {
  TABS = sortTabs(await tabGetAll());
  return TABS;
}

function tabNavItemHTML(t, all, curTabId) {
  const count = all.filter(e => e.tabId === t.id).length;
  const color = avatarColor(t.name);
  const initials = avatarInitials(t.name);
  return `<div class="nav-item tab-custom ${t.id === curTabId ? 'active' : ''}" data-tab-id="${t.id}" draggable="true">
    <span class="nav-icon" style="background:${color}">${initials}</span>
    <span class="nav-label">${esc(t.name)}</span>
    <span class="nav-fav ${t.favorite ? 'active' : ''}" data-action="toggle-favorite" data-tab-id="${t.id}" title="${t.favorite ? 'Unpin from favorites' : 'Pin to favorites'}">${t.favorite ? '★' : '☆'}</span>
    <span class="nav-count">${count}</span>
    <span class="nav-close" data-action="delete-tab" data-tab-id="${t.id}" title="Delete tab">×</span>
  </div>`;
}

async function renderTabsBar() {
  if (!isUnlocked()) { $('sidebar-tab-nav').innerHTML = ''; return; } // never reveal tab names/counts while locked
  await loadTabs();
  const all  = await dbGetAll();
  const wrap = $('sidebar-tab-nav');
  const favs = TABS.filter(t => t.favorite);
  const rest = TABS.filter(t => !t.favorite);
  const favHTML  = favs.map(t => tabNavItemHTML(t, all, curTabId)).join('');
  const restHTML = rest.map(t => tabNavItemHTML(t, all, curTabId)).join('');
  const divider  = favs.length && rest.length ? '<div class="nav-fav-divider"></div>' : '';
  wrap.innerHTML = favHTML + divider + restHTML;
  $('tab-security').classList.toggle('active', curTabId === 'security');
}

async function updateTabCounts() {
  const all = await dbGetAll();
  document.querySelectorAll('.tab-custom').forEach(t => {
    const id  = parseInt(t.dataset.tabId, 10);
    const cnt = all.filter(e => e.tabId === id).length;
    const el  = t.querySelector('.nav-count');
    if (el) el.textContent = cnt;
  });
}

async function addTab() {
  if (!isUnlocked()) return;
  const name = prompt('New tab name');
  if (!name || !name.trim()) return;
  const id = await tabAdd({ name: name.trim(), created: Date.now() });
  await renderTabsBar();
  switchTab(id);
}

async function renameTab(id) {
  if (!isUnlocked()) return;
  const tab = TABS.find(t => t.id === id);
  if (!tab) return;
  const name = prompt('Rename tab', tab.name);
  if (!name || !name.trim() || name.trim() === tab.name) return;
  await tabPut({ ...tab, name: name.trim() });
  await renderTabsBar();
}

async function deleteTabById(id) {
  if (!isUnlocked()) return;
  const all   = await dbGetAll();
  const tab   = TABS.find(t => t.id === id);
  const owned = all.filter(e => e.tabId === id);
  const msg   = owned.length
    ? `Delete "${tab?.name}" and its ${owned.length} secret${owned.length !== 1 ? 's' : ''}? This cannot be undone.`
    : `Delete "${tab?.name}"?`;
  if (!confirm(msg)) return;
  for (const e of owned) await dbDel(e.id);
  await tabDel(id);
  await loadTabs();
  markUnsaved();

  if (!TABS.length) {
    const newId = await tabAdd({ name: 'General', created: Date.now() });
    await renderTabsBar();
    switchTab(newId);
    return;
  }
  await renderTabsBar();
  if (curTabId === id) switchTab(TABS[0].id);
}

/* ── Add-entry form: type selector + collapsible panel ─ */
function resetAddForm() {
  curAddType = 'pw';
  $('type-select').querySelectorAll('.type-btn').forEach(b => b.classList.toggle('active', b.dataset.type === 'pw'));
  $('importer-ui').style.display          = 'none';
  $('env-importer-ui').style.display      = 'none';
  $('attachment-upload-ui').style.display = 'none';
  $('billing-fields-ui').style.display    = 'none';
  $('crypto-fields-ui').style.display     = 'none';
  $('n-content').style.display = '';
  $('n-name').value = ''; $('n-tag').value = ''; $('n-content').value = '';
  newEnvVars = null;
  updateNewEnvFileLabel();
  newAttachmentFile = null;
  updateAttachmentLabel();
  $('attachment-file-input').value = '';
  $('n-billing-cycle').value = 'monthly';
  $('n-billing-day').value = '';
  $('n-billing-month').value = String(new Date().getMonth() + 1);
  $('n-billing-month-wrap').style.display = 'none';
  $('n-billing-price').value = '';
  $('n-billing-reminder').value = String(BILLING_REMINDER_DAYS_DEFAULT);
  $('n-crypto-coin').value = 'btc';
  $('n-crypto-address').value = '';
  $('n-crypto-memo').value = '';
  updateCryptoMemoField('btc', $('n-crypto-memo-wrap'), $('n-crypto-memo-label'));
  updateCryptoHint('btc', $('n-crypto-hint'));
}

function setAddType(type) {
  curAddType = type;
  $('type-select').querySelectorAll('.type-btn').forEach(b => b.classList.toggle('active', b.dataset.type === type));
  $('importer-ui').style.display          = (type === 'key' || type === 'cert') ? '' : 'none';
  $('env-importer-ui').style.display      = type === 'env' ? '' : 'none';
  $('attachment-upload-ui').style.display = type === 'file' ? '' : 'none';
  $('billing-fields-ui').style.display    = type === 'billing' ? '' : 'none';
  $('crypto-fields-ui').style.display     = type === 'crypto' ? '' : 'none';
  $('n-content').style.display            = (type === 'env' || type === 'file' || type === 'billing' || type === 'crypto') ? 'none' : '';
}

function updateAttachmentLabel() {
  const lbl = $('attachment-file-label');
  if (!lbl) return;
  if (newAttachmentFile) {
    lbl.textContent = `✓ ${newAttachmentFile.name} (${formatBytes(newAttachmentFile.size)}) ready to encrypt`;
    lbl.style.color = 'var(--green)';
  } else {
    lbl.textContent = `Click or drop a file to encrypt (max ${formatBytes(MAX_ATTACHMENT_SIZE)})`;
    lbl.style.color = '';
  }
}

function toggleAddPanel(open) {
  addPanelOpen = open ?? !addPanelOpen;
  $('add-entry-panel').style.display = addPanelOpen ? '' : 'none';
  const btn = $('add-entry-btn');
  btn.textContent = addPanelOpen ? '× Cancel' : '+ Add';
  btn.classList.toggle('btn-pill-cancel', addPanelOpen);
  if (addPanelOpen) { resetAddForm(); $('n-name').focus(); }
}

function setViewMode(mode) {
  viewMode = mode;
  const c = $('list-container');
  c.classList.toggle('cards-grid', mode === 'grid');
  c.classList.toggle('cards-list', mode === 'list');
  $('view-grid-btn').classList.toggle('active', mode === 'grid');
  $('view-list-btn').classList.toggle('active', mode === 'list');
}

/* ── Entry helpers ──────────────────────────────────── */
async function addEntry(name, content, tag, type, tabId) {
  const encrypted = await aesEncrypt(content);
  return dbAdd({ name, tag: tag || '', type, tabId, encrypted, created: Date.now() });
}

// file.mimeType/fileName/size are stored unencrypted (same trust level as
// name/tag already are) so the UI can show/download without decrypting;
// only the actual file bytes go through AES-GCM.
async function addFileEntry(name, tag, tabId, file) {
  const encrypted = await aesEncryptBytes(file.buffer);
  return dbAdd({
    name, tag: tag || '', type: 'file', tabId,
    mimeType: file.mimeType, fileName: file.name, size: file.size,
    encrypted, created: Date.now(),
  });
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
  broadcastLock(); // tell any other open tab of this vault to relock too
  CK = null; SALT = null; CUR_KDF = KDF_PBKDF2;
  envCache.clear();
  clearClipboardNow(); // don't leave a copied secret sitting in the clipboard past a lock
  stopLock();
  curTabId = null;
  TABS = [];
  $('sidebar-tab-nav').innerHTML = '';
  $('sidebar-nav-wrap').classList.add('locked-hidden');
  $('sidebar-nav-divider').classList.add('locked-hidden');
  // Scrub any decrypted plaintext that was sitting in the (now hidden)
  // vault-view DOM — view/edit panels, staged .env values, the add form —
  // so it isn't recoverable via devtools after lock, only after unlock.
  $('list-container').innerHTML = '';
  $('v-search').value = '';
  toggleAddPanel(false);
  resetAddForm();
  $('change-pass-new').value = '';
  $('change-pass-confirm').value = '';
  closeExportConfirm(); // scrub any master key staged there and hide the overlay
  closeGenerator();     // scrub any generated secret sitting in the output box
  $('vault-view').style.display    = 'none';
  $('auth-view').style.display     = '';
  $('sidebar-meta').style.display  = 'none';
  $('sync-banner').style.display   = 'none';
  setAuthMode('unlock');
}

async function unlockUI() {
  $('auth-view').style.display    = 'none';
  $('vault-view').style.display   = '';
  $('sidebar-meta').style.display = 'block';
  $('tab-unlock').style.display   = '';
  $('unlock-key').value = '';
  updateSidebarMeta();
  updateCounts();
  startLock();
  await ensureTabsReady();     // requires CK — only ever called after CK is set
  await renderTabsBar();
  $('sidebar-nav-wrap').classList.remove('locked-hidden');
  $('sidebar-nav-divider').classList.remove('locked-hidden');
  resetAddForm();
  switchTab(TABS.length ? TABS[0].id : 'security');
  checkBillingReminders(); // fire-and-forget — one summary toast per unlock, not per render
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

/* ── Sidebar counts + meta (global, across every tab) ─ */
async function updateCounts(all) {
  if (!all) all = await dbGetAll();
  $('count-pw').textContent   = all.filter(e => e.type === 'pw').length;
  $('count-keys').textContent = all.filter(e => e.type === 'key').length;
  $('count-cert').textContent = all.filter(e => e.type === 'cert').length;
  $('count-env').textContent  = all.filter(e => e.type === 'env').length;
  $('count-file').textContent = all.filter(e => e.type === 'file').length;
  $('count-billing').textContent = all.filter(e => e.type === 'billing').length;
  $('count-crypto').textContent = all.filter(e => e.type === 'crypto').length;
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

/* ── Tab switching ───────────────────────────────────── */
function switchTab(tabId) {
  if (!isUnlocked()) return;
  curTabId = tabId;
  const isSecurity = tabId === 'security';
  $('vault-content-section').style.display = isSecurity ? 'none' : '';
  $('security-section').style.display      = isSecurity ? '' : 'none';
  $('topbar-controls').style.display       = isSecurity ? 'none' : '';
  $('list-meta').style.display             = isSecurity ? 'none' : '';

  const tab = TABS.find(t => t.id === tabId);
  $('current-tab-title').textContent = isSecurity ? 'Security' : (tab?.name || '');

  document.querySelectorAll('#sidebar-tab-nav .tab-custom').forEach(t =>
    t.classList.toggle('active', parseInt(t.dataset.tabId, 10) === tabId)
  );
  $('tab-security').classList.toggle('active', isSecurity);

  if (!isSecurity) {
    toggleAddPanel(false);
    renderEntryList();
  }
  resetLock();
}

/* ── Type badge (shared by both row renderers) ──────── */
function typeBadge(type) {
  const label = TYPE_LABELS[type] || '?';
  const color = TYPE_COLORS[type] || 'var(--text3)';
  return `<span class="type-badge" style="color:${color};border-color:${color}">${label}</span>`;
}

// Joins an entry's tag and (in cross-tab search results) its source tab
// name with a bullet, falling back to a non-breaking space to hold the
// line's height when there's nothing to show.
function entrySubLine(tag, tabName) {
  const parts = [tag, tabName].filter(Boolean).map(esc);
  return parts.length ? parts.join(' · ') : '&nbsp;';
}

/* ── Billing entries: recurring renewal (day/month + cycle) + price ──
   Billing is recurring, not a one-off event, so the calendar YEAR of the
   renewal is irrelevant and is never stored: only the day-of-month (every
   type) and, for an annual bill, the month too. The next occurrence is
   recomputed from "today" on every read — nothing is ever a stale stored
   date that silently goes "more and more overdue" after it passes without
   the badge/reminder ever rolling forward to the next real due date. */
const BILLING_MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// Clamps day to the actual last day of that year/month (e.g. day 31 in
// February becomes the 28th/29th) rather than overflowing into the next month.
function clampBillingDate(year, monthIndex0, day) {
  const lastDay = new Date(year, monthIndex0 + 1, 0).getDate();
  return new Date(year, monthIndex0, Math.min(Math.max(day, 1), lastDay));
}

// Reads old-format entries (a stored full 'renewalDate') transparently, so
// vaults/backups from before this change keep working without a forced
// resave — the day/month is simply extracted from the stored date.
function normalizeBillingData(data) {
  if (data.day != null) return data;
  if (data.renewalDate) {
    const d = new Date(`${data.renewalDate}T00:00:00`);
    return { ...data, day: d.getDate(), month: d.getMonth() + 1 };
  }
  return { ...data, day: 1, month: 1 };
}

function nextBillingRenewal(rawData) {
  const data = normalizeBillingData(rawData);
  const day = Math.min(Math.max(parseInt(data.day, 10) || 1, 1), 31);
  const today = new Date(); today.setHours(0, 0, 0, 0);

  if (data.cycle === 'annually') {
    const month = Math.min(Math.max(parseInt(data.month, 10) || 1, 1), 12) - 1;
    let candidate = clampBillingDate(today.getFullYear(), month, day);
    if (candidate < today) candidate = clampBillingDate(today.getFullYear() + 1, month, day);
    return candidate;
  }

  // monthly — month is irrelevant, only the day-of-month matters
  let candidate = clampBillingDate(today.getFullYear(), today.getMonth(), day);
  if (candidate < today) {
    const nextMonth = today.getMonth() + 1;
    candidate = nextMonth > 11
      ? clampBillingDate(today.getFullYear() + 1, 0, day)
      : clampBillingDate(today.getFullYear(), nextMonth, day);
  }
  return candidate;
}

function billingStatus(data) {
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const days = Math.round((nextBillingRenewal(data) - today) / 86400000);
  const reminderDays = data.reminderDays ?? BILLING_REMINDER_DAYS_DEFAULT;
  if (days === 0) return { days, cls: 'billing-due', label: 'Due today' };
  if (days <= reminderDays) return { days, cls: 'billing-soon', label: `Renews in ${days}d` };
  return { days, cls: 'billing-ok', label: `Renews in ${days}d` };
}

function billingScheduleLabel(data) {
  const d = normalizeBillingData(data);
  const day = Math.min(Math.max(parseInt(d.day, 10) || 1, 1), 31);
  if (data.cycle === 'annually') {
    const month = Math.min(Math.max(parseInt(d.month, 10) || 1, 1), 12);
    return `Annually · ${day} ${BILLING_MONTH_NAMES[month - 1]}`;
  }
  return `Monthly · day ${day}`;
}

function billingPriceLabel(data) {
  if (data.price == null || data.price === '') return '';
  return `$${Number(data.price).toFixed(2)}/${data.cycle === 'annually' ? 'yr' : 'mo'}`;
}

// Scans every tab's billing entries and toasts a short summary of anything
// due within its own reminder window. Called once per unlock, not on every
// render, so it doesn't spam the toast stack. The next occurrence is always
// recomputed from today (see nextBillingRenewal), so this never gets stuck
// repeating a stale date — once a bill's day passes, the very next check
// already reports its next-cycle occurrence instead.
async function checkBillingReminders() {
  const all = await dbGetAll();
  const billingEntries = all.filter(e => e.type === 'billing');
  if (!billingEntries.length) return;
  const due = [];
  for (const e of billingEntries) {
    try {
      const data = JSON.parse(await aesDecrypt(e.encrypted));
      const { days } = billingStatus(data);
      const reminderDays = data.reminderDays ?? BILLING_REMINDER_DAYS_DEFAULT;
      if (days <= reminderDays) due.push({ name: e.name, days });
    } catch {}
  }
  if (!due.length) return;
  due.sort((a, b) => a.days - b.days);
  const fmt = d => d.days === 0 ? `${d.name} (today)` : `${d.name} (${d.days}d)`;
  const shown = due.slice(0, 4).map(fmt).join(', ');
  const more  = due.length > 4 ? ` +${due.length - 4} more` : '';
  toast(`⏰ Billing due soon: ${shown}${more}`, 'info');
}

/* ── Entry list (mixed types, scoped to curTabId — or, with
   searchAllTabs on and a non-empty query, spanning every tab) ───── */
async function renderEntryList() {
  if (!isUnlocked() || curTabId === 'security' || curTabId == null) return;
  const q        = ($('v-search')?.value || '').toLowerCase();
  const crossTab = searchAllTabs && !!q;
  const all      = await dbGetAll();
  const tabNameById = crossTab ? Object.fromEntries(TABS.map(t => [t.id, t.name])) : null;
  const rows = all
    .filter(e => (crossTab || e.tabId === curTabId) &&
      (!q || e.name.toLowerCase().includes(q) || (e.tag || '').toLowerCase().includes(q)))
    .sort((a, b) => (a.created || 0) - (b.created || 0));
  updateCounts(all);
  $('list-meta').textContent = rows.length
    ? `Displaying 1 – ${rows.length} of ${rows.length}${crossTab ? ' across all tabs' : ''}`
    : '';

  const c = $('list-container');
  if (!rows.length) {
    c.innerHTML = `<div class="empty-state">No secrets${crossTab ? ' match your search' : ' in this tab yet'}.</div>`;
    return;
  }

  const rendered = await Promise.all(rows.map(async e => {
    const tabName = crossTab ? tabNameById[e.tabId] : null;
    if (e.type === 'env') {
      let vars = {};
      try { vars = JSON.parse(await aesDecrypt(e.encrypted)); envCache.set(e.id, vars); } catch {}
      return renderEnvItemHTML(e, vars, tabName);
    }
    if (e.type === 'file') return renderFileItemHTML(e, tabName);
    if (e.type === 'billing') {
      let data = {};
      try { data = JSON.parse(await aesDecrypt(e.encrypted)); } catch {}
      return renderBillingItemHTML(e, data, tabName);
    }
    if (e.type === 'crypto') {
      let data = {};
      try { data = JSON.parse(await aesDecrypt(e.encrypted)); } catch {}
      return renderCryptoItemHTML(e, data, tabName);
    }
    return renderEntryItemHTML(e, tabName);
  }));
  c.innerHTML = rendered.join('');
  c.querySelectorAll('.env-file-input').forEach(inp => inp.addEventListener('change', handleEnvFileInput));
}

function renderEntryItemHTML(e, tabName) {
  const color = avatarColor(e.name);
  const initials = avatarInitials(e.name);
  return `
    <div class="entry-card" data-id="${e.id}">
      <div class="entry-card-top">
        <span class="avatar" style="background:${color}">${initials}</span>
        ${typeBadge(e.type)}
      </div>
      <span class="entry-card-name">${esc(e.name)}</span>
      <div class="entry-card-sub">${entrySubLine(e.tag, tabName)}</div>
      <div class="entry-card-actions">
        <button class="btn btn-view"  data-action="view"   data-id="${e.id}">View</button>
        <button class="btn btn-copy"  data-action="copy"   data-id="${e.id}">Copy</button>
        <button class="btn btn-edit"  data-action="edit"   data-id="${e.id}">Edit</button>
        <button class="btn btn-del"   data-action="delete" data-id="${e.id}" title="Delete">×</button>
      </div>
      <div class="secret-area" id="sec-${e.id}"></div>
      <div class="edit-area" id="edit-${e.id}" style="display:none">
        <textarea class="edit-textarea" id="edit-ta-${e.id}" spellcheck="false"></textarea>
        <div class="edit-actions">
          <button class="btn btn-primary" data-action="edit-save"   data-id="${e.id}">Save</button>
          <button class="btn btn-ghost"   data-action="edit-cancel" data-id="${e.id}">Cancel</button>
        </div>
      </div>
    </div>`;
}

function renderBillingItemHTML(e, data, tabName) {
  const color    = avatarColor(e.name);
  const initials = avatarInitials(e.name);
  const { cls, label } = billingStatus(data);
  const priceLabel    = billingPriceLabel(data);
  const scheduleLabel = billingScheduleLabel(data);
  const norm = normalizeBillingData(data);
  const showMonth = data.cycle === 'annually';
  return `
    <div class="entry-card" data-id="${e.id}">
      <div class="entry-card-top">
        <span class="avatar" style="background:${color}">${initials}</span>
        ${typeBadge('billing')}
      </div>
      <span class="entry-card-name">${esc(e.name)}</span>
      <div class="entry-card-sub">${entrySubLine(e.tag, tabName)}</div>
      <div class="billing-info-row">
        <span class="billing-badge ${cls}">${label}</span>
        ${priceLabel ? `<span class="billing-price">${priceLabel}</span>` : ''}
        <span class="billing-schedule">${scheduleLabel}</span>
      </div>
      <div class="entry-card-actions">
        <button class="btn btn-edit" data-action="billing-edit" data-id="${e.id}">Edit</button>
        <button class="btn btn-del"  data-action="delete" data-id="${e.id}" title="Delete">×</button>
      </div>
      <div class="edit-area" id="edit-${e.id}" style="display:none">
        <div class="input-group">
          <label for="edit-billing-cycle-${e.id}">Cycle</label>
          <select id="edit-billing-cycle-${e.id}">
            <option value="monthly"  ${data.cycle === 'monthly'  ? 'selected' : ''}>Monthly</option>
            <option value="annually" ${data.cycle === 'annually' ? 'selected' : ''}>Annually</option>
          </select>
        </div>
        <div class="two-col" style="margin-bottom:10px">
          <div class="input-group" style="margin-bottom:0">
            <label for="edit-billing-day-${e.id}">Renews on (day)</label>
            <input type="number" min="1" max="31" id="edit-billing-day-${e.id}" value="${norm.day}">
          </div>
          <div class="input-group" id="edit-billing-month-wrap-${e.id}" style="margin-bottom:0;display:${showMonth ? '' : 'none'}">
            <label for="edit-billing-month-${e.id}">Month</label>
            <select id="edit-billing-month-${e.id}">
              ${BILLING_MONTH_NAMES.map((m, i) => `<option value="${i + 1}" ${norm.month === i + 1 ? 'selected' : ''}>${m}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="two-col" style="margin-bottom:10px">
          <div class="input-group" style="margin-bottom:0">
            <label for="edit-billing-price-${e.id}">Price</label>
            <input type="number" min="0" step="0.01" id="edit-billing-price-${e.id}" placeholder="0.00">
          </div>
          <div class="input-group" style="margin-bottom:0">
            <label for="edit-billing-reminder-${e.id}">Remind (days before)</label>
            <input type="number" min="0" step="1" id="edit-billing-reminder-${e.id}">
          </div>
        </div>
        <div class="edit-actions">
          <button class="btn btn-primary" data-action="billing-edit-save"   data-id="${e.id}">Save</button>
          <button class="btn btn-ghost"   data-action="billing-edit-cancel" data-id="${e.id}">Cancel</button>
        </div>
      </div>
    </div>`;
}

function renderCryptoItemHTML(e, data, tabName) {
  const color    = avatarColor(e.name);
  const initials = avatarInitials(e.name);
  const coin      = CRYPTO_COINS[data.coin];
  const coinLabel = coin?.label || data.coin || '?';
  const addr      = data.address || '';
  const shortAddr = addr.length > 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;
  const hasMemo   = !!(coin?.memoField);
  return `
    <div class="entry-card" data-id="${e.id}">
      <div class="entry-card-top">
        <span class="avatar" style="background:${color}">${initials}</span>
        ${typeBadge('crypto')}
      </div>
      <span class="entry-card-name">${esc(e.name)}</span>
      <div class="entry-card-sub">${entrySubLine(`${coinLabel} · ${shortAddr}`, tabName)}</div>
      <div class="entry-card-actions">
        <button class="btn btn-view"  data-action="view"        data-id="${e.id}">View</button>
        <button class="btn btn-copy"  data-action="copy"        data-id="${e.id}">Copy</button>
        <button class="btn btn-edit"  data-action="crypto-edit" data-id="${e.id}">Edit</button>
        <button class="btn btn-del"   data-action="delete"      data-id="${e.id}" title="Delete">×</button>
      </div>
      <div class="secret-area" id="sec-${e.id}"></div>
      <div class="edit-area" id="edit-${e.id}" style="display:none">
        <div class="two-col" style="margin-bottom:10px">
          <div class="input-group" style="margin-bottom:0">
            <label for="edit-crypto-coin-${e.id}">Cryptocurrency</label>
            <select id="edit-crypto-coin-${e.id}">${cryptoCoinOptionsHTML(data.coin)}</select>
          </div>
          <div class="input-group" id="edit-crypto-memo-wrap-${e.id}" style="margin-bottom:0;display:${hasMemo ? '' : 'none'}">
            <label for="edit-crypto-memo-${e.id}" id="edit-crypto-memo-label-${e.id}">${esc(coin?.memoField?.label || 'Memo')}</label>
            <input type="text" id="edit-crypto-memo-${e.id}" value="${esc(data.memo || '')}" autocomplete="off">
          </div>
        </div>
        <div class="input-group">
          <label for="edit-crypto-address-${e.id}">Wallet address</label>
          <input type="text" id="edit-crypto-address-${e.id}" value="${esc(addr)}" autocomplete="off" spellcheck="false">
        </div>
        <div class="edit-actions">
          <button class="btn btn-primary" data-action="crypto-edit-save"   data-id="${e.id}">Save</button>
          <button class="btn btn-ghost"   data-action="crypto-edit-cancel" data-id="${e.id}">Cancel</button>
        </div>
      </div>
    </div>`;
}

function renderFileItemHTML(e, tabName) {
  const color    = avatarColor(e.name);
  const initials = avatarInitials(e.name);
  const isImage  = (e.mimeType || '').startsWith('image/');
  return `
    <div class="entry-card" data-id="${e.id}">
      <div class="entry-card-top">
        <span class="avatar" style="background:${color}">${initials}</span>
        ${typeBadge('file')}
      </div>
      <span class="entry-card-name">${esc(e.name)}</span>
      <div class="entry-card-sub">${esc(e.fileName || '')}${e.size != null ? ' · ' + formatBytes(e.size) : ''}${tabName ? ` · ${esc(tabName)}` : ''}</div>
      <div class="entry-card-actions">
        ${isImage ? `<button class="btn btn-view" data-action="file-preview" data-id="${e.id}">Preview</button>` : ''}
        <button class="btn btn-copy" data-action="file-download" data-id="${e.id}">Download</button>
        <button class="btn btn-del"  data-action="delete" data-id="${e.id}" title="Delete">×</button>
      </div>
      ${isImage ? `<div class="secret-area" id="prev-${e.id}"></div>` : ''}
    </div>`;
}

function renderEnvItemHTML(e, vars, tabName) {
  const keys    = Object.keys(vars);
  const count   = keys.length;
  const preview = keys.slice(0, 3).join(', ') + (keys.length > 3 ? '…' : '');
  const color = avatarColor(e.name);
  const initials = avatarInitials(e.name);
  return `
    <div class="env-item" data-id="${e.id}">
      <div class="env-info-row">
        <span class="avatar avatar-sm" style="background:${color}">${initials}</span>
        ${typeBadge('env')}
        <span class="env-name">${esc(e.name)}</span>
        ${e.tag ? `<span class="entry-tag">${esc(e.tag)}</span>` : ''}
        ${tabName ? `<span class="entry-tag">${esc(tabName)}</span>` : ''}
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
              placeholder="value" autocomplete="off" data-lpignore="true" data-1p-ignore="true" data-bwignore="true">
            <button class="toggle-btn" data-target="eval-${e.id}" aria-label="Toggle">👁</button>
          </div>
          <button class="btn btn-primary" data-action="var-add" data-id="${e.id}"
            style="padding:9px 14px;white-space:nowrap;width:auto">+ Add</button>
        </div>
      </div>
    </div>`;
}

function renderVarTable(envId, vars) {
  const entries = Object.entries(vars);
  if (!entries.length)
    return `<div class="env-empty">No variables yet — add one below or import a .env file.</div>`;
  // Note: values are deliberately NOT embedded in this markup — not even
  // inside a display:none element — so nothing plaintext sits in the DOM
  // until the user explicitly clicks View or Edit on that specific row.
  return `<table class="env-table">
    <thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>
    <tbody>${entries.map(([k, v]) => `
      <tr data-key="${esc(k)}">
        <td>${esc(k)}</td>
        <td>
          <span class="env-val-masked">••••••••</span>
          <span class="env-val-plain" style="display:none"></span>
        </td>
        <td>
          <button class="btn btn-view" data-action="var-toggle"
            style="font-size:.72rem;padding:3px 8px">View</button>
          <button class="btn btn-copy" data-action="var-copy"
            data-env-id="${envId}" data-key="${esc(k)}"
            style="font-size:.72rem;padding:3px 8px">Copy</button>
          <button class="btn btn-edit" data-action="var-edit"
            data-env-id="${envId}" data-key="${esc(k)}"
            style="font-size:.72rem;padding:3px 8px">Edit</button>
          <button class="btn btn-del" data-action="var-delete"
            data-env-id="${envId}" data-key="${esc(k)}">×</button>
        </td>
      </tr>
      <tr class="var-edit-row" style="display:none">
        <td colspan="3">
          <div class="var-edit-area">
            <div class="input-with-toggle" style="flex:1;position:relative">
              <input type="password" class="var-edit-input"
                autocomplete="off" spellcheck="false"
                data-lpignore="true" data-1p-ignore="true" data-bwignore="true">
              <button class="toggle-btn" data-target-class="var-edit-input"
                aria-label="Toggle visibility">👁</button>
            </div>
            <button class="btn btn-primary" data-action="var-edit-save"
              data-env-id="${envId}" data-key="${esc(k)}"
              style="white-space:nowrap;width:auto;padding:8px 14px">Save</button>
            <button class="btn btn-ghost" data-action="var-edit-cancel"
              style="width:auto;padding:8px 14px">Cancel</button>
          </div>
        </td>
      </tr>`).join('')}
    </tbody>
  </table>`;
}

/* ── Entry actions (delegated — passwords/keys/certs) ─ */
async function handleEntryAction(e) {
  if (!isUnlocked()) return;
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  resetLock();
  const id     = parseInt(btn.dataset.id, 10);
  const action = btn.dataset.action;

  if (action === 'view') {
    const area = $(`sec-${id}`);
    if (!area) return;
    const open = area.classList.contains('active');
    if (!open) {
      const all   = await dbGetAll();
      const entry = all.find(e => e.id === id);
      if (entry.type === 'crypto') {
        const data = JSON.parse(await aesDecrypt(entry.encrypted));
        const memoField = CRYPTO_COINS[data.coin]?.memoField;
        const lines = [`Address: ${data.address}`];
        if (memoField && data.memo) lines.push(`${memoField.label.replace(' (optional)', '')}: ${data.memo}`);
        area.textContent = lines.join('\n');
      } else {
        area.textContent = await aesDecrypt(entry.encrypted);
      }
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
    if (!entry || entry.type === 'env') return;
    // Copy just the address for crypto entries — the memo/tag (when present)
    // is a separate field a receiver needs on top of it, not part of it.
    const secret = entry.type === 'crypto'
      ? JSON.parse(await aesDecrypt(entry.encrypted)).address
      : await aesDecrypt(entry.encrypted);
    await copyToClipboard(secret);
    btn.textContent = '✓ Copied';
    btn.classList.add('btn-copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('btn-copied'); }, 1500);
  }

  if (action === 'edit') {
    const editArea = $(`edit-${id}`);
    if (!editArea) return;
    const already  = editArea.style.display !== 'none';
    if (already) { editArea.style.display = 'none'; return; }
    // Close any other open edit areas
    document.querySelectorAll('.edit-area').forEach(el => el.style.display = 'none');
    // Collapse view area if open
    const secArea = $(`sec-${id}`);
    if (secArea && secArea.classList.contains('active')) {
      secArea.textContent = '';
      secArea.classList.remove('active');
      const viewBtn = document.querySelector(`[data-action="view"][data-id="${id}"]`);
      if (viewBtn) viewBtn.classList.remove('btn-view-active');
    }
    const all   = await dbGetAll();
    const entry = all.find(e => e.id === id);
    const plain = await aesDecrypt(entry.encrypted);
    const ta    = $(`edit-ta-${id}`);
    ta.value    = plain;
    editArea.style.display = '';
    ta.focus();
  }

  if (action === 'edit-save') {
    const ta      = $(`edit-ta-${id}`);
    const newVal  = ta.value;
    if (!newVal.trim()) { toast('Content cannot be empty', 'err'); return; }
    const saveBtn = document.querySelector(`[data-action="edit-save"][data-id="${id}"]`);
    saveBtn.disabled = true; saveBtn.textContent = 'Saving…';
    try {
      const all   = await dbGetAll();
      const entry = all.find(e => e.id === id);
      entry.encrypted = await aesEncrypt(newVal);
      entry.updated   = Date.now();
      await dbPut(entry);
      $(`edit-${id}`).style.display = 'none';
      ta.value = ''; // scrub plaintext out of the hidden textarea
      markUnsaved();
      toast('Entry updated', 'ok');
    } catch (err) {
      toast('Save failed: ' + err.message, 'err');
    } finally {
      saveBtn.disabled = false; saveBtn.textContent = 'Save';
    }
  }

  if (action === 'edit-cancel') {
    $(`edit-ta-${id}`).value = ''; // scrub plaintext out of the hidden textarea
    $(`edit-${id}`).style.display = 'none';
  }

  if (action === 'billing-edit') {
    const editArea = $(`edit-${id}`);
    if (!editArea) return;
    const already = editArea.style.display !== 'none';
    if (already) { editArea.style.display = 'none'; return; }
    document.querySelectorAll('.edit-area').forEach(el => el.style.display = 'none');
    const all   = await dbGetAll();
    const entry = all.find(e => e.id === id);
    const data  = normalizeBillingData(JSON.parse(await aesDecrypt(entry.encrypted)));
    const cycleSel  = $(`edit-billing-cycle-${id}`);
    const monthWrap = $(`edit-billing-month-wrap-${id}`);
    cycleSel.value = data.cycle || 'monthly';
    $(`edit-billing-day-${id}`).value      = data.day;
    $(`edit-billing-month-${id}`).value    = data.month;
    $(`edit-billing-price-${id}`).value    = data.price ?? '';
    $(`edit-billing-reminder-${id}`).value = data.reminderDays ?? BILLING_REMINDER_DAYS_DEFAULT;
    monthWrap.style.display = cycleSel.value === 'annually' ? '' : 'none';
    cycleSel.onchange = () => { monthWrap.style.display = cycleSel.value === 'annually' ? '' : 'none'; };
    editArea.style.display = '';
  }

  if (action === 'billing-edit-save') {
    const cycle = $(`edit-billing-cycle-${id}`).value;
    const day   = parseInt($(`edit-billing-day-${id}`).value, 10);
    if (!Number.isFinite(day) || day < 1 || day > 31) { toast('Day must be between 1 and 31', 'err'); return; }
    const month = cycle === 'annually' ? parseInt($(`edit-billing-month-${id}`).value, 10) : null;
    const price        = parseFloat($(`edit-billing-price-${id}`).value) || 0;
    const reminderDays = parseInt($(`edit-billing-reminder-${id}`).value, 10);
    const saveBtn = document.querySelector(`[data-action="billing-edit-save"][data-id="${id}"]`);
    saveBtn.disabled = true; saveBtn.textContent = 'Saving…';
    try {
      const all   = await dbGetAll();
      const entry = all.find(e => e.id === id);
      entry.encrypted = await aesEncrypt(JSON.stringify({
        day, month, cycle, price,
        reminderDays: Number.isFinite(reminderDays) ? reminderDays : BILLING_REMINDER_DAYS_DEFAULT,
      }));
      entry.updated = Date.now();
      await dbPut(entry);
      markUnsaved();
      toast('Billing entry updated', 'ok');
      await renderEntryList();
    } catch (err) {
      toast('Save failed: ' + err.message, 'err');
      saveBtn.disabled = false; saveBtn.textContent = 'Save';
    }
  }

  if (action === 'billing-edit-cancel') {
    $(`edit-${id}`).style.display = 'none';
  }

  if (action === 'crypto-edit') {
    const editArea = $(`edit-${id}`);
    if (!editArea) return;
    const already = editArea.style.display !== 'none';
    if (already) { editArea.style.display = 'none'; return; }
    document.querySelectorAll('.edit-area').forEach(el => el.style.display = 'none');
    const all   = await dbGetAll();
    const entry = all.find(e => e.id === id);
    const data  = JSON.parse(await aesDecrypt(entry.encrypted));
    const coinSel  = $(`edit-crypto-coin-${id}`);
    const memoWrap = $(`edit-crypto-memo-wrap-${id}`);
    const memoLbl  = $(`edit-crypto-memo-label-${id}`);
    coinSel.value = data.coin;
    $(`edit-crypto-address-${id}`).value = data.address || '';
    $(`edit-crypto-memo-${id}`).value    = data.memo || '';
    updateCryptoMemoField(data.coin, memoWrap, memoLbl);
    coinSel.onchange = () => updateCryptoMemoField(coinSel.value, memoWrap, memoLbl);
    editArea.style.display = '';
  }

  if (action === 'crypto-edit-save') {
    const coin    = $(`edit-crypto-coin-${id}`).value;
    const address = $(`edit-crypto-address-${id}`).value.trim();
    const addrErr = validateCryptoAddress(coin, address);
    if (addrErr) { toast(addrErr, 'err'); return; }
    const memoField = CRYPTO_COINS[coin].memoField;
    const memo = memoField ? $(`edit-crypto-memo-${id}`).value.trim() : '';
    if (memoField && !memoField.validate(memo)) {
      toast(`Invalid ${memoField.label.replace(' (optional)', '')}`, 'err');
      return;
    }
    const saveBtn = document.querySelector(`[data-action="crypto-edit-save"][data-id="${id}"]`);
    saveBtn.disabled = true; saveBtn.textContent = 'Saving…';
    try {
      const all   = await dbGetAll();
      const entry = all.find(e => e.id === id);
      entry.encrypted = await aesEncrypt(JSON.stringify({ coin, address, memo }));
      entry.updated = Date.now();
      await dbPut(entry);
      markUnsaved();
      toast('Crypto entry updated', 'ok');
      await renderEntryList();
    } catch (err) {
      toast('Save failed: ' + err.message, 'err');
      saveBtn.disabled = false; saveBtn.textContent = 'Save';
    }
  }

  if (action === 'crypto-edit-cancel') {
    $(`edit-${id}`).style.display = 'none';
  }

  if (action === 'delete') {
    if (!confirm('Delete this entry?')) return;
    await dbDel(id);
    markUnsaved();
    await renderEntryList();
    await updateTabCounts();
  }

  if (action === 'file-download') {
    const all   = await dbGetAll();
    const entry = all.find(x => x.id === id);
    if (!entry || entry.type !== 'file') return;
    try {
      const buf  = await aesDecryptBytes(entry.encrypted);
      const blob = new Blob([buf], { type: entry.mimeType || 'application/octet-stream' });
      const a    = document.createElement('a');
      a.href     = URL.createObjectURL(blob);
      a.download = entry.fileName || entry.name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 100);
    } catch (err) {
      toast('Decrypt failed: ' + err.message, 'err');
    }
  }

  if (action === 'file-preview') {
    const area = $(`prev-${id}`);
    if (!area) return;
    const open = area.classList.contains('active');
    if (open) {
      area.innerHTML = ''; // scrub the data: URI out of the DOM, not just hide it
      area.classList.remove('active');
      btn.textContent = 'Preview';
      return;
    }
    try {
      const all   = await dbGetAll();
      const entry = all.find(x => x.id === id);
      const buf   = await aesDecryptBytes(entry.encrypted);
      // data: URI (not blob:) — stays inside the existing CSP's img-src
      // 'self' data: with no policy change needed.
      const dataUrl = `data:${entry.mimeType || 'application/octet-stream'};base64,${b64e(buf)}`;
      area.innerHTML = `<img src="${dataUrl}" alt="${esc(entry.name)}" style="max-width:100%;border-radius:var(--radius);display:block">`;
      area.classList.add('active');
      btn.textContent = 'Hide';
    } catch (err) {
      toast('Decrypt failed: ' + err.message, 'err');
    }
  }
}

/* ── Env actions (delegated — env entries) ──────────── */
async function handleEnvAction(e) {
  if (!isUnlocked()) return;
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const envActions = ['env-toggle','env-import','env-export','env-delete','var-toggle','var-edit',
    'var-edit-save','var-edit-cancel','var-copy','var-delete','var-add'];
  if (!envActions.includes(action)) return;
  resetLock();
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
    await renderEntryList();
    await updateTabCounts();
    return;
  }
  if (action === 'var-toggle') {
    const row    = btn.closest('tr');
    const key    = row.dataset.key;
    const masked = row.querySelector('.env-val-masked');
    const plain  = row.querySelector('.env-val-plain');
    const show   = plain.style.display !== 'none';
    if (show) {
      // Hiding again — scrub the plaintext back out of the DOM, don't just visually mask it
      plain.textContent = '';
      plain.style.display  = 'none';
      masked.style.display = '';
      btn.textContent = 'View';
    } else {
      const vars = await getEnvVars(envId);
      plain.textContent = vars[key] ?? '';
      plain.style.display  = '';
      masked.style.display = 'none';
      btn.textContent = 'Hide';
    }
    return;
  }
  if (action === 'var-edit') {
    const varRow  = btn.closest('tr');
    const key     = varRow.dataset.key;
    const editRow = varRow.nextElementSibling;
    const input   = editRow.querySelector('.var-edit-input');
    const already = editRow.style.display !== 'none';
    // Close all other open edit rows in this table first, scrubbing their staged plaintext
    btn.closest('table').querySelectorAll('.var-edit-row').forEach(r => {
      r.style.display = 'none';
      const i = r.querySelector('.var-edit-input');
      if (i) i.value = '';
    });
    if (already) return;
    const vars = await getEnvVars(envId);
    input.value = vars[key] ?? '';
    editRow.style.display = '';
    input.focus();
    return;
  }
  if (action === 'var-edit-save') {
    const key    = btn.dataset.key;
    const input  = btn.closest('.var-edit-area').querySelector('.var-edit-input');
    const newVal = input.value;
    btn.disabled = true; btn.textContent = 'Saving…';
    try {
      const vars = await getEnvVars(envId);
      vars[key]  = newVal;
      await saveEnvVars(envId, vars);
      input.value = ''; // scrub before the re-render below even lands
      markUnsaved();
      toast(`${key} updated`, 'ok');
      await renderEntryList();
      reopenBody(envId);
    } catch (err) {
      toast('Save failed: ' + err.message, 'err');
      btn.disabled = false; btn.textContent = 'Save';
    }
    return;
  }
  if (action === 'var-edit-cancel') {
    const editRow = btn.closest('.var-edit-row');
    editRow.querySelector('.var-edit-input').value = ''; // scrub staged plaintext
    editRow.style.display = 'none';
    return;
  }
  if (action === 'var-copy') {
    const key  = btn.dataset.key;
    const vars = await getEnvVars(envId);
    const val = vars[key] ?? '';
    await copyToClipboard(val);
    btn.textContent = '✓';
    btn.classList.add('btn-copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('btn-copied'); }, 1500);
    return;
  }
  if (action === 'var-delete') {
    const key = btn.dataset.key;
    if (!confirm(`Delete "${key}"?`)) return;
    const vars = await getEnvVars(envId);
    delete vars[key];
    await saveEnvVars(envId, vars);
    markUnsaved();
    await renderEntryList();
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
    await renderEntryList();
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
  await renderEntryList();
  reopenBody(envId);
}

function reopenBody(envId) {
  const body = $(`env-body-${envId}`);
  const btn  = document.querySelector(`[data-action="env-toggle"][data-id="${envId}"]`);
  if (body) body.style.display = '';
  if (btn)  btn.textContent = '▲';
}

/* ── New-env import staging (used while adding an entry) ─ */
function updateNewEnvFileLabel() {
  const lbl   = $('new-env-file-label');
  if (!lbl) return;
  const count = newEnvVars ? Object.keys(newEnvVars).length : 0;
  lbl.textContent = count
    ? `✓ ${count} variable${count !== 1 ? 's' : ''} ready to import`
    : 'Click or drop a .env file to pre-populate (optional)';
  lbl.style.color = count ? 'var(--green)' : '';
}

/* ── Clipboard ──────────────────────────────────────── */
// Copies a secret and schedules an auto-clear in 30s (only clearing if the
// clipboard still holds exactly what we put there, so we don't stomp on
// something else the user copied in the meantime). Tracks the pending
// clear so lockVault() can fire it early instead of leaving the secret
// sitting in the clipboard until the 30s timer catches up.
async function copyToClipboard(value) {
  if (lastCopied?.timer) clearTimeout(lastCopied.timer);
  await navigator.clipboard.writeText(value);
  const timer = setTimeout(() => clearClipboardIfOurs(value), 30000);
  lastCopied = { value, timer };
}

function clearClipboardIfOurs(value) {
  navigator.clipboard.readText()
    .then(t => { if (t === value) return navigator.clipboard.writeText(''); })
    .catch(() => {});
  if (lastCopied?.value === value) lastCopied = null;
}

function clearClipboardNow() {
  if (!lastCopied) return;
  if (lastCopied.timer) clearTimeout(lastCopied.timer);
  clearClipboardIfOurs(lastCopied.value);
  lastCopied = null;
}

/* ── Misc UI ────────────────────────────────────────── */
function markUnsaved() { $('sync-banner').style.display = 'flex'; }

// Mirrors: echo "${APP}-${VERSION}-$(date -u +%Y%m%dT%H%MZ)"
function backupFileStamp() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  const ts = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}Z`;
  return `${APP}-${VERSION}-${ts}`;
}

async function exportBackup() {
  const all  = await dbGetAll();
  const tabs = await tabGetAll();
  const data = {
    version: VERSION, kdf: CUR_KDF, salt: b64e(SALT),
    iterations: CUR_KDF === KDF_PBKDF2 ? CUR_ITER : undefined,
    entries: all, tabs, ts: Date.now(),
  };
  const a   = document.createElement('a');
  a.href    = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type:'application/json' }));
  a.download = `${backupFileStamp()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 100);
  lastSyncTime = new Date();
  updateSidebarMeta();
  $('sync-banner').style.display = 'none';
}

// Re-derives a key from a candidate password against the CURRENT unlocked
// vault's salt/KDF/iterations and checks it actually opens an existing
// entry. Used to re-confirm the master key before a sensitive action
// (backup download) rather than trusting that the tab is still attended.
async function verifyMasterKey(pass) {
  try {
    const k = await deriveKey(pass, SALT, CUR_KDF, CUR_ITER);
    const entries = await dbGetAll();
    if (!entries.length) return true; // nothing to verify against — same as unlock's own edge case
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(entries[0].encrypted.iv) }, k, b64d(entries[0].encrypted.ct)
    );
    return true;
  } catch {
    return false;
  }
}

/* ── Export confirmation overlay — re-verify master key first ──────── */
function openExportConfirm() {
  if (!isUnlocked()) return;
  $('export-confirm-key').value = '';
  $('export-confirm-overlay').style.display = 'flex';
  $('export-confirm-key').focus();
  if (cooldownRemaining('export') > 0) applyCooldownUI('export', $('export-confirm-btn'), 'Confirm & download');
}

function closeExportConfirm() {
  $('export-confirm-key').value = ''; // scrub whatever was typed
  $('export-confirm-overlay').style.display = 'none';
}

async function confirmExport() {
  const pass = $('export-confirm-key').value;
  if (!pass) { toast('Enter your master key', 'err'); return; }
  const rem = cooldownRemaining('export');
  if (rem > 0) { toast(`Too many attempts — wait ${Math.ceil(rem / 1000)}s`, 'err'); return; }
  const btn = $('export-confirm-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';
  const ok = await verifyMasterKey(pass);
  btn.disabled = false; btn.textContent = 'Confirm & download';
  if (!ok) {
    registerFailedAttempt('export');
    toast('Incorrect master key', 'err');
    return;
  }
  registerSuccess('export');
  closeExportConfirm();
  await exportBackup();
}

/* ── Generator modal UI ──────────────────────────────── */
let genLastEnvLine = null;

function wireButtonGroup(containerId, onChange) {
  const container = $(containerId);
  if (!container) return;
  container.addEventListener('click', e => {
    const btn = e.target.closest('.type-btn');
    if (!btn || !container.contains(btn)) return;
    container.querySelectorAll('.type-btn').forEach(b => b.classList.toggle('active', b === btn));
    onChange?.();
  });
}

function groupValue(containerId, fallback) {
  return $(containerId)?.querySelector('.type-btn.active')?.dataset.val ?? fallback;
}

function resetGenOutput() {
  $('gen-output').value = '';
  $('gen-output-pub').value = '';
  $('gen-copy-btn').disabled = true;
  $('gen-copy-pub-btn').disabled = true;
  $('gen-copy-env-btn').disabled = true;
  genLastEnvLine = null;
}

function updateOpensslPreview() {
  const size = parseInt(groupValue('gen-enc-size', '32'), 10);
  const encoding = groupValue('gen-enc-encoding', 'hex');
  $('gen-enc-cmd').textContent = genOpensslPreview(size, encoding);
}

function openGenerator() {
  $('generator-overlay').style.display = 'flex';
  resetGenOutput();
}

function closeGenerator() {
  $('generator-overlay').style.display = 'none';
  resetGenOutput(); // scrub any generated secret sitting in the output box
}

function switchGenType(genType) {
  document.querySelectorAll('#gen-type-select .type-btn').forEach(b => b.classList.toggle('active', b.dataset.genType === genType));
  document.querySelectorAll('.gen-opts').forEach(el => el.style.display = 'none');
  $(`gen-opts-${genType}`).style.display = '';
  $('gen-output2-wrap').style.display = genType === 'rsa' ? '' : 'none';
  $('gen-copy-env-btn').style.display = genType === 'enc' ? '' : 'none';
  resetGenOutput();
}

async function runGenerate() {
  const genType = document.querySelector('#gen-type-select .type-btn.active')?.dataset.genType || 'password';
  const btn = $('gen-generate-btn');
  btn.disabled = true; btn.textContent = 'Generating…';
  try {
    let output = '', outputPub = null;
    if (genType === 'password') {
      const subtype    = groupValue('gen-pw-type', 'passphrase');
      const complexity = groupValue('gen-pw-complexity', 'simple');
      if (subtype === 'passphrase') {
        output = genPassphrase(complexity, groupValue('gen-pw-separator', 'space'), groupValue('gen-pw-digit', 'none'));
      } else if (subtype === 'chars') {
        output = genRandomString(genCharsetFor(complexity), GEN_PW_CHARLEN[complexity]);
      } else if (subtype === 'pin') {
        output = genRandomString(GEN_CHARSET_DIGITS, GEN_PW_PINLEN[complexity]);
      } else { // hex
        output = genHex(rnd(GEN_PW_HEXBYTES[complexity]));
      }
    } else if (genType === 'jwt') {
      const len = parseInt($('gen-jwt-length').value, 10);
      output = genHex(rnd(Math.ceil(len / 2))).slice(0, len);
    } else if (genType === 'apikey') {
      const format = $('gen-apikey-format').value;
      const len = parseInt($('gen-apikey-length').value, 10);
      if (format === 'hex') output = genHex(rnd(Math.ceil(len / 2))).slice(0, len);
      else if (format === 'base64url') { while (output.length < len) output += genBase64Url(rnd(32)); output = output.slice(0, len); }
      else output = genRandomString(GEN_CHARSET_LOWER + GEN_CHARSET_UPPER + GEN_CHARSET_DIGITS, len);
    } else if (genType === 'hmac') {
      output = genEncodedBytes(parseInt($('gen-hmac-size').value, 10), $('gen-hmac-encoding').value);
    } else if (genType === 'enc') {
      const size = parseInt(groupValue('gen-enc-size', '32'), 10);
      output = genEncodedBytes(size, groupValue('gen-enc-encoding', 'hex'));
      genLastEnvLine = `ENCRYPTION_KEY=${output}`;
    } else if (genType === 'rsa') {
      const pair = await genRsaKeyPair(parseInt($('gen-rsa-size').value, 10));
      output = pair.privatePem;
      outputPub = pair.publicPem;
    }
    $('gen-output').value = output;
    $('gen-copy-btn').disabled = !output;
    if (genType === 'rsa') { $('gen-output-pub').value = outputPub; $('gen-copy-pub-btn').disabled = !outputPub; }
    if (genType === 'enc') $('gen-copy-env-btn').disabled = !genLastEnvLine;
  } catch (err) {
    toast('Generate failed: ' + err.message, 'err');
  } finally {
    btn.disabled = false; btn.textContent = 'Generate';
  }
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
    const nk  = await deriveKeyPbkdf2(np, ns); // uses PBKDF2_ITERATIONS_CURRENT
    const re  = await reEncryptAll(entries, CK, nk);
    await dbClear();
    for (const e of re) { const { id, ...rest } = e; await dbAdd(rest); }
    CK = nk; SALT = ns; CUR_KDF = KDF_PBKDF2; CUR_ITER = PBKDF2_ITERATIONS_CURRENT;
    await metaPut('salt', b64e(ns));
    await metaPut('kdf',  KDF_PBKDF2);
    await metaPut('iterations', PBKDF2_ITERATIONS_CURRENT);
    envCache.clear();
    $('change-pass-new').value = ''; $('change-pass-confirm').value = '';
    markUnsaved();
    broadcastLock(); // any other open tab is now holding a stale key — force it to relock
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
  broadcastLock(); // other tabs must not keep operating on data that's about to be gone
  await dbClear(); await metaClr(); await tabsClear();
  CK = null; SALT = null; CUR_KDF = KDF_PBKDF2; envCache.clear(); stopLock();
  clearClipboardNow();
  curTabId = null; TABS = [];
  $('sidebar-tab-nav').innerHTML = '';
  $('sidebar-nav-wrap').classList.add('locked-hidden');
  $('sidebar-nav-divider').classList.add('locked-hidden');
  $('list-container').innerHTML = '';
  $('v-search').value = '';
  toggleAddPanel(false);
  resetAddForm();
  $('change-pass-new').value = '';
  $('change-pass-confirm').value = '';
  closeExportConfirm(); // scrub any master key staged there and hide the overlay
  closeGenerator();     // scrub any generated secret sitting in the output box
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
  await loadAttemptState();
  TAB_SORT_MODE = (await metaGet('tabSortMode')) || 'alpha';
  if (cooldownRemaining('unlock')  > 0) applyCooldownUI('unlock',  $('unlock-btn'),  'Unlock vault');
  if (cooldownRemaining('restore') > 0) applyCooldownUI('restore', $('restore-btn'), 'Restore & decrypt');

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
      CK = await deriveKeyPbkdf2(key, s); // uses PBKDF2_ITERATIONS_CURRENT
      SALT = s;
      CUR_KDF = KDF_PBKDF2;
      CUR_ITER = PBKDF2_ITERATIONS_CURRENT;
      await metaPut('salt', b64e(s));
      await metaPut('kdf',  KDF_PBKDF2);
      await metaPut('iterations', PBKDF2_ITERATIONS_CURRENT);
      $('new-key').value = ''; $('new-confirm').value = '';
      await unlockUI();
    } catch (err) { toast('Failed: ' + err.message, 'err'); }
    finally { btn.disabled = false; btn.textContent = 'Initialize encrypted storage'; }
  });

  /* Unlock — detect KDF, auto-migrate Argon2 vaults in background */
  $('unlock-btn').addEventListener('click', async () => {
    const key = $('unlock-key').value;
    if (!key) { toast('Enter your master key', 'err'); return; }
    const btn = $('unlock-btn');
    const rem = cooldownRemaining('unlock');
    if (rem > 0) { toast(`Too many attempts — wait ${Math.ceil(rem / 1000)}s`, 'err'); return; }
    btn.disabled = true; btn.textContent = 'Unlocking…';
    let failed = false;
    try {
      const saltStr = await metaGet('salt');
      if (!saltStr) throw new Error('No vault found');
      // No kdf in meta → old vault → Argon2id
      const kdf  = (await metaGet('kdf')) || KDF_ARGON2;
      // No stored iteration count → vault predates that field → it was
      // derived at the legacy iteration count.
      const iter = kdf === KDF_PBKDF2 ? ((await metaGet('iterations')) || PBKDF2_ITERATIONS_LEGACY) : undefined;
      const s    = b64d(saltStr);
      if (kdf === KDF_ARGON2) btn.textContent = 'Loading Argon2…';
      const k = await deriveKey(key, s, kdf, iter);
      // Verify against first entry
      const entries = await dbGetAll();
      if (entries.length) {
        await crypto.subtle.decrypt(
          { name:'AES-GCM', iv: b64d(entries[0].encrypted.iv) }, k, b64d(entries[0].encrypted.ct)
        );
      }
      CK = k; SALT = s; CUR_KDF = kdf; CUR_ITER = iter ?? PBKDF2_ITERATIONS_CURRENT;
      registerSuccess('unlock');
      await unlockUI();
      // Background-upgrade weak KDF params — migrateToPbkdf2 re-encrypts
      // under PBKDF2_ITERATIONS_CURRENT and updates CUR_KDF/CUR_ITER when done.
      if (kdf === KDF_ARGON2 || CUR_ITER < PBKDF2_ITERATIONS_CURRENT) migrateToPbkdf2(key);
    } catch (err) {
      failed = true;
      const msg = err.message?.includes('Argon2') || err.message?.includes('argon2')
        ? err.message : 'Incorrect master key';
      toast(msg, 'err');
    } finally { btn.disabled = false; btn.textContent = 'Unlock vault'; $('unlock-key').value = ''; }
    if (failed) {
      registerFailedAttempt('unlock');
      applyCooldownUI('unlock', btn, 'Unlock vault');
    }
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
    const rem = cooldownRemaining('restore');
    if (rem > 0) { toast(`Too many attempts — wait ${Math.ceil(rem / 1000)}s`, 'err'); return; }
    btn.disabled = true; btn.textContent = 'Restoring…';
    let failed = false;
    try {
      // No kdf field in backup → old backup → Argon2id
      const backupKdf = pendingBackup.kdf || KDF_ARGON2;
      // No iterations field → backup predates it → it was encrypted at the
      // legacy iteration count.
      const backupIter = backupKdf === KDF_PBKDF2 ? (pendingBackup.iterations || PBKDF2_ITERATIONS_LEGACY) : undefined;
      const s = b64d(pendingBackup.salt);
      if (backupKdf === KDF_ARGON2) btn.textContent = 'Loading Argon2…';
      const k = await deriveKey(key, s, backupKdf, backupIter);
      // Verify
      if (pendingBackup.entries?.length) {
        const e0 = pendingBackup.entries[0];
        await crypto.subtle.decrypt(
          { name:'AES-GCM', iv: b64d(e0.encrypted.iv) }, k, b64d(e0.encrypted.ct)
        );
      }
      // Write tabs first (remapping ids so entry.tabId stays consistent),
      // then entries — this also handles legacy backups with no tabs array.
      await dbClear();
      await tabsClear();
      const hasTabs = Array.isArray(pendingBackup.tabs) && pendingBackup.tabs.length;
      let tabIdMap = {};
      if (hasTabs) {
        for (const t of pendingBackup.tabs) {
          const { id: oldId, ...rest } = t;
          const newId = await tabAdd(rest);
          tabIdMap[oldId] = newId;
        }
      }
      for (const e of (pendingBackup.entries || [])) {
        const { id, tabId, ...rest } = e;
        await dbAdd({ ...rest, tabId: hasTabs ? tabIdMap[tabId] : undefined });
      }
      if (!hasTabs) await ensureTabsReady(); // legacy backup: recreate categories & backfill by type

      await metaPut('salt', pendingBackup.salt);
      await metaPut('kdf',  backupKdf);
      if (backupKdf === KDF_PBKDF2) await metaPut('iterations', backupIter);
      CK = k; SALT = s; CUR_KDF = backupKdf; CUR_ITER = backupKdf === KDF_PBKDF2 ? backupIter : PBKDF2_ITERATIONS_CURRENT;
      broadcastLock(); // restoring rewrites salt/kdf — any other open tab must relock

      // Immediately re-encrypt under current PBKDF2 params if the backup was
      // encrypted with Argon2id, or with a weaker (legacy) iteration count.
      if (backupKdf === KDF_ARGON2 || CUR_ITER < PBKDF2_ITERATIONS_CURRENT) {
        btn.textContent = backupKdf === KDF_ARGON2 ? 'Migrating to PBKDF2…' : 'Upgrading key derivation…';
        const entries = await dbGetAll();
        const ns = rnd(16);
        const nk = await deriveKeyPbkdf2(key, ns); // uses PBKDF2_ITERATIONS_CURRENT
        const re = await reEncryptAll(entries, CK, nk);
        await dbClear();
        for (const e of re) { const { id, ...rest } = e; await dbAdd(rest); }
        CK = nk; SALT = ns;
        await metaPut('salt', b64e(ns));
        await metaPut('kdf',  KDF_PBKDF2);
        await metaPut('iterations', PBKDF2_ITERATIONS_CURRENT);
        CUR_KDF = KDF_PBKDF2; CUR_ITER = PBKDF2_ITERATIONS_CURRENT;
        broadcastLock(); // any other open tab is now holding a stale key — force it to relock
        toast(backupKdf === KDF_ARGON2
          ? 'Backup restored & migrated to PBKDF2'
          : 'Backup restored & upgraded to current iteration count', 'info');
      }

      $('restore-key').value = '';
      markUnsaved();
      registerSuccess('restore');
      await unlockUI();
    } catch (err) {
      failed = true;
      const msg = err.message?.includes('Argon2') || err.message?.includes('argon2')
        ? err.message : 'Wrong key or corrupt backup';
      toast(msg, 'err');
    } finally { btn.disabled = false; btn.textContent = 'Restore & decrypt'; }
    if (failed) {
      registerFailedAttempt('restore');
      applyCooldownUI('restore', btn, 'Restore & decrypt');
    }
  });

  /* Sidebar tab nav: switch / rename (double-click) / favorite (star) / delete (× on hover) / add */
  $('sidebar-tab-nav').addEventListener('click', e => {
    const favBtn = e.target.closest('[data-action="toggle-favorite"]');
    if (favBtn) { e.stopPropagation(); toggleTabFavorite(parseInt(favBtn.dataset.tabId, 10)); return; }
    const closeBtn = e.target.closest('[data-action="delete-tab"]');
    if (closeBtn) { e.stopPropagation(); deleteTabById(parseInt(closeBtn.dataset.tabId, 10)); return; }
    const tabEl = e.target.closest('.tab-custom');
    if (tabEl) switchTab(parseInt(tabEl.dataset.tabId, 10));
  });
  $('sidebar-tab-nav').addEventListener('dblclick', e => {
    const labelEl = e.target.closest('.nav-label');
    if (!labelEl) return;
    const tabEl = labelEl.closest('.tab-custom');
    if (tabEl) renameTab(parseInt(tabEl.dataset.tabId, 10));
  });
  $('add-tab-btn').addEventListener('click', addTab);
  $('tab-security').addEventListener('click', () => switchTab('security'));
  $('tabs-sort-az-btn').addEventListener('click', setTabSortAlphabetical);

  /* Drag-and-drop tab reordering — dropping switches to 'manual' sort mode */
  let dragTabId = null;
  $('sidebar-tab-nav').addEventListener('dragstart', e => {
    const item = e.target.closest('.tab-custom');
    if (!item) return;
    dragTabId = parseInt(item.dataset.tabId, 10);
    item.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
  });
  $('sidebar-tab-nav').addEventListener('dragend', e => {
    e.target.closest('.tab-custom')?.classList.remove('dragging');
    dragTabId = null;
  });
  $('sidebar-tab-nav').addEventListener('dragover', e => {
    if (dragTabId != null) e.preventDefault(); // allow drop
  });
  $('sidebar-tab-nav').addEventListener('drop', async e => {
    e.preventDefault();
    const target = e.target.closest('.tab-custom');
    if (!target || dragTabId == null) return;
    await reorderTabs(dragTabId, parseInt(target.dataset.tabId, 10));
    dragTabId = null;
  });

  /* Search: typing filters the current tab, or every tab when "All tabs" is on */
  $('search-scope-btn').addEventListener('click', () => {
    searchAllTabs = !searchAllTabs;
    $('search-scope-btn').classList.toggle('active', searchAllTabs);
    renderEntryList();
  });

  /* Add-entry panel toggle + type selector */
  $('add-entry-btn').addEventListener('click', () => toggleAddPanel());
  $('cancel-add-btn').addEventListener('click', () => toggleAddPanel(false));
  $('type-select').querySelectorAll('.type-btn').forEach(b =>
    b.addEventListener('click', () => setAddType(b.dataset.type))
  );

  /* Crypto coin picker: populate from the single CRYPTO_COINS source of
     truth, and show/relabel the memo field + format hint per coin. */
  $('n-crypto-coin').innerHTML = cryptoCoinOptionsHTML('btc');
  $('n-crypto-coin').addEventListener('change', () => {
    const coin = $('n-crypto-coin').value;
    updateCryptoMemoField(coin, $('n-crypto-memo-wrap'), $('n-crypto-memo-label'));
    updateCryptoHint(coin, $('n-crypto-hint'));
  });

  /* Billing cycle: the month field only matters (and is only shown) for an annual bill */
  $('n-billing-month').innerHTML = BILLING_MONTH_NAMES.map((m, i) => `<option value="${i + 1}">${m}</option>`).join('');
  $('n-billing-cycle').addEventListener('change', () => {
    $('n-billing-month-wrap').style.display = $('n-billing-cycle').value === 'annually' ? '' : 'none';
  });

  /* Grid / list view toggle */
  $('view-grid-btn').addEventListener('click', () => setViewMode('grid'));
  $('view-list-btn').addEventListener('click', () => setViewMode('list'));
  setViewMode('grid');

  document.addEventListener('click', e => {
    const btn = e.target.closest('.toggle-btn');
    if (!btn) return;
    // data-target: find by ID; data-target-class: find nearest element by class within container
    const inp = btn.dataset.target
      ? $(btn.dataset.target)
      : btn.closest('.input-with-toggle')?.querySelector(`.${btn.dataset.targetClass}`);
    if (!inp) return;
    inp.type = inp.type === 'password' ? 'text' : 'password';
    btn.textContent = inp.type === 'password' ? '👁' : '🙈';
  });

  $('list-container').addEventListener('click', e => { handleEntryAction(e); handleEnvAction(e); });

  $('add-btn').addEventListener('click', async () => {
    if (curTabId === 'security' || curTabId == null) return;
    const name = $('n-name').value.trim();
    const tag  = $('n-tag').value.trim();
    if (!name) { toast('Title is required', 'err'); return; }

    if (curAddType === 'env') {
      await addEntry(name, JSON.stringify(newEnvVars || {}), tag, 'env', curTabId);
    } else if (curAddType === 'file') {
      if (!newAttachmentFile) { toast('Choose a file first', 'err'); return; }
      await addFileEntry(name, tag, curTabId, newAttachmentFile);
    } else if (curAddType === 'billing') {
      const cycle = $('n-billing-cycle').value;
      const day   = parseInt($('n-billing-day').value, 10);
      if (!Number.isFinite(day) || day < 1 || day > 31) { toast('Day must be between 1 and 31', 'err'); return; }
      const month = cycle === 'annually' ? parseInt($('n-billing-month').value, 10) : null;
      const price        = parseFloat($('n-billing-price').value) || 0;
      const reminderDays = parseInt($('n-billing-reminder').value, 10);
      await addEntry(name, JSON.stringify({
        day, month, cycle, price,
        reminderDays: Number.isFinite(reminderDays) ? reminderDays : BILLING_REMINDER_DAYS_DEFAULT,
      }), tag, 'billing', curTabId);
    } else if (curAddType === 'crypto') {
      const coin    = $('n-crypto-coin').value;
      const address = $('n-crypto-address').value.trim();
      const addrErr = validateCryptoAddress(coin, address);
      if (addrErr) { toast(addrErr, 'err'); return; }
      const memoField = CRYPTO_COINS[coin].memoField;
      const memo = memoField ? $('n-crypto-memo').value.trim() : '';
      if (memoField && !memoField.validate(memo)) {
        toast(`Invalid ${memoField.label.replace(' (optional)', '')}`, 'err');
        return;
      }
      await addEntry(name, JSON.stringify({ coin, address, memo }), tag, 'crypto', curTabId);
    } else {
      const content = $('n-content').value.trim();
      if (!content) { toast('Content is required', 'err'); return; }
      await addEntry(name, content, tag, curAddType, curTabId);
    }
    toggleAddPanel(false);
    markUnsaved();
    await renderEntryList();
    await updateTabCounts();
    toast('Entry saved', 'ok');
  });

  $('v-search').addEventListener('input', renderEntryList);

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

  $('new-env-import-zone').addEventListener('click', () => $('new-env-file-input').click());
  $('new-env-file-input').addEventListener('change', async e => {
    const f = e.target.files[0];
    if (!f) return;
    newEnvVars = parseDotEnv(await f.text());
    updateNewEnvFileLabel();
  });

  $('attachment-upload-zone').addEventListener('click', () => $('attachment-file-input').click());
  $('attachment-file-input').addEventListener('change', async e => {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > MAX_ATTACHMENT_SIZE) {
      toast(`File too large — max ${formatBytes(MAX_ATTACHMENT_SIZE)}`, 'err');
      e.target.value = '';
      return;
    }
    const buffer = await f.arrayBuffer();
    newAttachmentFile = { name: f.name, mimeType: f.type || 'application/octet-stream', size: f.size, buffer };
    if (!$('n-name').value) $('n-name').value = f.name;
    updateAttachmentLabel();
    e.target.value = '';
  });

  $('change-pass-btn').addEventListener('click', changePassword);
  $('wipe-btn').addEventListener('click', wipeVault);
  $('lock-btn').addEventListener('click', lockVault);
  $('export-btn').addEventListener('click', openExportConfirm);
  $('export-confirm-btn').addEventListener('click', confirmExport);
  $('export-confirm-cancel').addEventListener('click', closeExportConfirm);
  $('export-confirm-key').addEventListener('keydown', e => { if (e.key === 'Enter') confirmExport(); });
  // Click on the dimmed backdrop (not the card itself) closes it, same as pressing Cancel
  $('export-confirm-overlay').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeExportConfirm();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && $('export-confirm-overlay').style.display !== 'none') closeExportConfirm();
  });

  /* Generator modal */
  $('open-generator-btn').addEventListener('click', openGenerator);
  $('generator-close-btn').addEventListener('click', closeGenerator);
  $('generator-overlay').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeGenerator();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && $('generator-overlay').style.display !== 'none') closeGenerator();
  });
  $('gen-type-select').addEventListener('click', e => {
    const btn = e.target.closest('.type-btn');
    if (btn) switchGenType(btn.dataset.genType);
  });
  wireButtonGroup('gen-pw-type', () => {
    $('gen-pw-passphrase-opts').style.display = groupValue('gen-pw-type', 'passphrase') === 'passphrase' ? '' : 'none';
  });
  wireButtonGroup('gen-pw-complexity');
  wireButtonGroup('gen-pw-separator');
  wireButtonGroup('gen-pw-digit');
  wireButtonGroup('gen-enc-size', updateOpensslPreview);
  wireButtonGroup('gen-enc-encoding', updateOpensslPreview);
  $('gen-generate-btn').addEventListener('click', runGenerate);
  $('gen-copy-btn').addEventListener('click', async () => { await copyToClipboard($('gen-output').value); toast('Copied to clipboard', 'ok'); });
  $('gen-copy-pub-btn').addEventListener('click', async () => { await copyToClipboard($('gen-output-pub').value); toast('Public key copied', 'ok'); });
  $('gen-copy-env-btn').addEventListener('click', async () => { if (genLastEnvLine) { await copyToClipboard(genLastEnvLine); toast('.env line copied', 'ok'); } });
  updateOpensslPreview();

  document.addEventListener('keydown', resetLock);
  document.addEventListener('click',   resetLock);

  // Background tabs throttle setInterval (often to ~once/minute), which can
  // make the auto-lock fire late while hidden. Force an immediate check
  // the moment the tab becomes visible again so it never overshoots by
  // more than the throttled interval actually caused.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && isUnlocked() && lockEnd && Date.now() >= lockEnd) lockVault();
  });

  // Best-effort: ask the browser not to evict this origin's IndexedDB data
  // under storage pressure. Not a security control — just avoids losing
  // vault data to browser storage-eviction heuristics. Safe no-op if the
  // API is unavailable or the browser declines.
  navigator.storage?.persist?.().catch(() => {});

  $('unlock-key').addEventListener('keydown',   e => { if (e.key === 'Enter') $('unlock-btn').click(); });
  $('new-confirm').addEventListener('keydown',  e => { if (e.key === 'Enter') $('create-btn').click(); });
}

document.addEventListener('DOMContentLoaded', init);
