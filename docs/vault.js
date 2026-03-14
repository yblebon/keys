'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// FIX: Version baked in at build time — eliminates the config.json network
//      fetch that was unnecessary attack surface on every page load.
// ─────────────────────────────────────────────────────────────────────────────
const VAULT_VERSION = "1.1.0";
const DB_NAME       = "VaultDB";
const DB_VERSION    = 1;
const STORE_NAME    = "vault";
const BLOB_KEY      = "main";
const LOCK_TIMEOUT  = 5 * 60 * 1000;   // 5 min idle → auto-lock
const CLIP_TTL      = 30 * 1000;       // 30 s → clear clipboard

// ─────────────────────────────────────────────────────────────────────────────
// Module-scoped session state
// FIX: Raw password is NEVER retained after unlock. Only non-exportable
//      CryptoKey objects (aesKey, hmacKey) and the vault salt are kept.
//      sessionKeys is module-scoped, not window-scoped, limiting exposure.
// ─────────────────────────────────────────────────────────────────────────────
let sessionKeys  = null;   // { aesKey: CryptoKey, hmacKey: CryptoKey, salt: Uint8Array }
let vaultData    = { passwords: [], keys: [], certs: [] };
let activeTab    = 'passwords';
let stagedBlob   = null;
let db           = null;
let lockTimer    = null;
let lockInterval = null;
let lockRemaining = LOCK_TIMEOUT;

// ─────────────────────────────────────────────────────────────────────────────
// Password sanitization
// FIX: Removed .trim() — whitespace is valid and significant in passwords.
//      Silent trimming could make a password irrecoverable on another device.
//      NFC normalization is kept for cross-platform Unicode consistency.
//      The UI warns the user explicitly if edge whitespace is detected.
// ─────────────────────────────────────────────────────────────────────────────
function sanitizePassword(raw) {
    return raw.normalize('NFC');
}

function hasEdgeWhitespace(raw) {
    return raw !== raw.trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// ID generation
// FIX: Replaced Date.now() + Math.random() with crypto.getRandomValues().
//      Math.random() is not cryptographically secure.
// ─────────────────────────────────────────────────────────────────────────────
function generateId() {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// IndexedDB helpers
// ─────────────────────────────────────────────────────────────────────────────
async function openDB() {
    if (db) return db;
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => { db = req.result; resolve(db); };
        req.onupgradeneeded = e => {
            const d = e.target.result;
            if (!d.objectStoreNames.contains(STORE_NAME))
                d.createObjectStore(STORE_NAME);
        };
    });
}

async function getBlob() {
    const database = await openDB();
    return new Promise((resolve, reject) => {
        const tx = database.transaction(STORE_NAME, 'readonly');
        const req = tx.objectStore(STORE_NAME).get(BLOB_KEY);
        req.onsuccess = () => resolve(req.result ?? null);
        req.onerror   = () => reject(req.error);
    });
}

async function setBlob(value) {
    const database = await openDB();
    return new Promise((resolve, reject) => {
        const tx = database.transaction(STORE_NAME, 'readwrite');
        tx.objectStore(STORE_NAME).put(value, BLOB_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror    = () => reject(tx.error);
    });
}

async function clearDB() {
    if (db) { db.close(); db = null; }
    return new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase(DB_NAME);
        req.onsuccess = resolve;
        req.onerror   = reject;
        req.onblocked = () => alert('Delete blocked — close other tabs first.');
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation
//
// FIX (critical): The original code derived the HMAC key from a cheap
//   SHA-256(password + "hmac"), which was verified BEFORE Argon2id ran.
//   This allowed an attacker to brute-force passwords by checking the HMAC
//   in nanoseconds, completely bypassing the expensive KDF.
//
// Fix: Argon2id now outputs 64 bytes. The first 32 bytes become the AES-GCM
//   key; the last 32 bytes become the HMAC-SHA256 key. Both are imported as
//   non-exportable CryptoKey objects (extractable: false). An attacker must
//   pay the full Argon2id cost (≈190 MB RAM, 5 iterations) to verify any
//   single password guess.
// ─────────────────────────────────────────────────────────────────────────────
async function deriveKeys(pass, salt) {
    const sanitized = sanitizePassword(pass);
    const hash = await hashwasm.argon2id({
        password:    sanitized,
        salt,
        iterations:  5,
        parallelism: 1,
        memorySize:  194560,
        hashLength:  64,           // 32 bytes → AES  |  32 bytes → HMAC
        outputType:  'binary'
    });

    const aesKey = await crypto.subtle.importKey(
        'raw', hash.slice(0, 32),
        { name: 'AES-GCM' },
        false,                     // non-exportable
        ['encrypt', 'decrypt']
    );
    const hmacKey = await crypto.subtle.importKey(
        'raw', hash.slice(32, 64),
        { name: 'HMAC', hash: 'SHA-256' },
        false,                     // non-exportable
        ['sign', 'verify']
    );
    return { aesKey, hmacKey };
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypt vault → blob
// The salt is stored in the blob and is fixed for the lifetime of a given
// master key. A new IV is generated on every save (forward secrecy for
// individual snapshots). The HMAC authenticates (salt ‖ iv ‖ ciphertext).
// ─────────────────────────────────────────────────────────────────────────────
async function encryptVault(keys, salt) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, keys.aesKey,
        new TextEncoder().encode(JSON.stringify(vaultData))
    ));

    // Authenticate-then-encrypt: sign (salt ‖ iv ‖ ct)
    const toSign = new Uint8Array(salt.length + iv.length + ct.length);
    toSign.set(salt, 0);
    toSign.set(iv,   salt.length);
    toSign.set(ct,   salt.length + iv.length);
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', keys.hmacKey, toSign));

    const b64 = buf => btoa(String.fromCharCode(...buf));
    return { s: b64(salt), iv: b64(iv), ct: b64(ct), h: b64(hmac), v: 2 };
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy (v1) decryption path
//
// Old blobs have no `v` field and used a fundamentally different key scheme:
//   • Argon2id with hashLength: 32  → AES-GCM key only
//   • HMAC key = SHA-256(password + "hmac")  ← the KDF-bypass vulnerability
//   • IV stored under field name "i"
//
// We support decrypting them so users don't lose their data, then immediately
// re-save in the secure v2 format. The legacy path is ONLY used when the blob
// lacks `v: 2`; it is never used for new saves.
// ─────────────────────────────────────────────────────────────────────────────
async function decryptBlobLegacy(blob, pass) {
    const from64   = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const salt     = from64(blob.s);
    const iv       = from64(blob.i);
    const ct       = from64(blob.ct);
    const h        = from64(blob.h);
    const sanitized = sanitizePassword(pass);

    // Legacy HMAC key — derived from a cheap SHA-256, NOT Argon2id
    const hmacRaw  = await crypto.subtle.digest('SHA-256',
        new TextEncoder().encode(sanitized + 'hmac'));
    const hmacKey  = await crypto.subtle.importKey(
        'raw', hmacRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);

    const toVerify = new Uint8Array(salt.length + iv.length + ct.length);
    toVerify.set(salt, 0);
    toVerify.set(iv,   salt.length);
    toVerify.set(ct,   salt.length + iv.length);

    const valid = await crypto.subtle.verify('HMAC', hmacKey, h, toVerify);
    if (!valid) return null;

    // Legacy AES key — Argon2id with 32-byte output only
    const hash32   = await hashwasm.argon2id({
        password:    sanitized,
        salt,
        iterations:  5,
        parallelism: 1,
        memorySize:  194560,
        hashLength:  32,
        outputType:  'binary'
    });
    const aesKey = await crypto.subtle.importKey(
        'raw', hash32, { name: 'AES-GCM' }, false, ['decrypt']);

    const dec  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return JSON.parse(new TextDecoder().decode(dec));
}

// ─────────────────────────────────────────────────────────────────────────────
// Decrypt blob → { data, keys, salt }
// Returns null on any failure (wrong key, tampered data).
//
// Format detection:
//   blob.v === 2  →  new secure format (Argon2id 64-byte split keys)
//   no blob.v     →  legacy v1 format  (Argon2id 32-byte + SHA-256 HMAC)
//
// After a successful legacy decrypt the caller re-saves in v2 format
// automatically, so the migration is transparent to the user.
// ─────────────────────────────────────────────────────────────────────────────
async function decryptBlob(blob, pass) {
    try {
        if (!blob?.h) throw new Error('Missing integrity field');

        const from64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

        // ── v2 path (secure) ────────────────────────────────────────────────
        if (blob.v === 2) {
            const salt = from64(blob.s);
            const iv   = from64(blob.iv);
            const ct   = from64(blob.ct);
            const h    = from64(blob.h);

            const keys = await deriveKeys(pass, salt);

            const toVerify = new Uint8Array(salt.length + iv.length + ct.length);
            toVerify.set(salt, 0);
            toVerify.set(iv,   salt.length);
            toVerify.set(ct,   salt.length + iv.length);

            const valid = await crypto.subtle.verify('HMAC', keys.hmacKey, h, toVerify);
            if (!valid) throw new Error('Integrity check failed — wrong key or tampered data');

            const dec  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, keys.aesKey, ct);
            const data = JSON.parse(new TextDecoder().decode(dec));
            return { data, keys, salt, migrated: false };
        }

        // ── v1 legacy path ──────────────────────────────────────────────────
        // Blob has no `v` field — created by the original vault before v1.1.0.
        // Decrypt with the old scheme, then signal the caller to migrate.
        const data = await decryptBlobLegacy(blob, pass);
        if (!data) throw new Error('Legacy integrity check failed — wrong key or corrupted data');

        // Derive fresh v2 keys using a new salt so the re-save is fully secure
        const newSalt = crypto.getRandomValues(new Uint8Array(16));
        const newKeys = await deriveKeys(pass, newSalt);
        return { data, keys: newKeys, salt: newSalt, migrated: true };

    } catch (e) {
        console.error('Decryption error:', e.message);
        return null;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-save
// Uses cached session CryptoKeys — the raw password is never needed again
// after unlock. A new IV is generated on each save.
// ─────────────────────────────────────────────────────────────────────────────
async function autoSave() {
    if (!sessionKeys) return;
    try {
        const blob = await encryptVault(sessionKeys, sessionKeys.salt);
        await setBlob(blob);
        setBannerVisible(true);
        updateMeta();
    } catch (err) {
        const msg = err.name === 'QuotaExceededError' ? 'Storage full' : err.message;
        console.error('Save failed:', err);
        alert('Save failed: ' + msg);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session lock
// FIX: Auto-lock after LOCK_TIMEOUT ms of inactivity. On lock, all sensitive
//      data (CryptoKeys + plaintext vault) is cleared from memory before reload.
// ─────────────────────────────────────────────────────────────────────────────
function lockVault() {
    clearTimeout(lockTimer);
    clearInterval(lockInterval);
    sessionKeys = null;
    vaultData   = { passwords: [], keys: [], certs: [] };
    window.location.reload();
}

function resetLockTimer() {
    if (!sessionKeys) return;
    clearTimeout(lockTimer);
    lockTimer     = setTimeout(lockVault, LOCK_TIMEOUT);
    lockRemaining = LOCK_TIMEOUT;
}

function startLockCountdown() {
    lockRemaining = LOCK_TIMEOUT;
    clearInterval(lockInterval);
    lockInterval = setInterval(() => {
        lockRemaining = Math.max(0, lockRemaining - 1000);
        renderLockCountdown();
    }, 1000);
}

function renderLockCountdown() {
    const el = document.getElementById('lock-countdown');
    if (!el) return;
    const m = Math.floor(lockRemaining / 60000);
    const s = Math.floor((lockRemaining % 60000) / 1000);
    el.textContent = `${m}:${s.toString().padStart(2, '0')}`;
}

['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(evt =>
    document.addEventListener(evt, resetLockTimer, { passive: true })
);

// ─────────────────────────────────────────────────────────────────────────────
// UI helpers
// ─────────────────────────────────────────────────────────────────────────────
function setBannerVisible(show) {
    const el = document.getElementById('sync-banner');
    if (el) el.style.display = show ? 'flex' : 'none';
}

function updateMeta() {
    document.getElementById('sidebar-meta').style.display = 'block';
    document.getElementById('last-update').textContent =
        'Synced ' + new Date().toLocaleTimeString();
    const total = (vaultData.passwords?.length ?? 0)
                + (vaultData.keys?.length ?? 0)
                + (vaultData.certs?.length ?? 0);
    document.getElementById('entry-count').textContent =
        `${total} encrypted object${total !== 1 ? 's' : ''}`;

    const pw  = vaultData.passwords?.length ?? 0;
    const ky  = vaultData.keys?.length ?? 0;
    const cr  = vaultData.certs?.length ?? 0;
    setCount('count-pw',   pw);
    setCount('count-keys', ky);
    setCount('count-cert', cr);
}

function setCount(id, n) {
    const el = document.getElementById(id);
    if (el) el.textContent = n;
}

// ─────────────────────────────────────────────────────────────────────────────
// renderList
// FIX: Replaced innerHTML + template literals with explicit DOM construction.
//      The original approach was brittle — any new field added without
//      escaping would introduce an XSS vector. textContent is safe by design.
// ─────────────────────────────────────────────────────────────────────────────
function renderList() {
    const container = document.getElementById('list-container');
    if (!container) return;
    container.textContent = '';   // safe clear, no innerHTML

    const query = document.getElementById('v-search')?.value.toLowerCase() ?? '';
    const list  = (vaultData[activeTab] ?? []).filter(e =>
        e.name.toLowerCase().includes(query) ||
        (e.tag ?? '').toLowerCase().includes(query)
    );

    if (list.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = query ? 'No matching entries.' : 'No entries yet.';
        container.appendChild(empty);
        return;
    }

    list.forEach(e => {
        const item = document.createElement('div');
        item.className = 'entry-item';

        // Header row
        const row = document.createElement('div');
        row.className = 'entry-row';

        const meta = document.createElement('div');
        const name = document.createElement('span');
        name.className = 'entry-name';
        name.textContent = e.name;          // textContent — safe
        meta.appendChild(name);

        if (e.tag) {
            const tag = document.createElement('span');
            tag.className = 'entry-tag';
            tag.textContent = e.tag;        // textContent — safe
            meta.appendChild(tag);
        }

        // Action buttons
        const actions = document.createElement('div');
        actions.className = 'entry-actions';

        const btnView = mkBtn('View',  'btn-view');
        const btnCopy = mkBtn('Copy',  'btn-copy');
        const btnDel  = mkBtn('×',     'btn-del');

        // Secret area
        const secretArea = document.createElement('div');
        secretArea.className = 'secret-area';

        btnView.addEventListener('click', () => {
            const open = secretArea.classList.contains('active');
            // textContent — safe: user's own stored content, displayed only to them
            secretArea.textContent = open ? '' : e.content;
            secretArea.classList.toggle('active', !open);
            btnView.textContent = open ? 'View' : 'Hide';
            btnView.classList.toggle('btn-view-active', !open);
        });

        btnCopy.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(e.content);
                // FIX: Clear clipboard after CLIP_TTL (30 s) to prevent
                //      secrets persisting in clipboard history indefinitely.
                setTimeout(async () => {
                    try { await navigator.clipboard.writeText(''); } catch { /* ignore */ }
                }, CLIP_TTL);
                const prev = btnCopy.textContent;
                btnCopy.textContent = '✓ Copied';
                btnCopy.classList.add('btn-copied');
                setTimeout(() => {
                    btnCopy.textContent = prev;
                    btnCopy.classList.remove('btn-copied');
                }, 1500);
            } catch {
                alert('Clipboard access denied by browser.');
            }
        });

        btnDel.addEventListener('click', async () => {
            if (!confirm(`Delete "${e.name}"? This cannot be undone.`)) return;
            // FIX: Strict === comparison (was ==, which coerces types)
            vaultData[activeTab] = vaultData[activeTab].filter(x => x.id !== e.id);
            await autoSave();
            renderList();
            updateMeta();
        });

        actions.append(btnView, btnCopy, btnDel);
        row.append(meta, actions);
        item.append(row, secretArea);
        container.appendChild(item);
    });
}

function mkBtn(label, cls) {
    const b = document.createElement('button');
    b.className = `btn ${cls}`;
    b.textContent = label;
    return b;
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth tab helpers
// ─────────────────────────────────────────────────────────────────────────────
function switchAuthTab(mode) {
    ['unlock', 'new', 'restore'].forEach(m =>
        document.getElementById('auth-' + m).style.display = 'none'
    );
    document.getElementById('auth-' + mode).style.display = 'block';
    document.querySelectorAll('.tab[data-mode]').forEach(t =>
        t.classList.toggle('active', t.dataset.mode === mode)
    );
}

function showVault() {
    document.getElementById('auth-view').style.display  = 'none';
    document.getElementById('vault-view').style.display = 'block';
    resetLockTimer();
    startLockCountdown();
    renderList();
    updateMeta();
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {

    // FIX: Version is set from the baked-in constant — no config.json fetch.
    document.getElementById('app-version').textContent = `v${VAULT_VERSION}`;

    // DB availability check
    try {
        await openDB();
    } catch {
        alert('IndexedDB unavailable — vault cannot function in this browser.');
        return;
    }

    // Determine initial view: existing vault → unlock, new install → create
    const existing = await getBlob();
    if (existing) {
        document.getElementById('tab-unlock').style.display = 'block';
        switchAuthTab('unlock');
    } else {
        switchAuthTab('new');
    }

    // Password visibility toggles
    document.querySelectorAll('.toggle-btn').forEach(btn =>
        btn.addEventListener('click', e => {
            e.preventDefault();
            const input = document.getElementById(btn.dataset.target);
            const show  = input.type === 'password';
            input.type       = show ? 'text' : 'password';
            btn.textContent  = show ? '🔒' : '👁';
        })
    );

    // Auth tabs
    document.querySelectorAll('.tab[data-mode]').forEach(el =>
        el.addEventListener('click', () => switchAuthTab(el.dataset.mode))
    );

    // Vault section tabs
    document.querySelectorAll('.tab[data-tab]').forEach(el =>
        el.addEventListener('click', () => {
            activeTab = el.dataset.tab;
            document.querySelectorAll('.tab[data-tab]').forEach(t =>
                t.classList.toggle('active', t === el)
            );
            const isSec = activeTab === 'security';
            document.getElementById('vault-content-section').style.display =
                isSec ? 'none' : 'block';
            document.getElementById('security-section').style.display =
                isSec ? 'block' : 'none';
            document.getElementById('importer-ui').style.display =
                !isSec && (activeTab === 'keys' || activeTab === 'certs') ? 'block' : 'none';
            if (!isSec) renderList();
        })
    );

    // ── Unlock ────────────────────────────────────────────────────────────────
    const unlockBtn = document.getElementById('unlock-btn');
    unlockBtn.addEventListener('click', async () => {
        const raw = document.getElementById('unlock-key').value;
        if (!raw) return;

        if (hasEdgeWhitespace(raw)) {
            // FIX: Explicit warning instead of silent trim
            const proceed = confirm(
                'Your password starts or ends with a space.\n\n' +
                'These spaces have been preserved exactly as typed. ' +
                'If this is unintentional, cancel and retype without edge spaces.'
            );
            if (!proceed) return;
        }

        unlockBtn.textContent = 'Decrypting…';
        unlockBtn.disabled = true;

        const blob   = await getBlob();
        const result = await decryptBlob(blob, raw);

        unlockBtn.textContent = 'Unlock Vault';
        unlockBtn.disabled = false;

        if (result) {
            // FIX: Raw password discarded here. Only non-exportable CryptoKeys
            //      are retained in sessionKeys for the duration of the session.
            sessionKeys = { aesKey: result.keys.aesKey, hmacKey: result.keys.hmacKey, salt: result.salt };
            vaultData   = result.data;
            document.getElementById('unlock-key').value = '';   // zero input

            if (result.migrated) {
                // Legacy v1 vault detected — re-save in v2 format transparently
                await autoSave();
                alert(
                    'Vault migrated to secure v2 format.\n\n' +
                    'Your data has been re-encrypted with the new key scheme. ' +
                    'Download a fresh backup to replace your old one.'
                );
            }
            showVault();
        } else {
            alert('Incorrect key or corrupted vault.');
        }
    });

    // ── Create new vault ──────────────────────────────────────────────────────
    const createBtn = document.getElementById('create-btn');
    createBtn.addEventListener('click', async () => {
        const raw1 = document.getElementById('new-key').value;
        const raw2 = document.getElementById('new-confirm').value;

        if (raw1 !== raw2) { alert('Keys do not match.'); return; }
        if (sanitizePassword(raw1).length < 10) {
            alert('Key must be at least 10 characters.'); return;
        }

        if (hasEdgeWhitespace(raw1)) {
            const proceed = confirm(
                'Your password starts or ends with a space.\n\n' +
                'Spaces will be preserved. Continue?'
            );
            if (!proceed) return;
        }

        createBtn.textContent = 'Initializing…';
        createBtn.disabled = true;

        const salt  = crypto.getRandomValues(new Uint8Array(16));
        const keys  = await deriveKeys(raw1, salt);

        // FIX: Clear raw password from DOM immediately after KDF
        document.getElementById('new-key').value     = '';
        document.getElementById('new-confirm').value = '';

        createBtn.textContent = 'Initialize Encrypted Storage';
        createBtn.disabled = false;

        sessionKeys = { aesKey: keys.aesKey, hmacKey: keys.hmacKey, salt };
        await autoSave();
        showVault();
    });

    // ── Add entry ─────────────────────────────────────────────────────────────
    document.getElementById('add-btn').addEventListener('click', async () => {
        const name    = document.getElementById('n-name').value.trim();
        const content = document.getElementById('n-content').value;
        if (!name || !content.trim()) {
            alert('Title and content are both required.'); return;
        }

        vaultData[activeTab].push({
            id:      generateId(),          // FIX: crypto.getRandomValues-based
            name,
            content,
            tag:     document.getElementById('n-tag').value.trim()
        });

        document.getElementById('n-name').value    = '';
        document.getElementById('n-content').value = '';
        document.getElementById('n-tag').value     = '';

        await autoSave();
        renderList();
    });

    // ── Export backup ─────────────────────────────────────────────────────────
    document.getElementById('export-btn').addEventListener('click', async () => {
        const blob = await getBlob();
        if (!blob) return;

        // FIX: Timestamp removed from export — it was metadata leakage that
        //      could be used to correlate vault activity to a specific time.
        const pkg = { version: VAULT_VERSION, payload: blob };
        const url = URL.createObjectURL(
            new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' })
        );
        const a = document.createElement('a');
        a.href     = url;
        a.download = `vault_backup_v${VAULT_VERSION}.json`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        setBannerVisible(false);
    });

    // ── Restore from backup ───────────────────────────────────────────────────
    document.getElementById('restore-zone').addEventListener('click', () =>
        document.getElementById('file-input').click()
    );

    document.getElementById('file-input').addEventListener('change', e => {
        const file = e.target.files[0];
        if (!file) return;
        const r = new FileReader();
        r.onload = ev => {
            try {
                const imp  = JSON.parse(ev.target.result);
                stagedBlob = imp.payload ?? imp;
                const label = document.getElementById('file-label');
                label.textContent = `Staged: ${imp.version ?? 'unknown version'}`;
                label.classList.add('staged');
            } catch {
                alert('Invalid JSON file.');
            }
        };
        r.readAsText(file);
    });

    const restoreBtn = document.getElementById('restore-btn');
    restoreBtn.addEventListener('click', async () => {
        if (!stagedBlob) { alert('No backup staged yet.'); return; }
        const raw = document.getElementById('restore-key').value;
        if (!raw)  { alert('Enter the master key for this backup.'); return; }

        restoreBtn.textContent = 'Decrypting…';
        restoreBtn.disabled = true;

        const result = await decryptBlob(stagedBlob, raw);

        restoreBtn.textContent = 'Restore & Decrypt';
        restoreBtn.disabled = false;

        if (result) {
            sessionKeys = { aesKey: result.keys.aesKey, hmacKey: result.keys.hmacKey, salt: result.salt };
            vaultData   = result.data;
            document.getElementById('restore-key').value = '';
            await autoSave();

            if (result.migrated) {
                alert(
                    'Legacy backup restored and migrated to v2 format.\n\n' +
                    'Your data has been re-encrypted with the new secure key scheme. ' +
                    'Download a fresh backup to replace your old one.'
                );
            }
            showVault();
        } else {
            alert(
                'Restoration failed.\n\n' +
                'Possible reasons:\n' +
                '• Wrong master key\n' +
                '• File is corrupted or not a valid vault backup'
            );
        }
    });

    // ── Content importer (for keys / certs) ───────────────────────────────────
    document.getElementById('content-zone').addEventListener('click', () =>
        document.getElementById('content-uploader').click()
    );
    document.getElementById('content-uploader').addEventListener('change', e => {
        const file = e.target.files[0];
        if (!file) return;
        const r = new FileReader();
        r.onload = ev => {
            document.getElementById('n-content').value = ev.target.result;
            if (!document.getElementById('n-name').value)
                document.getElementById('n-name').value = file.name;
        };
        r.readAsText(file);
    });

    // ── Change master key ─────────────────────────────────────────────────────
    const changeBtn = document.getElementById('change-pass-btn');
    changeBtn.addEventListener('click', async () => {
        const raw1 = document.getElementById('change-pass-new').value;
        const raw2 = document.getElementById('change-pass-confirm').value;

        if (raw1 !== raw2) { alert('Keys do not match.'); return; }
        if (sanitizePassword(raw1).length < 10) {
            alert('Key must be at least 10 characters.'); return;
        }
        if (!confirm('Re-encrypt the entire vault with the new key?')) return;

        changeBtn.textContent = 'Re-encrypting…';
        changeBtn.disabled = true;

        try {
            // New password → new salt → new keys
            const newSalt = crypto.getRandomValues(new Uint8Array(16));
            const newKeys = await deriveKeys(raw1, newSalt);

            // FIX: Clear raw password from DOM immediately
            document.getElementById('change-pass-new').value     = '';
            document.getElementById('change-pass-confirm').value = '';

            sessionKeys = { aesKey: newKeys.aesKey, hmacKey: newKeys.hmacKey, salt: newSalt };
            await autoSave();
            alert('Key updated — vault re-encrypted with new credentials.');
        } catch (e) {
            alert('Change failed: ' + e.message);
        } finally {
            changeBtn.textContent = 'Update & Re-encrypt';
            changeBtn.disabled = false;
        }
    });

    // ── Lock & Wipe ───────────────────────────────────────────────────────────
    document.getElementById('lock-btn').addEventListener('click', () => lockVault());

    document.getElementById('wipe-btn').addEventListener('click', async () => {
        if (confirm('Permanently delete ALL vault data? This cannot be undone.')) {
            await clearDB();
            window.location.reload();
        }
    });

    // ── Search ────────────────────────────────────────────────────────────────
    document.getElementById('v-search').addEventListener('input', renderList);
});