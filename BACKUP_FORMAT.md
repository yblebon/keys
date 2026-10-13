# Keys — Backup File Format Specification

This document specifies the exact, interoperable format of the `.json` backup
file exported by **Keys** (`docs/vault.js` / `docs/index.html`), so a
separate, independent application can read (and optionally write) the same
files — importing and decrypting every secret Keys can hold.

Reflects the app as of `VERSION = "v2.1.0"`. Field-by-field compatibility
rules are called out explicitly so an implementer can also read backups
exported by older versions of the app.

## Contents
1. [Overview](#1-overview)
2. [Backup file — top-level object](#2-backup-file--top-level-object)
3. [Key derivation](#3-key-derivation)
4. [Encryption of each secret value](#4-encryption-of-each-secret-value)
5. [Entry object](#5-entry-object)
6. [Per-type decrypted content](#6-per-type-decrypted-content)
7. [Tab object](#7-tab-object)
8. [What's intentionally NOT in the backup](#8-whats-intentionally-not-in-the-backup)
9. [Filename convention](#9-filename-convention)
10. [Reference pseudocode](#10-reference-pseudocode)
11. [Security notes for implementers](#11-security-notes-for-implementers)
12. [Worked example](#12-worked-example)

---

## 1. Overview

Keys is a client-side, zero-network secrets manager. All data lives in the
browser's IndexedDB; the backup file is the *only* portable representation of
a vault. To be compatible, your app must be able to:

- derive the same 256-bit AES key from the user's master password + the
  backup's salt (and KDF parameters),
- decrypt every entry's individually-encrypted AES-256-GCM payload,
- parse the per-type JSON payloads for `env`, `billing`, and `crypto` entries.

Nothing in the backup is encrypted *as a whole file* — it's a plaintext JSON
document in which specific field values are themselves ciphertext.

## 2. Backup file — top-level object

```json
{
  "version": "v2.1.0",
  "kdf": "pbkdf2",
  "salt": "base64-encoded-16-random-bytes",
  "iterations": 1200000,
  "entries": [ /* Entry objects, §5 */ ],
  "tabs": [ /* Tab objects, §7 */ ],
  "ts": 1760000000000
}
```

| field | type | meaning / compatibility rule |
|---|---|---|
| `version` | string | App version tag, informational only. Not used to gate parsing. |
| `kdf` | `"pbkdf2"` \| `"argon2id"` | Key derivation function used to encrypt this backup. **Absent on very old (pre-KDF-field) backups → treat as `"argon2id"`.** |
| `salt` | string (base64) | 16 raw random bytes, input to the KDF. |
| `iterations` | integer | PBKDF2 iteration count. Only meaningful when `kdf === "pbkdf2"`. **Absent → treat as `600000`** (the legacy default before this field existed). Current app always writes `1200000` for anything newly encrypted. |
| `entries` | array | See §5. |
| `tabs` | array | See §7. **Absent/empty on very old (pre-tabs) backups** — in that case, entries won't reference a valid `tabId`; treat all entries as belonging to one default group. |
| `ts` | integer (epoch ms) | Export timestamp, informational only. |

## 3. Key derivation

### 3.1 PBKDF2 — current algorithm (implement this one)

- **Algorithm:** PBKDF2-HMAC-SHA256
- **Password input:** the master password's raw UTF-8 bytes (no Unicode
  normalization is applied by the app)
- **Salt:** raw bytes from base64-decoding the backup's `salt`
- **Iterations:** the backup's `iterations` field, or `600000` if absent
- **Output:** 32 bytes (256 bits), used *directly* as the AES-256-GCM key
  (no further HKDF/expansion step)

Equivalents:
```js
// Node.js
crypto.pbkdf2Sync(password, saltBytes, iterations, 32, 'sha256')
```
```python
# Python
hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, iterations, dklen=32)
```
```js
// Browser (what the app itself does)
const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
  keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
);
```

### 3.2 Argon2id — legacy only (optional to implement)

Only relevant if `kdf === "argon2id"` (backups from before the app switched
to PBKDF2-by-default). Parameters, matching the `argon2-browser` library the
app uses:

- type: Argon2id
- parallelism: 1
- time (iterations): 3
- memory: 65536 KiB (64 MiB)
- hash length: 32 bytes
- salt: same raw bytes as above

**Recommendation:** a read-only importer can reasonably skip Argon2id
support entirely and just reject such backups with "please re-open this
backup in Keys first to upgrade it" — the app itself auto-upgrades any
Argon2id vault to PBKDF2 the moment it's next unlocked or restored, so
Argon2id backups are a shrinking, legacy-only case.

## 4. Encryption of each secret value

- **Cipher:** AES-256-GCM, key = the 32 bytes from §3, **no AAD**.
- Every individual secret value is encrypted **separately** (not the backup
  as a whole), each with its own fresh random **12-byte IV**.
- The ciphertext is exactly what `crypto.subtle.encrypt` produces: raw
  ciphertext with the 16-byte GCM authentication tag **appended** (the
  standard WebCrypto / "combined" convention — not a separately-stored tag).

Stored shape, used identically for every entry type:
```json
"encrypted": { "iv": "base64, 12 bytes", "ct": "base64, ciphertext+16-byte tag appended" }
```

Decrypt: `AES-256-GCM-Decrypt(key, iv, ct)` → raw bytes. GCM authentication
failure (wrong password, or the file was tampered with) must throw/fail —
treat that as "incorrect master key or corrupt backup," never as empty data.

**To verify a candidate master password** before trusting it: derive the
key, then attempt to decrypt `entries[0].encrypted`. Success (including the
edge case of zero entries, where there's nothing to check) means the
password is accepted.

For all types **except** `file`, decrypt → UTF-8-decode the bytes to get a
string (which for `env`/`billing`/`crypto` is itself JSON — see §6). For
`file`, the decrypted bytes **are** the original uploaded file, byte-for-byte.

## 5. Entry object

```json
{
  "id": 1,
  "name": "GitHub",
  "tag": "work",
  "type": "pw",
  "tabId": 1,
  "created": 1759000000000,
  "updated": 1759100000000,
  "encrypted": { "iv": "...", "ct": "..." }
}
```

`type: "file"` entries carry three additional **plaintext** (unencrypted)
fields alongside `encrypted` (which holds just the raw file bytes):
```json
{ "mimeType": "application/pdf", "fileName": "contract.pdf", "size": 48213 }
```

| field | type | notes |
|---|---|---|
| `id` | integer | Original IndexedDB key. **Don't treat as a stable external identifier** — the app itself discards and reassigns fresh ids on every restore. |
| `name` | string | Plaintext display name. Not encrypted. |
| `tag` | string | Plaintext free-form label, `""` if unset. Not encrypted. |
| `type` | string | One of: `pw`, `key`, `cert`, `env`, `file`, `billing`, `crypto`. |
| `tabId` | integer | References a Tab's `id` (§7). May be absent on very old entries — treat as uncategorized. |
| `created` / `updated` | integer (epoch ms) | Informational. `updated` only present if the entry was ever edited. |
| `encrypted` | object | Per §4. |
| `mimeType`/`fileName`/`size` | — | `file` entries only; plaintext. |

## 6. Per-type decrypted content

| `type` | decrypted content |
|---|---|
| `pw`, `key`, `cert` | Plain UTF-8 text — the secret itself (password, key material, cert PEM, …). Opaque; store/display as-is. |
| `env` | JSON object, flat string→string map: `{"API_KEY":"...", "DB_URL":"..."}` |
| `file` | Raw binary — the original file, unmodified. |
| `billing` | JSON object, see §6.1 |
| `crypto` | JSON object, see §6.2 |

### 6.1 `billing`

```json
{ "day": 15, "month": 3, "cycle": "annually", "price": 49.99, "reminderDays": 7 }
```

| field | type | notes |
|---|---|---|
| `day` | integer 1–31 | Day-of-month the bill renews. |
| `month` | integer 1–12 or `null` | **Required when `cycle === "annually"`**; irrelevant when `"monthly"` (recurs every month on `day` regardless of month). |
| `cycle` | `"monthly"` \| `"annually"` | |
| `price` | number | No currency field — just a number (app assumes a single implicit currency). |
| `reminderDays` | integer | Days-before-due to flag as "coming up." Defaults to `7` if absent. |

**Legacy format** (entries created before `day`/`month` existed) instead have:
```json
{ "renewalDate": "2026-03-15", "cycle": "annually", "price": 49.99, "reminderDays": 7 }
```
If `day` is absent but `renewalDate` is present, derive
`day = date.getDate()`, `month = date.getMonth() + 1` from it and discard
the year — the year is never semantically meaningful for a recurring bill.

**Computing the next due date** (never stored — always computed from
"today"): find the next occurrence of `day` in the current month (monthly)
or in `month` of the current year (annually), clamping to that month's
actual last day (e.g. day 31 in February → the 28th/29th). If that date has
already passed, advance to next month (monthly) or next year (annually).
There is no "overdue" state by design — the computed date is always today or
in the future, which is also what fixes the classic bug of a reminder
getting stuck on a date that's already passed.

### 6.2 `crypto`

```json
{ "coin": "xrp", "address": "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh", "memo": "104598" }
```

| field | type | notes |
|---|---|---|
| `coin` | string | One of: `btc`, `ethereum`, `xrp`, `usdt`, `monero`, `bnb`, `tron`, `solana`. |
| `address` | string | The wallet address. |
| `memo` | string | Secondary identifier. **Only meaningful for `xrp`** (numeric destination tag) **and `monero`** (16- or 64-hex-char payment ID) — `""` or absent for every other coin. Always a field *separate* from the address; never concatenate it into the address string. |

Address format reference (lenient sanity-check patterns, useful if you also
want to validate on write — not required just to read):

| coin | pattern (JS regex) |
|---|---|
| `btc` | `^(1[1-9A-HJ-NP-Za-km-z]{25,34}\|3[1-9A-HJ-NP-Za-km-z]{25,34}\|bc1[a-zA-HJ-NP-Z0-9]{25,90})$` |
| `ethereum` | `^0x[a-fA-F0-9]{40}$` |
| `xrp` | `^r[1-9A-HJ-NP-Za-km-z]{24,34}$` |
| `usdt` | `^(0x[a-fA-F0-9]{40}\|T[1-9A-HJ-NP-Za-km-z]{33}\|[1-9A-HJ-NP-Za-km-z]{32,44})$` (ERC-20 / TRC-20 / Solana-style) |
| `monero` | `^[48][0-9A-Za-z]{94}$` |
| `bnb` | `^(0x[a-fA-F0-9]{40}\|bnb1[a-z0-9]{38})$` |
| `tron` | `^T[1-9A-HJ-NP-Za-km-z]{33}$` |
| `solana` | `^[1-9A-HJ-NP-Za-km-z]{32,44}$` |

`xrp` memo validation: `^\d{1,10}$` (or empty). `monero` memo validation:
16 or 64 hex characters (or empty).

## 7. Tab object

```json
{ "id": 1, "name": "Personal", "created": 1759000000000, "order": 2, "favorite": true }
```

| field | type | notes |
|---|---|---|
| `id` | integer | Referenced by `Entry.tabId`. Reassigned on import — don't treat as stable. |
| `name` | string | Plaintext tab name. |
| `created` | integer (epoch ms) | Informational. |
| `order` | integer | Optional. Only meaningful if the source vault's sort mode was "manual" (see §8 — the mode itself isn't exported). |
| `favorite` | boolean | Optional. Pins the tab to the top of the list. |

## 8. What's intentionally NOT in the backup

The following are vault-local UI/runtime state, kept only in the browser's
IndexedDB `meta` store, and are **never** part of the exported JSON:

- tab sort mode (`alpha` vs `manual`) — a restored vault always defaults to
  alphabetical sort, regardless of the source vault's setting (`tabs[].order`
  values are still present and preserved, just inert until sort mode is
  switched to manual again)
- failed-login attempt counters / rate-limit state
- last-sync timestamp, grid/list view preference

## 9. Filename convention

```
${APP}-${VERSION}-$(date -u +%Y%m%dT%H%MZ).json
```
e.g. `keys-v2.1.0-20261013T0930Z.json`. Cosmetic only — not parsed on import;
any `.json` file with the right structure works.

## 10. Reference pseudocode

```
function decryptBackup(backup, masterPassword):
    kdf        = backup.kdf or "argon2id"
    iterations = backup.iterations or 600000     # only used if kdf == "pbkdf2"
    salt       = base64_decode(backup.salt)

    key = kdf == "pbkdf2"
        ? pbkdf2_hmac_sha256(masterPassword, salt, iterations, dklen=32)
        : argon2id(masterPassword, salt, t=3, m_kib=65536, p=1, dklen=32)  # legacy only

    tabs_by_id = { t.id: t for t in backup.tabs }   # may be empty on very old backups

    decrypted = []
    for entry in backup.entries:
        iv = base64_decode(entry.encrypted.iv)
        ct = base64_decode(entry.encrypted.ct)      # ciphertext || 16-byte GCM tag, combined
        raw = aes_256_gcm_decrypt(key, iv, ct)       # MUST raise on auth failure

        if entry.type == "file":
            content = raw                            # original file bytes, as-is
        else:
            text = utf8_decode(raw)
            content = json_parse(text) if entry.type in ("env", "billing", "crypto") else text

        decrypted.append({ **entry, "content": content, "tab": tabs_by_id.get(entry.tabId) })

    return decrypted
```

## 11. Security notes for implementers

- Never log, transmit, or persist the master password or the derived key.
- Treat a GCM authentication failure as "wrong password or corrupted file" —
  never fall back to using unauthenticated/partial plaintext.
- Use a cryptographically secure RNG (not `Math.random`/`random.random`) for
  any *new* salts or IVs your app generates — never reuse a salt or IV from
  an existing backup for new data.
- If you also want to **write** backups Keys itself can restore: use
  PBKDF2-SHA256 with `iterations >= 1200000`, set `"kdf": "pbkdf2"`, and
  populate `"iterations"` explicitly. Don't emit `"kdf": "argon2id"` for new
  data — Keys only reads that for backward compatibility.

## 12. Worked example

A backup with one `pw` entry and one `billing` entry, in a single tab:

```json
{
  "version": "v2.1.0",
  "kdf": "pbkdf2",
  "salt": "qf3Zt8m8c9n0y8s1gkQz1A==",
  "iterations": 1200000,
  "ts": 1760200000000,
  "tabs": [
    { "id": 1, "name": "Personal", "created": 1760000000000, "favorite": false }
  ],
  "entries": [
    {
      "id": 1, "name": "GitHub", "tag": "work", "type": "pw", "tabId": 1,
      "created": 1760000001000,
      "encrypted": { "iv": "Zm9vYmFyYmF6", "ct": "base64-ciphertext-plus-tag==" }
    },
    {
      "id": 2, "name": "Netflix", "tag": "", "type": "billing", "tabId": 1,
      "created": 1760000002000,
      "encrypted": { "iv": "cXV1eHF1dXg=", "ct": "base64-ciphertext-plus-tag==" }
      // decrypts to: {"day":15,"month":null,"cycle":"monthly","price":15.99,"reminderDays":7}
    }
  ]
}
```
