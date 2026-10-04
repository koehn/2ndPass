# 2ndPass portable backup format, version 1

This is a standalone recovery specification for `.moparchive` files produced by
2ndPass in October 2026. It intentionally contains enough information to recreate
a decoder after reverting the application source. It describes the portable
logical archive, **not** a v7 `.mopfile` checkpoint, CloudKit record or offline
recovery private key. The archive and its separate key file are both required.
Neither original device keys nor the original CloudKit zone are required.

Preserve this document with the backup instructions, separately from the key.
A second copy is retained under `dist/migration-preservation/` so an ordinary Git
checkout/reset does not remove the specification. `git clean -x` or deleting
`dist` can remove that copy; keep an external copy for long-term recovery.

## Binary container and key file

All sizes here are bytes; MiB means 1,048,576 bytes.

| Part | Exact representation |
| --- | --- |
| Header / authenticated additional data | UTF-8 `2NDPASS-PORTABLE-ARCHIVE-1` followed by one LF byte (`0a`), 27 bytes total |
| Nonce | 12 raw bytes, immediately after the header |
| Ciphertext | AES-256-GCM encrypted UTF-8 JSON; no compression |
| Authentication tag | Last 16 bytes of the file |
| Key text | Exact ASCII prefix `2ndpass-archive-key-v1:` followed by 64 hexadecimal digits representing the 32-byte AES key |

The whole file is `header || nonce || ciphertext || tag`. The **exact header,
including its newline**, is AES-GCM additional authenticated data (AAD). It is
not included in the encrypted plaintext. There is no salt, password derivation,
MAC outside GCM, signature, length word or trailing checksum. Generate a fresh
random 256-bit key for every export and a fresh 96-bit nonce; never reuse a nonce
with the same key. CryptoKit's `AES.GCM.SealedBox.combined` has precisely the
`nonce || ciphertext || tag` layout used here.

The key writer emits lowercase hex with no final newline. Readers accept upper
or lowercase hex and trim only trailing ASCII LF, CR, space and TAB bytes. The
prefix is case-sensitive; leading whitespace, a BOM, embedded whitespace and
nonhex characters are invalid. The key is **not a password** and is **not** an
account/device offline recovery key. Do not apply PBKDF2, SHA-256 or another KDF
to it. Decode the hexadecimal digits directly.

Maximum file size is 268,435,456 bytes (256 MiB). Minimum size is 55 bytes
(header plus nonce/tag); an empty JSON payload still fails document validation.
The maximum plaintext JSON size for a writer is 268,435,401 bytes. Reject a wrong
header or oversized input before allocating large decoded structures. Authenticate
GCM before interpreting any plaintext. A failed tag means wrong key or damaged
input; do not attempt partial or unauthenticated recovery.

## Decoder recipe independent of Swift

1. Read the key as bytes; apply the exact trimming/prefix/hex rules above.
2. Check the file's size and first 27 bytes.
3. Set `nonce = file[27:39]`, `ciphertext = file[39:-16]`, and `tag = file[-16:]`.
4. Decrypt AES-256-GCM using the decoded key, nonce, ciphertext, tag and the
   27-byte header as AAD. Libraries that accept ciphertext plus tag should receive
   `file[39:]`. For example, Python's `cryptography` AESGCM API accepts
   `AESGCM(key).decrypt(file[27:39], file[39:], file[:27])`.
5. Decode the authenticated bytes as UTF-8 JSON; validate version, limits and
   the reference graph described below. Reject invalid or missing structures.
6. Keep decoded record bytes exact, including newlines and NUL bytes. Never
   print decrypted JSON or key material to diagnostic logs. A rescue tool may
   write plaintext only to an explicitly requested protected destination.

The JSON writer uses sorted object keys and unescaped `/` characters. Neither
canonical ordering nor identical whitespace is required for reading: GCM
already authenticates the original byte sequence. Swift `Data` values are
standard padded Base64 strings. UUIDs are hyphenated strings; item IDs and record
IDs must use canonical uppercase UUID spelling. Swift `Date` values are JSON
numbers of seconds since **2001-01-01T00:00:00Z**, possibly fractional or negative,
not Unix seconds or ISO-8601 text. Add 978307200 to convert to Unix seconds.
Optional Swift properties are normally omitted when absent; readers may also
accept JSON `null` for optional fields. Never infer absent required fields from
Swift initializer defaults.

## Root JSON object

| Key | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Integer `1`; reject other versions |
| `name` | yes | Source vault name |
| `items` | yes | Array of item objects, including trashed/archived items |
| `itemIDs` | yes | Object mapping each exact item name to its stable UUID string |
| `references` | yes | Object mapping each current field's relative path to a record UUID string |
| `records` | yes | Object mapping record UUID strings to `{ "itemID": UUID-string, "bytes": Base64-string }` |
| `security` | no | History, credential-account metadata and optional derived scan cache |
| `exclusions` | yes | Array of informational strings describing things not restored |

The `bytes` of every record are the **logical plaintext field value** inside
the outer encrypted archive. They are not legacy vault ciphertext. Both visible
and concealed current fields have records; retained historical values have
separate records. Record IDs and item IDs live in separate namespaces and must
not be reassigned silently.

A minimal empty archive plaintext is:

```json
{"exclusions":[],"itemIDs":{},"items":[],"name":"restored","records":{},"references":{},"version":1}
```

A one-field example (synthetic secret `example`, Base64 `ZXhhbXBsZQ==`) is:

```json
{"exclusions":[],"itemIDs":{"Example":"11111111-1111-4111-8111-111111111111"},"items":[{"fields":[{"path":"password","type":"password"}],"name":"Example","type":"login"}],"name":"personal","records":{"22222222-2222-4222-8222-222222222222":{"bytes":"ZXhhbXBsZQ==","itemID":"11111111-1111-4111-8111-111111111111"}},"references":{"Example/password":"22222222-2222-4222-8222-222222222222"},"version":1}
```

## Items and fields

An item has required `name` (string), `type` (string), `fields` (nonempty array).
Optional keys are `deletion`, `autoFill`, `metadata`, `credential` as defined below.
`storageID` is a transient application projection and is **not serialized**.

Item type values: `login`, `password`, `apiCredential`, `secureNote`, `database`,
`sshKey`, `passkey`, `paymentCard`, `identity`, `document`, `custom`.

A field has required `path` and `type` strings. Optional keys:

- `value`: visible string projection; must be absent/null for concealed fields.
  The corresponding record remains the authoritative portable value.
- `historyID`: UUID identifying this field's entry in `security.histories`.
- `passwordQuality`: integer 0–4 (`veryWeak`, `weak`, `fair`, `strong`, `veryStrong`).
- `isTemplate`: Boolean; `label`: human-readable string.

`recordVersion` is a transient projection and is **not serialized**.

Field type values: `text`, `username`, `website`, `email`, `password`, `otp`,
`concealed`, `notes`, `recoveryCodes`, `privateKey`, `cardNumber`,
`expirationMonthYear`, `date`, `phone`, `attachment`, `bankAccount`, `address`.
Concealed types are `password`, `otp`, `concealed`, `recoveryCodes`, `privateKey`,
`cardNumber`, `attachment`, `bankAccount`, `address`.

A field path has one percent-encoded field component, or two components
`section/field`. A current reference key is `encode(item.name) + "/" + field.path`.
Encode components from UTF-8 bytes: leave only ASCII letters, digits, `-._~`
unescaped; encode every other byte as uppercase `%HH`. Components cannot be
empty or contain decoded NUL. Decoded names use Unicode NFC normalization; a
valid stored reference must exactly equal its re-encoded normalized form. A
reference has two or three components total and no URI prefix or vault name.
A literal slash inside a component is `%2F`, not a path separator.

Vault names are 1–63 UTF-8 bytes: lowercase ASCII letters/digits in nonempty
hyphen-separated segments (no leading/trailing/repeated hyphen).

### Optional item objects

- `deletion`: required `id` UUID, `originalName` string, `deletedAt` Date number.
  The previous application used a 30-day retention interval; restoring a backup
  must not silently discard expired trash or its records.
- `autoFill`: optional `username`, `password`, `oneTimeCode` strings identifying
  field paths. Absent/null means automatic selection.
- `metadata`: required `tags` array of strings, `favorite` Boolean, `archived`
  Boolean; optional Date numbers `createdAt`, `addedAt`, `updatedAt`; optional
  `source` object with required `provider`, `container`, `item` strings.
- `credential`: required `version` integer 1, `algorithm` (`ed25519`, `p256`,
  `rsa`), `publicKey` Base64, `purposes` array (`ssh`, `git-signing`, `passkey`).
  Optional `relyingParty`, `userName` strings and `userHandle`, `credentialID`
  Base64 data. Public key is 1–2048 decoded bytes; purposes are nonempty/unique.
  For a passkey, purposes must be exactly `["passkey"]`, algorithm `p256`, public
  key 65 bytes, relying party nonempty without `/` or `:`, user name nonempty,
  user handle 1–64 bytes, credential ID 32 bytes. Nonpasskeys omit all four
  passkey-specific properties. Software private material is in the concealed
  `credentialPrivateKey` field record; preserve its bytes unchanged.

## Field payloads and attachments

Treat record payloads as opaque bytes when transporting/restoring them. Text
fields normally contain UTF-8. Specialized fields may contain UTF-8 JSON; do not
flatten, normalize or reinterpret them merely to restore a backup. Preserve the
field type, public credential metadata and byte value together. This also
preserves software SSH/Git/passkey credentials without needing the old vault
ciphertext format or hardware key.

An `attachment` record contains UTF-8 JSON with required `fileName` (string) and
`data` (standard padded Base64 of original file bytes). File contents are limited
to 8 MiB. The filename is 1–255 UTF-8 bytes, cannot be `.` or `..`, and cannot
contain `/`, backslash or NUL. Never concatenate an untrusted filename into a
path without validation or overwrite existing files implicitly. Attachment bytes
are in this record; there are no external CKAsset URLs or sidecar files to fetch.

## Security metadata

`security`, when present, has required arrays `histories` and `accounts`, and an
optional `passwordChecks` array. All of it is inside the encrypted archive.

Each history object has required `id` (UUID), `itemID` (item UUID string), `path`
(field path), and `entries` array. Each entry has `id` (historical record UUID
string) and `replacedAt` (Date number). A history belongs to an existing field of
type `password` or `concealed`, and that field's `historyID` equals the history's
`id`. Retain the array order; at most 20 entries per field. Historical records
are not present in the current `references` map.

Each credential-account object has required `id` UUID, `service` string,
`account` string, `registrations` array and `recoveryMethod` string. Optional
keys: `linkedItemID` item UUID string, `relyingParty` string, `userHandle` Base64
(1–64 decoded bytes). Service and account must be nonblank. Each registration has
required `id` UUID, `protocolName`, `publicIdentifier`, `deviceID`, `deviceLabel`
strings, `external` Boolean and `state` string (`generated`, `confirmed`,
`removed`). Optional `localIdentityID` UUID, `confirmedAt` Date number,
`confirmedBy` string. Protocol names: `ssh`, `git-signing`, `x509`, `webauthn`,
`generic-signing`, `generic-ecdh`. Public identifier/device ID/device label must
be nonempty; confirmed entries require finite confirmedAt and nonempty
confirmedBy. Registration IDs are unique per account, at most 100 registrations
per account. Service/account/recoveryMethod and registration text fields are at
most 4096 UTF-8 bytes and contain no control characters other than newline.

Password-check objects contain required `record` string, `context` string array,
`weak`, `exposed` Booleans, `checkedAt` Date number, `scope` string, `evaluator`
integer, `batch` UUID; optional `breachCheckedAt` Date and `reuseGroup` UUID. They
are disposable derived results, not secret data. Restore discards this cache and
recalculates it; do not treat historical scan results as current security evidence.

Hardware credential registrations are informational: no Secure Enclave private
key or other device private scalar is exported. On restore, mark registrations
`external = true`; do not imply that their referenced private keys were restored.
Original enrollment, membership, CloudKit permissions and recovery authority are
not reinstated. The destination is a new owner-only vault with fresh encryption
and independently established authority.

## Required graph and size validation

- At most 65,536 items and 262,144 records; item names unique; `itemIDs` keys equal
  item names exactly; item UUID values unique and canonical uppercase.
- Field paths unique inside each item; each field has exactly one current
  reference. Current references have unique record IDs. Every referenced record
  exists and its `itemID` equals the owning item UUID.
- Field `historyID`s are unique globally. History IDs and `(itemID,path)` pairs
  are unique. Every historical entry record exists, belongs to that item, and
  is used only once across the entire current/history graph. Dates must be finite.
- The set of all records equals the set of current and historical referenced
  records: reject missing and orphaned records rather than silently dropping them.
- All record keys are canonical uppercase UUID strings. Each record has at most
  16 MiB decoded bytes; the sum of decoded record bytes is at most 256 MiB. The
  encrypted file limit and JSON encoding overhead may impose a tighter bound.
- Every current reference string is at most 4096 UTF-8 bytes. `exclusions` has at
  most 128 strings, each at most 4096 UTF-8 bytes. These strings are informational
  data, never commands or policy instructions.
- Credential-account IDs are unique. Any linkedItemID refers to an existing
  item. Check credential metadata as specified above.

A recovery implementation should preserve unknown optional metadata when it can
round-trip it. If it cannot represent a field type or required relationship,
stop with an explicit unsupported-format error; never claim a complete restore
while dropping secrets, histories or attachments.

## Restore and rollback procedure

1. Keep the original vault/archive/key unchanged. Use a distinct destination
   vault UUID/name; do not overwrite the source or reset its trust checkpoints.
2. Authenticate and validate the archive offline first. Report item/record counts
   without printing values. Validate all records, including history and trash.
3. Create destination authority from the current authenticated device. Reencrypt
   the decoded logical records for that destination; do not copy legacy key grants.
4. Persist the source archive digest (SHA-256 of the entire encrypted file),
   requested name and destination ID for retries. Persist authority before the
   atomic initial item transaction. Retrying must preserve committed later edits.
5. Read back the restored fields/history/attachments and test a representative
   sample before deleting any old source. Retain the source backup until real
   device/cloud acceptance is complete.

The original archive bytes need not be reproduced byte-for-byte by a new writer:
random key/nonce and JSON formatting will change the ciphertext. Logical contents
and graph preservation are the compatibility requirement. A Git rollback does
not require preserving the archive implementation itself: regenerate the reader
from this document, or use an older compatible export and repeat migration.
