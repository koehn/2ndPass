# Vault v7

V7 replaces v6 without migration or a compatibility reader. Old cloud zones,
local checkpoints, attachment caches, device keys, and backups remain untouched.
Create a new vault and import the source document after updating all clients.

## Wire format

The canonical JSON revision retains the signed header, catalog, field `records`,
author, and signature, and adds an `itemKeys` map keyed by stable item UUID.
Each item key entry contains a positive `generation` and one HPKE envelope for
every current ordinary/recovery recipient. The field table remains flat for
lookup: each record carries its owning `itemID`; its `envelopes` map is empty.
The encrypted catalog contains `itemIDs` (name to UUID), `references` (path to
field-record UUID), and the existing typed item metadata. These mappings are
validated together; one item UUID cannot belong to multiple names.

Each item uses a random 256-bit AES key. Fields are independently AES-GCM sealed
with random nonces; authenticated data contains the v7 field domain, vault UUID,
item UUID, item-key generation, and field-record UUID. Item HPKE contexts contain
the v7 item-key domain, vault UUID, item UUID, generation, and recipient fingerprint.
Catalog keys are independent, freshly generated per revision, and remain bound
to membership epoch. Catalog authenticated data includes the header, record-table
digest, and item-key table. Signatures cover all three tables and the header.

Attachment records store ciphertext digest/size; loaded ciphertext is never
serialized into the revision. Backups include ciphertext blobs and use
`mop-attachment-backup-7`. Existing revision/blob/backup size limits remain.

## Operations

- Creating an item generates a key and generation 1. Editing a field preserves
  that key but generates a fresh field UUID and nonce. Unchanged records remain.
- Rename, trash, and restore preserve item identity and keys. Purge drops records
  and removes unused item-key entries.
- Enrollment unwraps each item key once and appends only new recipient envelopes.
  It does not load attachments or rewrite existing ciphertext/envelopes.
- Role-only changes preserve item key material entirely.
- Removal, replacement of an existing recovery recipient, and in-place recovery
  advance every item-key generation and re-encrypt all retained fields, including
  recently deleted items and attachments, under fresh keys. Recovery retains the vault UUID and offline authority.
- Item keys exist only within operation-local scopes. No shared plaintext key
  cache or vault master key is introduced. Temporary plaintext is wiped where
  practical; Swift/CryptoKit do not guarantee erasure of all copies.

An unwrapped item key exposes every field in that item. Cloud observers can see
opaque item grouping as well as record and recipient counts. Prior authorized
recipients can retain old plaintext, keys, or snapshots; removal protects newly
published ciphertext, not copies already obtained.

## Publication and isolation

Initial creation and ordinary publication share a four-task attachment uploader.
It validates all required blobs first, skips existing digests, drains outstanding
tasks on failure/cancellation, and must finish before revision upload and head CAS.
The existing publication journal still reconciles ambiguous head commits.
Downloads and hardware operations remain sequential. UI progress reports items,
then encrypted-file uploads and revision publication.

Cloud zones use `mop-v7-UUID` and record types `MopV7Revision`, `MopV7Attachment`,
`MopV7Head`, and `MopV7Enrollment`. Account-wide offline recovery additionally uses
`MopRecoveryConfiguration` in a separate private account zone. Probe zones are Development-only and excluded
from discovery. Account bindings, enrollment domains, Keychain services, local
state and AutoFill storage/identifiers use v7 namespaces. Application identifiers,
CloudKit container and entitlements are unchanged. An explicitly opened old
revision or backup returns an unsupported-format error.

## Validation and cutover

Run `swift test` for model, service, publication, and UI-model coverage. The opt-in
`profileDeviceRemovalScenarios` benchmark exercises the production v7 engine;
`ItemKeyProfileTests` remains a primitive-level comparison, not the production
format. Hardware timings and cloud probes require host authentication.

Install matching Mac/iPhone/iPad/AutoFill builds, create a new `personal` vault,
import the user's source file, then enroll mobile devices. Verify independent
mobile sync and offline-device removal. Old data is deliberately not deleted.
