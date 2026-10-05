# Item vault architecture

The app, CLI and AutoFill use `ItemVaultService`. Each cloud vault contains independently encrypted, signed item records. A shared device-local Core Data store commits each item change together with its pending upload and delivery receipt. CKSyncEngine transfers records; Core Data CloudKit mirroring is not enabled.

## Encryption and authority

Each device has independent Secure Enclave agreement and signing keys. Item keys are wrapped for authorized devices with HPKE. Concealed fields, retained history and attachments are encrypted separately inside the item envelope. Signed envelopes bind the vault, item, revision and exact signed membership authority. Per-item revision checks reject known older revisions and equal-revision forks; they do not prove the completeness or freshness of the entire cloud inventory.

Membership is a separately pinned, signed history. Device-only Keychain trust records bind the account, CloudKit container/environment, database, zone owner, vault and genesis. Discovery alone does not install trust or replace an existing pin.

## Item envelope format

`ItemEnvelope` uses format `2ndpass-item-envelope-2`. Its header contains `vault`, `item`, `version`, monotonic `generation`, stable `keyGeneration`, optional `base`, the exact signed membership-state digest and the author's fingerprint. The envelope contains `encryptedCatalog`, an `encryptedRecords` map, recipient `envelopes` and a signature over the header and ciphertext components.

Signature, catalog, recipient-key and record contexts have separate domains: `2ndpass-item-envelope-signature-2`, `2ndpass-item-envelope-catalog-2`, `2ndpass-item-envelope-key-2` and `2ndpass-item-envelope-record-2`. Recipient contexts bind membership and recipient identity; record contexts bind vault, item, key generation and record identity. Fresh edits can reuse unchanged ciphertext while assigning fresh changed-record identities. Revision generation is not encryption-key generation.

Verify against the independently selected destination vault/item and an independently pinned membership history. Never derive authority from the item's author-supplied roster. The implementation in `Sources/MopVaultNext/ItemEnvelope.swift` defines encoding and validation; the portable archive has a separate standalone specification.

## Local storage and synchronization

The App Group store partitions records and pending work by account/database/vault. One process holds the synchronization lease per account/database. The GUI normally owns it; the CLI requests work or acquires the lease. AutoFill uses the shared store without a competing long-lived engine. Each client authenticates separately.

Local saves work offline and survive restarts. GUI success means a local commit. CLI writes normally wait up to 20 seconds for their exact delivery receipts; `--local-save` returns after local commit and `--offline` prevents network use. A cloud timeout leaves work queued, reports receipt IDs and exits nonzero. Do not repeat a write merely because confirmation timed out.

Independent item edits synchronize independently. Conflicting versions are preserved; unresolved conflicts block affected publication. Conflict-review integration and physical concurrent-edit acceptance remain release work. Background execution and notifications are opportunistic, not a delivery deadline.

## Same-account connection

Private vault discovery and device connection are automatic. Keep an existing device unlocked while another device joins. The authenticated private iCloud database is an explicit bootstrap trust channel. A joining device signs a scoped request; an existing device signs an additive membership successor and rewraps item keys. The joining device verifies its original request, authority history, scope and metadata decryption before installing trust. No human comparison or approval step is required.

Admission preserves concealed-field ciphertext while updating recipient wrappers. Durable staging and conditional membership publication make interrupted admission resumable. A signed record-count hint supports initial download progress; it is not proof of a complete remote inventory.

## Catalog and secret access

Lists use a device-encrypted display catalog: one device-wrapped catalog key per vault and independently encrypted rows bound to source item versions. The catalog includes visible/search metadata, including notes, but excludes passwords, OTP seeds, attachments and private-key contents. It is derived local data, excluded from cloud publication and portable archives. Damaged or outdated rows are rebuilt with transactional source-version checks.

Lock clears plaintext views and the session catalog key. Exact reads, edits, AutoFill and exports verify authoritative item state; partial display lists cannot establish completeness. Plaintext and temporary item keys enter authorized process memory during use.

## Backups and capabilities

Portable archives preserve locally available transferable items, fields, retained history, trash, attachments and software credential bytes. Each archive has an independent generated key. Restore creates a new owned vault; it does not restore device-local private keys or membership. The current exporter cannot certify complete remote inventory.

Same-account vaults, local editing, history, trash/restore, password checks, password/TOTP AutoFill and portable backup/restore are connected. Cross-account sharing, device removal, account recovery, permanent vault deletion, general document import and credential-account management are unavailable. Independent attachment transfer remains planned; ciphertext travels with its item envelope.

See [security](SECURITY.md), [CloudKit schema](CLOUDKIT.md), [backup and restore](BACKUPS.md), [validation](VALIDATION.md) and [roadmap](ROADMAP.md).
