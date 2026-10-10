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

Local commits also journal publication and account reconciliation operations. The runtime uses one durable application-work coordinator for setup reconciliation and deferred incoming records, with persisted retry deadlines; CKSyncEngine continues to schedule native transfers. Incoming record bytes (including materialized encrypted assets) are stored before application or change-token advancement. Missing membership is retried independently. Quarantine is scoped, deduplicated, and retains at most 32 MiB of payload per account. The pending inbox allows 256 MiB, or a single individually valid larger record; unapplied data is never evicted to make room.

Locking releases private-key authorization but permits already signed, encrypted uploads after public account, membership, and provisioning checks. Signing, admission, key repair, and content inspection still require an authorized session. Completed receipts expire after 30 days; a missing receipt means confirmation is unknown, never successful. Compact superseded-version markers survive receipt expiry to preserve replay protection.

The separate `ContentEnvelope`/`ContentKeyGrant` v3 primitives are experimental and are **not selected by current GUI/CLI/AutoFill storage or CloudKit records**. Current clients still use the v2 format described above and its enrollment/repair flow. The clean preview namespace cutover, incremental coordination transport, grant-backed sessions/recovery, and retirement of legacy sync UI remain outstanding; do not treat these primitives as a completed migration or release approval.

The opt-in preview store lives at `ContentPreview3/Content3.sqlite`. Its separate Core Data model adds indexed content-key metadata, grants, and missing-grant work. Opening it requires the preview layout and disables migration; using that layout with a legacy path fails. Model metadata also prevents a renamed or copied preview database from being opened by the legacy migration path. No startup code selects it yet. Local content, its outbox/receipt, exact randomized grant bytes, and membership/provisioning prerequisites share one transaction and the existing cross-process vault boundary. Grant preparation finishes locally without claiming delivery; exact grant acknowledgments record delivery separately. The key-authority checkpoint remains stable for additive admission and changes for revocation/recovery so missing access schedules rotation rather than obsolete-key grants. `GrantBackedContentStorage` derives that checkpoint from verified history and rejects invalid or mis-scoped content/grants before persistence.

The isolated v3 editing path signs the content author and the original key authority separately. Ordinary edits advance storage ancestry and logical revision while retaining the key generation and grants; additive enrollment supplies only a new recipient grant. Owner-authorized rotation changes the key and ciphertext while preserving the logical revision. Recovery-authorized admission also requires rotation. The historical authority path permits narrowly checked owner device removal for decryption, but obsolete keys cannot pass publication checks.

V3 reconciliation first authenticates versions and available ancestry. Missing proof retains both branches; it never chooses by generation alone. A known common ancestor suffices without downloading older unrelated history. Differing concurrent representations require authorized plaintext comparison; identical contents produce a supersession decision, not a delivery acknowledgment. Deletion versus editing stays in review. An offline edit can be regenerated on a server rotation only after proving that the server plaintext is unchanged from their common ancestor. The preview inbox now commits these decisions with receipt updates and a local-head/authority CAS. Competing branches reference immutable archived versions; an exact echo confirms its own receipt, while redundant predecessors or identical local contents become superseded. The authorized comparison session and publication permit are checked again at commit. GUI/CLI/AutoFill integration is still outstanding.


Independent item edits synchronize independently. Conflicting versions are preserved; unresolved conflicts block affected publication. Conflict-review integration and physical concurrent-edit acceptance remain release work. Background execution and notifications are opportunistic, not a delivery deadline.

## Same-account connection

Private vault discovery and device connection are automatic. Keep an existing device unlocked while another device joins. The authenticated private iCloud database is an explicit bootstrap trust channel. A joining device signs a scoped request; an existing device signs an additive membership successor and rewraps item keys. The joining device verifies its original request, authority history, scope and metadata decryption before installing trust. No human comparison or approval step is required.

Admission preserves concealed-field ciphertext while updating recipient wrappers. Durable staging and conditional membership publication make interrupted admission resumable. A signed record-count hint supports initial download progress; it is not proof of a complete remote inventory.

## Catalog and secret access

Lists use a device-encrypted display catalog: one device-wrapped catalog key per vault and independently encrypted rows bound to source item versions. The catalog includes visible/search metadata, including notes, but excludes passwords, OTP seeds, attachments and private-key contents. It is derived local data, excluded from cloud publication and portable archives. Damaged or outdated rows are rebuilt with transactional source-version checks.

Lock clears plaintext views and the session catalog key. Exact reads, edits, AutoFill and exports verify authoritative item state; partial display lists cannot establish completeness. Plaintext and temporary item keys enter authorized process memory during use.

## Backups and capabilities

Portable archives preserve locally available transferable items, fields, retained history, trash, attachments and software credential bytes. Each archive has an independent generated key. Restore creates a new owned vault; it does not restore device-local private keys or membership. The current exporter cannot certify complete remote inventory.

Same-account vaults, local editing, history, trash/restore, password checks, AutoFill, portable backup/restore, device removal, account recovery and signed permanent vault deletion use the V3 coordinator. Cross-account sharing remains outside this cutover. Ciphertext attachments travel with their item envelope.

See [CloudKit schema](CLOUDKIT.md), [portable cutover](ITEM-SYNC-MIGRATION.md), [validation](VALIDATION.md) and [roadmap](ROADMAP.md).

The content protocol separates immutable signed versions, conditional mutable heads and signed recipient key grants. Additive enrollment updates membership and grants without changing logical content revisions. Security transitions rotate affected keys while preserving unchanged logical content. The account coordinator journals prerequisites, transfers, incoming records and cleanup. Publicly verified prepared payloads may transfer while locked; secret-dependent work waits for unlock.

The shared item facade uses V3 content for catalog, reveal, editing, metadata, conflicts and portable archives. Import commits the complete vault, policy, grants, receipts and provisioning work atomically. Retrying the same pinned import preserves later edits. Export rejects unresolved branches and a changing local snapshot, and retains existing hardware-bound credential limits. Existing legacy stores and zones are preserved and accessed for export using the previous preview build.

The native adapter has a single content/grant transport path and no independent retry coordinator. Incoming bytes and downloaded assets become durable before engine checkpoints. Indexed dependencies replace whole-vault repair scans. Only committed membership heads advance pinned trust; discovery and immutable proposals are hints. Invalid signatures enter bounded quarantine. Identical logical content converges during an authorized session; different concurrent content and deletion/edit races remain reviewable branches.

Production activation requires independent cryptographic review, schema validation and signed physical device acceptance. Software and simulator checks alone do not establish these gates.
