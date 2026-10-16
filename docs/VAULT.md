# Item vault architecture

The app, CLI and AutoFill use `ItemVaultService`, a mandatory grant-backed session,
and one current content protocol. V2 item envelopes and their session/repository
entry points have been removed. There is no V2 reader, migration or fallback.

## Content and authority

`ContentEnvelope` encrypts and signs item components. `ContentKeyGrant` separately
wraps an item key for each authorized device or recovery recipient. The logical
catalog is `ItemContentCatalog`; edits use `ItemContentPatch` and vault settings
use `VaultMetadata`. Their content encoding is unchanged by the type extraction.
`ItemEditOrigin` records authenticated edit attribution.

Ordinary edits advance storage ancestry and logical revision while retaining the
key generation and grants. Additive enrollment supplies grants without changing
content. Device-removal rotation changes keys and ciphertext while retaining the
logical revision. Recovery-authorized admission also requires rotation. Historical
read authorization does not authorize publishing with an obsolete key.

Membership is an independently pinned, signed history. Discovery never installs
trust or replaces a pin. Existing membership formats and authorization rules remain
in use for enrollment, removal and recovery; they do not imply implemented
cross-account sharing.

## Persistence and synchronization

The shared App Group store remains `ContentPreview3/Content3.sqlite`, with model
identifier `MopContentPreview3`. Existing current-format stores, pending mutations,
receipts, recipient grants, enrolled identities and keys remain supported. Older
models are rejected before opening, with automatic migration disabled.

The Core Data model shape is deliberately unchanged. Some unused entity declarations
remain to preserve current-store compatibility; their retired behavioral APIs have
been removed. Shared transactions, pending mutations, receipts, indexes and version
and conflict value types serve the current protocol and are not V2 implementations.

One process holds the synchronization lease per account/database. Core Data commits
content, exact prepared grants, pending publication and receipts atomically.
CKSyncEngine transfers records; Core Data CloudKit mirroring is not used. Incoming
bytes are persisted before advancing transport checkpoints. Account, authority and
local-head checks guard application and publication. Retry deadlines survive restart.

Local saves work offline. GUI success means a local commit. CLI writes normally
wait up to 20 seconds for exact cloud receipts; `--local-save` returns after commit
and `--offline` prevents network use. A timeout leaves work queued and reports
receipt IDs; do not repeat the write. Receipt expiry means unknown delivery.

Already signed encrypted work can transfer while locked, subject to public account,
authority and provisioning checks. Signing, key repair and plaintext comparison
require authorization. Normal delivery does not require `sp vault sync`.

## Grants, conflicts and local caches

Recipient-specific zones are the only grant destinations. Content remains in its
current vault zone; there is no old-zone copying, migration cursor or maintenance
workflow. See [recipient grants](RECIPIENT-GRANT-ZONES.md).

Reconciliation authenticates ancestry and retains unresolved concurrent branches.
Generation alone never selects a winner. Plaintext equivalence requires an authorized
session; supersession is distinct from delivery acknowledgment. Conflict choices
are durable and checked against the exact reviewed local and remote versions.
Deletion versus editing remains an explicit conflict.

Catalog projections and password-health results are encrypted device-local caches.
Health cache writes publish no cloud records. Parent-version checks prevent stale
results; damaged derived caches can be recomputed. Lock clears authorized plaintext.
`LocalPasswordHealthEnvelope` and its existing cryptographic domains are intentional
survivors, not a second cloud item format.

## Product boundaries

Automatic same-account enrollment, recovery reconnection, device removal, vault
deletion, portable backups, native AutoFill, SSH text-key conversion and local
hardware credentials remain. General document import, cross-account sharing and
credential-account management are unimplemented roadmap requirements.

Portable archives use [version 2](formats/PORTABLE-BACKUP-v2.md). V1 archives are
unsupported. No cleanup operation resets devices, deletes live cloud data, changes
signing identities or deploys schema. Production review and physical iCloud/Secure
Enclave acceptance remain separate from software validation.
