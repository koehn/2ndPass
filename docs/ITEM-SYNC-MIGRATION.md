# Item vault implementation status

The app, CLI and AutoFill use the shared item-level service. See [architecture](VAULT.md) for encryption, persistence, device connection and synchronization; [validation](VALIDATION.md) for recorded acceptance; and [roadmap](ROADMAP.md) for remaining work.

Implemented: independently signed item records, transactional local saves/outbox, exact delivery receipts, exclusive synchronization ownership, automatic same-account connection, encrypted display catalogs, selective edits, retained history, trash/restore, portable backup/restore and password-check caching.

Remaining: conflict-review integration and physical concurrent-edit acceptance, cross-account sharing, device removal, account recovery, permanent vault deletion, general document import, credential-account management, independent attachment transport and bounded cleanup of retained staging/receipts/quarantine.

Local saves work offline. Background execution is opportunistic; pending work resumes when an authorized synchronization owner can run. Backup exports cannot currently certify complete remote inventory.
