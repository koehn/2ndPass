# Native application

The Mac, iPhone and iPad app uses `ItemVaultService` and the shared encrypted App Group store, also used by the CLI and AutoFill.

## Opening a vault

First-device discovery must finish successfully before an empty account offers vault creation. Existing same-account vaults connect automatically; keep an existing device unlocked. Connection, initial item download and local key preparation have separate progress states. Connected vaults can open locally while discovery continues.

Unlock authenticates access to device keys. Lists reopen from an encrypted display catalog and update from store notifications. Editing and sheets defer disruptive refreshes. Lock clears protected views and in-memory drafts.

## Editing and synchronization

Saves commit locally before cloud delivery and work offline. Pending work survives restarts. A local save is not a confirmed upload. Refresh, foregrounding, unlock and cloud notifications can resume synchronization. Conflicting data is preserved; conflict-review integration and physical acceptance remain unfinished.

Recent lists show the newest 50 active, unarchived items per category. Search filters those results. Usage timestamps stay device-local and are excluded from backups. History and Recently Deleted support explicit restore operations.

## Available workflows

Create/rename vaults, edit/read items, inspect history, trash/restore, check password health, use password/TOTP AutoFill and export/restore portable archives. General document import, account recovery, device removal, sharing, permanent vault deletion and credential-account management are unavailable.

See [backups](BACKUPS.md), [AutoFill](AUTOFILL.md), [architecture](VAULT.md) and [validation](VALIDATION.md).
