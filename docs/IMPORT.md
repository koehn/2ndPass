# Import and restore

General password-manager document import is not connected to the current vault service. CSV, Bitwarden JSON and 1Password 1PUX parsers exist in the source, but their presence does not make application import available. See [import mappings](IMPORT-MAPPINGS.md) for parser details, not a supported end-to-end workflow.

The supported restore path uses an encrypted portable archive and its separate generated key. See [backup and restore](BACKUPS.md) for dry-run validation, resumable restore IDs, preservation rules and limits. Restoring creates an independent owned vault; connecting another device uses automatic same-account enrollment instead.

Portable restore preserves transferable fields, metadata, retained history, trash and attachment bytes. Device-local hardware keys cannot be imported or restored. Source password-manager exports contain plaintext secrets; retain access to the source until an integrated import workflow is available and verified.

Attachments in current items are encrypted inside the item envelope and synchronize with it, rather than downloading on demand. Opening/exporting decrypts local bytes after authentication. Independent attachment transport is planned.
