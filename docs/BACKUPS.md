# Portable backup and restore

Export a locally stored vault snapshot and keep its generated key separately:

```sh
sp vault backup --offline --vault VAULT_UUID /path/vault.moparchive --key-file /separate/path/vault.key
sp vault restore-backup /path/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID --dry-run
sp vault restore-backup /path/vault.moparchive --key-file /separate/path/vault.key --name restored --restore-id NEW_UUID
```

Generate a fresh UUID once and retain it for retries. Both archive and key are required. Output refuses to overwrite existing files. A dry run validates input without creating a vault. Restore creates an independent owned vault and preserves later edits on completed retries; verify restored contents before discarding the source.

Archives preserve transferable fields, item metadata, retained history, trash, attachment bytes and cloud software credential bytes. Hardware registration references are informational: Secure Enclave private keys cannot be exported or restored. Restore does not reinstate sharing, device authority or account recovery configuration.

The format is bounded at 256 MiB. Oversized or invalid archives fail rather than silently omit data. The exporter reads local inventory and cannot certify a complete remote inventory. Finish downloading and inspect the source before relying on an export; a successful export alone does not prove all remote items were present.

Retain an independent copy of the [portable archive specification](formats/PORTABLE-BACKUP-v1.md) with your recovery materials so a reader can be recreated without the installed app. Protect the archive key separately from the archive. Account-wide recovery of a live cloud vault is not currently available.
