# Document import requirements and supported restore

General CSV, JSON and 1PUX document import is unimplemented. Its parsers, planning
models, UI and commands have been removed. The [mapping requirements](IMPORT-MAPPINGS.md)
remain a future design reference; they are not evidence of an implemented feature.

Portable archive v2 restore is supported and creates an independent owned vault.
See [backups](BACKUPS.md). Automatic same-account enrollment connects another device
to an existing vault. SSH file import and explicit text-key conversion remain
supported separately; see [cloud credentials](CLOUD-KEY-CREDENTIALS.md).

Current attachments are encrypted item components. Opening or exporting decrypts
local bytes after authentication. Independent attachment transport remains planned.
