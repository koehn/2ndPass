# Account and device identity

An account scope derives from the CloudKit container, environment and opaque account record ID. It is a namespace, not a decryption key.

Each device generates independent Secure Enclave agreement and signing keys. Device-only Keychain representations and the App Group store are shared by the signed app, CLI and AutoFill on that device; authentication remains per-client.

Same-account private vaults are discovered and connected automatically. Keep an existing device unlocked while admission completes. The private iCloud database is an explicit bootstrap trust channel: signed requests bind scope and device keys, and the joining device verifies the signed grant, original request and metadata decryption before pinning authority. Existing pins cannot be replaced by discovery.

An attacker with write access through the trusted account/container channel may gain admission when an existing unlocked device processes the request. Signing-key possession is not hardware attestation. Observed account changes invalidate local bindings; offline clients cannot observe remote changes.

Cross-account sharing is unavailable. Device removal is a preview feature; membership exclusion and key rotation continue through the account coordinator, with physical acceptance pending. Account recovery is implemented; physical acceptance remains pending. See [recovery](OFFLINE-RECOVERY.md). Portable restore creates a new vault from an archive and its separate key. See [security](SECURITY.md), [architecture](VAULT.md) and [backups](BACKUPS.md).
