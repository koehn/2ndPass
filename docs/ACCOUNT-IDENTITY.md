# Account and device identity

An account scope derives from the CloudKit container, environment and opaque account record ID. It is a namespace, not a decryption key.

Each device generates independent Secure Enclave agreement and signing keys. Device-only Keychain representations and the App Group store are shared by the signed app, CLI and AutoFill on that device; authentication remains per-client.

Same-account private vaults are discovered and connected automatically. Keep an existing device unlocked while admission completes. The private iCloud database is an explicit bootstrap trust channel: signed requests bind scope and device keys, and the joining device verifies the signed grant, original request and metadata decryption before pinning authority. Existing pins cannot be replaced by discovery.

An attacker with write access through the trusted account/container channel may gain admission when an existing unlocked device processes the request. Signing-key possession is not hardware attestation. Observed account changes invalidate local bindings; offline clients cannot observe remote changes.

Cross-account sharing, device removal and account recovery are unavailable. Portable restore creates a new vault from an archive and its separate key. See [security](SECURITY.md), [architecture](VAULT.md) and [backups](BACKUPS.md).
