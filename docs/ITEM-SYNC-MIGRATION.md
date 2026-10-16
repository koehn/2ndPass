# Supported storage and archive versions

Only the current content/grant protocol is supported. Latest-format cloud vaults,
recipient grant zones, enrolled identities, keys and pending local work remain
supported across this cleanup. The store path, model identifier, Keychain services,
CloudKit identifiers and cryptographic domains remain unchanged.

V2 vault support has been removed. Older stores fail without migration or rewriting;
there is no compatibility reader, old grant-zone routing or automatic reset. Do not
copy an older database into the current store path.

Portable archive v2 is an independent backup contract. V1 archives and keys are
explicitly unsupported, with no conversion path. See [backups](BACKUPS.md) and the
[standalone v2 specification](formats/PORTABLE-BACKUP-v2.md).

Production connections still require `MOP_CONTENT_SYNC_V3_REVIEWED`. Physical
macOS/iOS, iCloud and Secure Enclave acceptance must be recorded independently of
software tests. This cleanup does not enable that gate or deploy schema.
