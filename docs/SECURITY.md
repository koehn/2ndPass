> Current policy (2026-09-26): same-account device enrollment is automatic while
> an owner device is unlocked. This supersedes the manual comparison requirements
> below for own-account enrollment only. The private CloudKit mailbox is trusted
> for bootstrap identity: account/mailbox compromise can admit an attacker while
> an owner is unlocked, and a malicious mailbox can substitute an initial root.
> Signed ancestry remains enforced after pinning. Cross-account sharing retains
> explicit verification and approval. Hardware private keys remain nonexportable.
> Retired device UUIDs are blocked, and honest removed clients require explicit
> Reconnect with fresh keys. An attacker retaining iCloud access could still
> request admission under a new identity; revoke account access to prevent that.

# Security and key management

**Onboarding update:** Recovery is optional. A vault starts with one owner device
and no recovery recipient. An authorized owner can add hardware recovery later,
including access to existing secrets. Without a surviving authorized device or
configured recovery device, access is lost. iCloud discovery is an untrusted
enrollment hint, never device approval. No format compatibility layer is used.


Mop v6 coordinates device hardware protection and shared vaults. The application targets use `MopVaultNext` through `NativeVaultService`; the CLI, GUI, background verifier and AutoFill no longer link the old vault/cloud software-key targets. The old source files remain for historical reference, outside the package build graph. There is no old-format reader or migration. Existing user data is not deleted.

See the [architecture proposal and alternatives](VAULT-NEXT.md), [plain-language explanation](SECURITY-EXPLAINER.md), and [validation evidence](VAULT-NEXT-VALIDATION.md). Second-account participant behavior and signed iOS hardware acceptance remain unverified release gates.

## Keys and memory

Each device generates separate P-256 agreement and signing private keys in Secure Enclave. The implementation requires hardware availability; it never falls back to software private keys. Opaque device-bound key representations are stored in the non-synchronizable Data Protection Keychain with `WhenUnlockedThisDeviceOnly`. They are not portable private scalars or recoverable device backups.

Access control uses `privateKeyUsage` and `userPresence`. Mop preauthorizes an `LAContext` with device-owner authentication, then disables surprise interaction for key operations. The GUI may retain this authorization context until lock/expiry; CLI sessions end with their command; AutoFill starts fresh authorization and locks after each fill. Providers release all key handles after operations. Session lock invalidates the context and generation, cancels work and rejects late results.

**Invalidating an LAContext is not established as revoking an already-used signing handle.** A real-host probe found signing still succeeded through such a handle. Mop therefore clears handles and independently guards its operation/session state. In-flight operations and submitted cloud mutations may finish; journals reconcile their outcomes.

CryptoKit HPKE (`P256_SHA256_AES_GCM_256`) wraps a distinct random 256-bit AES-GCM key for each record and for the catalog, separately to every approved device and any configured hardware recovery device. No vault-wide symmetric master key is retained. Reads open only the catalog and requested record. Adding devices unwraps/re-wraps record keys without opening values. Removing recipients rotates current records one at a time.

The Enclave protects private key generation/use; **AES keys, HPKE derived state, passwords and command inputs reach application memory**. Owned temporary Data/SecretBytes buffers are wiped where practical. Swift strings, Foundation/CryptoKit copies, allocator behavior and OS copies prevent a comprehensive erasure guarantee. Password-strength calculation also sees plaintext on an edit. No claim is made that AES or an entire password remains inside the Enclave.

## Identity and authority

An account identifier is a deterministic namespace derived from container, environment and CloudKit account record ID. It is not a private key. Each device has a distinct key fingerprint and device ID. Device requests bind account scope, purpose, both public keys and a proof-of-possession signature. Owners compare request fingerprints independently. This is not remote hardware attestation or proof of physical device separation.

There is exactly one owner account, with one or more approved devices. Editors write contents; viewers read. Only the owner's previously authorized devices may change ordinary membership. A personal vault has one member account and uses exactly the same access rules. Invitations bind a checkpoint, account, role, nonce and expiry; acceptance proves the device's signing-key possession; final owner approval wraps existing record keys to that device. Logging into an account and accepting CKShare do not themselves authorize device keys.

Cloud permissions are a separate boundary. Nonpublic zone-wide shares grant a participant read-only/read-write transport permissions. The application verifies participant/account bindings, actual shared-zone owner, container and environment; the default-owner alias is never accepted as a shared address. Unexpected identity mappings fail closed. Actual participant-side behavior still needs a second-account check.

Removal commits fresh keys/ciphertext before reconciling CloudKit permissions. A failed permission update is retried with `reconcile-share`; cryptographic removal already protects subsequent contents. Authorized malicious code can request hardware operations and retain results. Removed people can retain copied values or old ciphertext/keys. Rotation does not change a password at its external service.

## Integrity, synchronization and offline access

Canonical complete revisions are signed with a domain separator, parent hash, generation, membership epoch and roster. Verify the author against the verified parent, never its self-declared new role. AEAD and HPKE contexts bind vault/object/recipient/epoch; catalog authentication additionally binds the record table and header. Inputs and ancestry work are bounded.

Content-addressed CloudKit assets are immutable from the client's perspective. A head uses `ifServerRecordUnchanged` and real server change tags. Conflicting writes fail without automatic secret replay. A private atomic journal is persisted before submission. A dropped acknowledgement is resolved by verified ancestry; an unchanged head remains uncertain until an explicit conditional version barrier fences the old request. An OS file lease excludes other app/CLI/extension writers for that local vault.

Initial roots are persisted before publication. A submitted creation is reconciled using the same UUID/root; a missing head does not authorize resurrection. Local watermarks reject observed rollback and forks. No protocol here proves global freshness against a server withholding all new revisions, or guarantees availability against malicious transport writers.

Offline reads require a local independently pinned checkpoint, a prior account binding, and local hardware authorization. Known sign-out/restriction or an observed account change denies that binding. An offline client cannot discover unobserved account changes or remote revocation. Writes and membership operations require online validation. Cached plaintext passwords are not stored; catalog metadata may be held by the visible UI.

## Recovery, backups and disclosure

Recovery is optional and hardware-only. When configuring it, keep an enrolled recovery device separate and retain encrypted backups with independent checkpoint evidence. Same-account recovery replaces the roster using the recovery signature. Lost-account recovery decrypts a verified backup one record at a time into a new UUID/root under a new account, preserving the source. If all ordinary and recovery device keys are lost, backups/account restoration alone cannot recover the data.

Cloud-visible metadata includes vault name/UUID, public roster/key graph, ciphertext sizes and timing. Item names, field names, visible field values and deletion metadata are encrypted in the catalog. AutoFill intentionally publishes website/username/credential-kind locators to Apple's credential identity store; it re-resolves them from an authenticated catalog before filling. Clipboard and subprocess destinations receive plaintext by design.

Keychain access groups, provisioning and hardened-runtime validation limit which signed clients may use device representations. They are not a defense against compromised already-authorized code. No automatic data cleanup, conversion, key export or publishing deployment was performed for this change.

## Cloud enrollment approval

Own-account device requests travel through an untrusted iCloud mailbox automatically.
An existing owner device must compare the 96-bit transcript code shown on the new
device and explicitly approve. The new device must also confirm the code match
locally before pinning any root; the server cannot make that trust decision. Device names and Apple Account login are not
cryptographic approval. The mailbox never pins a trust root merely on discovery;
the receiving device validates the approved chain and invitation nonce before
registering the vault. The existing journal handles interrupted membership commits.
See [CloudKit enrollment](CLOUDKIT.md#automatic-own-device-enrollment) for bounds,
transport metadata and remaining live acceptance.

### Device removal and explicit reconnection (2026-09-26)

Removed device UUIDs are retained in signed membership and cannot be readmitted.
Own-account automatic enrollment rejects their old outstanding requests. An honest
removed client deletes its ordinary Keychain identity record (the stored opaque
Secure Enclave key representations), drops handles, clears managed account caches,
and persists a minimal removal marker. This is local deletion of usable key
references, not a claim of remote hardware erasure or proof of physical zeroization.
Separate hardware recovery identities and user-exported backups are not deleted.

The removal marker gates all normal account operations and survives relaunch.
Only explicit Reconnect clears it after successful cleanup; fresh keys then identify
a new device. This is not a ban on an adversary controlling the Apple Account:
they could create a new identity in another client and request automatic admission.
Offline clients retain historical access until learning of the signed revocation.
Cloud errors alone never authorize deleting a device identity.
