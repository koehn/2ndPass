# 2ndPass vault architecture

2ndPass uses device-generated Secure Enclave P-256 encryption and signing keys,
CryptoKit HPKE for item-key envelopes, AES-256-GCM for the catalog and fields, and
signed, parent-linked revisions published by a conditional CloudKit head update.
Each vault occupies a CloudKit zone, privately owned until shared through CKShare.
One owner account administers the vault; other accounts are editors or viewers.

See [Vault v7](VAULT-V7.md) for the wire format, [security and key management](SECURITY.md)
for the trust boundaries, and the [validation record](V7-VALIDATION-2026-09-27.md)
for measured results and remaining acceptance work.

## Verified platform boundary

Apple documents that Secure Enclave P-256 private keys are generated on the
device, cannot be imported as plaintext, and perform ECDH/signing without giving
the application the plaintext private scalar. This does **not** mean HPKE, AES,
derived symmetric keys, or decrypted passwords remain inside the Enclave.
HPKE's recipient API returns plaintext Data. The application must consume the
32-byte secret key to perform AES-GCM decryption. Passwords must reach 2ndPass,
AutoFill, the clipboard when requested, and authorized child commands.

References checked on 2026-09-25:

- [Apple: protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: Secure Enclave key agreement](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement)
- [Apple: HPKE recipient](https://developer.apple.com/documentation/cryptokit/hpke/recipient)
- [Apple: user presence access control](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
- [Apple: macOS Keychain implementations and entitlements](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Apple: CKShare](https://developer.apple.com/documentation/cloudkit/ckshare)
- [Apple: zone sharing sample](https://github.com/apple/sample-cloudkit-zonesharing)
- [Apple: conditional record saves](https://developer.apple.com/documentation/cloudkit/ckrecordsavepolicy/ifserverrecordunchanged)
- [Apple: atomic record operations](https://developer.apple.com/documentation/cloudkit/ckmodifyrecordsoperation/isatomic)

The installed Xcode CryptoKit Swift interface explicitly declares
`SecureEnclave.P256.KeyAgreement.PrivateKey: HPKEDiffieHellmanPrivateKey`, available
since macOS 14/iOS 17, below 2ndPass's minimum deployment targets. Compilation proves
API compatibility; hardware execution, OS prompts, context invalidation,
cross-process Keychain access, and real CloudKit sharing need separate evidence.

Persist only opaque Enclave key representations in non-synchronizable Data
Protection Keychain items, scoped to account/container/environment. Use
`WhenUnlockedThisDeviceOnly` plus `.privateKeyUsage` and `.userPresence` on the
keys. No fallback software device key. An unavailable Enclave blocks enrollment.
Reuse an LAContext for a bounded authorized session; invalidate it on lock,
account change, protected-data loss, and timeout, and close the operation provider
and discard all CryptoKit key handles. The local hardware probe found that an
already-created signing handle **still signs after context invalidation**. Thus
invalidation is not established as retroactive OS revocation of a handle. Every
provider operation needs an application-enforced closed/generation check and
bounded handle ownership. Do not promise a separate
biometric prompt for each secret or assume `evaluatePolicy` alone enforces key
use: the key's access control is the protection boundary. Biometry/passcode
fallback follows the OS user-presence policy. Test CLI, app, and extension access
under their actual provisioning profiles. A serialized Enclave representation
is not a portable recovery key and must not be treated as synchronized identity.

## Accounts, devices, and trust

An account is a stable opaque 2ndPass member UUID plus its authenticated CloudKit
participant identity in the container/environment. It groups roles and device
approvals; it has no decryption private key. Do not use names/email addresses as
cryptographic identity or assume an owner's private-database user ID is identical
to the identifier exposed in another participant's sharing context. Bind and
test the participant mapping during acceptance; keep display names separate.
The live owner-side probe confirmed that `CKShare.owner.userIdentity.userRecordID`
and `currentUserParticipant` use `__defaultOwner__`, while `CKContainer.userRecordID`
returns an opaque account record ID. This is a contextual alias, not a portable
account identifier. Normalize it only for a verified local owner/private-database
context; reject it as a shared-database owner address. Participant-side mapping
still requires a second actual Apple Account test.

A device identity contains member UUID, device UUID, encryption public key,
signing public key, and a proof-of-possession signature over a domain-separated
enrollment request. Its fingerprint hashes both keys and account binding. A
self-signature proves possession, not entitlement, hardware provenance, or that
the key belongs to the intended person. Ordinary Enclave keys offer no remote
attestation through this API; a malicious participant may submit software keys.

The first owner device signs genesis, which the creating device pins locally.
For another device on the same Apple Account, an unlocked owner automatically
processes enrollment through the private CloudKit mailbox. This channel establishes
initial trust; subsequent revisions must follow the pinned signed history.
Cross-account sharing requires independent fingerprint verification and owner
approval. Account login alone does not decrypt a vault: an enrolled owner must
publish key envelopes for the joining device.

### Apple Account authentication

Apple's [two-factor authentication](https://support.apple.com/en-us/102660), the
default for most accounts, protects a new-device sign-in with the account password
and verification through a trusted device or phone number. Optional
[Security Keys for Apple Account](https://support.apple.com/en-us/102637) strengthen
this against phishing. 2ndPass uses the operating system's authenticated iCloud
session; it does not collect the Apple Account password or verification code.

**Unfinished sharing design:** cross-account vault sharing is not yet implemented
as a supported feature. Preliminary code would share the mailbox's zone, so
account-private mailbox isolation must be addressed when completing sharing.
See [the design review](SECURITY.md#shared-zone-enrollment-exposure). This is not
classified as a current product vulnerability or a reason to add another approval
ceremony to ordinary same-account enrollment.

## Membership and invitation state machine

There is exactly one owner account. Owner devices can invite, grant/revoke
devices, change roles, rotate recovery, and remove accounts. Editors can change
contents; viewers can decrypt. Neither can change membership. An account role
applies to its enrolled device list. A discovered device gains access only after
an owner publishes its cryptographic grant. Owner transfer is a separate recovery/export
operation into a new owner zone, since CloudKit zone ownership is not assumed
transferable.

For the manual/cross-account flow, invitation states are: prepared, transport invited, transport accepted, key request
received, independently verified, cryptographically granted. Cancellation/expiry
before grant confers no key access. An invitation binds vault UUID, random nonce,
intended member UUID, role, expiry, and owner checkpoint. Acceptance signs that
invitation and the accepting device keys. Approval requires a current owner,
matching unused invitation, proof of possession, and fingerprint confirmation.
Replay, wrong vault/member/role, expired requests, and changed keys fail closed.
Do not include decryption keys in URLs or send invitations automatically.

Use CKShare with `publicPermission = .none`. Owner uses privateCloudDatabase;
participants use sharedCloudDatabase and the **actual ownerName** from accepted
metadata. Cloud addresses must include database scope and ownerName as well as
zone UUID; UUID alone is insufficient. Cloud permissions and 2ndPass roles must both
allow an action. A CKShare acceptance is not a 2ndPass membership grant. CloudKit
may expose historical ciphertext and metadata to a newly accepted participant.
Transport invitation and cryptographic membership are not one atomic transaction;
persist progress and reconcile them explicitly. Never claim completion from one
side alone. Viewers' request exchange may use exported request files/QR rather
than granting temporary CloudKit write permission.

## Device addition and removal

For an approved device, an owner opens each current item key once and creates an
HPKE envelope for the new device, preserving existing item envelopes and field
ciphertext. It decrypts the catalog, including visible values, and reseals it
with a fresh catalog key for the resulting revision. Concealed field plaintext
and attachment plaintext need not be decrypted merely to add a recipient. Publish all envelopes and the owner-signed
membership in one revision. Enrollment grants current contents, not arbitrary
historical revisions. An offline owner cannot approve a device. New owner devices
are enrolled per vault; account login does not imply access to every vault.

Removing an account removes all its devices. Removing a device removes only its
key pair. Removal rotates the catalog key and **all retained item keys**, reseals
each retained record, including recently deleted items, and omits removed recipients. Replacing an existing recovery recipient
requires the same rotation; adding the first recovery recipient only adds item-key
envelopes and reseals the catalog. Field edits receive fresh record IDs and nonces while preserving the item key. The new
membership epoch and all rotated ciphertext publish together at the head CAS.
Staging is not a committed removal. After CAS, revoke CloudKit transport access
where applicable; if that fails, report crypto removal complete/transport cleanup
pending. Device-level CloudKit access cannot be revoked independently when the
account remains authorized, so the cryptographic grant is essential.

An edit racing removal either commits first and is included in the rotation, or
loses CAS and must be rebuilt after reauthorization. Do not automatically retry a
stale edit with old recipients. A removed editor may still damage accessible
cloud storage; signatures prevent accepting its forged state, not denial of
service. A server fork or withheld newer state cannot be globally detected by an
isolated client. Cached old state remains readable offline.

## Recovery
The account-wide offline recovery authority is distinct from ordinary device
membership. A verified offline copy adds its public agreement and signing keys to
all owned vaults. New vaults inherit the configured authority. The
`offline-recovery-1` required feature prevents older clients from dropping it.

The `mop-account-recovery-v1` private CloudKit zone stores public configuration,
conditional-update versions, operation progress, and reserved encrypted genesis
records. Vault creation reserves its exact genesis before upload, fencing it
against key lifecycle changes. An interrupted reservation can be resumed without
the creating device. Each vault publishes membership and rotated data atomically;
account-wide replacement is resumable, not a cross-zone transaction.

Fresh-device recovery trusts authenticated private CloudKit for initial identity
and freshness, validates the available signed chain and account binding, then
opens the catalog using the offline key. Read-only access uses transient key
handles; it does not enroll the device or publish to AutoFill. Completion rotates
all retained data and adds the recovering device while preserving existing devices, accounts, and roles.
Missing attachment data leaves recovery incomplete and healthy fields readable.
The offline authority is retained after recovery.

Replacement/revocation rotates data one vault at a time. Retain both offline copies
until all vaults complete; signed membership is authoritative over progress
metadata. A copy of old ciphertext remains decryptable with its original key.
Apple Account recovery and backup restoration are separate and outside SALE-1.

## Format, signatures, and publication

The format is `mop-vault-v7`. The header identifies the vault, generation, parent
revision, membership epoch, members, devices, and recovery public keys. The
revision includes an encrypted catalog, field-record table, and item-key table.
Each item has a random AES-256-GCM key shared by its separately encrypted fields;
the catalog has a separate key. Each authorized recipient has an HPKE envelope
for every item key and the catalog key.

Field authenticated data binds the vault, item, item-key generation, and field
record. Item HPKE contexts bind the vault, item, generation, and recipient
fingerprint. Catalog authentication binds the header and record/key tables.
Signatures cover the canonical revision with a format-specific domain. SHA-256
content hashes and P-256 ECDSA signatures protect revision identity and authorship.
[Vault v7](VAULT-V7.md) specifies the format and storage namespaces.

Validate an ordinary revision's signer and authorization against its validated
**parent**, not just its self-declared roster. Contents-only revisions must retain
membership. Membership changes require a device that was an owner in the parent,
or the parent's recovery authority for explicit recovery. Genesis needs a pinned
independent root. Validate exact parent hash and incrementing generation/epoch;
reject unauthorized self-promotions, new recovery keys, and revoked signers.
Fresh-device approval carries a verified checkpoint; follow its signed descendants.
Local generation/digest watermarks reject observed rollback and same-generation
substitution relative to intact trusted local state, but do not prove global
freshness. They are files, not hardware monotonic state; restoring the whole
local trust store can remove evidence of newer observations.

Reuse immutable uploads + manifest + `.ifServerRecordUnchanged` head publication.
Journals bind the expected parent, operation ID, proposed revision, and membership
epoch. Persist before submission; reconcile uncertain results from committed
ancestry, never replay mutations blindly. No cross-zone atomicity is assumed.
An unchanged head after a timeout is still uncertain: the request may remain in
flight. Explicit reconciliation can conditionally save the unchanged head to
advance its server version, fencing the old request. The private-database live
probe verified that CloudKit advances the change tag and rejects a late save
using its former version. If a competing save wins first, refetch and verify its
ancestry. Do not clear a pending journal merely because the head is unchanged.
No CRDT or automatic secret merge: conflict retains the user's draft for explicit
refresh/reapply. Writes and membership operations require online authorization.
Offline reads use only previously verified snapshots, clearly showing staleness;
no offline enrollment or revocation guarantee. Notifications are refresh hints.

## Memory and client access

Item keys exist only in operation-local scopes. Owned temporary secret buffers
are wiped where practical; Swift strings and framework copies prevent a complete
erasure guarantee. The unlocked UI retains its decoded catalog and verified
encrypted records, not unwrapped item keys or a cache of concealed passwords.
All clients use the same hardware-backed authorization and membership checks.
Test-only software keys are not a runtime fallback.

## Validation

Automated tests cover membership transitions, key rotation, malformed records,
publication conflicts, and cancellation. Hardware authorization, signed Keychain
access, CloudKit permissions, and cross-account behavior also require physical
acceptance checks. See the [validation record](V7-VALIDATION-2026-09-27.md);
software fixtures do not substitute for platform evidence.

## Device removal lifecycle

Settings on all Apple platforms and `sp vault devices` share account-device
management. Removal spans the private vaults locally enrolled on the managing
device, with preflight last-owner checks and independently journaled publications.
It is not an atomic account-wide CloudKit transaction and does not affect unknown
vaults. Signed membership accumulates retired device UUIDs; membership and recovery
revisions preserve that set. Automatic or manual acceptance cannot reuse a retired
UUID. An explicit reconnect generates a new identity.
