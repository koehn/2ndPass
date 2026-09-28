> Superseded for format and storage by [Vault v7](VAULT-V7.md). The material below records the v6 design and validation history.

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

# 2ndPass next vault architecture

**Onboarding update:** Recovery is optional. A vault starts with one owner device
and no recovery recipient. An authorized owner can add hardware recovery later,
including access to existing secrets. Without a surviving authorized device or
configured recovery device, access is lost. iCloud discovery is an untrusted
enrollment hint, never device approval. No format compatibility layer is used.


Proposal written before production changes, 2026-09-25. This is the intended
replacement for v5, not a description of shipped behavior. Existing v5 data,
Keychain items, backups, and cloud zones must remain untouched. No migration,
dual reader, or sharing on v5 is planned. Implementation and acceptance status
belong in `VAULT-NEXT-VALIDATION.md`; incomplete gates must remain visible.

**Confirmed product decision (2026-09-25): hardware-only recovery.** No portable
software recovery private key, private-key export/import, or software fallback is
part of v6. The initial portable-recovery alternative was rejected by the user;
the experimental implementation was removed before application integration.

## Recommendation and alternatives

Use device-generated Secure Enclave P-256 encryption and signing keys, CryptoKit
HPKE for individual key envelopes, AES-256-GCM for the catalog and records, and
signed, parent-linked revisions published by a conditional CloudKit head update.
Use one CloudKit zone per vault, privately owned until shared through CKShare.
One owner account administers the vault; other accounts are editors or viewers.
A personal vault is precisely a vault with one account member. Device approval
is explicit, even for another device on the same Apple Account.

| Design | Benefit | Reason to choose/reject |
| --- | --- | --- |
| Synchronized account software private key | Easy enrollment | Reject: long-lived private key reaches every application process and prevents individual device revocation. |
| Enclave-wrapped software account private key | Smaller storage change | Reject: the account private key still enters application memory on unlock. |
| Enclave devices wrapping a shared vault master key | Few envelopes | Reject: retaining the master key enables bulk decryption without further hardware operations. |
| Enclave devices with a wrap per catalog/secret key | Established constructions, bounded key exposure | Choose; storage grows with secrets × devices and enrollment requires an online authorized device. |
| MLS or custom group ratchet | Efficient large dynamic groups | Defer: substantially more state and recovery complexity than a small password vault needs. |

No custom ECDH/HKDF encryption protocol is needed: CryptoKit's HPKE suite
`P256_SHA256_AES_GCM_256` already supports Secure Enclave recipient keys.
Use independent encryption and signing keys rather than sharing a P-256 scalar.

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
Subsequent devices and invited accounts exchange a full fingerprint/QR over an
independent authenticated channel. Owner approval signs the exact device request
and vault checkpoint. The recipient verifies the owner's fingerprint/checkpoint
independently before pinning. Never trust a public key simply because CloudKit
returned it. New devices require an owner device or recovery, not just account
login. Keep private local trust separate from cloud discovery metadata.

## Membership and invitation state machine

There is exactly one owner account. Owner devices can invite, grant/revoke
devices, change roles, rotate recovery, and remove accounts. Editors can change
contents; viewers can decrypt. Neither can change membership. An account role
applies to its explicitly approved device list. No implicit delegation from a
member's newly discovered device. Owner transfer is a separate recovery/export
operation into a new owner zone, since CloudKit zone ownership is not assumed
transferable.

Invitation states: prepared, transport invited, transport accepted, key request
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

For an approved device, an owner opens each current catalog/secret key once and
creates an HPKE envelope for the new device. No existing plaintext value needs to
be decrypted merely to add a recipient. Publish all envelopes and the owner-signed
membership in one revision. Enrollment grants current contents, not arbitrary
historical revisions. An offline owner cannot approve a device. New owner devices
are enrolled per vault; account login does not imply access to every vault.

Removing an account removes all its devices. Removing a device removes only its
key pair. Removal rotates the catalog key and **all current secret keys**, reseals
each current record, and omits removed recipients. Recovery recipient changes
require the same rotation. New values always receive fresh IDs/keys. The new
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

When recovery is configured, use a separate hardware recovery device with its own device-generated Enclave
P-256 encryption and signing keys. The recovery slot contains only its public
keys. Enroll it with the same independent fingerprint verification as a normal
device, but give it explicit recovery authority instead of ordinary member roles.
Keep that device secure and available offline. Private key representations are
not portable backups. There is no recovery seed/private-key file and no software
private-key provider in the v6 module.

A hardware recovery device can decrypt an accessible snapshot and sign a recovery
transition, enrolling a replacement owner device and replacing the recovery
recipient. Rotate every current secret/catalog key and remove all old devices.
Proof of possession establishes the signing key, not hardware attestation or
physical separation. 2ndPass cannot cryptographically prove that the recovery key
was generated on a different physical device through these APIs; the operator
must keep an independently verified recovery device. Multiple keys on one Mac
are not protection against losing that Mac.

Losing one device: approve a replacement from an existing owner device and revoke
the lost one. Losing a viewer/editor's devices: ask the owner to enroll another.
Losing all ordinary owner devices: use the separate hardware recovery device,
independent checkpoint, and accessible encrypted backup/cloud snapshot. Losing a
recovery device while an owner device survives: enroll a replacement recovery
device and rotate every key.

Losing Apple Account access: a hardware key does not restore CloudKit transport
access. With an accessible encrypted backup and a surviving authorized recovery
device, create a recovered vault in a new account/zone with a new UUID/root,
rotate keys, and reinvite members. Never overwrite/delete the original vault.
The surviving device can operate on the backup while offline; publication into
the destination account requires that account's authenticated transport.

Losing **every authorized and recovery device** makes decryption impossible,
even with the encrypted backup, Apple Account access, or support intervention.
This is the user-selected security tradeoff. Without an accessible snapshot,
hardware keys alone cannot recreate data. There is no support backdoor or
portable recovery exception. Existing v5 recovery files are preserved but are
not accepted by the v6 implementation.

## Format, signatures, and publication

Use an incompatible `mop-vault-v6` namespace, new domain strings and state
namespace. Encrypted backups contain only v6 documents and public trust evidence.
Header contains vault UUID, format, generation, parent digest, membership epoch,
member/device roster, recovery public keys, and encrypted-key envelopes. Metadata
exposure includes vault name, public membership graph, device keys, size/timing.
Catalog contains item metadata/references; each concealed value has an independent
record. Limit document size, members, devices, record count, and ancestry work.

HPKE context binds format, vault, epoch, recipient fingerprint, purpose, and
record UUID. AES-GCM associated data binds equivalent object identity; catalog
AAD additionally binds header and complete record-table digest. Signatures cover
the entire canonical revision (excluding signature) with a format-specific domain.
Sort dictionary keys and set-valued arrays and reject duplicates before signing.
Use SHA-256 content hashes and raw P-256 ECDSA signatures. No unsigned role fields.

Validate an ordinary revision's signer and authorization against its validated
**parent**, not just its self-declared roster. Contents-only revisions must retain
membership. Membership changes require a device that was an owner in the parent,
or the parent's recovery authority for explicit recovery. Genesis needs a pinned
independent root. Validate exact parent hash and incrementing generation/epoch;
reject unauthorized self-promotions, new recovery keys, and revoked signers.
Fresh-device approval carries a verified checkpoint; follow its signed descendants.
Local generation/digest watermarks reject observed rollback and same-generation
substitution, but do not prove global freshness.

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

## Memory and existing bypass paths

Use short synchronous unwrap/consume scopes. Wipe owned HPKE-returned Data after
constructing the transient SymmetricKey; release each key before the next record.
Do not cache secret keys. Decrypt catalog on demand and discard its key; retaining
decrypted catalog for an unlocked UI is distinct from retaining a master key.
Swift/CryptoKit copies, strings, framework buffers and subprocess environments
cannot be comprehensively erased. Memory wiping is best effort, not a guarantee.

Replace these paths as one coordinated release:

- `UserIdentity.AccountIdentity`, `CloudIdentity.accountIdentity`, and
  `SynchronizedIdentityStore`: remove software account-key loading/creation from
  production; leave existing Keychain items untouched.
- `VaultSession` owner casts, `adoptOwner`, creation, trust bootstrap, restore,
  and cached catalog key: use device authorization and parent-verified membership.
- `CommandVaultAuthorization`, CLI init/import/recovery, `VaultService.Worker`,
  AutoFill extension/service and any noninteractive retrieval: same hardware key
  provider and OS ACL; no separate synchronized-key shortcut.
- `VaultDocument`, CloudManifest, CloudVault trust/history, CloudRepository
  discovery/cache, AppleCloudTransport: strict v6 validation and full shared-zone
  address. Restoring contents never restores old grants.
- Test-only software keys belong in test/prototype code and must not be a runtime
  feature flag, unavailable-hardware fallback, or shipping UI fixture.

Copied plaintext and previously unwrapped keys cannot be revoked. An authorized
compromised process may ask the Enclave to decrypt while the OS permits it and
may exfiltrate results. Hardware protection prevents exporting the device private
scalar, not misuse of its authorized operations. Neither signatures nor CloudKit
permissions prevent an authorized reader sharing passwords outside 2ndPass.

## Staged implementation and release gates

1. Standalone prototype: compile HPKE with Enclave recipients; exercise creation,
   representation reload, signing, wrong context, lock/cancel, and no-interaction
   access. Probe real CKShare owner/participant addresses and CAS behavior using
   disposable explicitly named test zones. Never silently touch existing zones.
2. Implement strict format, hardware provider, membership/transition validator,
   scoped cache and shared transport. Switch app/CLI/AutoFill together; no v5
   sharing interim and no migration layer.
3. Automated two-account/four-device model exercises enrollment, roles, removals,
   recovery, malicious transitions, conflicts and dropped acknowledgements.
   Separately run signed physical Mac/iOS and two actual Apple Accounts.
4. Shared service-backed CLI/UI for requests, approval, invitations, acceptance,
   member/device lists, removal progress, recovery, and conflict resolution.
5. Replace current security/user docs only when implementation warrants their
   claims. Record exact commands/results and outstanding physical acceptance.

Do not count software fixtures as Secure Enclave, biometric, Keychain sync,
CloudKit permission, delivery, or multi-account evidence. A prototype failure is
a platform/integration finding to resolve, not permission to ship software keys.

## Automatic own-account device enrollment implementation

Same-account requests, invitations, acceptance and approved encrypted checkpoints
now travel through a bounded private-zone iCloud mailbox. An enrolled owner
compares the 96-bit SHA-256 transcript code with the new device and approves.
The new device explicitly confirms that match locally before pinning a root;
a server-provided approval or confirmation field cannot establish bootstrap
trust. This reuses signed invitation/acceptance and conditional membership
publication, with no private-key transport or automatic approval on account login.
Other-account sharing remains a separate permission/invitation flow.
See CLOUDKIT.md for schema, bounds, concurrency and metadata exposure.

### Device removal lifecycle (2026-09-26)

Settings on all Apple platforms and `2ndpass vault devices` share account-device
management. Removal spans the private vaults locally enrolled on the managing
device, with preflight last-owner checks and independently journaled publications.
It is not an atomic account-wide CloudKit transaction and does not affect unknown
vaults. Signed membership accumulates retired device UUIDs; membership and recovery
revisions preserve that set. Automatic or manual acceptance cannot reuse a retired
UUID. An explicit reconnect generates a new identity.

A verified revocation writes a durable account-local removal marker before deleting
the ordinary device Keychain record or caches. Cleanup is retryable; app/extension
operations and registry writes refuse the removed account. Checkpoint cleanup takes
per-vault leases and preserves lock inodes. Exported backups and separately scoped
hardware recovery keys are outside this cleanup. The marker remains until an explicit
Reconnect action. This supersedes the prior honest-client auto-readmission behavior;
account compromise can still enroll an attacker with fresh keys.
