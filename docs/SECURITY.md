# Security and key management

This document describes 2ndPass v7's implemented security model, reviewed against the
source on 2026-09-26. For a user-oriented overview, see
[How 2ndPass protects your secrets](SECURITY-EXPLAINER.md). The
[validation record](VAULT-NEXT-VALIDATION.md) distinguishes implementation and
model tests from physical-device evidence. This document is not a claim of an
independent security audit or completed release acceptance.

The GUI, CLI, background verifier and AutoFill use `MopVaultNext` through
`NativeVaultService`. Historical software-key vault/cloud sources are outside
the application dependency graphs. There is no software device-key fallback,
old-format reader, or automatic migration in this implementation.

## Trust boundaries and threat model

2ndPass encrypts vault contents before uploading them, grants access to specific
device public keys, and verifies signed revisions against previously trusted
state. Its protections have distinct dependencies:

- **Device hardware and Apple platform security:** Secure Enclave protects device
  private-key operations; Keychain and code-signing access controls protect the
  stored device identity. 2ndPass relies on these implementations and local
  authentication, rather than implementing its own hardware security boundary.
- **Authorized 2ndPass code:** plaintext and temporary record keys enter the app's
  process. Code able to act as an authorized client can request permitted
  hardware operations and retain their results.
- **Apple Account and private CloudKit mailbox during same-account enrollment:**
  automatic enrollment trusts this channel for initial identity. An attacker
  controlling it can request admission while an existing owner's 2ndPass session is
  unlocked. A malicious mailbox can substitute a joining device's initial root.
- **Locally pinned state after enrollment:** signed ancestry and local checkpoints
  constrain later updates. They do not establish the authenticity of an initial
  root independently of its bootstrap channel, or prove that the server has
  supplied the newest revision.

CloudKit is Apple's application data service. Its transport permissions and 2ndPass's
cryptographic membership are separate controls. A stolen ciphertext copy alone
is insufficient to decrypt secrets; active account/mailbox control has the
additional enrollment consequences above. 2ndPass does not promise availability
against a malicious server, secrecy from an authorized recipient, or protection
of plaintext on a compromised endpoint.

## Hardware keys, Keychain and authentication

### What the Secure Enclave does

The Secure Enclave is an isolated hardware security subsystem. 2ndPass creates two
separate P-256 private keys per device: a key-agreement key used to open encrypted
item-key envelopes, and a signing key used to authenticate requests and vault
revisions. Private scalar values are not exported to 2ndPass. The shipping
`EnclaveDevice` provider requires `SecureEnclave.isAvailable` and has no software
fallback. Software key providers used in tests do not establish hardware behavior.

Apple's [Secure Enclave overview](https://support.apple.com/guide/security/sec59b0b31ff/web)
and [key protection documentation](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
describe the platform boundary. 2ndPass uses its P-256 operations; it does not run the
whole vault engine, AES record decryption, or the UI inside the Enclave.

### What is stored on the device

The Keychain is Apple's OS-managed credential store, distinct from the Enclave.
2ndPass persists opaque, device-bound representations of the two hardware keys in
the Data Protection Keychain. These are not portable private scalars or a
recoverable backup of the device identity. The items are non-synchronizable,
scoped to 2ndPass's signing access group, and use `WhenUnlockedThisDeviceOnly`.
Copying their bytes to another device does not provide portable device keys.

Keychain access groups, provisioning and hardened-runtime validation constrain
which signed clients can use these representations. They are not defenses
against malicious code already executing with an authorized client's privileges.
Deleting the Keychain identity removes usable local references; it is not proof
of physical zeroization of every hardware or storage location.

### What unlocking authorizes

Key access controls use `privateKeyUsage` and `userPresence`. 2ndPass preauthorizes an
`LAContext` (Apple's local-authentication context) using device-owner
authentication, then disables unexpected interactive prompts during key
operations. This is the platform's authentication policy, not a promise that
biometrics are the only permitted authentication method.

The GUI may reuse that authorization until session lock or expiry. Therefore a
successful operation need not produce a fresh prompt. CLI sessions end with their
command; AutoFill starts fresh authorization and locks after each fill. Providers
release hardware-key handles after operations. Session lock invalidates the
context and session generation, cancels work, and rejects late results.

Invalidating an `LAContext` is **not established as revoking an already-used
signing handle**: a real-host probe found signing still succeeded through such a
handle. 2ndPass consequently clears handles and independently guards operation and
session state. In-flight hardware operations or submitted cloud mutations may
finish after cancellation; journals reconcile cloud outcomes.

## Encryption and plaintext lifetime

Each item has a distinct random 256-bit AES-GCM key shared by its fields. Fields use independent random nonces and remain separately encrypted. The catalog has a
separate key and contains item names, field descriptions, references, visible
field values and deletion metadata. Concealed field values are stored in their
separate records. Each authorized ordinary device and any configured recovery
device receives an encrypted copy, or *envelope*, of each item's key and the catalog key.

Envelopes use CryptoKit HPKE with `P256_SHA256_AES_GCM_256`. HPKE combines public-key
agreement and symmetric encryption so an object key can be encrypted to a
recipient's public key and opened using its private key. There is no retained
vault-wide symmetric master key. Per-item keys bound key exposure to one item;
they do not prevent an authorized device from deliberately reading every record.

For a normal password read:

1. The service checks session and account state and obtains a verified vault
   revision, from online validation or an eligible local offline checkpoint.
2. The device opens its catalog-key envelope and authenticates/decrypts the catalog
   to locate the requested record.
3. It opens its envelope for that item's key using the hardware agreement key.
4. AES-GCM authenticates and decrypts the record in application memory. The result
   goes to the requested UI, AutoFill, clipboard or command destination.
5. Providers release their key handles; owned temporary buffers are wiped where
   practical. The engine retains no private or symmetric key between operations.

Adding a recipient unwraps each item key once and adds only the new recipient envelope, preserving existing envelopes and ciphertext. Role-only changes preserve item keys and envelopes. Removing a recipient creates fresh item keys and ciphertext for all retained records, including recently deleted items, processing plaintext one field at a time. Catalog operations decrypt
catalog data, including visible field values, even when no password is revealed.

AES keys, HPKE-derived state, passwords, edited values and command inputs can
reach application memory. Password-strength calculation also sees plaintext.
`Data`/`SecretBytes` buffers are wiped where practical, but Swift strings,
Foundation/CryptoKit copies, allocators and OS copies prevent a comprehensive
memory-erasure guarantee. The Enclave protects private keys; it does not make
plaintext immune to process compromise, screenshots, clipboard readers, or the
program receiving a password.

## Identity, membership and enrollment

### Accounts, devices and roles

An account identifier is a deterministic namespace derived from the CloudKit
container, environment and account record ID. It is not a secret or private key.
Each device has a UUID and a fingerprint covering its public identity. Requests
bind account scope, purpose and both public keys, with a signature proving
possession of the signing key. This is **not remote hardware attestation** or
proof that two identities belong to separate physical devices.

A vault has exactly one owner account, with one or more authorized devices.
Owners control ordinary membership; editors can write contents; viewers can
read. A personal vault uses these same rules with one member account. Recovery
has separate, explicitly configured authority described below.

### Automatic same-account enrollment

A new device authenticates locally and submits a signed request through the
private CloudKit enrollment mailbox. An existing owner's unlocked 2ndPass session
processes it, supplies an invitation, checks the acceptance and publishes a
signed membership grant with key envelopes for the new device. Automatic
processing refuses a locked service without initiating authentication. It needs
an opportunity to run; unlocking the OS alone is not an enrollment guarantee.

There is **no required human comparison code or approval step** in this flow.
The new device checks invitation structure, scope, signatures, membership and
accepted invitation nonce before registering the vault. Its initial checkpoint,
however, comes from the trusted account mailbox. Self-consistent signatures do
not independently authenticate the first owner key presented by that mailbox.

Consequences of this usability choice:

- Account/mailbox compromise can admit an attacker's new identity while an
  existing owner session is unlocked, granting access to existing contents.
- A malicious mailbox can substitute an initial root for a joining device.
  Existing devices with pinned state still enforce signed ancestry.
- Device names and proof of signing-key possession do not establish that a
  request belongs to the intended person or uses genuine hardware-backed keys.
- Removing an attacker identity is insufficient while the attacker retains
  account access: a fresh identity can request automatic admission.

Requests are scoped, signed and short-lived (24 hours). The mailbox is bounded
to 32 unique exchanges and the format size limit. Retired device UUIDs are
rejected; accepted invitation nonces are recorded in signed membership. These
checks address malformed input, stale requests and replay; they do not repair a
compromised bootstrap identity channel.

### Cross-account sharing

Sharing with another account retains explicit invitation, independent identity
verification and owner approval. Invitations bind a checkpoint, recipient
account, role, nonce and expiry. Acceptance proves signing-key possession; final
owner approval adds device envelopes for existing records. Accepting an Apple
CloudKit share (`CKShare`) alone does not grant cryptographic vault membership.

Nonpublic, zone-wide shares separately grant read-only or read-write transport
permissions. 2ndPass checks participant/account bindings, actual shared-zone owner,
container and environment. The default-owner alias is not accepted as a shared
address; unexpected mappings fail closed. Real participant-side behavior remains
a second-account validation requirement.

## Authenticity, tampering and synchronization

AES-GCM detects changes to protected ciphertext or its authenticated context.
Item HPKE contexts bind vault, item UUID, recipient fingerprint and item-key generation, independently of membership epoch. Field AES-GCM contexts bind vault, item UUID, key generation and field-record UUID. Catalog envelopes retain membership-epoch binding.
Record authenticated data binds vault and object; catalog authenticated data
binds the header and digest of the record table. These bindings prevent valid
pieces being silently substituted into a different context.

Complete canonical revisions are signed, including a domain separator, parent
hash, generation, membership epoch, roster, catalog and records. A revision's
authority is checked against the **verified parent**, not a role it assigns
itself in the new revision. Canonical decoding rejects alternate representations;
structure, input sizes and ancestry work are bounded. Signatures identify an
authorized signer, not whether an authorized editor's changes are desirable.

A locally pinned checkpoint anchors subsequent ancestry checks. Local watermarks
reject observed rollback and forks. This does not prove global freshness: a
server can withhold all new revisions, and a client with no independent prior
state cannot infer history that it has never seen. Deleting local trust evidence
also removes the basis for its previous observations.

Content-addressed CloudKit assets are treated as immutable by the client. Head
updates use `ifServerRecordUnchanged` and actual server change tags, so competing
writes conflict instead of silently overwriting each other. 2ndPass does not
resolve conflicts by blindly replaying secret changes.

A private atomic journal is persisted before submission. When an acknowledgement
is lost, verified ancestry can establish whether the operation committed. An
unchanged head alone is inconclusive: an explicit conditional version barrier
must fence an old request before treating it as unable to commit. Initial roots
are persisted before publication; interrupted creation reuses the same UUID and
root. A missing cloud head does not authorize resurrection.

An OS file lease excludes competing app, CLI and extension writers for the same
local vault. Filesystem validation and durability mechanisms are covered in the
[validation record](VAULT-NEXT-VALIDATION.md); successful model tests are not a
power-loss or physical-interruption guarantee. Cloud writers can still deny
service by deleting or withholding data or interfering with transport.

## Removal, offline access and reconnection

Removal publishes fresh encryption keys and ciphertext excluding removed
recipients before reconciling CloudKit permissions. Failed permission updates
are retried with `reconcile-share`; the committed cryptographic removal already
protects subsequent contents. A pending or uncertain publication must be
reconciled before claiming removal completed.

Removal cannot retract copied passwords, old record keys, or old ciphertext that
a recipient could already decrypt. Re-encrypting an unchanged password does not
invalidate it at the website: change that password if its former holder must
lose access to the external service. A viewer can copy secrets; an editor can
also make authorized content changes. Neither role can be made trustworthy by
cryptography alone.

Signed membership retains retired device UUIDs and rejects their reuse. An
honest client that verifies its own removal persists a removal marker, deletes
its ordinary Keychain identity, releases handles and clears managed account
caches. The marker survives relaunch and blocks normal account operations.
Explicit **Reconnect** completes cleanup and clears it so fresh device keys can
be created. Recovery identities and user-exported backups are preserved. Cloud
errors alone do not authorize identity deletion.

The Settings device-removal action covers personal vaults enrolled on the
managing device, not every unrelated or never-enrolled vault. Removing multiple
vault memberships is a series of publications, not one global atomic revocation.
Local cleanup is honest-client behavior, not remote erasure of an adversary's
copies. Reconnect restrictions do not stop a malicious account holder from using
another client and a new identity.

Offline reads require a previously pinned local checkpoint, a prior account
binding and hardware authorization. That checkpoint inherits the trust of its
original enrollment or import. Known sign-out, account restriction or observed
account change denies the binding. An offline client cannot discover an
unobserved account change or remote revocation and can retain historical access.
Writes and membership operations require online validation. Plaintext passwords
are not stored in the vault cache; visible catalog metadata can remain in UI
memory during use.

## Recovery and backups

Recovery is optional: a new vault starts with one owner device and no recovery
recipient. An authorized owner can add a hardware recovery identity later,
including access to existing records. Recovery keys use the hardware provider;
there is no portable seed or software recovery private-key file.

A recovery device is a powerful recipient, able to decrypt records and authorize
recovery. It does not automatically acquire ordinary owner/editor membership.
Keep it physically separate from ordinary devices, and keep encrypted backups
with independent checkpoint evidence. A second identity on the same physical
machine does not provide protection against losing that machine.

Same-account recovery uses a recovery signature to replace the ordinary roster
and configure replacement recovery authority. Lost-account recovery verifies a
backup and decrypts/re-encrypts its records one at a time into a new vault UUID
and root under another account, preserving the source. Backup verification needs
trusted checkpoint evidence; signatures alone do not identify an arbitrary
backup's initial root as yours.

If all authorized ordinary and configured recovery device keys are lost, the
vault is unrecoverable. Restoring an Apple Account or possessing ciphertext
backups does not recreate those device-bound private keys.

## Metadata and intentional disclosure

Cloud-visible data includes vault name/UUID, public membership and key graph,
ciphertext sizes and update timing. Enrollment additionally exposes request
metadata, including device names and public identities, to the private mailbox.
Item names, field names, visible field values and deletion metadata are encrypted
inside the catalog. Encryption does not hide all usage patterns or membership.

AutoFill intentionally publishes website, username and credential-kind locators
to Apple's credential identity store. It re-resolves them from an authenticated
catalog before filling. This metadata is a privacy tradeoff for credential
discovery, not publication of the password itself. Clipboard, subprocess and
website destinations receive plaintext by design; 2ndPass cannot control how they
retain or disclose it afterward.

## Attacks and practical limits

| Scenario | Protection | Boundary or remaining risk |
| --- | --- | --- |
| Someone copies cloud ciphertext or an encrypted backup | Per-item keys with separate field encryption and device-specific key envelopes | Active mailbox control can additionally enable automatic enrollment; old authorized recipients may retain decryptable copies. |
| Someone steals a locked device | Hardware-bound keys, Keychain accessibility and local authentication | Depends on platform security and authentication credentials; an unlocked authorized session has broader access. |
| Someone tampers with records or grants themselves a role | Authenticated encryption, complete revision signatures and parent-authority checks | Initial same-account bootstrap trusts the mailbox; authorized writers can still make valid harmful edits. |
| A server replays or forks history | Pinned checkpoints, ancestry verification and local watermarks | Withheld updates cannot be detected as globally stale; availability is not guaranteed. |
| An attacker replays an enrollment request | Scope, expiry, acceptance checks, consumed nonces and retired UUIDs | A fresh identity can be admitted if the attacker still controls the account mailbox. |
| A removed person keeps old data | Rotation excludes them from current and later encrypted revisions | Copies and unchanged external passwords remain usable; offline clients learn revocation later. |
| Malware compromises an authorized 2ndPass process | Private scalars remain behind the hardware boundary | Malware may request operations, read plaintext and copy results. Hardware protection is not endpoint immunity. |
| Every enrolled device is lost | Optional separate hardware recovery plus verified backups | Without surviving ordinary or recovery keys there is no decryption backdoor. |

## Evidence and source map

Recorded evidence includes real Enclave signing/HPKE, authentication behavior,
Keychain reload and private-database CloudKit checks on one Mac, plus automated
membership, enrollment, revocation, recovery and publication models. Second-account
CloudKit sharing, separate physical recovery devices, and signed iPhone/iPad and
actual AutoFill workflows still require the physical acceptance checks in
[VAULT-NEXT-VALIDATION.md](VAULT-NEXT-VALIDATION.md). Simulator compilation and
software-key tests do not prove those platform behaviors. No new hardware
validation was performed for this documentation revision.

The principal implementation entry points are:

- [Device.swift](../Sources/MopVaultNext/Device.swift) and
  [DeviceKeychain.swift](../Sources/MopVaultNext/DeviceKeychain.swift): hardware
  providers, access controls, stored representations and handle lifetime.
- [Crypto.swift](../Sources/MopVaultNext/Crypto.swift),
  [Revision.swift](../Sources/MopVaultNext/Revision.swift) and
  [VaultEngine.swift](../Sources/MopVaultNext/VaultEngine.swift): encryption,
  signed format, membership changes and recovery.
- [Enrollment.swift](../Sources/MopVaultNext/Enrollment.swift) and
  [NativeVaultService.swift](../Sources/MopAppSupport/NativeVaultService.swift):
  mailbox validation, automatic grants, session/account enforcement and removal.
- [Publication.swift](../Sources/MopVaultNext/Publication.swift),
  [FileVerifiedStateStore.swift](../Sources/MopVaultNext/FileVerifiedStateStore.swift)
  and [CloudRevisionTransport.swift](../Sources/MopVaultNext/CloudRevisionTransport.swift):
  ancestry, journals, local state and conditional cloud publication.

The [architecture proposal](VAULT-NEXT.md) explains design alternatives. Historical
entries in that proposal and the validation log may describe earlier enrollment
policies; the automatic same-account policy above is the current behavior.
