# Security and key management

This document describes 2ndPass v7's implemented security model, reviewed against the
working-tree source on 2026-09-29. For a user-oriented overview, see
[How 2ndPass protects your secrets](SECURITY-EXPLAINER.md). The
[validation record](VAULT-NEXT-VALIDATION.md) distinguishes implementation and
model tests from physical-device evidence. This document is not a claim of an
independent security audit or completed release acceptance.

The GUI, CLI, background verifier and AutoFill use `MopVaultNext` through
`NativeVaultService`. Historical software-key vault/cloud sources are outside
the application dependency graphs. There is no software device-key fallback,
old-format reader, or automatic migration in this implementation.

**Sharing design status:** cross-account vault sharing is not yet implemented as
a supported product feature. Preliminary protocol, transport and UI code exists,
but enrollment mailbox isolation remains a design detail to address before
completing sharing. See [shared-zone enrollment exposure](#shared-zone-enrollment-exposure).
This is an unfinished-feature design issue, not a current product vulnerability.

## Trust boundaries and threat model

2ndPass encrypts vault contents before uploading them, grants access to specific
device public keys, and verifies signed revisions against previously trusted
state. Its protections have distinct dependencies:

- **Device hardware and Apple platform security:** Secure Enclave protects device
  private-key operations; Keychain and code-signing access controls protect the
  stored device identity. 2ndPass relies on these implementations and local
  authentication, rather than implementing its own hardware security boundary.
- **Authorized 2ndPass code:** plaintext and temporary per-item keys enter the app's
  process. Code able to act as an authorized client can request permitted
  hardware operations and retain their results.
- **Apple account/device security and provisioned CloudKit access during
  same-account enrollment:** automatic enrollment trusts the user's private,
  entitlement-protected 2ndPass CloudKit namespace for initial identity. An
  attacker able to operate an authorized client in that user's iCloud context
  may request admission when an unlocked owner session processes the exchange.
  Account credentials alone do not authorize arbitrary container writes.
  A compromised bootstrap mailbox can also substitute a joining device's root.
- **Locally pinned state after enrollment:** signed ancestry and local checkpoints
  constrain later updates. They do not establish the authenticity of an initial
  root independently of its bootstrap channel, or prove that the server has
  supplied the newest revision.

CloudKit is Apple's application data service. Its transport permissions and 2ndPass's
cryptographic membership are separate controls. A stolen ciphertext copy alone
is insufficient to decrypt secrets; active control of this authorized account/container channel has the
additional enrollment consequences above. 2ndPass does not promise availability
against a malicious server, secrecy from an authorized recipient, or protection
of plaintext on a compromised endpoint.

## Composed Apple + 2ndPass trust model

The enrollment path composes Apple device/account security, code signing and
provisioning, applicable sandbox boundaries, CloudKit entitlements, private
per-user storage, Secure Enclave device identities, and 2ndPass's membership,
signature and encryption protocol:

1. Apple authenticates the system's iCloud/Apple Account environment.
2. Signed, provisioned clients use entitlements for the selected CloudKit
   container and Development or Production environment. An arbitrary app does
   not acquire this access merely by knowing the user's account credentials.
3. The native client accesses that authenticated user's private database in the
   container. Intentional CKShare access is a separate, scoped sharing path.
4. A new device generates independent hardware-bound agreement and signing keys
   (or reopens its existing device-local identity); it does not copy another
   device's private keys.
5. Its signed enrollment request travels through that private CloudKit namespace.
6. An already-enrolled owner device checks the request and acceptance, signs a
   membership revision, and wraps the item keys for the requesting device.

This is a deliberate composition: ordinary same-account enrollment reuses Apple's
account/device authentication and provisioned application access rather than
requiring a second human comparison ceremony. 2ndPass still requires its own
cryptographic membership grant. It neither queries nor participates directly in
Apple's private iCloud Keychain trust-circle implementation. CloudKit account
availability is not a query of that trust circle or proof of a particular Apple
sign-in ceremony.

**Platform qualification:** iOS/iPadOS enforce [application sandboxing](https://support.apple.com/guide/security/sec15bfe098e/web); the Mac
AutoFill extension explicitly enables App Sandbox and outbound network access.
The current Mac app and CLI packaging does **not** enable App Sandbox. They rely
on code signing, provisioning, restricted Keychain/CloudKit entitlements and the
hardened runtime for the boundaries described here. App Groups share local files;
they are not interchangeable with Keychain access groups or CloudKit entitlements.

Apple documents [container entitlement isolation](https://developer.apple.com/documentation/cloudkit/ckcontainer),
[private database access](https://developer.apple.com/documentation/cloudkit/ckcontainer/privateclouddatabase),
[provisioning and restricted entitlements](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles),
and [Mac sandbox boundaries](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox).
See also the concrete [CloudKit configuration](CLOUDKIT.md).

## Common attacks and how 2ndPass responds

### Stealing stored vault data

An attacker might copy a device's files, an encrypted backup, or the records in
iCloud. 2ndPass encrypts item fields with per-item AES-GCM keys and encrypts the
catalog with a separate key before storage or upload. Those keys are wrapped for
authorized devices using HPKE. Opening them requires a device's non-exportable
Secure Enclave private key and local authorization; there is no master-password
hash in the vault for an attacker to crack offline. Device-key representations
are stored in the non-synchronizing, device-bound Data Protection Keychain.

Copying encrypted data therefore does not supply the means to decrypt it. This
protection does not extend to plaintext exports or credentials already copied out
of the app, and some cloud metadata, such as vault names and record sizes, remains
visible.

### Reading secrets from memory

Malware may try to inspect an unlocked password manager's process. 2ndPass keeps
long-lived device private keys inside the Secure Enclave and decrypts concealed
fields on demand. Its unlocked read cache holds verified encrypted records and
the decoded catalog, not a cache of revealed passwords or unwrapped item keys.
Owned secret buffers are wiped when released. Locking clears session state and
hardware-key handles, invalidates authentication, and rejects late results.

A password must still enter application memory to be displayed, copied, or
filled, and temporary symmetric keys also enter memory. These measures reduce
exposure; they cannot defeat an attacker who controls the authorized process or
operating system. Swift strings and framework copies also prevent a guarantee
that every plaintext copy is immediately erased.

### Replacing or modifying the app

A modified binary could attempt to steal passwords as they are used. Apple code
signing, provisioning, and Keychain access groups restrict access to the stored
device identity. The macOS client checks its signing identity and requires the
hardened runtime, with debugger access and library-validation bypass entitlements
disabled. These controls make simply patching or re-signing a binary insufficient
to inherit the legitimate app's Keychain access and constrain code injection.

They depend on the operating system enforcing those boundaries. Malicious code
with an accepted signing identity, or code already running inside an authorized
client, can misuse access after authorization. Device enrollment proves possession
of keys; it is not remote attestation that a device runs an approved binary.

### Altering or replaying cloud records

Authenticated encryption detects changes to encrypted contents. Signed revisions,
membership checks, and locally pinned checkpoints let 2ndPass reject unauthorized
updates and rollbacks that conflict with its trusted history. A server can still
withhold updates or deny service; a valid older view is not proof that no newer
revision exists. Initial enrollment also relies on the account or invitation
channel described above.

### Capturing copied or displayed passwords

Concealed fields, timed re-concealment, and the locked screen reduce casual visual
exposure. Secret clipboard writes are local to the device and expire; locking
also clears the app's clipboard content when it has not been replaced. These
controls shorten exposure, but cannot retract a password that a clipboard reader,
screen capture, or receiving application has already copied.

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
Copying their bytes, local vault storage or CloudKit records does not reveal the
underlying private keys or let them be moved to another machine. 2ndPass holds
opaque CryptoKit key references and asks the Secure Enclave to perform private-key
operations; decrypted item keys and secrets are outside that hardware boundary.

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

### Apple Account authentication

Apple's [two-factor authentication](https://support.apple.com/en-us/102660) protects
new-device sign-ins with an account password and verification through a trusted
device or phone number. It is the default for most accounts. Optional
[account security keys](https://support.apple.com/en-us/102637) add phishing
protection. 2ndPass uses the OS-authenticated iCloud session, without collecting
Apple Account credentials. These controls protect the enrollment channel; they
are separate from vault unlock and the offline recovery key.
A compromised authenticated session or trusted device can still undermine that
channel, so account recovery and trusted-device security matter too.

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

- An attacker with sufficient control of the user's Apple environment to operate
  an authorized 2ndPass client and access the user's private 2ndPass container may
  submit a valid request. If an enrolled owner session processes the exchange
  while unlocked and online, it may automatically grant that identity owner
  membership and access to existing contents. Knowing an Apple Account password
  alone does not establish these capabilities.
- A malicious mailbox can substitute an initial root for a joining device.
  Existing devices with pinned state still enforce signed ancestry.
- Device names and proof of signing-key possession do not establish that a
  request belongs to the intended person or uses genuine hardware-backed keys.
- Removing an attacker identity is insufficient while the attacker retains
  authorized access to that private container: a fresh identity can request
  automatic admission. Revocation must also address the compromised Apple/client
  access path.

Requests are scoped, signed and short-lived (24 hours). The mailbox is bounded
to 32 unique exchanges and the format size limit. Retired device UUIDs are
rejected; accepted invitation nonces are recorded in signed membership. These
checks address malformed input, stale requests and replay; they do not repair a
compromised bootstrap identity channel.

### Shared-zone enrollment exposure

Cross-account vault sharing is unimplemented as a supported feature. The following
reviews preliminary sharing code and a design constraint for completing it; it
is not classified as a vulnerability in the current product.

The intended account-exclusive mailbox assumption holds for an unshared personal
zone, but the current implementation stores `MopV7Enrollment/enrollment` in the
vault zone and uses a zone-wide `CKShare`. Apple documents that
[zone sharing includes its records and permits writable participants to modify them](https://developer.apple.com/documentation/cloudkit/shared-records).
Reading through the owner's `privateCloudDatabase` does not make a shared record
exclusive to that owner.

If sharing were completed with this layout, it could introduce an editor-to-owner
enrollment path:
a writable participant with the ability to issue authorized container operations
could alter the mailbox. Account/member fields in a request are self-signed;
they are not server-authenticated provenance for each exchange. An unlocked
owner may sign a grant for a request claiming its account. The adapter's
`.private` guard constrains honest local calls, not another client's writes to
the shared zone. Existing model transports do not establish this CloudKit
isolation. No live two-account exploit was attempted in this audit.

Address mailbox isolation as part of implementing sharing, then validate it with
disposable accounts. Preserve ordinary automatic same-account enrollment. The
preliminary explicit invitation flow does not by itself establish isolation of
the automatic path. This design concern is distinct from account credential theft
and does not imply a failure of Apple's container entitlements.

### Cross-account sharing

The preliminary design for sharing with another account uses explicit invitation, independent identity
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
state cannot infer history that it has never seen. Deleting or restoring older local trust evidence also removes the basis for its
previous observations. These checkpoints are private local files, not a hardware
monotonic counter; an attacker able to replace the trusted local state is outside
this rollback guarantee.

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

Removal cannot retract copied passwords, old per-item keys, or old ciphertext that
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
be created. Public offline-recovery configuration and user-exported copies are preserved. Cloud
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
Offline recovery is optional and account-wide for owned cloud vaults. The app
generates a random 256-bit secret, derives separate P-256 agreement and signing
keys with versioned HKDF-SHA256 labels and account-scope binding, and requires
re-entry or re-import before activation. The file and grouped paper code include
an error-detection checksum, not a password or additional encryption factor.

The secret and derived private keys are never persisted by the application except
through explicit user export. They exist in memory during the visible ceremony
or a recovery session. Locking, backgrounding, cancellation, and account changes
invalidate handles. Controllable buffers are wiped; Swift strings, CryptoKit, OS
file dialogs, printing, and other framework-owned copies cannot be guaranteed
wiped. The recovery client and its operating system must be trusted.

Anyone possessing both the offline secret and copied ciphertext can decrypt it
without signing into iCloud. Account binding prevents accidental or unauthorized
cross-account application recovery; it is not a second cryptographic factor.
One offline copy therefore exposes every vault covered by that authority. Keep
it physically separate from daily-use devices and avoid synchronized storage.

A fresh installation must first sign into the same Apple Account. Apple may
require its own trusted-phone-number or account recovery process; this code
cannot satisfy those requirements. Recovery then relies on accessible live
CloudKit data. Account loss requires a separately exported backup and is outside
this feature, as is backup restoration.

Fresh-device bootstrap trusts authenticated private CloudKit for provenance and
freshness while validating account scope, signed vault structure/transitions,
recovery authority and decryption. Encryption to a public key alone does not
prove provenance. Without a surviving checkpoint this path does not independently
detect server rollback, omission, or denial of service.

Read-only recovery access does not revoke previous devices. Completion adds the recovering device while preserving all existing devices,
accounts, and roles and rotates retained item, catalog, and attachment encryption.
Unavailable attachments postpone completion while healthy data remains readable.
The offline key remains valid until explicitly replaced or revoked.

Account-wide replacement/revocation is resumable across per-vault atomic commits.
Keep both offline copies until completion; incomplete coverage is reported. New
vault creation is fenced during lifecycle changes. Removal cannot retract copied
plaintext, old ciphertext, or exported backups. Physical-platform recovery
acceptance and independent cryptographic review remain required before relying
on the feature as the only recovery route.

## Metadata and intentional disclosure

Cloud-visible data includes vault name/UUID, public membership and key graph,
ciphertext sizes and update timing. Enrollment additionally exposes request
metadata, including device names and public identities, to the mailbox. When the vault
zone is shared, that mailbox metadata is also within the zone share.
Item names, field names, visible field values and deletion metadata are encrypted
inside the catalog. Encryption does not hide all usage patterns or membership.

AutoFill intentionally publishes website, username and credential-kind locators
to Apple's credential identity store. It re-resolves them from an authenticated
catalog before filling. This metadata is a privacy tradeoff for credential
discovery, not publication of the password itself. Clipboard, subprocess and
website destinations receive plaintext by design; 2ndPass cannot control how they
retain or disclose it afterward.

## CLI and extension disclosure boundaries

`sp read` emits plaintext to stdout or the selected output file. `inject`
emits a plaintext rendering to stdout or a generated file and inserts values
literally, without destination-format escaping. `run` resolves references into
the launched program's environment. The child, its dependencies and any
subprocesses receiving those variables become part of the trusted computing base
for the released secrets. Environment variables are not encrypted storage: the
recipient, inherited descendants, diagnostic tooling or sufficiently privileged
host software may expose them. Output files default to mode 0600; permissions do
not encrypt them or prevent authorized readers, backups or later copies.

Default `run` masking filters exact secret bytes in captured stdout/stderr. It
cannot constrain transformed output, direct file writes, network traffic or what
an arbitrary child does with plaintext. `--no-masking` disables that filter.
These are necessary disclosure boundaries for developer automation, not an
extension of vault encryption to the receiving process.

The sandboxed app, separately distributed CLI, and AutoFill extension intentionally
share the provisioned Keychain access group and device identity on a device. The
CLI has its own `.CLI` App ID/profile and remains unsandboxed for developer
automation. Its signature authorizes only the existing shared vault groups and
CloudKit container. The extension has its own
App ID/profile, shares the App Group's local checkpoints/index, and can access
the same CloudKit container. This makes extension code part of the vault's
trusted computing base, not a metadata-only helper. Each fill authenticates
freshly, re-resolves the locator against verified data, and hands a plaintext
credential to AuthenticationServices and the receiving app/site. OS protections
and recipient behavior govern it afterward. See [AutoFill](AUTOFILL.md).

A sufficiently privileged attacker on an unlocked endpoint may invoke authorized
Enclave operations and observe item keys, secrets, clipboard data, AutoFill or
CLI destinations even if it cannot extract the non-exportable device private
key. Extraction resistance and resistance to key use are different guarantees.

## Apple Passwords / iCloud Keychain

Secure Enclave protection is not unique to 2ndPass. Apple documents substantial
hardware-backed protection in [Keychain data protection](https://support.apple.com/guide/security/secb0694df1a/web).
Apple Passwords/iCloud Keychain is integrated deeper into the operating system;
its full implementation is not publicly inspectable. 2ndPass makes its
non-exportable device identity and per-item wrapping an explicit, inspectable
part of its end-to-end vault protocol. This is a concrete design distinction,
not evidence that 2ndPass is categorically more secure. Source availability enables
inspection but does not substitute for professional review.

## Attacks and practical limits

| Scenario | Protection | Boundary or remaining risk |
| --- | --- | --- |
| Someone copies cloud ciphertext or an encrypted backup | Per-item keys with separate field encryption and device-specific key envelopes | Authorized private-container control can additionally enable automatic enrollment; old authorized recipients may retain decryptable copies. |
| Someone steals a locked device | Hardware-bound keys, Keychain accessibility and local authentication | Depends on platform security and authentication credentials; an unlocked authorized session has broader access. |
| Someone tampers with records or grants themselves a role | Authenticated encryption, complete revision signatures and parent-authority checks | Initial same-account bootstrap trusts the mailbox; authorized writers can still make valid harmful edits. |
| A server replays or forks history | Pinned checkpoints, ancestry verification and local watermarks | Withheld updates cannot be detected as globally stale; availability is not guaranteed. |
| An attacker replays an enrollment request | Scope, expiry, acceptance checks, consumed nonces and retired UUIDs | A fresh identity can be admitted if the attacker still has authorized access to the private container. |
| A removed person keeps old data | Rotation excludes them from current and later encrypted revisions | Copies and unchanged external passwords remain usable; offline clients learn revocation later. |
| Malware compromises an authorized 2ndPass process | Private scalars remain behind the hardware boundary | Malware may request operations, read plaintext and copy results. Hardware protection is not endpoint immunity. |
| Every enrolled device is lost | Offline recovery copy plus access to the same Apple Account and live vault data | Without the offline secret or surviving ordinary keys there is no decryption backdoor. Missing cloud data and account loss require a separate backup route. |

## Evidence and source map

Recorded evidence includes real Enclave signing/HPKE, authentication behavior,
Keychain reload and private-database CloudKit checks on one Mac, plus automated
membership, enrollment, revocation, recovery and publication models. Second-account
CloudKit sharing, offline recovery on physical devices, and signed iPhone/iPad and
actual AutoFill workflows still require the physical acceptance checks in
[VAULT-NEXT-VALIDATION.md](VAULT-NEXT-VALIDATION.md). Simulator compilation and
software-key tests do not prove those platform behaviors. The SALE-1 validation record is in [offline recovery](OFFLINE-RECOVERY.md); physical acceptance is pending. 2ndPass has not yet
been independently audited. Protocol design correctness and implementation
correctness are separate questions; neither source availability nor model tests
establishes both. The [documentation audit](security-audit/2026-09-29-documentation.md)
records source evidence, corrections and auditor questions.

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

The [vault architecture](VAULT-NEXT.md) describes enrollment, membership, recovery,
and publication. [Vault v7](VAULT-V7.md) specifies the wire format.

## The device-local `local` vault

`local` is intentionally distinct from portable encrypted cloud vaults. Its
asymmetric private keys are generated inside the Secure Enclave and never become
exportable plaintext in application memory. The dedicated `MopLocalIdentity`
module cannot call CloudKit or the cloud vault engine. Public DTOs contain no
opaque references; non-synchronizable, device-only Keychain records hold those
references. Cloud operations reject local selections before account discovery,
authentication, or transport use. Normal sharing, export, recovery, and backup
operate only on cloud schemas.

A copied application directory or cloud compromise cannot reconstruct a local
private identity on another device. Key references are not a recovery mechanism.
Device loss or erasure permanently removes access; register independent SSH keys,
passkeys, or certificates on other devices beforehand. 2ndPass cannot back up,
escrow, or restore these keys. Imported private keys remain ordinary cloud-vault
secrets and cannot be reclassified as local identities.

Hardware isolation does not prevent operation-oracle abuse by malware controlling
an unlocked authorized process. Authorization scopes limit identities, purposes,
operations and lifetime; they do not attest a trustworthy endpoint. Inputs, public
metadata, signatures and key-agreement results exist outside the enclave. ECDH
results are symmetric secret material in normal memory, although the identity’s
private asymmetric key stays inside the enclave. External review should cover
session revocation races, cross-process deletion, Keychain accessibility and access
groups, protocol parsing, relying-party binding, and same-device reference deletion.

Device-bound WebAuthn responses always report BE=0/BS=0; having another independent
passkey is not backup eligibility for the first credential. Apple credential-provider
acceptance of these flags requires physical-device validation and may prevent use
on current platforms. See [local vault operation and acceptance](LOCAL-VAULT.md).
2ndPass is not FIPS certified and makes no blanket Apple-module certification claim.

### SSH agent caller authorization

The local SSH agent authenticates only after receiving a valid signing request;
public-key enumeration needs no authentication. Wrapped-command mode restricts
connections to the recorded command process instance and its current descendants.
Standalone approvals are scoped to the exact kernel-audited process instance and
identity, defaulting to five minutes, rather than all clients with the socket path.
macOS peer audit tokens and `proc_pidpath_audittoken` detect exited/reused/exec-changed
peers; process start times and repeated ancestry checks bind wrapped requests to
the launched command. Unverifiable callers fail closed. Inputs are purpose-checked
before authentication and authorization/caller validity is checked again before
returning signatures. Stop cancels pending authentication and revokes cached contexts.
Device lock/sleep and user-session switching stop the agent, as does the 12-hour
session limit. Wrapped command exit revokes its approvals immediately.

This is an operation-access boundary, not protection against code injection into
an authorized process. A cooperating authorized process can relay requests or
pass its socket; peer identity does not authenticate the original source behind
such a relay. Destination binding and forwarding restrictions are not implemented.
The system authentication prompt identifies the local executable and key but does
not claim a verified remote host. Physical-device review must exercise Touch ID,
lock/sleep during an outstanding prompt, and late Secure Enclave results.

### Cloud software key credentials

Typed cloud SSH/Git credentials and passkeys store normalized software private keys
as concealed encrypted item payloads, with public protocol metadata inside the
encrypted catalog. Authorized members can obtain software key material; these
credentials do not inherit Secure Enclave non-extractability. Owner/editor writes
and member reads use the existing vault permission boundary. Recovery and
revocation have the same limitations as other cloud secrets. Hardware keys remain
non-exportable and never enter this format. See [supported cloud keys and
validation limits](CLOUD-KEY-CREDENTIALS.md).
