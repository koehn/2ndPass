# The device-local `local` vault

`local` appears alongside cloud vaults, with a fixed name. It holds asymmetric
identities whose private keys are generated in this device’s Secure Enclave. It
cannot hold passwords, imported private keys, TOTP seeds, notes, or bearer tokens.
It has no CloudKit account, sharing, normal vault export, backup, or recovery.
Public keys, certificate requests, and certificates can be exported.

**Device loss, erasure, or replacement permanently loses these identities.**
Register an independent credential on another device before relying on one.
This is the redundancy model used with hardware security keys: two devices have
two independently generated private keys. Registering another passkey does not
back up or copy the first passkey.

## Usage

```sh
sp vault list --vault local
sp list --vault local
sp item catalog --vault local
sp item create --vault local --type ssh --name deploy --acknowledge-device-loss
sp item public-key --vault local deploy
sp ssh-agent --vault local --identity deploy -- ssh user@example.com
sp item delete --vault local deploy
```

Creation accepts `ssh`, `git-signing`, or `x509`. Interactive creation prints the
loss/redundancy warning and requires acknowledgement; scripts must supply the
acknowledgement flag. Passkeys are created through a website’s WebAuthn flow,
not by manufacturing a generic key through the CLI. Generic signing and ECDH
are internal consumers only; there is no arbitrary-data signing command.

The agent authorizes selected identities once per explicitly started session.
It offers only SSH keys by default; `--purpose git-signing` selects Git identities.
Repeat `--identity` to limit the identities offered. Authorization ends on expiry
(12 hours maximum), stop, child exit, device lock/sleep, or detection of a deleted
identity. Only SSH authentication payloads and Git SSHSIG payloads in the `git`
namespace are accepted for their respective purposes. No destination binding,
agent forwarding restrictions, or arbitrary `ssh-add -T` signing are promised.

Sockets live in a fresh owner-only directory with mode 0600 on the socket. Startup
uses explicit readiness/error reporting; 32 clients and 1 MiB frames bound socket
resource use. Child commands retain terminal ownership. Foreground stop signals
clean up the socket and directory.

## Git SSH signing

Create a `git-signing` identity. Save its public key (never a private key) and
configure the repository:

```sh
sp item create --vault local --type git-signing --name git-key --acknowledge-device-loss
sp item public-key --vault local git-key > git-key.pub
git config gpg.format ssh
git config user.signingKey "$PWD/git-key.pub"
printf 'you@example.com %s\n' "$(cat git-key.pub)" > allowed_signers
git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
sp ssh-agent --vault local --purpose git-signing --identity git-key -- git commit -S
sp ssh-agent --vault local --purpose git-signing --identity git-key -- git tag -s v1 -m v1
git verify-commit HEAD
git verify-tag v1
```

Alternatively, inline ECDSA public keys require Git’s `key::` prefix. Identity
rows provide copyable setup commands. No global configuration is changed.
See [Git configuration](https://git-scm.com/docs/git-config).

## Device-bound passkeys

**Development compatibility override:** Registration and assertion currently advertise
`BE=1, BS=1` at the user's request to test Apple platform acceptance. These flags
do not describe the actual storage: the private key remains device-local,
non-exportable, and cannot be backed up or recovered. This overrides the flag
behavior described below; browser acceptance still requires physical-device testing.

Enable 2ndPass as a credential provider in system AutoFill settings. In a website’s
passkey registration flow choose 2ndPass, acknowledge device loss, and authenticate.
Register a second passkey on a different device as your independent recovery path.

The provider implements standard ES256 WebAuthn registration (`fmt=none`, COSE EC2
P-256) and assertion. It uses random 32-byte credential IDs, exact relying-party
and allow-list matching, fresh user verification, and ECDSA over authenticator data
plus the system-supplied client-data hash. Signature counters are unsupported and
reported as zero. Both registration and assertion truthfully report **BE=0, BS=0**.
No private-key import/export or proprietary passkey substitute is involved.

**Platform acceptance remains unverified.** An
[Apple engineer says credential-provider responses require both backup flags](https://developer.apple.com/forums/thread/745605).
An independent passkey on another device does not make this credential backed up,
so 2ndPass will not set those flags to work around a platform rejection. The
implemented extension is an on-device compatibility probe as well as the intended
registration/assertion path. No OS version is currently certified by this project
as accepting the truthful device-bound responses. Test minimum supported and
current physical-device OS versions before relying on it. Unsupported WebAuthn
extensions, attestation formats, and algorithms are not advertised.

Public credential suggestions go to Apple’s local credential identity store.
Private keys and protocol metadata remain device-only in the Keychain. Cloud
catalog refresh preserves local suggestions. If delivery fails, the record is
retained: inspect and explicitly delete it in `local` after confirming it is not
registered at the service. Never automatically destroy a potentially registered key.

## Certificates

```sh
sp item create --vault local --type x509 --name client --acknowledge-device-loss
sp item csr --vault local client --common-name Client --organization Example \
  --dns client.example.com --email client@example.com --uri urn:example:client --ip 127.0.0.1 > client.csr
sp item certificate attach --vault local client issued-chain.pem
sp item certificate show --vault local client
sp item certificate export --vault local client > public-chain.pem
```

CSRs use SwiftASN1 DER construction and enclave ECDSA/SHA-256. Swift Certificates
parses PEM/DER certificates. The leaf key must match the identity; renewal replaces
only the public certificate chain. Attachment is **not trust-chain validation**.
Validity, expiry, subject, issuer, and extensions are displayed. Arbitrary external
TLS applications cannot consume these keys yet. Arrange reissuance or a separate
authorized identity before device loss.

## Storage and authorization

`MopLocalIdentity` depends on Core, Auth, Keychain, SwiftASN1, and Swift Certificates;
it has no CloudKit or MopVaultNext dependency. `VaultPresentation.local` and
`VaultSelection.local` never become cloud descriptors. Local catalogs contain
`LocalIdentity` summaries, not ordinary `VaultItem` fields.

The version-2 record stores validated immutable identity properties, typed protocol
metadata, and an internal opaque CryptoKit key representation in non-synchronizable
`WhenUnlockedThisDeviceOnly` Data Protection Keychain storage. That opaque reference
is never placed in public DTOs, CLI JSON, application files, or backup archives.
Old unshipped records produce an explicit unsupported-version error. No existing
identity is rotated or deleted: use its previous development build to register a
replacement credential and explicitly remove the old record.

Keys use `SecureEnclave.P256.Signing.PrivateKey` or
`SecureEnclave.P256.KeyAgreement.PrivateKey`, generated with `.privateKeyUsage` and
`.userPresence`. All private-key operations use the enclave. Public keys, metadata,
protocol messages, signatures, certificates, CSRs, and ECDH shared-secret results
can exist in ordinary application memory. There is no software fallback.

Authorization is scoped to identity UUIDs, purpose, operation, and expiry. Creation,
deletion, CSR generation, certificate attachment, and passkey use require fresh
one-operation authorization. SSH/Git reuse a session context. Revocation invalidates
the context; checks before and after signing reject late results. Key handles are
operation-local. Same-device malware can still abuse an authorized operation path;
hardware isolation does not make an unlocked endpoint trustworthy.

macOS 15 and iOS 18 remain the deployment targets. Newer Secure Enclave ML-DSA/
ML-KEM APIs exist in current SDKs (availability starts at OS 26 for those APIs);
hardware availability is separate and they are not exposed in this implementation.
See [Apple’s SecureEnclave APIs](https://developer.apple.com/documentation/cryptokit/secureenclave).

2ndPass is **not FIPS certified**. No blanket Apple-module validation claim is made;
certificates cover specific hardware, firmware, OS, and configurations. Consult
[Apple’s certification scope](https://support.apple.com/en-sg/guide/certifications/apc3a7433eb89/web).

## Acceptance

Automated protocol tests use disposable software fixtures and prove wire/DER
interoperability only. Physical Secure Enclave tests are opt-in with
`MOP_LOCAL_HARDWARE_TESTS=1` from a properly signed test host with the application
Keychain access group. They create uniquely named disposable identities, never
modify pre-existing ones, and require user presence. Unsigned `swift test` cannot
establish hardware behavior.

Still required on physical macOS 15/iOS 18 and current OS releases:

- Generate, terminate the process, reopen, and compare public keys; authenticate to
  a real SSH server and verify the interactive prompt/terminal works.
- Verify user presence, cancellation, lock/sleep revocation, concurrent requests,
  deletion during an operation, and refusal of late results.
- Verify enclave signature and ECDH agreement; verify that copied references on a
  second physical device cannot reconstruct the identity. Never archive real keys
  or opaque references for this test; use disposable lab fixtures only.
- Register and assert a passkey, inspect BE/BS/UP/UV, test allow-list and discoverable
  flows, wrong RP, cancellation, dismissal, lock, restart, and suggestion refresh.
  Capture the exact platform rejection if BE=0/BS=0 is rejected.
- Register another independent passkey on another device; remove the first
  disposable credential and confirm the second remains usable.
- Verify missing hardware UI, repeated creation, certificate renewal/expiry,
  irreversible deletion warnings, offline discovery, and loss acknowledgement.

### Vault-qualified identity references

Identity consumers select a vault independently of the key's purpose. Use a name
with `--vault`, or an item reference containing both:

```sh
sp list --vault local
sp item public-key --vault local deploy
sp item public-key sp://local/deploy
sp ssh-agent --vault local --identity deploy -- ssh user@example.com
sp ssh-agent --identity sp://local/deploy -- ssh user@example.com
sp ssh-agent --purpose git-signing --identity sp://local/git-key -- git commit -S
sp item csr sp://local/client --common-name Client
sp item certificate show sp://local/client
sp item delete sp://local/deploy
```

The GUI provides **Copy Reference** in the identity detail panel and row menu.
`sp list --vault local` (including `--json`) emits these item references. Names and
vaults are percent-encoded, so `deploy key` becomes `sp://local/deploy%20key`.
Item references contain two path components; existing secret-field references
remain separate and contain an additional field component. Renaming an item changes
its name-based reference.

The agent requires `--vault` when enumerating a vault or selecting bare names/UUIDs.
Repeat `--identity` to select multiple identities. A conflicting `--vault` and
reference is an error. SSH, Git, and certificate operations in non-local vaults
are not implemented yet; their selectors are accepted and routed to an explicit
unsupported-backend error, without opening the local identity store.
