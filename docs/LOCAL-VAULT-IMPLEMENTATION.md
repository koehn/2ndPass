# Local vault implementation report — 2026-09-30

This implements the device-local identity architecture and protocol paths on top of
`bd451bb`. The user’s passkey clarification is reflected throughout: redundancy
means registering another independent passkey on another device, never copying or
backing up a private key. Physical-device acceptance is outstanding; the passkey
provider’s truthful backup flags may be rejected by Apple’s platform.

## Deliverables

| # | Deliverable | Implemented behavior and evidence |
|---|---|---|
| 1 | Architecture | Dedicated `MopLocalIdentity` target; versioned internal record and separate immutable public identity; typed protocol metadata, purpose, capabilities and access policy. `VaultPresentation` presents cloud/local together without a fake cloud descriptor. |
| 2 | Synced-vault isolation | Local selection and catalog routes precede cloud discovery. Local identities never become `VaultItem`/`ItemCatalog`; cloud engine creation/rename reserve `local`. UUID addressing still permits existing cloud-name collisions. Legacy string service boundaries explicitly reject local references. |
| 3 | Files changed | See the inventory below. Package and Xcode dependency resolution plus third-party notices include SwiftASN1, Swift Certificates and transitive Swift Crypto. |
| 4 | Item types | SSH, Git signing, X.509 certificate identities, and WebAuthn registration/assertion paths. Generic signing/ECDH remain internal. No arbitrary secrets, imported keys, placeholder JWT/recovery types, or generic signing CLI. |
| 5 | Exact APIs/algorithms | `SecureEnclave.P256.Signing.PrivateKey`, `.signature(for:)`, `SecureEnclave.P256.KeyAgreement.PrivateKey`, `.sharedSecretFromKeyAgreement(with:)`; P-256 ECDSA/SHA-256 and ECDH; `.privateKeyUsage` plus `.userPresence`; device-owner authentication contexts. macOS 15/iOS 18 unchanged. |
| 6 | Enclave operations | Identity private-key generation, ECDSA private-key operation and ECDH private-key operation. Public key conversion, protocol encoding and SHA-256 hashing of public protocol data take place outside. |
| 7 | Ordinary-memory data | Public metadata/keys, internal opaque handles during use, protocol inputs, signatures, CSRs, certificates, and derived ECDH shared-secret results. No exportable identity private bytes. Opaque references are excluded from public DTOs/output/files. |
| 8 | CloudKit safeguards | Module has no CloudKit/MopVaultNext dependency; dedicated non-synchronizable `WhenUnlockedThisDeviceOnly` Keychain records. Native service rejects local references before account/auth/transport, including read, export, sharing and recovery routes. Boundary test confirms no state directory/authentication is created. |
| 9 | SSH agent | Purpose and identity filters; validated SSH authentication messages, bounded frames and clients, fresh 0700 directory/0600 socket, length rejection, explicit readiness/error handling, concurrent clients and cleanup. Extensions remain honestly unsupported. Existing real OpenSSH key listing and signature interoperability tests pass. Real enclave SSH server authentication remains a physical acceptance item. |
| 10 | Git signing | `--purpose git-signing`, restricted `SSHSIG` namespace, copyable setup including `key::` for inline ECDSA keys. Real Git commit/tag signing and verification pass with a software protocol fixture. Hardware signing still requires physical acceptance. |
| 11 | Passkeys | AutoFill registration, direct assertion and credential picker; RP/credential matching, fresh user verification, local metadata, public suggestion publishing, standard ES256/COSE, none attestation, zero counter, truthful BE=0/BS=0. UI requires device-loss acknowledgement and recommends a second independent credential. macOS/iOS extension builds pass; Apple platform acceptance has not been demonstrated. No OS version is claimed validated. |
| 12 | X.509/mTLS | SwiftASN1 CSR DER, CN/O/OU/C subject and DNS/email/URI/IPv4/IPv6 SANs; Swift Certificates parsing, leaf-key match, renewal and public export. OpenSSL verifies generated CSRs; certificate matching/renewal tests pass. Attachment does not validate trust. External TLS consumers are deferred. |
| 13 | Physical tests | Opt-in signed-host test covers generation, reopening, stable public key, signature verification, ECDH and deletion. Cross-process/restart, another physical device, actual lock/user-presence behavior, real SSH authentication and WebAuthn registration/assertion acceptance remain manual physical tests. Simulator builds are not security evidence. |
| 14 | External security review | Authorization lifecycle/late-result races, same-device malware’s operation-oracle access, cross-process deletion, Keychain entitlement/access-control assumptions, SSH purpose parsing, WebAuthn RP/client-data trust boundary, backup-flag compatibility, certificate DER and chain handling. No FIPS certification claim. |
| 15 | Loss/redundancy documentation | Vault/create/detail/delete UI, CLI warnings/acknowledgement, passkey registration prompt, `LOCAL-VAULT.md`, `AUTOFILL.md`, README and distinct `SECURITY.md` section. SSH backup registration, certificate reissuance and independent passkeys described. |

## Validation

- Full `swift test`: **390 tests passed; one physical-device test skipped**.
- Real Git/OpenSSH interoperation: signed commit and annotated tag verified; Git
  ECDSA inline-key configuration corrected to use `key::` after a failing test.
- OpenSSL verifies CSR signature and subject/SAN encoding.
- Certificate parser tests cover matching, mismatch and renewed public certificates.
- macOS app/AutoFill extension build with `CODE_SIGNING_ALLOWED=NO`: passed.
- iOS simulator app/AutoFill extension build with `CODE_SIGNING_ALLOWED=NO`: passed.
- `git diff --check`: clean.

Build commands:

```sh
swift test
xcodebuild -project Apple/Mop.xcodeproj -scheme Mop -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project Apple/Mop.xcodeproj -scheme Mop -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

No installed application, registered service credential, or existing development
identity was modified by validation. Tests that use software private-key fixtures
are explicitly protocol tests, not proof of Secure Enclave properties. Hardware
acceptance requires the signed app/provider, physical devices and user interaction.

## Changed-file inventory

- `Sources/MopLocalIdentity/`: `LocalIdentity.swift`, `LocalIdentityStore.swift`,
  `LocalAuthorization.swift`, `LocalPasskey.swift`, `LocalPasskeySuggestions.swift`,
  `LocalCertificate.swift`, `SSHAgent.swift`, `StoreSSHAgentBackend.swift`,
  `SSHPublicKey.swift`, `GitSetup.swift`. The original model moved from MopCore;
  store/SSH files moved from MopKeychain.
- `Sources/MopCore/`: `VaultSelection.swift`, `MopError.swift`.
- `Sources/MopAppSupport/`: `VaultPresentation.swift`, `LocalVaultService.swift`,
  `NativeVaultService.swift`, `AutoFill.swift`.
- `Sources/MopCLI/`: `LocalCommands.swift`, `LocalItemCommands.swift`, `Mop.swift`,
  `VaultCommands.swift`.
- `Sources/MopUI/`: `AppModel.swift`, `ContentView.swift`, `ItemCollection.swift`,
  `LocalVaultView.swift`, `VaultDetailsView.swift`.
- `Sources/MopVaultNext/`: `VaultEngine.swift`, `Items.swift`.
- `Apple/AutoFill/`: `CredentialProviderViewController.swift`,
  `LocalPasskeyPrompt.swift`, `Info.plist`.
- `Tests/MopLocalIdentityTests/`: moved identity/agent/public-key tests plus
  `PasskeyTests.swift`, `LocalInteroperabilityTests.swift`, `PhysicalDeviceTests.swift`.
- AppSupport/App/CLI tests: local service/model tests, import references and CLI
  validation updated for isolated models and vault-oriented commands.
- Package manifest/lockfiles, Xcode project/lockfile, Apple third-party notices,
  README, and local-vault/AutoFill/security documentation.

## Remaining acceptance restrictions

Apple’s [credential-provider clarification](https://developer.apple.com/forums/thread/745605)
requires backup flags that conflict with device-bound semantics. Another independent
passkey does not change BE/BS for this one. This implementation does not misstate
those flags: it exposes the intended provider flow for physical compatibility
validation, and may fail on affected OS versions. Do not describe the current
build as a validated working passkey provider before completing those tests.

The explicit hardware suite is disabled unless `MOP_LOCAL_HARDWARE_TESTS=1` in a
properly signed test host. Full physical acceptance, a second-device reference-copy
lab test, GUI accessibility/manual workflows, and external security review remain
outstanding. Development record version 1 is not migrated or destroyed; the error
instructs users to use the prior build for explicit removal after replacement.
