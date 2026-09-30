# Device-local vault (`local`)

`local` is a fixed, device-only vault that holds non-exportable identities backed by the Secure Enclave. Unlike the synchronized v7 vaults, it has no account, no iCloud database, no CloudKit sync, no recovery, and no sharing. Its keys are generated in the Secure Enclave on the device, are referenceable by the app, CLI, and AutoFill on that device only, and can never be exported, copied, or moved to another device.

The first identity use is OpenSSH: a device-local identity can answer an SSH agent's `SSH2_AGENTC_SIGN_REQUEST`, so `git push` and `ssh` work with a key whose private half never leaves the enclave.

## Model

The model lives in [MopCore/LocalIdentity.swift](../Sources/MopCore/LocalIdentity.swift) and is deliberately separate from the cloud catalog:

- **`LocalVault`** — the fixed vault. `name == "local"`, `id == "local-vault"`, `isLocal == true`. `rename(to:)` always throws: the vault cannot be renamed.
- **`LocalIdentityProtocol`** — what the identity is for: `ssh`, `git-signing`, `tls-client`, `x509`, `webauthn`, `jwt`, `api-signing`, `recovery`, `generic-signing`, `generic-ecdh`. `isSigning` is true for all except `generic-ecdh`.
- **`LocalIdentityAlgorithm`** — the hardware key type. Only `p256-signing` (ECDSA, `isSigning`) and `p256-key-agreement` (ECDH) are accepted; there is no software algorithm. The protocol and algorithm must agree (a signing protocol needs a signing key and vice versa), or construction fails before any key is generated.
- **`LocalIdentityCapabilities`** — a fixed, non-increasing option set: `.signing`/`.authentication` for `p256-signing`, `.keyAgreement` for `p256-key-agreement`.
- **`LocalIdentity`** — `id`, `name` (1–64 chars, single-line, no NUL), `algorithm`, `protocolType`, `capabilities`, the x963 `publicKey` (never secret), `createdAt`, and non-sensitive `metadata` (e.g. an SSH comment). There is no private-key field by construction.

## What `local` supports

- **List** the device's identities and their public keys.
- **Create** an identity for a protocol; the Secure Enclave generates the key and only the public half is stored alongside the identity record.
- **Delete** a single identity.
- **Public key** for an identity (OpenSSH line for signing identities, x963 otherwise).
- **Sign** data with a signing identity (used by the SSH agent).
- **SSH agent** — serve an in-process OpenSSH agent that signs for the device's identities.

## What `local` does not support

These are rejected by construction, not merely hidden in the UI:

- **No export, backup, or recovery.** The private keys cannot be written out, so there is nothing to export, back up, or restore.
- **No sharing or sync.** No account, no enrollment, no other device.
- **No rename** of the vault or of an individual identity.
- **No vault deletion.** `local` is part of the device; only individual identities can be deleted.
- **Not a general secret store.** No passwords, TOTP seeds, API bearer tokens, symmetric keys, notes, arbitrary secrets, or imported PEM/PKCS#8/private keys. If it is not a non-exportable Secure Enclave key identity, it does not belong in `local`.

The store in [MopKeychain/LocalIdentityStore.swift](../Sources/MopKeychain/LocalIdentityStore.swift) implements `list`, `read`, `publicKey`, `create`, `sign`, `deriveSharedSecret`, and `delete`. There is no export, no rename, and no `deleteVault` method at all.

## CLI

The command surface lives in [MopCLI/LocalCommands.swift](../Sources/MopCLI/LocalCommands.swift). `2ndpass vault list` includes the `local` row.

```
2ndpass local list [--json]                 # list identities and public keys
2ndpass local create NAME [--protocol ...]  # create a non-exportable identity
2ndpass local public-key ID_OR_NAME         # print the public key
2ndpass local sign ID_OR_NAME [--file ..]   # sign stdin or a file (UTF-8)
2ndpass local delete ID_OR_NAME [-y]        # delete an identity
2ndpass ssh-agent -- COMMAND ...            # run COMMAND with a device-local SSH agent
```

`local create`, `local sign`, `local delete`, and `ssh-agent` require biometric/Touch ID authorization. `local list` and `local public-key` do not. `--protocol` accepts any `LocalIdentityProtocol` raw value (default `ssh`); the algorithm is derived from the protocol.

`ssh-agent` authorizes once, starts an in-process OpenSSH agent on a temporary socket, sets `SSH_AUTH_SOCK`, and runs the child. For example:

```
2ndpass ssh-agent -- git push
2ndpass ssh-agent -- ssh deploy@host
```

The agent answers `SSH2_AGENTC_REQUEST_IDENTITIES` and `SSH2_AGENTC_SIGN_REQUEST` for the device's signing identities and rejects unknown keys. Signing dispatch reuses the session's authorization context rather than re-prompting per signature.

## App support

[MopAppSupport/LocalVaultService.swift](../Sources/MopAppSupport/LocalVaultService.swift) is the facade the UI and CLI build on. It is deliberately **not** a cloud `VaultService` — the local vault has no account, transport, or revision history.

- **`LocalIdentityCatalog.build(identities:)`** projects `[LocalIdentity]` into a read-only `ItemCatalog` where each item is an `.sshKey` carrying only the public key (OpenSSH line or x963) and the protocol/algorithm. No `privateKey` field is ever produced, and `storageID` carries the keychain UUID so detail/sign/delete resolve the exact Secure Enclave key. `canEdit` is `false`.
- **`LocalVaultPolicy`** is a pure, store-free policy. It allows `list`, `create`, `deleteItem`, `publicKey`, `sign` and rejects `renameVault`, `renameItem`, `export`, `share`, `deleteVault`, returning a concise reason for each. This is unit-testable without a Secure Enclave.
- **`LocalVaultService`** wraps `LocalIdentityStore` and enforces the policy; its forbidden-operation methods (`renameVault`, `renameItem`, `export`, `share`, `deleteVault`) always throw `.localOperationForbidden` so no caller can route them through the local vault.

## Security notes

- Newly created keys require device-owner user presence for private-key operations, using the preauthorized session context. Identities created by earlier development builds without this access control retain their original protection. Create replacement identities and update the public keys trusted by your services before deleting those older identities; this update does not rotate existing keys automatically.
- Deleting an identity in the GUI or CLI requires explicit device-owner authorization.
- Keys are generated and used in the Secure Enclave via the Keychain; only the x963 public key is stored with the identity record. The private half is never readable by 2ndPass or any process.
- Because there is no export path, the vault is safe to keep on a lost device only in the sense that its keys cannot be carried off; deleting the app or the identities removes the references.
- There is no FIPS 140-3 Secure Enclave claim made here; verify that separately before relying on it.
- Passkey/WebAuthn credential-provider exposure is not yet wired; `webauthn` identities are creatable and usable for signing but a system credential provider is a separate effort.

## Verification

- Unit-tested without hardware: the model (name validation, protocol/algorithm agreement), the SSH public-key encoding, the SSH agent framing/dispatch, the catalog projection (public-key-only, no private key), and the policy (allowed vs forbidden).
- Requires a physical device (Secure Enclave): real key generation, `sign`, `deriveSharedSecret`, `delete`, and the SSH agent serving a live `ssh`/`git` session. The simulator has no Secure Enclave.

See [security](SECURITY.md), [the CLI](../README.md), and [architecture](VAULT-NEXT.md) for the surrounding trust model.
