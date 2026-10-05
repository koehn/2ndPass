# Security and key management

2ndPass is a development preview, not an independently audited credential store. The [vault architecture](VAULT.md) describes the current service and storage model.

## Device keys and plaintext

Production device identities use separate Secure Enclave agreement and signing keys, with device-only Keychain representations shared through provisioned access groups. There is no software fallback for production hardware identities. Proof of signing-key possession is not remote hardware attestation.

Item keys are wrapped with HPKE and contents use authenticated encryption. Authorized processes necessarily handle decrypted secrets and temporary symmetric keys. Hardware protection cannot prevent a compromised unlocked process from capturing plaintext. The separate `local` vault holds hardware-generated credential keys that cannot be exported, synchronized or restored.

## Account and enrollment trust

Same-account automatic enrollment trusts the authenticated private CloudKit container as a bootstrap channel, together with scoped signed requests, membership history and metadata decryption. An existing unlocked device grants additive membership without a human approval ceremony. An attacker able to write through that trusted account/container channel may obtain admission while an existing device processes the request. Protect the Apple Account and authorized devices accordingly.

Discovery is not authority. Existing device-only trust pins cannot be replaced by a cloud-supplied genesis. Observed account changes invalidate sessions and local account bindings. Offline access cannot detect unobserved account changes, remote revocation or missing remote updates.

## Integrity, synchronization and conflicts

Signed item envelopes bind exact membership authority and per-item revisions. Known older revisions and equal-revision forks are rejected. There is no global proof of inventory completeness or freshness. An authorized writer can write new content at a higher revision. Cloud deletion, omission and corruption can deny service.

Local item changes and pending uploads commit atomically. Delivery receipts distinguish durable local saves from confirmed cloud writes. Conflicts preserve both versions and block affected publication; integration and physical conflict acceptance remain incomplete. Without a global publication fence, stale writers may submit old-key ciphertext; later rejection cannot retract that disclosure.

## Local caches and locking

The encrypted display catalog contains visible metadata, including notes, but no concealed fields or item keys. It is scoped to this device and checked against authoritative item versions. It does not protect against rollback of an entire local store. Lock clears plaintext views and session keys. GUI authorization lasts until lock/expiry; CLI commands own their sessions; AutoFill authenticates afresh and locks after filling. Hardware handles and individual secret keys are released after operations.

## CLI and extension disclosure boundaries

`read` and `inject` release plaintext to stdout or files. `run` passes plaintext environment values to the child, its dependencies and inheriting descendants. Those programs are trusted with the secrets. Exact-byte output masking does not constrain transformed output, files, network traffic or diagnostics. File permissions do not encrypt output, and deletion is not secure erasure.

AutoFill publishes website/username suggestion metadata to Apple's credential system, not passwords or OTP seeds. Selected credentials are resolved again after authentication. Clipboard recipients and applications receiving filled values also receive plaintext.

## Backups and unavailable operations

Portable archives use a generated key independent of device keys. Anyone with both the archive and its key can recover its transferable contents. Keep them separately. Exports reflect local inventory and cannot currently prove remote completeness. See [backup and restore](BACKUPS.md).

Cross-account sharing, device removal, account recovery and permanent vault deletion are unavailable. No current workflow promises revocation or recovery of a live vault after all device keys are lost. Copies already disclosed to a recipient cannot be retracted. General document import and credential-account management also require integration.

## Validation

User-reported same-account enrollment and basic synchronization/offline-edit scenarios are recorded in [validation](VALIDATION.md). Software tests and simulator builds do not establish Secure Enclave behavior, Production schema readiness, cross-account permissions or independent security review.
