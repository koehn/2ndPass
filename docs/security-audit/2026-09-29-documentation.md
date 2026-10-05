> Historical source-review evidence; use the original Git revision to reproduce it. This is not the current architecture or release acceptance. See [current security](../SECURITY.md) and [validation](../VALIDATION.md).

# Security documentation audit — 2026-09-29

Scope: current implementation at the recorded revision and repository/website documentation.
This is a source-based documentation and threat-model audit, not an independent
professional security audit or live penetration test. Existing and concurrently
arriving application/test changes were preserved. This task changed prose and
source comments only; it did not change cryptography, entitlements or behavior.
Website source was updated and built locally, not deployed to the public host.

## Material corrections

- Described Apple account/device security, signing/provisioning, CloudKit
  entitlements and private per-user storage as layers beneath 2ndPass device
  membership. Account credentials alone do not authorize arbitrary native
  container writes. No private iCloud Keychain trust-circle integration is claimed.
- Documented intentional automatic same-account enrollment while an enrolled
  owner session can process requests unlocked and online. Corrected stale claims
  requiring code comparison; retained manual CLI commands as optional diagnostics.
- Made independent, non-exportable Secure Enclave agreement/signing identities
  explicit, with opaque device-bound representations. Distinguished private-key
  extraction from authorized key use and plaintext capture on a compromised host.
- Corrected per-secret/per-record key descriptions to per-item keys shared by
  separately encrypted fields, plus a fresh catalog key per revision. Enrollment
  decrypts catalog metadata but need not decrypt concealed fields/attachments.
- Clarified append-only item-key wrapping on addition, preservation on role-only
  changes, and full retained-item rotation/re-encryption on recipient removal,
  existing recovery-recipient replacement and in-place recovery. Old keys,
  ciphertext and plaintext cannot be revoked retroactively.
- Separated revision authenticity/integrity, stale-write detection and rollback
  against intact local checkpoints from absolute freshness and availability.
  Local trust files are not hardware monotonic state.
- Explained CLI stdout/environment/file disclosure and AutoFill's shared Keychain
  identity, fresh session and plaintext destination. Exact-byte output masking
  cannot constrain arbitrary child behavior.
- Documented recovery as a security/availability tradeoff, without a vendor-held
  recovery master key; corrected the suggestion that the shipping recovery command
  runs offline (only the pure recovery computation is independent of transport).
- Corrected schema/format/runbook references at the recorded revision; marked historical
  reports and benchmarks without rewriting their recorded results. In particular,
  `IMPORT.md` incorrectly claimed current v6 readability.
- Kept Apple Passwords comparisons conservative: Apple also uses hardware-backed
  Keychain protection. Inspectability is not a comparative security verdict.
  Independent audit and physical acceptance remain outstanding.

Earlier account-compromise shorthand understated Apple's access-control layers.
Mandatory-comparison and unqualified private-mailbox claims overstated enrollment
isolation. Existing freshness, copied-secret and memory-erasure caveats were
substantially correct and have been preserved and clarified.

## Unfinished sharing design requiring human review

**Design detail for future sharing: shared-zone enrollment isolation.**
The maintainer clarified that cross-account vault sharing is unimplemented as a
supported product feature. Preliminary transport, protocol and UI code exists,
but this issue belongs to completing that design, not to the classification of
current product vulnerabilities. The earlier release-blocking vulnerability
framing is withdrawn. The source observations remain relevant to implementation:
account-private enrollment must not become writable through a future zone share.

1. `CloudRevisionTransport.enrollment` and `saveEnrollment` use the fixed
   `enrollment` record in `zone(address)`, the same zone as vault records.
2. `share(with:role:at:)` creates `CKShare(recordZoneID: zone(address))` and assigns
   editors `.readWrite`. Apple documents that zone shares include their records
   and that writable participants can change/delete shared records. See
   [Apple Shared Records](https://developer.apple.com/documentation/cloudkit/shared-records).
3. The `.private` guard describes the local caller's database view, not exclusive
   server-side writer provenance. The owner continues to access shared records
   through its private database.
4. `DeviceRequest.validate` checks a self-signed account/member binding;
   `EnrollmentRequest.validate` compares it to the owner address. Neither proves
   which authenticated account wrote each exchange. `automaticEnrollment` can
   subsequently sign an owner grant for an accepted request.

Design inference if sharing were completed with these code paths unchanged:
a malicious writable participant capable of authorized container operations could
claim the owner account in a new key request and induce automatic owner admission.
This is not a claim that arbitrary unprovisioned apps or stolen account passwords
can access the container. It also does not require forging an owner's signature:
the concern is inducing the legitimate owner to make a grant.

No live two-account exploit was attempted. The service-test server keys mailboxes
by `address.binding` and stubs share permissions, so its passing enrollment tests
would not establish real shared-zone isolation. When implementing sharing, keep
bootstrap records in an account-private namespace that is never shared, or
establish an equivalent authenticated boundary. Validate it with disposable
accounts and preserve ordinary automatic same-account enrollment. Any test or
prototype shared mailboxes also need to be accounted for. This documentation
change does not implement sharing or resolve that design detail.

Other distinctions from the requested conceptual model:

- The Mac app/CLI are hardened but not App Sandbox targets; the Mac extension is
  sandboxed and iOS/iPadOS use their platform sandbox. This is a documented
  packaging choice, not by itself a newly demonstrated defect.
- App/CLI/extension share a device-local identity; keys are not regenerated for
  every executable or reinstall that can reopen the existing Keychain item.
- Key possession is not remote hardware attestation. The shipping provider uses
  Enclave keys, but signatures do not prove a remote recipient did so.
- Surviving viewer/editor hardware can retain decryption ability without owner
  enrollment authority. Accessible ciphertext and trusted checkpoint evidence
  are additional recovery requirements.

## Source evidence and review coverage

| Claims | Primary implementation inspected |
| --- | --- |
| Device creation, opaque storage, access controls | `MopVaultNext/Device.swift`, `DeviceKeychain.swift`; `MopAuth/Authentication.swift` |
| HPKE, item/catalog hierarchy, signed transitions | `MopVaultNext/Crypto.swift`, `Revision.swift`, `Items.swift`, `VaultEngine.swift`, `Membership.swift` |
| Account scope, enrollment, cross-account and recovery routing | `MopVaultNext/Exchange.swift`, `Enrollment.swift`; `MopAppSupport/NativeVaultService.swift`, `NextRegistry.swift`; `MopUI/AppModel.swift` |
| Cloud addresses, conditional publication, checkpoints | `MopVaultNext/CloudRevisionTransport.swift`, `Publication.swift`, `FileVerifiedStateStore.swift` |
| CLI disclosure | `MopCLI/Mop.swift`, `OutputOptions.swift`, `Execute.swift`, `EnvironmentBlock.swift`, `MaskedExecute.swift` |
| AutoFill and extension access | `MopAppSupport/AutoFill.swift`, `AutoFillSession.swift`; `Apple/AutoFill/CredentialProviderViewController.swift`, entitlements |
| Signing/provisioning and build scope | `MopKeychain/SigningIdentity.swift`, `MobileSigningIdentity.swift`; `scripts/signing-config.py`, `package.sh`; Apple entitlements/project; `Package.swift` |

Paths beginning with module names are under `Sources/`. The package graph excludes
historical `MopVault`/`MopCloudKit` software-account implementations; they are not
evidence of current app cryptography. Review used repository-wide keyword/file
searches, not only the requested minimum document list.

Public website pages, its README and canonical-document generator were inspected.
Other inspected documents include root/assets/examples READMEs, security guides,
architecture/wire-format, CloudKit/account, GUI/mobile/AutoFill, CLI manpage/examples,
imports/mappings, build/release/Homebrew/branding, roadmap/mobile plan, historical
security/UI reviews, validation reports and profiling notes. Historical evidence
was retained; unchanged applicable claims were not rewritten merely for style.

## Auditor and physical-acceptance questions

- When implementing vault sharing, resolve shared-zone bootstrap isolation, including an accepted transport
  participant not yet cryptographically enrolled and stale share permissions.
- Validate actual signed app/CLI/extension Keychain-group access and denial to
  re-signed/unprovisioned clients on supported physical platforms. Inspect built
  artifacts, not just entitlement templates.
- Validate Secure Enclave authorization reuse, cancellation/lock races, handle
  release and recovery after account changes on separate physical devices.
- Review HPKE/AES context separation, canonical signatures, parent authority,
  invitation replay, random-key generation and complete retained-item rotation.
  Structural validation cannot prove that an authorized writer used fresh entropy.
- Exercise rollback/fork/withholding, restored local trust state, interrupted
  filesystem writes, uncertain cloud commits and cross-account permission changes.
- Review plaintext lifetime, UI/framework copies, AutoFill metadata/destinations,
  CLI child environments/masking and supply-chain/signing-key compromise. Protocol
  correctness and implementation correctness require separate assurance.

## Changed files

- `README.md`
- `docs/SECURITY.md`, `SECURITY-EXPLAINER.md`, `VAULT-NEXT.md`, `CLOUDKIT.md`,
  `ACCOUNT-IDENTITY.md`, `AUTOFILL.md`, `GUI.md`, `MOBILE.md`, `EXAMPLES.md`,
  `IMPORT.md`, `VALIDATION.md`, `RELEASING.md`, `ROADMAP.md`, `BRANDING.md`,
  `IOS-IPADOS-PLAN.md`, `ITEM-KEY-BENCHMARK-2026-09-27.md`,
  `REMOVAL-PROFILING-2026-09-27.md`
- `docs/man/sp.1`; historical banners in
  `docs/security-audit/2026-09-23.md` and `2026-09-24-review.md`; this report
- `website/src/security.md`, `docs.md`, `faq.md`, `index.njk`
- Comments only in `Sources/MopVaultNext/Enrollment.swift`, `Membership.swift`,
  `CloudRevisionTransport.swift`, `Sources/MopCLI/CommandVaultAuthorization.swift`

## Validation performed

Website build passed; its checker validated seven pages for local links, assets,
anchors and duplicate IDs. `git diff --check` passed. Changed repository Markdown
files have no missing relative file targets. The manpage renders with `mandoc`;
stale mixed man/mdoc macros were corrected and lint passes.
No app behavior tests, hardware authorization, production schema changes, cloud
writes, signing or deployment were performed by this documentation audit.
