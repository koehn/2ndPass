# Project direction and roadmap

Current clients use independently encrypted item records, a shared device-local store and CKSyncEngine. Local saves, portable backup/restore and automatic same-account connection are implemented. User-reported enrollment and basic synchronization/offline-edit acceptance are recorded in [validation](VALIDATION.md). This remains a development preview.

2ndPass is an Apple-native password and secrets manager built for the
command line. It began with a practical need: keep passwords and other secrets
in an encrypted vault and make them available to commands at runtime, without
depending on a separate password-manager vendor.

The motivation included wanting the freedom to leave a vendor whose choices no
longer aligned with the maintainer's values. 2ndPass should extend that same freedom
to its own users: they should be able to inspect, modify, continue using, and
leave 2ndPass. Matching every feature of a competing password manager is not the goal.

This document tracks implementation progress and remaining release requirements;
it is not a release schedule. The [README](../README.md) describes current behavior, and
[validation](VALIDATION.md) defines release acceptance requirements.

## Implementation status — October 6, 2026

The current preview includes the following work. Implementation and recorded
physical checks are separate from completion of the paid-release checklist.

| Area | Implemented in the preview | Remaining work |
| --- | --- | --- |
| Item storage and synchronization (SALE-10) | Shared App Group Core Data store, CKSyncEngine transport, encrypted local saves/outbox, exact delivery receipts, automatic same-account connection, and cached display catalogs. User-reported checks cover iPhone → Mac/iPad delivery, Mac edits, and offline iPhone edits uploading after reconnect. | Physical restart/interruption, receipt supersession, account-change, and concurrent-edit acceptance; independent attachment transport and bounded cleanup. |
| Conflict review (SALE-10) | Conflict inbox and item banners, with a review dialog identifying each version's device, update time, and deletion state. Users can keep the local or remote version; failed resolution retains both versions for retry. | Physical concurrent-edit and conflict/history preservation checks. The current dialog offers whole-version selection, not field-by-field comparison or merging. |
| Password security health (SALE-2) | Security findings for exposed, reused, and weak passwords; encrypted per-item check results and a local security index; independent check lifetimes, incremental results, and changed-password strength updates before network checks finish. | Real CloudKit propagation, simultaneous-device behavior, signed macOS UI, and full accessibility/appearance acceptance. Credential-account redundancy management (SALE-3) remains unavailable. |
| Native AutoFill (SALE-12) | Password, TOTP, and passkey flows; incremental suggestion publication with durable retry state; selected-item resolution without a whole-catalog read; new-login saving on iOS/iPadOS 26.2+. | Signed platform and live-site acceptance, password generation and existing-login updates, and the Firefox/Chrome lifecycle (SALE-4/SALE-5). |
| Cloud key credentials (SALE-6/SALE-13) | Cloud passkey and SSH creation/use, supported OpenSSH imports, and portable restoration of software credential bytes. Device-local hardware credentials remain separate. | Physical SSH/Git/IDE and passkey acceptance, recovery and sharing integration, and documented device-bound passkey compatibility checks. |
| History and portability (SALE-9/SALE-11) | Per-field retained history with restore/clear, plus portable archive export/restore using an independent archive key. Basic backup/restore has user-reported acceptance. | Complete remote inventory verification, fresh-identity/loss-of-account scenarios, physical history/conflict preservation, and SALE-1 master-recovery-key integration. General document import still needs service integration. |
| Distribution and Pro (SALE-14/SALE-15) | Sandboxed Mac app, separate CLI packaging, and entitlement status reporting. Subscription scaffolding targets an annual Pro product. | Signed clean-machine distribution and developer workflows, Free/Pro enforcement, purchase publication, final commercial decisions, and purchase/downgrade acceptance. Purchases and enforcement remain disabled in the preview. |

See [validation](VALIDATION.md) for the scope of recorded physical checks,
[security health and history](SECURITY-HEALTH.md), [AutoFill](AUTOFILL.md),
[cloud keys](CLOUD-KEY-CREDENTIALS.md), [backups](BACKUPS.md), and
[subscription status](SUBSCRIPTIONS.md) for current behavior and limitations.

The next durability milestone is physical validation of the implemented conflict
review and queued-write lifecycle. In parallel, remaining feature integration
includes recovery, cross-account sharing, device removal, permanent vault deletion,
general document import, and credential-account management. Every implemented
flow still needs the complete SALE-8 UI review before a paid release.

## Paid App Store release checklist

Recorded September 30, 2026; status updated October 6, 2026. These are required
before putting 2ndPass up for sale, alongside the existing
[release validation gates](VALIDATION.md). All items below remain open for full
release acceptance; implemented portions are summarized above.
It supersedes earlier deferrals of passkeys and cross-account sharing for the
paid release. Free/Pro packaging is the chosen direction (SALE-15); prices and
subscription versus permanent-unlock purchase options remain undecided.

- [ ] **SALE-1 — Offline master recovery key.** Generate a recovery keypair and
  let the user retain the private key offline. Add the public key as an additional
  recovery recipient for the vault catalog, items, and attachments. Devices on
  the same iCloud account must be able to recover vault access using that key.
  Acceptance: key generation, offline-copy setup, and recovery work end to end
  on supported platforms, including when all previously enrolled devices are
  unavailable. Define account binding, key replacement/revocation, and coverage
  of existing and newly written data. Review the changed threat model and update
  the recovery documentation when implemented. Account recovery is currently unavailable; see [recovery status](OFFLINE-RECOVERY.md).
- [ ] **SALE-2 — Password security health.** Provide a screen showing passwords
  found in Have I Been Pwned (HIBP), reused passwords, weak/simple passwords, and
  actionable guidance for resolving findings. Acceptance: findings identify
  affected accounts, refresh after corrections, and distinguish an unavailable
  or incomplete check from a clean result. Design breach checks so plaintext
  passwords are not sent to the service.
- [ ] **SALE-3 — Device-local credential redundancy.** Security health must flag
  accounts whose device-local credential exists on only one device and prompt
  the user to register backup/alternate keys on other devices. Acceptance:
  distinguish an alternate credential actually registered with the account from
  a key merely generated on another device; define how registration is confirmed
  and show uncertainty when redundancy cannot be established. Do not imply that
  a device-local private key can be copied or synchronized.
- [ ] **SALE-4 — Firefox extension.** Complete the browser integration and its
  installation, connection, unlock, and everyday credential workflows.
  Acceptance: validate against supported Firefox/macOS versions, including
  origin matching, permission boundaries, locked/unavailable app behavior, and
  actionable connection errors.
- [ ] **SALE-5 — Chrome extension.** Complete the equivalent Chrome integration
  and validate its installation, connection, unlock, credential workflows,
  origin matching, permission boundaries, and failure states on supported versions.
- [ ] **SALE-6 — Cloud-vault passkeys, SSH keys, and other key credentials.**
  Let users explicitly choose cloud-vault storage for supported key types as an
  alternative to device-local storage. Acceptance: document the supported key
  types and protection/recovery differences; verify creation/import where
  applicable, use, synchronization, recovery, and sharing permissions. Preserve
  the device-local option for keys generated in the Secure Enclave. Existing SSH
  private keys can be imported into cloud vaults only, never into the device-local
  vault; Secure Enclave keys cannot be exported or moved out of hardware. See
  SALE-13 for imported-key workflows.
- [ ] **SALE-7 — Cross-account vault sharing.** Finish sharing between multiple
  iCloud accounts. Acceptance: complete invitations, acceptance, editor/viewer
  permissions, revocation, conflict handling, and reconnection with real accounts
  and physical devices. Resolve the documented
  [account and enrollment trust boundary](SECURITY.md#account-and-enrollment-trust)
  and explain that revocation cannot retract previously copied secrets.
- [ ] **SALE-8 — Impeccable UI across platforms and devices (mandatory release
  gate).** Review and finish every screen, pane, dialog, and flow on macOS, iOS,
  and iPadOS, including every feature in this checklist and browser-extension surfaces.
  Acceptance: maintain a complete surface/flow inventory and sign off each entry
  across supported device sizes, window sizes, orientations, light/dark appearance,
  text sizes, and accessibility input/navigation. Cover onboarding, import,
  enrollment, vault/item management, AutoFill, security health, recovery, sharing,
  settings, and purchase flows, including empty, loading, success, error, offline,
  locked, and destructive-confirmation states. Resolve visual and interaction
  defects before sale; representative screenshots alone are not sign-off for
  unreviewed screens or flows.
- [ ] **SALE-9 — Portable export and independently restorable backups.** Provide
  a documented portable export preserving secrets, custom fields, and attachments,
  with explicit handling of unsupported/non-exportable credentials. Provide an
  encrypted backup that can be restored using the offline master recovery key
  from SALE-1 without any previously enrolled device. Acceptance: verify export
  completeness and backup restoration with disposable vaults, including deleted
  cloud data and loss of the original Apple account. Define an explicit restore
  into a new account without depending on access to the old account; distinguish
  this backup restore from same-account recovery of a live cloud vault. Explain
  plaintext export exposure and device-local key exclusions.
- [ ] **SALE-10 — Offline creation and editing.** Allow new credentials and
  changes to existing items to be saved while offline or while iCloud is
  unavailable. Acceptance: encrypted pending changes survive app/device restarts,
  remain usable locally, and show clear pending-sync versus confirmed-sync status.
  Reconcile account, membership, and revision state on reconnect; preserve
  conflicting values for explicit resolution rather than silently losing secrets.
  Keep vault deletion and ownership/recovery operations online-only initially.
- [ ] **SALE-11 — Secret history and rollback.** Retain previous secret values
  and provide a straightforward per-item restore action without restoring an
  entire vault. Acceptance: recover an accidentally overwritten password or API
  token; preserve history through synchronization and encrypted backup/restore.
  Define retention, permanent deletion, access permissions, and recovery-key
  coverage for historical values. Distinguish restoring a stored value from
  reactivating a credential that has been revoked at its service.
- [ ] **SALE-12 — Complete browser credential lifecycle.** Explicitly include
  generate → fill → save → update in the Firefox and Chrome integrations
  (SALE-4/SALE-5), and finish supported native AutoFill creation/update workflows.
  Acceptance: create a login and capture a changed password end to end; confirm
  the target account/vault before updating, preserve the previous value, handle
  cancellation and failed saves without silent loss, and avoid duplicate records.
  Document platform limitations and provide a clear app handoff where native
  AutoFill cannot support a step.
- [ ] **SALE-13 — Existing SSH keys as usable cloud-vault credentials.** Import
  existing OpenSSH private keys into cloud vaults and use them through the SSH
  agent and Git signing workflows, not merely as stored text. Existing private
  keys must never be imported into the device-local vault: that vault only holds
  keys generated in the Secure Enclave. Acceptance: document supported formats
  and algorithms, handle encrypted private-key imports, and verify authentication
  and signing with SSH, Git, and representative IDE workflows. Verify key
  selection, unlock/approval, lock revocation, synchronization, and recovery.
- [ ] **SALE-14 — Mac App Store sandboxing and developer-tool distribution.**
  Establish and validate an App Sandbox-compliant Mac App Store distribution
  architecture. Acceptance: prove clean-machine installation and updates preserve
  working CLI access, `sp run`, secret injection, SSH-agent sockets, Git signing,
  browser-extension communication, and app/extension vault access with appropriate
  entitlements. Document any separately distributed companion and its installation
  and signing requirements. Validate the actual distribution artifacts; development
  builds alone do not establish sandbox compatibility or App Store acceptance.
- [ ] **SALE-15 — Free/Pro tiers and a single Pro entitlement.** Launch with a
  useful Free tier and one Pro upgrade for Apple-using developers and engineers.
  Implement the packaging and entitlement rules below across the app, CLI,
  AutoFill, and browser integrations. Acceptance: verify purchases, restoration
  on another device, pending/cancelled/failed purchases, refunds/revocations,
  offline entitlement handling, and subscription expiry if subscriptions are
  offered. Enforce capacity rules consistently without deleting data, blocking
  recovery/export, or revoking cryptographic vault membership. Include upgrade,
  restore-purchase, and expired-entitlement flows in SALE-8 UI acceptance.

Implementation notes for SALE-2, SALE-3, and the basic-history portion of SALE-11
are in [security health and history](SECURITY-HEALTH.md). These items remain open
until their physical-platform, real-service, and UI acceptance gates are complete.

Track implementation and acceptance evidence against these stable IDs. Check an
item off only when its behavior and acceptance are complete; passing builds alone
does not close a feature or the UI release gate.

### Free/Pro packaging and entitlement rules

- **Free:** A small, fully functional vault, with a provisional limit of 25 items
  and a small attachment allowance. Include all supported Apple platforms,
  synchronization across the user's own devices, browser extensions, passwords,
  notes, TOTP, passkeys, offline editing, basic secret history, security health,
  and device-local credential redundancy warnings. Include CLI reads, injection,
  `sp run`, SSH-agent/Git-signing workflows, and supported device-local identities
  within the evaluation limits so engineers can try the actual product.
- **Pro:** Unlimited items, multiple cloud vaults, cross-account sharing, and a
  larger attachment allowance, with all developer capabilities included. A
  single Pro entitlement unlocks the tier across supported platforms and clients;
  do not sell separate device, platform, or key-type upgrades. Unlimited items
  does not remove documented technical vault/storage limits.
- **Security and ownership:** Both tiers have the same cryptographic protections.
  Export, encrypted backup, master recovery, and missing backup-key warnings must
  remain available without Pro. Do not charge per device or discourage enrolling
  another device for redundancy. Imported SSH private keys remain cloud-vault
  only; tiering does not change Secure Enclave constraints.
- **Expiry or downgrade:** Preserve existing credentials and attachments, reads
  and use of existing credentials, export, and recovery. Restrict additions beyond
  Free capacity or paid management workflows instead of locking users out. Do not
  delete excess items or vaults, remove enrolled devices, or silently revoke shared
  access. Show clear entitlement and capacity status with an actionable upgrade
  path. A transient purchase-service outage must not be treated as confirmed
  expiry; define and test cached/offline entitlement behavior.
- **Implementation decisions still required:** Finalize the Free item limit,
  attachment allowances, counting of device-local identities/history/trashed
  items, import-over-limit behavior, and who needs Pro to create or participate
  in sharing. Define subscription/permanent-unlock products, pricing, and
  downgrade management rules before shipping. Keep purchase entitlement separate
  from vault authorization and provide a verified entitlement path for CLI and
  extensions. A separate Personal or Team tier is not part of this release.

## Supporting priorities

### 1. Make migration in and out practical

Add imports from common password-manager exports and a documented, portable
export path suitable for moving to another tool. Document the vault format and
recovery process so data access does not depend solely on the official app.
Handle plaintext interchange files explicitly and explain their exposure.

Portable archive export/restore is available with an independent archive key. General CSV/JSON/1PUX import still needs service integration; parser code alone does not complete that workflow. Exports cannot yet certify complete remote inventory. See [import status](IMPORT.md) and [backups](BACKUPS.md).

### 2. Make runtime access exceptionally reliable

Keep secret references, environment injection, configuration templates, and CLI
authentication central to the product. Improve these workflows based on actual
use, including actionable errors and predictable behavior when connectivity or
authentication fails. Preserve clear documentation of output-masking limits and
of how secrets reach child processes.

### 3. Strengthen durability and confidence

Complete the signed physical-device and Production CloudKit acceptance in
[validation](VALIDATION.md), including recovery, interrupted synchronization,
account changes, and upgrades. Seek independent security review before promoting
2ndPass for broad use as a primary credential store.

Offline creation and editing commit encrypted changes locally and queue synchronization. Basic offline-edit delivery has user-reported physical acceptance. Conflict review now supports explicit local/remote version selection. Complete physical concurrent-edit acceptance, restart/interruption scenarios, receipt supersession and account-change handling without losing either version. Independent attachment transfer and bounded cleanup of staging, receipts and quarantine remain work.

### 4. Make distribution accessible

Provide signed builds so using 2ndPass does not require users to provision and build
their own application. Start with a small beta of Apple-using developers and use
their migration, installation, recovery, and everyday workflow experience to
guide further work. Observe continued use and concrete blockers before expanding
the feature list.

Paid App Store distribution is an option for funding packaging and maintenance,
not a prerequisite for the project's success. Evaluate Mac App Store packaging
and CLI compatibility through SALE-14. The chosen packaging is a free download
with a single Pro entitlement, as described in SALE-15. Prices and subscription
versus permanent-unlock options remain undecided. Access to existing
credentials and export should not depend on continued payment. Source availability and
paid, maintained distribution can coexist.

## Current implementation boundaries

Cross-account sharing, account recovery, device removal, permanent vault deletion, general document import and credential-account management are unavailable. Cloud-key creation/use routes through item reads and saves, and software credential bytes survive portable restore; full physical acceptance remains pending. Device-local hardware credentials remain separate and cannot be synchronized or restored.

The checklist boxes represent full release acceptance, not source implementation. All remain open until the described gates are evidenced. Implemented portions include password checks, basic history, portable archives, offline saves, distribution scaffolding and entitlement reporting. Free/Pro enforcement and purchase publication remain disabled in the preview. Complete the remaining integration and physical checks before treating any of these as release-ready.
