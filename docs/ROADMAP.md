# Project direction and roadmap

**Current v7 update:** The coordinated hardware/shared-vault cutover is implemented. The current workflow is documented in [the README](../README.md) and [validation status](V7-VALIDATION-2026-09-27.md); remaining physical acceptance is not implied by historical build notes below.

2ndPass is an Apple-native password and secrets manager built for the
command line. It began with a practical need: keep passwords and other secrets
in an encrypted vault and make them available to commands at runtime, without
depending on a separate password-manager vendor.

The motivation included wanting the freedom to leave a vendor whose choices no
longer aligned with the maintainer's values. 2ndPass should extend that same freedom
to its own users: they should be able to inspect, modify, continue using, and
leave 2ndPass. Matching every feature of a competing password manager is not the goal.

This document describes direction, not features already delivered or a release
schedule. The [README](../README.md) describes current behavior, and
[validation](VALIDATION.md) defines release acceptance requirements.

## Paid App Store release checklist

Recorded September 30, 2026. These are required before putting 2ndPass up for
sale, alongside the existing [release validation gates](VALIDATION.md). All items
below are open; this checklist records intended behavior, not shipped support.
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
  the recovery documentation when implemented. Implementation and automated checks
  are recorded in [offline recovery](OFFLINE-RECOVERY.md); production schema deployment,
  physical-platform acceptance, and independent cryptographic review remain pending.
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
  [enrollment-mailbox isolation requirement](SECURITY.md#shared-zone-enrollment-exposure)
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

Import now supports common CSV exports, Bitwarden JSON, and 1Password 1PUX; see
[Importing password-manager data](IMPORT.md). Portable third-party export remains
planned; encrypted v7 2ndPass backup export remains available. For future format changes, prioritize preserving access to
existing user data and provide an explicit compatibility or migration path.
This does not change the current rejection of pre-v7 formats.

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

Add offline item creation and editing as the next substantial enhancement.
Persist encrypted local changes across restarts, make them available locally,
and distinguish local saves from confirmed cloud synchronization. Reconcile
against current account, ownership, and revision state before publishing.
Merge independent edits where safe and preserve conflicting changes for explicit
resolution rather than silently discarding a password. Keep vault deletion and
ownership/recovery operations online-only initially.

Offline editing requires application-level persistence and conflict handling;
CloudKit cannot merge 2ndPass's encrypted contents. Current offline access remains
read-only until that work is implemented and validated.

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

Device hardware protection is implemented. Cross-account vault sharing remains
an unfinished feature with preliminary code; mailbox isolation and cross-account
physical-device validation are part of completing it. Removing
access cannot retract secrets already copied by a recipient.

Cloud-vault passkeys and cross-account sharing are now prerequisites for paid
App Store release, as tracked above. SALE-1 remains pending until offline recovery is implemented and validated. Future expansion
beyond this checklist should follow the maintainer's needs or evidence from
people actually using 2ndPass.
