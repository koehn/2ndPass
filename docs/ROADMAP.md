# Project direction and roadmap

**V6 update:** The coordinated hardware/shared-vault cutover is implemented. The current workflow is documented in [the README](../README.md) and [validation status](VAULT-NEXT-VALIDATION.md); remaining physical acceptance is not implied by historical build notes below.

Mop is an open-source, Apple-native password and secrets manager built for the
command line. It began with a practical need: keep passwords and other secrets
in an encrypted vault and make them available to commands at runtime, without
depending on a separate password-manager vendor.

The motivation included wanting the freedom to leave a vendor whose choices no
longer aligned with the maintainer's values. Mop should extend that same freedom
to its own users: they should be able to inspect, modify, continue using, and
leave Mop. Matching every feature of a competing password manager is not the goal.

This document describes direction, not features already delivered or a release
schedule. The [README](../README.md) describes current behavior, and
[validation](VALIDATION.md) defines release acceptance requirements.

## Open source first

Keep the project open source under its existing [MIT license](../LICENSE).
Prioritize useful documentation, inspectable implementation, and a practical path
for others to build and maintain it. Publishing source enables review; it does not
by itself establish security or guarantee contributors and support.

The initial audience is Apple-using developers who want personal passwords and
runtime secrets in one native application. A useful, sustainable project for
that audience is a successful outcome without becoming a general-purpose
commercial password-manager business.

Mop still depends on Apple platforms, Secure Enclave, and CloudKit. Independence
from a separate password-manager service does not mean independence from Apple.
Portable exports and a documented vault format should preserve users' options.
Cross-platform clients and alternate synchronization providers are not current
commitments.

## Ordered priorities

### 1. Make migration in and out practical

Add imports from common password-manager exports and a documented, portable
export path suitable for moving to another tool. Document the vault format and
recovery process so data access does not depend solely on the official app.
Handle plaintext interchange files explicitly and explain their exposure.

Current import/export supports encrypted v6 Mop backups only; general migration
support is planned. For future format changes, prioritize preserving access to
existing user data and provide an explicit compatibility or migration path.
This does not change the current rejection of pre-v6 formats.

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
Mop for broad use as a primary credential store.

Add offline item creation and editing as the next substantial enhancement.
Persist encrypted local changes across restarts, make them available locally,
and distinguish local saves from confirmed cloud synchronization. Reconcile
against current account, ownership, and revision state before publishing.
Merge independent edits where safe and preserve conflicting changes for explicit
resolution rather than silently discarding a password. Keep vault deletion and
ownership/recovery operations online-only initially.

Offline editing requires application-level persistence and conflict handling;
CloudKit cannot merge Mop's encrypted contents. Current offline access remains
read-only until that work is implemented and validated.

### 4. Make distribution accessible

Provide signed builds so using Mop does not require users to provision and build
their own application. Start with a small beta of Apple-using developers and use
their migration, installation, recovery, and everyday workflow experience to
guide further work. Observe continued use and concrete blockers before expanding
the feature list.

Paid App Store distribution is an option for funding packaging and maintenance,
not a prerequisite for the project's success. Evaluate Mac App Store packaging
and CLI compatibility before committing to that channel. A paid app or one-time
unlock with a clear future-upgrade policy is the initial commercial direction to
explore; pricing and a business model are not decided. Access to existing
credentials and export should not depend on continued payment. Open source and
paid, maintained distribution can coexist.

## Features deferred until there is a demonstrated need

- **Passkeys:** Add when the maintainer or users need them to use Mop as their
  primary credential manager. Their hardware and recovery model needs a separate
  design and acceptance effort.

Shared vaults are now implemented together with device hardware protection in v6.
Their cross-account and physical-device release gates remain outstanding. Removing
access cannot retract secrets already copied by a recipient.

Passkeys are not a prerequisite for an initial open-source release. Prioritize
the original runtime-secrets problem, user control, and reliable operation over
feature parity. Future expansion should follow the maintainer's needs or evidence
from people actually using Mop.
