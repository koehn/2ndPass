# Retired implementation cleanup

## Scope and preservation

The application now requires the current content/grant session. V2 encryption,
legacy repository behavior, general document-import parsers, cross-account
sharing and credential-account-management scaffolding, grant maintenance and
old-zone migration have been removed. Portable archives now use version 2 and
explicitly reject version 1. Only `sp://` references are supported; retired
`mop://` references fail before secret-dependent child execution.

The cleanup preserves current store paths, model identifiers and entity shape,
Keychain services, cryptographic domains, recipient grant zones and current
pending-work keys. No live data reset, cloud deletion, signing identity change
or schema deployment was performed. Existing recipient-zone and authentication
lifetime work was integrated rather than reset.

## Review stages

1. Shared logical content types and current-protocol test fixtures.
2. Mandatory content/grant session; removal of V2 behavior and optional layouts.
3. Unsupported surfaces, old grant routing and distribution upgrade paths removed.
4. Portable archive v2, metadata exclusions and independent wire fixture.
5. Requirements/documentation reconciliation and software validation.

These are logical review stages in the working tree, not separate commits.

## Intentional survivors

- Core Data declarations such as `Conflict` and `AdmissionItem` remain part of
  the deployed model shape. Their retired behavioral entry points are gone.
- Shared `Item`, pending mutations, receipts, transaction boundaries, revision
  indexes and conflict/version value types support the current content engine.
- `sync-journal-v1` storage keys and existing capacity-retry journal decoding
  preserve current pending work; their version labels are not V2 vault support.
- Local password-health envelopes retain encryption, signature verification,
  exact parent checks and authorization lifetime. They never enter cloud output.
- Signed membership verification remains shared by enrollment, removal and
  recovery. Removing future-sharing screens does not change signed formats.
- Idle catalog/AutoFill maintenance scheduling remains functional; it is separate
  from the removed grant-maintenance workflow.
- Stable application, store, Keychain and cryptographic identifiers retain their
  historical names deliberately.

## Software validation — October 16, 2026

The full elevated Swift suite passed 701 tests after the final repository API
simplification, manual-enrollment removal and populated-health archive exclusion. Commands use the cache settings and access in `AGENTS.md`.
The suite includes current-store reopening and pending work, old-store rejection
without rewriting, local health cache behavior, authorization, recipient-zone
repair, current conflict resolution, removal/recovery, and archive v2 checks.
Core Data printed temporary test-store teardown diagnostics; the runner exited
successfully with all test assertions passing.

- CLI smoke: 104 checks passed, including retired-command and reference rejection.
- Signing configuration, install layout/rollback, GUI isolation, signed CLI cask
  archive generation checks passed. Installer signing is stubbed in layout tests.
- Subscription CLI reporting and generated Bash/zsh/manpage checks passed.
  Fish source was checked; fish runtime was unavailable.
- Log-audit tooling: 2 tests passed. Website deployment tooling: 3 tests passed.
- Website build and link/asset/anchor/duplicate-ID checks passed.
- `git diff --check` passed.

The capacity drain/replay test received an explicit replay barrier after an iOS
run exposed an observer race in its intermediate assertion. The focused Swift
regression passes without removing its final checkpoint/restart assertions.

The background-editor UI test now preserves visible editing after background
return, as confirmed by the user, and still requires explicit lock to discard the
draft. Enrollment and backup UI assertions use the current automatic enrollment
entry point and portable backup label. Vault details opens through the vault
context menu. Locked-entry tests no longer try to open unavailable Settings;
the duplicate trust-failure test was consolidated into the retained test that
also verifies background return does not retry authentication.

macOS Debug app and AutoFill builds passed with signing disabled.
iOS app simulator build passed. All 465 iOS software tests passed in the final
run. All 22 retained iOS UI cases passed across the initial run and focused
reruns after corrections: 18 unchanged cases, then background editing,
enrollment entry, identity-pending entry and vault settings/field actions.
The final vault-settings rerun exited successfully. Initial failing assertions
are described above; they are not counted as successful runs.

iOS AutoFill generic simulator build passed with signing disabled.

## Readable-version initialization regression — October 16, 2026

Routing now uses a standalone durable local completion checkpoint before reading
the item revision index. It preserves existing readable references and does not
restore retired grant-zone migration code. Existing stores perform one pass to
establish the new checkpoint, skipping references already present.

The full elevated Swift suite passed 704 tests. After the final cancellation
guard and assertion, all 6 focused `ReadableContentTests` passed again on macOS
and on the iOS simulator; the Xcode runner exited successfully. Tests count index
reads to prove completed initialization skips the full scan on repeated routing
calls and after reopening the store. They also cover reference preservation,
normal promotion and new-item reads, cancellation, and interrupted retry.
`git diff --check` and Xcode project syntax validation passed.

The physical iPad launch has not been reprofiled; these checks establish removal
of repeated initialization scans, not a measured total launch CPU reduction.

## Acceptance boundaries

No newly signed distribution bundle was produced, so the separate real-signature
`test-tooling.py` end-to-end installer check was not run against this cleanup.
Unsigned app builds and stubbed packaging checks do not establish signed release
acceptance. Physical Secure Enclave, iCloud convergence, removal, deletion and
recovery require acceptance on real devices. Prior dated reports in
`VALIDATION.md` and the retained authentication evidence do not
validate this cleanup.
