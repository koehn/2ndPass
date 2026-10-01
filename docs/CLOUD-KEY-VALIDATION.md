# Cloud key credential validation — 2026-10-01

Implementation is present; SALE-6/SALE-13 remain unchecked until physical-device,
live iCloud, cross-account, server, and IDE acceptance is complete.

## Automated results

- Full Swift test suite: passed, 425 Swift Testing tests plus 4 XCTest tests.
  Covers existing vault/local identity/CLI/UI-model regressions and the new
  credential tests. Later parser boundary and passkey-service checks also passed.
- OpenSSH-generated Ed25519, P-256, and RSA imports: passed unencrypted and
  bcrypt/AES-256-CTR encrypted cases, including incorrect passphrase rejection.
- Real OpenSSH agent listing and Git commit/tag signing/verification: passed for
  Ed25519, P-256, and RSA. These use software fixtures, not enrolled cloud devices.
- Passkey ES256 signature verification, exact RP and allow-list isolation,
  failed-save handling, cloud-only import enforcement, public-only projection,
  membership/revocation, and model recovery preserving credential IDs: passed.
- macOS app and AutoFill extension: build passed.
- iPhone/iPad simulator build-for-testing: passed.
- Unsigned iOS Release device build: passed. This is compilation, not device use.
- Storage-picker UI test: passed on iPhone 18 Pro and iPad Pro 13-inch (M5)
  simulators, iOS 27. It checks that naming a key does not choose storage,
  explicit cloud selection enables creation, and switching to Import resets
  storage and requires a file. The iPhone screenshot was inspected.
- `git diff --check`: passed.

## Environment and test repairs

The restricted sandbox blocked module caches, Unix sockets, process inspection,
and pasteboards. The full suite passed with the required execution permissions;
see [AGENTS.md](../AGENTS.md) for repeatable commands and limitations.

An initial UI attempt stalled before test-case output, and a retry found a
Generate/Import toggle interaction failure. The control was replaced with an
explicit segmented selector and the same behavioral test passed on both device
families. Failed Xcode runs also hung during diagnostics collection; use
`-collect-test-diagnostics never` for a bounded retry when appropriate and confirm
old task-owned runners have exited before starting another against that simulator.

## Remaining release acceptance

### UI follow-up, 2026-10-01

- Replaced the passkey prompt with a credential header, grouped storage form,
  concise protection text, and a persistent action bar. macOS sizes the sheet to
  its content; longer content remains scrollable. Both extension builds passed.
- Credential filters now use the existing guarded collection transition instead
  of silently refusing navigation whenever an editor exists. Regression tests
  cover unchanged editors and save/discard handling for modified drafts.
- iPhone and iPad simulator UI tests passed for repeated filter navigation after
  opening an item editor, checking search-field position and reachability.
  The originally reported repeated sliding animation was not reproduced in the
  baseline simulator runs; confirmation on the affected device remains needed.

### Device and account acceptance

Follow the checklist in [Cloud key credentials](CLOUD-KEY-CREDENTIALS.md#compatibility-and-validation).
No physical Secure Enclave or live cloud credential acceptance was performed here.
In particular, truthful local passkey backup flags may be rejected by Apple or by
sites that saw the earlier development override. No existing local credential was
migrated or deleted. Real cross-account sharing remains coordinated with SALE-7.
