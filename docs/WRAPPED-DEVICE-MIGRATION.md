# Enclave-wrapped cloud identities

Cloud vaults now use separate software P-256 agreement and signing keys. A
device-only Secure Enclave P-256 key protects their 64-byte private-key bundle
with HPKE P256/SHA256/AES-GCM-256. The authenticated context binds the format
version/domain, public identity, and exact account/environment/vault scope.
The wrapping representation and encrypted bundle are stored together in a
non-synchronizable `WhenUnlockedThisDeviceOnly` Data Protection Keychain item
under `mop.wrapped-device.v1`. Existing `mop.device-identity.v7` records are retained.

## Unlock and lock

The native backend authenticates the user, opens all locally enrolled cloud-vault
software keys, and owns them in one `UnlockedDeviceCache` for that authentication
session. Membership changes and sync reloads borrow independently revocable
leases from the cache. Closing one vault view cannot invalidate another vault's
keys or the shared authentication context. Lock, account retirement, and
reauthentication revoke the cache synchronously, including borrowers retained by
delayed tasks. An invalidated cache cannot accept new roots. The next unlock must
open the encrypted bundles through fresh hardware authentication.

Software reads, key unwrapping, and signatures do not retain or call an LAContext.
They continue after the original hardware authorization expires. Device-local
SSH, passkey, and certificate identities are unchanged and remain enclave keys.
AutoFill and CLI use independent authenticated caches; no plaintext keys cross
process boundaries.

## Automatic launch migration

Migration begins during the first authenticated unlock after launch, for every
locally enrolled cloud vault, including unselected vaults. It cannot run secret
operations before user authentication. Newly discovered, unenrolled vaults use
the new identity when they enroll through the existing flow.

1. Create or reopen a durable wrapped replacement in a separate Keychain namespace.
   Concurrent app/extension creation uses the Keychain winner. Never overwrite or
   delete the previously enrolled key.
2. The previous owner signs an additive membership proposal that admits the new
   public identity to the same account. The existing membership journal handles
   cloud compare-and-swap, confirmed readback, independent trust pinning, and
   recipient policy. Offline or interrupted publication remains pending; until
   confirmation, the app uses the previous identity. Competing proposals are
   serialized and rebased against the verified history, including additions.
3. Once admitted, transfer available content-key grants to the replacement. Item
   ciphertext, pending edits, trust genesis, and content keys are not rewritten
   for this additive admission. Repeated/interrupted transfers keep the exact
   durable grants already prepared. Grants for current generations use the normal
   publication journal. Locally archived compatible generations are preserved
   locally without bypassing obsolete-publication checks.
4. Open the migrated session and save its recipient routing. Once all current local
   item generations have replacement grants and earlier rotations are complete,
   journal removal of the old identity, signed by the replacement. Cloud-confirmed
   removal triggers the ordinary content-key rotation workflow. Do not treat the
   locally signed removal as committed authority.
5. Late content from older clients uses durable grant preparation or rotation.
   Retained legacy keys may decrypt a source only when the pinned history shows
   both the predecessor and the currently authorized replacement as same-account
   owners together. This does not restore the predecessor's signing authority or
   bypass key-epoch checks. Unseen old grants can still require enclave use.

No new recovery code, genesis, or second device is required to authorize this
replacement. Cloud availability is required to confirm membership, and legacy
migration work may require renewed authentication if the hardware authorization
expires before all old grants have arrived. This does not stop ordinary migrated
software-key operations. Removed identities are never automatically restored.

Legacy keys are deliberately not deleted from the local Keychain: offline devices
and obsolete key epochs may still require decryption. Their membership is retired
automatically after local grant readiness. Migration does not grant a new identity
access across an obsolete security epoch; the ordinary rotation workflow decrypts
and re-encrypts under current authority. Original grants and hardware key material
remain available as sources. Upgrade the app, AutoFill, and CLI together on each
device; an old executable cannot use the new software identity after retirement.

## Verification and limits

`WrappedDeviceTests` exercise bound bundle authentication, wrong keys/tampering,
reads and signatures after the unlock gate expires, lock, and authenticated
re-unlock. `WrappedDeviceMigrationTests` cover cache lifetime and delayed work,
restart before admission, grant-transfer interruption/retry, unchanged ciphertext
and pending edits, competing admissions, automatic retirement, rotation using a
retired source, late grants, and refusal to re-admit a removed replacement.
The full suite also exercises the existing journal's cloud acknowledgment and
membership conflict recovery.

The standalone `prototypes/WrappedSession` experiment observed real enclave
authorization loss after 660 seconds on the development Mac while software reads
and writes continued, then verified revocation and fresh authenticated re-unlock.
Automated tests use software wrapping keys at internal test boundaries; they do
not establish physical iOS behavior or live CloudKit migration. Validate a signed
build with disposable cloud vaults on each supported platform before release:

- Launch with two old-identity vaults, unlock once, and check both admit replacements.
- Interrupt before/after membership confirmation and during grant transfer; relaunch.
- Verify pending edits, metadata, conflicts, and late updates from an older client.
- Leave a migrated session idle beyond hardware authorization lifetime; read and
  edit, switch vaults, and allow membership-driven session reloads without prompts.
- Lock or switch accounts while work is in flight; verify old borrowers cannot act.
- Unlock again and verify an explicit system authentication requirement.

The software private keys can be extracted from a compromised unlocked process.
Owned temporary buffers are wiped and key objects released on lock, but Swift and
CryptoKit copies prevent a guarantee of complete physical memory zeroization.

## Validation recorded 2026-10-21

- Full Swift regression suite passed with `swift test --disable-sandbox --no-parallel`
  and the required macOS permissions. An earlier concurrent run hit the existing
  idle-work queue timing assertion; its isolated rerun also passed. No assertion
  was weakened.
- Final focused tests passed after the grant ordering, revoked-vault launch filter,
  and metadata-readiness review: `swift test --disable-sandbox --filter
  'wrappedDevice|wrappedMigration|unlockedDeviceCache'`.
- Native `Mop` builds (including AutoFill) succeeded for generic macOS and iOS
  destinations with `CODE_SIGNING_ALLOWED=NO`. Derived data directories were
  `.build/wrapped-device-macos` and `.build/wrapped-device-ios`; package checkouts
  were reused through `-clonedSourcePackagesDirPath .build`.
- No application was installed and no live cloud vault was migrated by this
  validation. Signed physical-device and live CloudKit acceptance remain pending.
