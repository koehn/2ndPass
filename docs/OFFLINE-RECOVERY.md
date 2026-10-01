# Offline recovery (SALE-1)

Offline recovery restores owned live cloud vaults after loss of all enrolled
devices. The user must regain sign-in to the **same Apple Account** first.
The recovery copy cannot recover Apple Account credentials, replace Apple's
second-factor requirements, retrieve missing cloud data, or restore into another
account. Account-loss recovery requires a separately exported backup; backup
export/restoration is outside this feature.

## Copy setup and key format

Open **Settings → Recovery → Set Up or Verify Recovery…** and generate a copy.
Recovery covers all owned iCloud vaults. Export a uniquely named file or
print/write down the displayed code, then re-import/re-enter it before activation.
The file and code have equal authority. Store them separately from enrolled
devices, outside synchronized storage. The clipboard is never populated
automatically. Printing is explicit and relies on the operating system/printer.

Version 1 starts with 32 uniformly random bytes. The derivation salt is SHA-256 of
UTF-8, sorted-key JSON for `account`, `container`, and `environment`, with no
escaped slashes. Each key is HKDF-SHA256(secret, salt, info, 32), where info is
`2ndpass/offline-recovery/v1/agreement/N` or
`2ndpass/offline-recovery/v1/signing/N`. N is a decimal counter starting at zero;
reject scalars outside [1, P-256 order - 1] and increment. Encryption and signing
are separate keys. No password-based derivation is involved.

The paper code is `SP1-` followed by uppercase hexadecimal secret bytes and an
8-hex-character checksum, grouped in fours. Whitespace, hyphens, and letter case
are normalized during import. The checksum is the first four bytes of
SHA-256(`2ndpass/recovery-code/v1` UTF-8 || secret); it detects entry errors and
provides no additional security. The JSON file has format
`2ndpass-recovery-1`, the scope, public fingerprint, and code. Both are bounded to
8 KiB on import. The deterministic public identity UUID comes from the first 16
bytes of SHA-256(`2ndpass/offline-recovery/v1/identity` || agreement public key ||
signing public key), using X9.63 public-key encodings.

`Tests/MopVaultNextTests/OfflineRecoveryTests.swift` includes fixed vectors for
public test secret bytes 0 through 31. `scripts/recovery-vectors.py` calculates
them independently using Python standard-library HMAC/SHA-256 and P-256 arithmetic.
This interoperability check is not an independent cryptographic audit.

## Publication and failure behavior

The account-private `mop-account-recovery-v1` zone stores public configuration and
per-vault lifecycle progress with conditional updates. Configuration is part of
the authenticated CloudKit trust boundary. Signed vault membership determines
which key actually protects each vault; progress metadata alone grants no access.

Creation reserves its exact signed encrypted genesis in that record before
upload. Creation and lifecycle operations cannot acquire the same configuration
version. Another device can finish the reserved creation. Ordinary content writes
remain per-vault conditional publications; conflicts require refreshed state.

Setup adds recipient envelopes for existing item keys and reseals the catalog.
New items and new vaults inherit the authority. Replacement and revocation rotate
retained item keys and attachment ciphertext before each vault's head commit.
Account-wide completion is not atomic: keep **both** offline copies during
replacement. Interrupted operations retain their target and progress in CloudKit.
Fresh-device recovery may require opening both copies, completing each matching
vault, then resuming replacement as its restored ordinary owner.

Read-only recovery retains key handles only in the active session. Healthy fields
can be read and attachments explicitly saved before completion. Missing/corrupt
attachments postpone completion without blocking healthy fields. Normal writes,
AutoFill publication, and ordinary enrollment are not enabled by read-only access.
Complete each vault to publish rotated encryption and replacement ordinary
membership that preserves all existing devices, accounts, and roles, then clear earlier enrollment exchanges. Closing or locking requires
re-entry of the offline copy. The offline authority remains after recovery. A durable local recovery marker allows
retries after a committed cloud update to finish local registration and enrollment
cleanup without publishing another recovery revision.

## Trust and acceptance

Account binding is application authorization, not a second encryption factor.
Anyone holding the secret and copied ciphertext can decrypt it offline. One copy
covers all owned vaults and is correspondingly powerful. A trusted recovery
client/OS is required. Controllable secret buffers are wiped, but framework-owned
CryptoKit, text, export, and printing copies cannot be guaranteed erased.

Fresh-device bootstrap verifies the available signed revision chain, account
binding, current recovery authority and decryption. Its initial provenance and
freshness depend on authenticated private CloudKit. It cannot independently
detect a server rollback, omitted vaults, or denial of service without surviving
checkpoint evidence. Revocation never retracts old ciphertext or plaintext.

Retired recipient configurations are rejected explicitly, including in required
history; there is no migration. Existing v7 vaults without those configurations
remain readable. `offline-recovery-1` causes unsupported clients to reject affected
vaults rather than silently dropping recipients.

Automated coverage includes deterministic derivation, copy verification, account
mismatches, setup/new data, rotation, fresh-install recovery, interrupted
replacement with loss of the initiating device, missing attachments, session lock,
and reserved creation resumption. Physical macOS/iPhone/iPad CloudKit acceptance
and independent cryptographic review remain **pending**. Do not mark SALE-1
release acceptance complete until those checks are recorded.

## Testing with your existing devices

Use disposable vaults where possible. Save and verify an offline recovery copy
before either test. Keep it outside the app and off the device being reset. Stay
signed into the same Apple Account. Completing recovery keeps previous ordinary
devices and other accounts connected to each recovered vault; the offline recovery key remains enabled.
Quit or lock every other enrolled copy of 2ndPass to prevent automatic enrollment.

### Case 1: Remove a device when another owner remains

1. Open **Settings → Devices** and remove the device you will test. This removes
   access in 2ndPass, not your Apple Account. The last owner cannot be removed.
2. If removal was performed on another device, open 2ndPass on the test device
   while online so it can detect removal and clear its local access.
3. Choose recovery from **Settings → Recovery → Recover Vault Access…** or the
   enrollment screen. Do not choose Reconnect or start ordinary enrollment.
4. Import your saved recovery file or enter your paper code. Open read-only
   access and verify fields and attachments.
5. Complete recovery for each vault, then verify ordinary reads and writes.
   Lock and restart the app and verify access without entering the offline copy.

This exercises recovery following explicit device revocation.

### Case 2: Reset your only device for recovery testing

1. Open **Settings → Recovery → Set Up or Verify Recovery…**. Check coverage and
   finish any incomplete setup, replacement, or revocation first.
2. Expand **Test recovery on this device**. Import your saved recovery file or
   enter the code from your offline copy. Do not generate a new key for this step.
3. Select **Reset This Device for Recovery Testing…**, read the confirmation,
   and choose **Verify Copy and Reset This Device**.
4. The app checks that the copy can recover every owned cloud vault, including
   retained records and attachments fetched from iCloud. A failed verification
   leaves your device keys intact. Incomplete coverage and locally registered
   shared vaults prevent the reset.
5. On success, iCloud vault device keys, local cloud checkpoints, enrollment state,
   cloud attachment caches, and cached cloud vault records are cleared. Local-only
   vaults and their keys are not changed. The iCloud vaults, recovery configuration,
   and old cloud membership remain unchanged, simulating loss of the device.
   A local removal marker blocks automatic enrollment across restarts.
6. The recovery dialog opens. Enter the offline copy again; it is not carried
   over from reset verification. Browse your recovered data, then complete each
   vault. Completion adds device access and preserves the previous membership.
7. Verify ordinary reads and writes, lock and restart the app, then verify access
   again without your offline copy. Repeat the test with the other copy format
   to cover both file and paper recovery.

If local deletion fails after verification, the app reports incomplete cleanup
and keeps ordinary access blocked. Restart while online to retry cleanup before
recovery. Do not choose Reconnect during the test. The reset intentionally retains
only the removal barrier and account binding needed to prevent enrollment; it
removes vault trust checkpoints. It is a controlled fresh-trust test, not an OS
factory reset. Reinstalling alone does not reliably erase Keychain keys or caches.

Perform physical-platform acceptance on signed macOS, iPhone, and iPad builds;
a simulator cannot validate real Secure Enclave behavior. Successful reset
verification cannot guarantee that iCloud data will remain available afterward.
