# Recovery and device loss

An optional account recovery code can decrypt owned cloud item vaults when all enrolled devices are unavailable. Sign into the same Apple Account on the new device, choose **Recover with an Offline Code**, and import the recovery file or enter the paper code. Preview the contents, then complete recovery for selected or all listed vaults. Existing devices retain access, and the recovery code remains enabled.

**Warning: without a valid, activated recovery code or access to at least one enrolled device, your cloud vaults are completely inaccessible.** There is no password reset or administrative bypass that can recover their encryption keys.

**Access to your Apple Account is also required to access or recover vaults stored in that account’s iCloud.** Losing Apple Account access prevents cloud recovery even if you still have the recovery code; the code cannot restore or bypass Apple Account access.

A previously exported portable archive and its separate key can restore the saved contents into a new vault; they do not restore access to the original cloud vaults. **Items in device-local vaults can never be backed up from their device or recovered on another device.** Neither a recovery code nor a portable archive protects those items. See [backups](BACKUPS.md) and [the local vault](LOCAL-VAULT.md).

## Setup and coverage

In Recovery settings, choose **Generate Recovery Code** and save a copy outside your devices and iCloud, then re-import it or enter the code and choose **Verify and Enable Recovery**. Previously saved `SP1` codes and `2ndpass-recovery-1` files can be activated too. Generation alone does not change protection. Coverage updates automatically from repository events as grants and content are delivered. New and restored vaults include the configured recipient at creation; incomplete key changes block new creation.

The code derives account-scoped encryption and signing keys. Its private material stays in memory during the ceremony and is cleared on lock, backgrounding, or dismissal. Only public configuration and encrypted progress are retained. Never treat a saved code as protecting a vault until activation and coverage verification finish.

CLI equivalents:

```sh
sp vault recovery generate --output /offline/recovery.json
sp vault recovery activate --file /offline/recovery.json
sp vault recovery status
sp vault recovery open --file /offline/recovery.json
sp vault recovery open --file /offline/recovery.json --complete
```

`--fingerprint` is optional on activation and checks the fingerprint shown at generation. The normal vault-selection option limits the vaults recovered by `open --complete`.

## Interruption and missing grants

Keep the app open while authorizing recovery. Active secret operations defer the inactivity lock; manual and system locks still apply. Private recovery material is cleared when the ceremony ends, the app backgrounds, or it locks. Persisted signed membership changes, content and grants can continue without the code. Secret-dependent work waits for an authorized unlock or re-entry of the recovery code. A restart retains incomplete recovery state and keeps ordinary access and AutoFill blocked until required enrollment, download and rotation work completes.

Recovery uses the same content/grant representation, durable account coordinator and CKSyncEngine as ordinary sync. Membership commitments, key rotation and missing-grant work are journaled. Missing grants are indexed; signed requests travel through the account coordination zone. An authorized owner or the explicitly authorized recovery session can prepare replacement grants. A request cannot reconstruct an unavailable encryption key. Recovery enrollment and recovery-recipient changes require key rotation; ordinary additive device enrollment preserves content keys and logical revisions.

Incoming versions are authenticated before reconciliation. Identical logical contents converge during an authorized session without a conflict prompt. Different concurrent edits, deletion versus editing, and unverifiable ancestry remain preserved for review. A user's choice is durable before returning; the lease owner verifies the current cloud head before committing it. No recovery-specific sync restart, duplicate-conflict batch scan, missing-envelope relay, or manual Refresh step is used.

Completion verifies the initial download and outstanding grant/rotation work. It does not certify unpublished edits on unavailable devices. Newly arriving items participate in the same indexed reconciliation automatically.

## Replacement and revocation

Activate a different verified code to replace the existing key. Retain both copies until every vault finishes. Interrupted changes resume automatically. **Unlock to Finish Setup** is shown when authorization is required; `sp vault recovery resume` remains an explicit authorization entry point. Verifying the same code again also resumes its existing change; do not generate a replacement just because setup was interrupted. Errors appear beside the action and in an alert. Preparation and record updates show record counts; cloud discovery and synchronization show their current phase. `sp vault recovery revoke` removes recovery access from rewritten vault contents. Recipient changes re-encrypt retained contents with fresh keys while keeping enrolled devices; ordinary additive enrollment preserves existing item content keys, while recovery admission rotates them. Old keys can still decrypt previously copied ciphertext.

## Limits and validation

Recovery covers vault metadata, items, retained history, trash, attachments, encrypted health records, and cloud software key credentials. Device-local Secure Enclave credential private keys cannot be backed up or restored. Recovery does not restore Apple Account access or missing cloud data. Cross-account sharing and compatibility with earlier app versions are outside this implementation; update participating devices.

Portable archives and their separate keys remain an independent restore path; see [backups](BACKUPS.md). The destructive local recovery-test reset is not offered.

Automated tests exercise cryptographic authorization, fresh-device bootstrap, recipient replacement/revocation, and restart after committed cloud writes using a simulated authenticated transport. Physical-device/iCloud acceptance is still required: keep all original devices offline, recover on a fresh device, then verify an original device still reads, edits, and synchronizes after returning.
