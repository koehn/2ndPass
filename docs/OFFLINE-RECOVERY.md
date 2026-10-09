# Recovery and device loss

An optional account recovery code can decrypt owned cloud item vaults when all enrolled devices are unavailable. Sign into the same Apple Account on the new device, choose **Recover with an Offline Code**, and import the recovery file or enter the paper code. Preview the contents, then complete recovery for selected or all listed vaults. Existing devices retain access, and the recovery code remains enabled.

**Warning: without a valid, activated recovery code or access to at least one enrolled device, your cloud vaults are completely inaccessible.** There is no password reset or administrative bypass that can recover their encryption keys.

**Access to your Apple Account is also required to access or recover vaults stored in that account’s iCloud.** Losing Apple Account access prevents cloud recovery even if you still have the recovery code; the code cannot restore or bypass Apple Account access.

A previously exported portable archive and its separate key can restore the saved contents into a new vault; they do not restore access to the original cloud vaults. **Items in device-local vaults can never be backed up from their device or recovered on another device.** Neither a recovery code nor a portable archive protects those items. See [backups](BACKUPS.md) and [the local vault](LOCAL-VAULT.md).

## Setup and coverage

In Recovery settings, choose **Generate Recovery Code** and save a copy outside your devices and iCloud, then re-import it or enter the code and choose **Verify and Enable Recovery**. Previously saved `SP1` codes and `2ndpass-recovery-1` files can be activated too. Generation alone does not change protection. Check Coverage reports whether existing cloud records have been updated. New and restored vaults include the configured recipient at creation; incomplete key changes block new creation.

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

## Interruption and missing envelopes

Keep the app open during recovery. Active recovery work temporarily defers the app’s inactivity lock; the normal idle timer restarts when the operation finishes or fails. Manual and system locks still apply, and leaving the recovery screen or backgrounding it ends the hold. macOS may independently require fresh device authentication. Progress moves through preview, enrollment, repair/download, verification, and completion. A restart returns to recovery rather than normal vault use; recovered vault access and AutoFill remain blocked until completion. Re-enter the code only if unfinished work still needs it. Encrypted updates staged for the new device can be replayed without retaining the code.

Recovery installs acknowledged cloud rewrites locally before restarting sync. If independent rewrites still create a conflict, an unlocked app with active synchronization clears it automatically only after all decrypted records, retained history, metadata, and edit attribution match. Only verified differences appear in conflict review; either selected version is published using current recovery protection. Identical versions are reconciled automatically. While checks run, the app shows “Checking sync differences”; unavailable or failed automatic work shows a retry status, never a choice between identical or unchecked versions.

Conflict cleanup retries after successful synchronization startup, including when the cloud returns no new records. It compares contents before pausing transfers, then resolves batches of up to 25 duplicate conflicts under one transport pause. Each item still uses a conditional version check; a stale choice remains unresolved while other items can complete. Interruption preserves committed resolutions and leaves unfinished conflicts for the next pass. On macOS, watch cleanup with `log stream --style compact --level info --predicate 'subsystem == "com.koehn.mop" AND category == "Conflicts"'`. Counts distinguish duplicates found, resolutions committed, deferred work without an active sync adapter, and failures. The first resolution failure in each pass logs its error domain and code; logs omit item names and secret contents. Missing edit timestamps in the review window do not indicate a synchronization failure.

Both normal enrollment and recovery request missing envelopes through the authenticated private iCloud relay. Requests identify the requester, vault, record/version, and membership state and carry the requesting device's signature. An authorized device that can decrypt the record can publish a repaired envelope. Recovery can do this locally using its code without an original device. If no available key can decrypt a record, it remains pending; a request cannot reconstruct a missing key.

Completion verifies the records encountered in a full cloud download pass. It does not certify unpublished edits on unavailable devices. Later arrivals use the same repair mechanism.

## Replacement and revocation

Activate a different verified code to replace the existing key. Retain both copies until every vault finishes. **Resume Recovery Setup** (or `sp vault recovery resume`) continues an interrupted change. Verifying the same code again also resumes its existing change; do not generate a replacement just because setup was interrupted. Errors appear beside the action and in an alert. Preparation and record updates show record counts; cloud discovery and synchronization show their current phase. `sp vault recovery revoke` removes recovery access from rewritten vault contents. Recipient changes re-encrypt retained contents with fresh keys while keeping enrolled devices; enrolling a new device preserves existing item content keys. Old keys can still decrypt previously copied ciphertext.

## Limits and validation

Recovery covers vault metadata, items, retained history, trash, attachments, encrypted health records, and cloud software key credentials. Device-local Secure Enclave credential private keys cannot be backed up or restored. Recovery does not restore Apple Account access or missing cloud data. Cross-account sharing and compatibility with earlier app versions are outside this implementation; update participating devices.

Portable archives and their separate keys remain an independent restore path; see [backups](BACKUPS.md). The destructive local recovery-test reset is not offered.

Automated tests exercise cryptographic authorization, fresh-device bootstrap, recipient replacement/revocation, and restart after committed cloud writes using a simulated authenticated transport. Physical-device/iCloud acceptance is still required: keep all original devices offline, recover on a fresh device, then verify an original device still reads, edits, and synchronizes after returning.
