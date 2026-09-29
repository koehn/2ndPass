> Historical measurements preceding the v7 cutover. Statements about the then-current production format are not current architecture claims. See [Vault v7](VAULT-V7.md) and [v7 validation](V7-VALIDATION-2026-09-27.md); measurements below are preserved as recorded.

# Device-removal profiling — 2026-09-27

Synthetic fixtures; no existing vault contents or device keys are used.
Measured on an Apple M5 Pro Mac with 64 GiB RAM, macOS 27.0 (26A428),
Apple Swift 6.4, release optimization. These are **Mac measurements**, not iPhone timings.

## Software-key baseline

Three repetitions per scenario; medians in seconds. Fixture creation and authentication
are excluded. The removal column includes key rotation, envelope creation,
catalog encryption, signing, and revision construction. Its unwrap column is a
subset, not additional time. Local attachment reads use recently written files;
this is a warm filesystem/app-cache comparison, not a flushed physical-disk test.

| Scenario | Removal | Key unwraps | Local attachment load | Publication validation | Two catalog loads |
|---|---:|---:|---:|---:|---:|
| 100-fields | 0.095 | 0.009 | 0.000 | 0.003 | 0.003 |
| 908-fields | 0.833 | 0.077 | 0.000 | 0.021 | 0.024 |
| 6287-fields | 5.827 | 0.535 | 0.000 | 0.164 | 0.184 |
| 17-attachments-38MB | 0.060 | 0.002 | 0.015 | 0.001 | 0.001 |
| 6287-fields-17-attachments | 5.928 | 0.541 | 0.019 | 0.167 | 0.184 |
| 6287-fields-5-devices | 10.919 | 0.541 | 0.000 | 0.249 | 0.229 |

Three-device scenarios revoke one device and wrap new keys for the two remaining
devices; the five-device scenario wraps for four remaining devices. Fields are
48-byte synthetic values, except attachment fields. Full-size scenarios contain
6,287 encrypted records; the attachment scenario replaces 17 of those with a
total of approximately 38 MB. Items group up to seven fields. This reproduces the
record and attachment scale, not the user's exact private catalog.

## Secure Enclave results

One measured removal per scenario using newly generated hardware keys on the same
Mac. Authentication and fixture creation are excluded. Peer public keys are
software fixtures; only the removing owner's private-key operations use the
Secure Enclave, as they do in the app. These runs followed the software run;
SwiftPM serialized the benchmark/build processes.

| Scenario | Removal (s) | Unwrapping (s, included) | Unwrap calls |
|---|---:|---:|---:|
| 100-fields | 0.594 | 0.502 | 102 |
| 908-fields | 5.285 | 4.501 | 910 |
| 6287-fields | 36.906 | 31.451 | 6289 |
| 17-attachments-38MB | 0.163 | 0.096 | 19 |
| 6287-fields-17-attachments | 36.443 | 31.008 | 6289 |
| 6287-fields-5-devices | 41.620 | 31.250 | 6289 |

For 6,287 fields plus attachments, unwrapping accounts for approximately **85%**
of the 36.44-second removal, averaging **4.93 ms per unwrap**. There are 6,289
unwraps: one per field plus two catalog reads in the engine. Field-loop work
other than unwrapping is mostly per-recipient HPKE envelope creation and symmetric
reencryption; this benchmark does not claim an exact split between those.

The 17-attachment-only case takes 0.163 seconds with hardware keys. Reading and
verifying the 38 MB from local files takes about 0.021 seconds in the full case.
Thus attachment **cryptography** is not the principal CPU bottleneck on this Mac.

## Development-build check

The installed apps are development builds, so the full-size hardware case was
also measured once in Debug mode: **37.815 seconds**, of which **31.889 seconds**
were key unwrapping. This is close to the 36.443-second release result. Debug's
two catalog loads took 0.744 seconds versus 0.187 seconds in release. Build
optimization does not explain the bulk of this delay on this Mac.

## Live CloudKit measurements

Actual Development CloudKit transport on this Mac and connection, with random
synthetic attachment payloads. The 17 blobs total 38,083,740 bytes. A valid signed
7,628,347-byte synthetic revision approximates the real checkpoint size. Each
stage includes the transport's account checks, serialization, temporary-file work,
and CloudKit request overhead. Authentication, fixture construction, zone creation,
and cleanup are excluded from removal component totals.

| Stage | Requests | Total wall time (s) |
|---|---:|---:|
| attachment_upload | 17 | 28.113 |
| revision_upload | 1 | 1.996 |
| head_read | 1 | 0.118 |
| head_publish | 1 | 0.347 |
| attachment_first_read | 17 | 60.261 |
| attachment_repeat_read | 17 | 3.362 |
| revision_read | 1 | 14.952 |

The first and repeat reads use the CloudKit API; Apple service/asset caches were
not flushed, so these are not guarantees of network traffic on every request.
A populated **application** attachment cache avoids these requests altogether;
the local-file measurement was about 0.02 seconds for the full attachment set.

These network timings are single-run observations, not stable service benchmarks.
A new head only publishes after the attachment and revision uploads complete.
The probe zone was deleted successfully. No normal user-vault zone was changed.

## Bounded concurrent upload comparison

A second disposable Development zone used fresh random payloads of the same
sizes. At most four independent attachment uploads were active at once. All
uploads finished before the revision and conditional head commit.

| Upload stage | Sequential | Four at a time |
|---|---:|---:|
| 17 attachment blobs, 38 MB | 28.113 s | 10.671 s |
| 7.6 MB revision | 1.996 s | 4.023 s |
| Attachment plus revision uploads | 30.109 s | 14.695 s |

The attachment phase was **2.63× faster (62% less time)**. Including the revision
upload, the measured upload sequence was about **51% shorter**. These were
sequentially conducted single runs with new payloads, not a randomized repeated
network benchmark; the revision timing difference illustrates network variability.
The concurrent zone was also deleted successfully.

Concurrency exists only in the profiling helper. Production attachment uploads
remain sequential. Reproduce with the same signed helper using
`MopVaultNextCheck profile-cloud-concurrent`.

## Interpretation

* Hardware key unwrapping dominates local computation: about 31 of 36 seconds
  for this record count. AES over the attachment bytes is comparatively cheap.
* Attachments matter primarily through transfer: roughly 60 seconds for first
  retrieval and 28 seconds for the new encrypted uploads in this run.
* As a component-level illustration, hardware rotation plus sequential uploads,
  revision upload, and the head read/commit sum to about 67 seconds with cached
  attachments, or 127 seconds when adding the first attachment retrieval. This
  is **not** a measured end-to-end removal; it excludes application preflight,
  catalog/registry work, any missing revision downloads, and retries. iPhone
  CPU, Secure Enclave, storage and network behavior were not measured.
* More recipients add public-key wrapping work: software-only removal goes
  from 5.83 to 10.92 seconds when remaining recipients increase from two to four.

A bounded-concurrency attachment uploader is an incremental latency optimization.
It must preserve the existing order: all blobs, then revision, then conditional
head publication. Reducing the thousands of Secure Enclave unwraps requires a
separate key-hierarchy design and security review; merely moving work off the UI
thread does not remove that work.

## Reproduce

```sh
MOP_PROFILE_REMOVAL=1 swift test -c release --filter profileDeviceRemovalScenarios
MOP_PROFILE_REMOVAL=1 MOP_PROFILE_HARDWARE=1 MOP_PROFILE_REPEATS=1 \
  swift test -c release --filter profileDeviceRemovalScenarios
```

The second command requires authentication and creates transient Secure Enclave
keys. It does not read persisted application keys. Without the opt-in variable,
the profiling test returns immediately. Set `MOP_PROFILE_SCENARIO` to a scenario
name to run only that case; omit `-c release` for Debug. Run benchmarks serially.

The `MopVaultNextCheck profile-cloud` mode requires a provisioned Development
app bundle. It creates a `mop-v6-probe-…` zone excluded from normal discovery,
uploads random synthetic assets, measures first and repeat retrievals, and deletes
that probe zone after success. A failed run prints its zone name for cleanup.

## Raw observations

* [Software keys](profiling/removal-software-2026-09-27.jsonl)
* [Secure Enclave, release](profiling/removal-enclave-2026-09-27.jsonl)
* [Secure Enclave, Debug](profiling/removal-enclave-debug-2026-09-27.jsonl)
* [Sequential CloudKit](profiling/removal-cloud-2026-09-27.jsonl)
* [Concurrent CloudKit](profiling/removal-cloud-concurrent-2026-09-27.jsonl)

Benchmark sources: `Tests/MopVaultNextTests/RemovalProfileTests.swift` and
`prototypes/vault-next/package-check.swift`. The attempted stack samples found
already-exited processes; no sampled-stack conclusions are included.
