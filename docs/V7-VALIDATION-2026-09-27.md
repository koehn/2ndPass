# V7 implementation validation — 2026-09-27

## Completed

- Full Swift suite: **288 tests passed** across vault (40), core (47), CLI (14),
  UI/model (110), and app support (77). Opt-in hardware profiling is recorded separately.
- macOS application and AutoFill extension build succeeded; signed bundle passed
  `codesign --verify --deep --strict` and opens successfully.
- iOS application and AutoFill extension build succeeded. Installed successfully
  on the connected iPhone and iPad without uninstalling either app.
- Installed Mac app uses `MopApp` as its executable to coexist with the bundled
  lowercase `sp` CLI on case-insensitive filesystems, matching package.sh.
- Old application bundle retained at `.build/v6-app-before-v7/2ndPass.app`.
  No v6 vault, key, cache, cloud zone, or backup was deleted or migrated.

The new tests cover append-only enrollment without loaded attachments, unchanged
role-transition item material, one item unwrap per edit, key rotation for deleted
items, old-key rejection, field/vault/item/generation substitution, signed
membership tampering, missing envelopes, unsupported old formats, four-upload
limits, failure/cancellation draining, and prohibition of premature publication.
Existing service tests cover enrollment, sync, offline removal, recovery, caches,
publication conflicts, and uncertain-commit recovery.

## Production engine measurements

Synthetic fixture: exactly **908 items, 6,287 fields, three initial recipients**;
removal leaves two and enrollment adds a fourth. Each operation uses **909
unwraps: 908 item keys plus one catalog key**. Attachment scenario has 17 blobs,
38,083,740 plaintext bytes, 38,084,216 ciphertext bytes. Checkpoint is approximately
3.09 MB, compared with approximately 6.82 MB in the earlier v6 synthetic fixture.

| Operation | Attachments | Software median (3 runs) | Secure Enclave (1 run) |
|---|---|---:|---:|
| Removal | None | 1.091 s | 5.483 s |
| Enrollment | None | 0.749 s | 5.176 s |
| Removal | 17 / 38 MB | 1.125 s | 6.026 s |
| Enrollment | 17 / 38 MB | 0.750 s | 6.683 s |

Release build, M5 Pro Mac. Timings include VaultEngine revision construction and
validation, but exclude cloud publication, initial disk load, and subsequent
catalog rendering. Enrollment timings exclude invitation/acceptance setup.
Development builds were active during part of the hardware run; these are
single-run observations, not controlled latency guarantees. Hardware removal
with attachments is substantially below the earlier full-engine v6 result of
36.44 seconds. No iPhone/iPad timing claim is made.

Reproduce:

```sh
MOP_PROFILE_REMOVAL=1 MOP_PROFILE_REPEATS=3 MOP_PROFILE_SCENARIO=6287-fields,6287-fields-17-attachments swift test -c release --filter profileDeviceRemovalScenarios
MOP_PROFILE_REMOVAL=1 MOP_PROFILE_HARDWARE=1 MOP_PROFILE_REPEATS=1 MOP_PROFILE_SCENARIO=6287-fields,6287-fields-17-attachments swift test -c release --skip-build --filter profileDeviceRemovalScenarios
```

## Live CloudKit probe

A signed helper successfully created v7 Development record types, uploaded 17
synthetic blobs (38,083,740 bytes) with concurrency four in **10.262 s**, uploaded a
separate 7,628,559-byte synthetic revision in **2.607 s**, and conditionally
published its head in **0.372 s**. The helper uses the real v7 transport with its
own equivalent bounded task group; production's shared uploader is covered by
unit tests. This is component profiling, not a complete 908-item cloud removal.

Only the disposable zone
`mop-v7-probe-B54A01CB-7A36-47EE-870A-D26A8FE72761` was deleted afterward; deletion
was confirmed by the probe. No user vault was accessed by the probe.

Raw data: [software](profiling/v7-engine-software-2026-09-27.jsonl),
[hardware](profiling/v7-engine-hardware-2026-09-27.jsonl),
[CloudKit](profiling/v7-cloud-2026-09-27.jsonl).

## Remaining live acceptance

The installed Mac app displays an empty `personal` vault. The import-file path
has been requested; the user's source data has not been imported by this task.
Physical-device enrollment, subsequent iPhone-to-iPad sync with the Mac stopped,
and removal of an offline physical device remain to be exercised after import.
Model/service tests cover these behaviors but do not substitute for that live check.
