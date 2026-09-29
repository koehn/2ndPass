> Historical measurements preceding the v7 cutover. Statements about the then-current production format are not current architecture claims. See [Vault v7](VAULT-V7.md) and [v7 validation](V7-VALIDATION-2026-09-27.md); measurements below are preserved as recorded.

# Item-key prototype benchmark — 2026-09-27

A test-only prototype with one wrapped key per item reduces the measured Secure Enclave removal loop from **35.72 seconds to 5.14 seconds (6.96×)**. Combining item keys with append-only enrollment reduces enrollment cryptographic work from **40.11 seconds to 4.86 seconds (8.24×)**. These are local cryptographic measurements, not complete app operation timings. Production vault format and application behavior are unchanged.

## Method

- Mac M5 Pro, 64 GiB RAM, macOS 27.0; release Swift build.
- Exactly 908 synthetic items, 6,287 fields: 839 items with seven fields, 69 with six.
- Two payload scenarios: 48 bytes per field; or first 17 fields replaced with attachments totaling 38,083,740 plaintext bytes. Both contain 6,287 fields overall.
- Three initial devices; removal leaves two; enrollment adds a fourth.
- Real Secure Enclave owner key, generated solely for the benchmark after Mac authentication. Peer keys are software test keys. No existing vaults, keys, CloudKit records, or application data are accessed.
- Software measurements: median of three repetitions. Secure Enclave: one repetition per scenario, layout, and operation. Fixed execution order, not randomized; small differences are noise.
- Both layouts use the same Apple HPKE P-256/SHA-256/AES-GCM envelope implementation and AES-GCM field encryption. Each field uses an independent random nonce and authenticated vault/item/field identity. Keys are unwrapped once per group and used within that group, with no cross-operation plaintext-key cache.
- Field layout has one group per field; item layout has one group per item. Both are primitive-level synthetic implementations. The field layout mirrors current encryption work, rather than invoking the entire production VaultEngine.
- Removal unwraps each old key, decrypts and re-encrypts every field using a new group key, and creates envelopes for the two remaining devices. Attachment bytes are included in this timed encryption work.
- “Rewrap all” enrollment preserves ciphertext and symmetric keys but regenerates envelopes for all four devices under a new generation, analogous to current membership-epoch coupling.
- “Append only” enrollment preserves existing envelopes and ciphertext, adding just one envelope per group. This prototype decouples key generation from membership changes; production adoption would also require authenticated membership and compatibility design.
- Timings include context encoding, envelope operations, field encryption/decryption where applicable, and output construction. Exclude fixture generation, result checks, catalog keys, revision encoding/signing/validation, disk I/O, and cloud transfers. Thus unwrap counts are **6,287 versus 908**, without the two catalog unwraps seen in the previous full-engine profile.

## Results: Secure Enclave

| Operation | Attachments | Field keys | Item keys | Speedup |
|---|---:|---:|---:|---:|
| Remove device | None | 36.081 s | 5.154 s | 7.00× |
| Remove device | 17 / 38 MB | 35.717 s | 5.135 s | 6.96× |
| Add device, rewrap all | None | 40.137 s | 5.768 s | 6.96× |
| Add device, rewrap all | 17 / 38 MB | 40.107 s | 5.834 s | 6.88× |
| Add device, append only | None | 33.465 s | 4.825 s | 6.94× |
| Add device, append only | 17 / 38 MB | 33.421 s | 4.865 s | 6.87× |

With attachments, removal unwrap time alone falls from 31.253 to 4.482 seconds. The two optimizations combined compare field-key rewrap-all enrollment (40.107 s) to item-key append-only enrollment (4.865 s).

## Results: software keys

| Operation | Attachments | Field keys, median | Item keys, median |
|---|---:|---:|---:|
| Remove device | None | 5.137 s | 0.750 s |
| Remove device | 17 / 38 MB | 5.137 s | 0.774 s |
| Add device, rewrap all | None | 9.429 s | 1.363 s |
| Add device, rewrap all | 17 / 38 MB | 9.514 s | 1.389 s |
| Add device, append only | None | 2.963 s | 0.428 s |
| Add device, append only | 17 / 38 MB | 3.008 s | 0.435 s |

## Validation and interpretation

All 48 measured cases passed. Outside the timed intervals, the remaining/new device unwraps every output key and decrypts every field, comparing the full plaintext with the synthetic input. Removal outputs contain no removed-device envelope. Enrollment preserves every field ciphertext, and append-only enrollment preserves every existing envelope.

The prototype supports adopting the item-key performance tradeoff: one unwrapped key grants access to all fields in that item. This is a performance experiment, not a reviewed format implementation or migration. It does not establish end-to-end iPhone performance or validate all production security invariants.

Attachment AES work is small relative to hardware unwrap latency on this Mac. Device removal still rewrites and uploads attachments, so the earlier CloudKit bottleneck remains. Bounded concurrent uploads are a complementary improvement. Enrollment preserves ciphertext, so unchanged attachment blobs can remain unchanged.

## Reproduce

`Tests/MopVaultNextTests/ItemKeyProfileTests.swift` is opt-in and otherwise returns immediately.

```sh
MOP_PROFILE_ITEM_KEYS=1 MOP_PROFILE_REPEATS=3 swift test -c release --filter profileItemKeyLayout
MOP_PROFILE_ITEM_KEYS=1 MOP_PROFILE_HARDWARE=1 MOP_PROFILE_REPEATS=1 swift test -c release --skip-build --filter profileItemKeyLayout
```

The second command requests Mac authentication. Raw results:

- [Software JSONL](profiling/item-key-software-2026-09-27.jsonl)
- [Secure Enclave JSONL](profiling/item-key-enclave-2026-09-27.jsonl)
- [Earlier full-engine and CloudKit measurements](REMOVAL-PROFILING-2026-09-27.md)
