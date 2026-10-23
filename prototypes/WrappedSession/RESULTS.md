# Hardware validation — 2026-10-21

Environment reported by the probe: macOS Version 27.0.1 (Build 26A434).
Compiled with `swiftc -swift-version 6`; ran the executable with hardware access
outside the Codex filesystem sandbox. No production vault or identity was used.

Commands:

```sh
/tmp/mop-wrapped-session --self-test
/tmp/mop-wrapped-session --run
```

Both exited 0. The hardware run waited 660 seconds without enclave operations.
Its final output was:

```text
PASS: original context now requires interaction (com.apple.LocalAuthentication:-1004)
PASS: signed write and decrypted read — after observed authentication expiry
PASS: signed write and decrypted read — after explicit LAContext invalidation
PASS: lock rejects reads, writes, and delayed work holding the old session
PASS: fresh noninteractive context cannot unlock (com.apple.LocalAuthentication:-1004)
Authenticate again in the system prompt to complete re-unlock verification.
PASS: signed write and decrypted read — fresh authenticated re-unlock
PASS: re-unlock does not revive old session
PASS: all hardware checks
```

Initial authenticated hardware unwrap and the initial unauthenticated negative
control also passed. Software checks passed signed encryption/decryption,
tamper rejection, lock revocation including delayed work, and reading an earlier
record through a new session.

Conclusion: on this Mac, an authenticated enclave unwrap could bootstrap software
keys that continued to operate after the original context lost noninteractive
enclave authorization. The original record remained readable; closing the
provider revoked subsequent use; fresh successful system authentication restored
access through a new provider. The observed error establishes renewed interaction
was needed after the wait, not the exact moment or internal cause of expiry.

These results validate the isolated prototype, not production app integration,
physical memory erasure, cross-process persistence, iOS, recovery, or sync. See
README.md for the test boundaries and reproduction instructions.
