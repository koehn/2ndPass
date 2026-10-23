# Wrapped software-key hardware prototype

Standalone macOS experiment. It does not import Mop modules, access existing
Keychain identities, alter membership, or touch production vaults. It generates
a disposable Secure Enclave P-256 wrapping key with `userPresence`,
`privateKeyUsage`, and `WhenUnlockedThisDeviceOnly` protection. Only its opaque
representation and the HPKE-encrypted software-key bundle are retained, in memory,
for the lifetime of the run. No persistent Keychain item is created by this code.

The bundle contains separate software P-256 encryption and signing private keys.
Records use a random AES-256-GCM content key, HPKE to wrap that key, and a software
signature over the encapsulated key, wrapped key, and ciphertext. HPKE uses
P256/SHA256/AES-GCM-256 with a prototype-specific context string. This exercises
the same algorithm family as Mop but is not a production provider or migration.

## Build and run

From the repository root:

```sh
CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache \
  swiftc -swift-version 6 Prototypes/WrappedSession/main.swift \
  -o /tmp/mop-wrapped-session
/tmp/mop-wrapped-session --self-test
/tmp/mop-wrapped-session --run
```

Run the hardware command outside the filesystem sandbox, on a real Mac with a
Secure Enclave. Complete the first system authentication prompt and keep the Mac
awake and screen unlocked. A second prompt occurs after the wait and lock checks.
Canceling a prompt fails the run; it does not count as a successful re-unlock.
The test uses device-owner authentication, which may offer a password fallback.
It sets Touch ID reuse duration to zero; it does not request a particular enclave
authorization timeout.

The default wait is 660 seconds. To explore longer authorization lifetimes:

```sh
/tmp/mop-wrapped-session --run --wait-seconds 1200
```

There are no enclave operations during the wait, to avoid repeatedly exercising
and potentially refreshing authorization. At the end, the probe reconstructs an
enclave handle with the original authenticated context, with interaction disabled,
and attempts to unwrap the bundle. Only recognized interaction-required errors
count as observed authorization expiry. Unexpected errors fail the run. Continued
success is explicitly inconclusive, even if the software lifecycle checks pass.
This checks loss of noninteractive authorization; it does not diagnose the exact
internal OS timeout mechanism.

## Checks and exit status

- Signed writes and decrypted reads immediately after authenticated unlock.
- A fresh, unauthenticated, interaction-disabled context cannot unwrap the bundle.
- After the wait, an enclave control operation requires interaction, while the
  original software session can still write/sign and decrypt new and old records.
- Software operations also continue after explicit invalidation of the original
  LAContext. This deterministic check is reported separately from natural expiry.
- Closing the session rejects reads and writes, including a delayed worker that
  captured the old session before lock. Closing waits for admitted operations.
- A fresh noninteractive unlock is denied again after lock.
- Fresh successful system authentication opens a new session that can read prior
  records and write new ones. The old session remains revoked.

Exit 0 means all selected checks passed. For `--self-test`, that makes **no hardware
claim**. Hardware exit 2 means lifecycle checks passed but natural expiry was not
observed. Exit 1 means a check, authentication, or platform operation failed.
Exit 64 means invalid command-line arguments.

## Limits

Key properties are released on close; temporary mutable buffers are reset on exit
from their scopes. Swift/CryptoKit copies mean this is not proof of physical
zeroization. The software private keys are accessible to an attacker who can read
the unlocked process's memory. The lock test establishes provider revocation,
not erasure of plaintext already returned to a caller.

This prototype does not verify app sleep/background handling, production lock
integration, iOS behavior, persistence across process restart, Keychain access
groups, cross-device migration, recovery, or CloudKit. All records are synthetic
and in memory. No secret or key bytes are printed.
