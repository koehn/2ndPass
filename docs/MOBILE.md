# Shared Apple application

2ndPass uses shared SwiftUI views and an application model on macOS 15+, iOS 18+ and iPadOS 18+. `Sources/MopUI` owns the interface; `MopApp` is the entry point. Open `Apple/Mop.xcodeproj` and select the `Mop` scheme.

The app and AutoFill share the encrypted App Group store and device-only Keychain identity. Same-account connection is automatic while an existing device is unlocked. Local saves work offline; synchronization resumes when the authorized owner can run. iOS suspension and Data Protection can delay background work. Notifications do not guarantee immediate delivery.

## Build and test

```sh
scripts/mobile.sh build
scripts/mobile.sh test
MOP_SIMULATOR_DESTINATION='platform=iOS Simulator,id=SIMULATOR_UUID' scripts/mobile.sh test
```

The build checks simulator and unsigned device compilation. Configure signing/provisioning for hardware use. Follow [validation](VALIDATION.md) and the repository sandbox notes. UI sample-data fixtures cannot establish authentication, real iCloud or Secure Enclave behavior.

For Mac distribution use `scripts/package.sh` for the sandboxed app and `scripts/package-cli.sh` for the separate CLI. The app does not embed the CLI.

## Sessions and data

Private mobile state uses complete Data Protection and is excluded from device backup. Lock clears session keys, protected views and unsaved drafts. Copying the database does not copy hardware private keys. Export portable backups with their separate archive keys; device-local credentials are not restorable.

See [native application](GUI.md), [AutoFill](AUTOFILL.md), [backup and restore](BACKUPS.md) and [current capabilities](VAULT.md).
