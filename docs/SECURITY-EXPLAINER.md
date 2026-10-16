# How 2ndPass protects secrets

Your device's Secure Enclave protects its identity keys. Those keys open encrypted item keys; the app uses item keys to decrypt requested secrets. Passwords and temporary keys necessarily enter authorized process memory. Local credential keys stay inside hardware and cannot be synchronized or recovered.

Each edit is saved encrypted on this device before iCloud delivery. Independently signed items and signed membership history help detect tampering relative to trusted state. They cannot prove that the cloud supplied every item or the latest inventory.

Other devices on your Apple Account connect automatically while an existing device is unlocked. This deliberately trusts the authenticated private iCloud container for initial admission. Protect your Apple Account as well as your devices.

Keep a portable archive and its separate key for independent restoration. Device removal and permanent cloud-vault deletion are preview features awaiting physical acceptance; deletion availability depends on the build gates described in [the native application guide](GUI.md). Live account recovery and sharing have separate status described in the linked guides. Read the [security model](SECURITY.md), [vault architecture](VAULT.md), [backups](BACKUPS.md) and [validation status](VALIDATION.md) for details.
