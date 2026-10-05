# Cloud key credentials

Choose **New → New SSH Key** to generate or import a usable key. Choose **Save in**
on every creation; no destination is silently selected. Create passkeys from a
website's registration flow, select 2ndPass, and choose a cloud vault or **This
Device — Secure Enclave**. Cloud-key workflows request online access; local save and confirmed cloud publication are distinct states.

The interface follows Apple's Passwords lists and credential details. SSH creation,
import, public-key copying, and setup guidance also draw on
[1Password's SSH key workflows](https://www.1password.dev/ssh/manage-keys).

## Supported types

| Operation | Cloud vault | Device-local vault |
| --- | --- | --- |
| Passkey registration/use | ES256 / P-256 | Secure Enclave P-256, subject to platform compatibility |
| SSH/Git generation | Ed25519 (default), P-256 | Secure Enclave P-256 |
| SSH/Git import | Ed25519, P-256, RSA 2048–8192 bits | Never supported |
| Certificates/CSR | Not included in this feature | Existing local workflows |

Imports accept single-key `openssh-key-v1` files with the OpenSSH PEM envelope.
Unencrypted files and bcrypt/AES-256-CTR encrypted files are supported. KDF rounds
are limited to 1024, salt to 1024 bytes, passphrase to 4096 bytes, and input to 1 MiB.
Legacy PEM/PKCS#1/PKCS#8 envelopes, other curves, DSA, hardware-reference files,
and other ciphers are rejected with an error. RSA uses SHA-256/SHA-512 signatures;
SHA-1 signing is rejected. RSA generation is not offered.

The importer validates structure, check integers, padding, and public/private-key
agreement. It derives public keys and fingerprints rather than trusting supplied
fields. The file passphrase decrypts the import only; it is not retained. The
normalized private key is encrypted by the vault. Import does not delete the
original file. Passkey import/export and cloud certificate use are not implemented.
Ordinary secret fields may still store unsupported material without making it a
usable credential.

## Protection, synchronization, recovery, and sharing

Cloud private keys are software keys stored as concealed encrypted item payloads.
An authorized process can access private material during use; they do not have the
non-extractability of a Secure Enclave key. Typed public metadata stays in the
encrypted catalog. Public AutoFill suggestions contain RP, username, credential ID,
user handle, and an opaque vault-scoped locator, never a private key.

Cloud credentials use encrypted item storage and same-account synchronization. Portable archives preserve transferable software key bytes. Account recovery, cross-account sharing and device removal are unavailable. Credential-account registration evidence is separate from key creation/use and remains unconnected. See [backups](BACKUPS.md).

Archived/deleted items are excluded from selection and suggestions on refresh. Deleting an item does not revoke the credential at its website or server.

Local keys remain generated inside the Secure Enclave. They cannot be imported,
exported, moved into cloud storage, synchronized, or recovered on another device.
Register an independent key or recovery method before relying on a local key.

Local passkeys now report `BE=0, BS=0`. The earlier development override reported
backup flags that did not match their actual storage. Existing local records are
retained, but sites may require re-registration following that correction. Apple
platform acceptance of device-bound provider credentials must be tested; do not
work around rejection by falsely setting backup flags. Cloud passkeys use backup flags with UP/UV and a zero signature counter. Verify publication and backup-flag semantics end to end before release: local save success alone does not establish cloud delivery. No registration response is delivered after a failed save.

## SSH and Git

```sh
sp item create --vault personal --type ssh --name server --algorithm ed25519
sp item create --vault personal --type git-signing --name commits --algorithm p256
sp item import-ssh --vault personal --name imported --purpose ssh ~/.ssh/id_ed25519
sp item public-key --vault personal server
sp ssh-agent --vault personal --identity server -- ssh user@example.com
```

Encrypted CLI imports prompt on the terminal without echo. No passphrase option or
plaintext temporary file is used. Existing SSH text items require an explicit
Save action. Saving validates the stored OpenSSH private key and converts it
into an agent-ready credential in the same vault, preserving notes and other
edits. Enter its passphrase if encrypted and choose SSH authentication or Git
signing in the editor. The public key and fingerprint are derived automatically;
neither is editable. Invalid keys leave the draft intact. The file passphrase is
not retained after conversion. The CLI also supports `import-ssh --convert`.

For Git signing, register the public key with your Git provider as a signing key:

```sh
git config gpg.format ssh
git config user.signingkey 'key::ssh-ed25519 PUBLIC_KEY_BASE64'
sp ssh-agent --vault personal --purpose git-signing --identity commits -- git commit -S
```

The detail view supplies copyable commands for the actual key and vault. SSH
transport authentication (including Git fetch/push over SSH) and Git commit
signing are distinct purposes. Select keys explicitly to avoid offering more keys
than a server permits. Each agent session serves one vault. With no command,
`sp ssh-agent` runs in the foreground and prints its socket path; set
`SSH_AUTH_SOCK` in the terminal/IDE to that path. The IDE must use an agent-capable
SSH/Git client. This does not install a persistent agent or modify IDE settings.

Approvals remain scoped to the selected key and client process, or to the wrapped
command tree. Lock, sleep, expiry, cancellation, and observed access removal deny
subsequent signatures; late results are discarded. The agent does not support
adding keys through `ssh-add`: use the import workflow instead.

## Compatibility and validation

Use compatible app, CLI and AutoFill builds together. Physical cloud-key use and publication behavior need end-to-end acceptance with the item service; retained cryptographic tests alone are not proof of delivery.

Automated software tests cover generation/import, encrypted files and wrong
passphrases, RSA SHA-2, real OpenSSH agent listing, real Git commit/tag signing and
verification for each algorithm, passkey signature/RP isolation, save failure,
concealed catalog projection, membership, revocation, and model recovery. These
are not hardware or live iCloud acceptance evidence.

Outstanding release acceptance (do not mark SALE-6 or SALE-13 complete yet):

- Physical Mac/iPhone/iPad passkey registration and assertion on minimum and
  current supported OS versions; inspect BE/BS/UP/UV and local rejection behavior.
- Same-account synchronization and use on a second device; replacement-device
  recovery preserving key material and passkey identifiers.
- Two real accounts exercising owner/editor/viewer permissions and revocation,
  including offline clients; coordinate with SALE-7's sharing acceptance.
- SSH authentication against representative servers; Terminal, VS Code, and a
  JetBrains IDE selection, approval, lock, and reconnect workflows.
- VoiceOver, large text, keyboard navigation, and narrow layouts on physical
  devices; complete the broader SALE-8 UI review separately.

See [recorded validation results](CLOUD-KEY-VALIDATION.md) and
[repository validation notes](../AGENTS.md) for required sandbox permissions.
