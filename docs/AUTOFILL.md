# Password and TOTP AutoFill

2ndPass includes a native credential provider extension for iOS/iPadOS 18+ and macOS
15+. Enable 2ndPass in the system AutoFill/password-provider settings, then open and
unlock 2ndPass. Each authenticated catalog refresh publishes login websites,
usernames and opaque password/code credential identifiers to 2ndPass's Apple credential identity
store. 2ndPass also writes the same metadata fields plus credential kind to a shared local index;
the extension displays cached usernames and websites in its picker without authentication. It does not depend on Apple returning its stored suggestions to the extension.
Only undeleted Login items with a usable username and valid HTTP(S) website are
indexed. Edit Item → Use for AutoFill provides explicit username, password, and
verification-code field choices. Choices are encrypted catalog metadata; missing
choices retain automatic selection of standard fields. Usernames must use a
nonsecret Username, Email, or Text field; passwords use Password or Concealed;
codes use OTP. Missing or incompatible explicit choices never fall back silently.
The editor can add correctly typed fields and websites. Optional OTP absence is
not a broken-password warning. Existing items need no migration; mixed older
writing clients are not supported for preserving the new mappings.

Settings → AutoFill shows provider enabled state, publication health, and the last
successful system suggestion update. Enable AutoFill uses Apple’s supported prompt;
Open AutoFill Settings and Open Verification Code Settings use supported settings
APIs. Refresh Suggestions rebuilds from authenticated catalogs. A publication
failure is reported separately and never makes a successful vault save fail.
Unavailable vaults retain their prior suggestions during a partial refresh. Catalog
eligibility alone is not proof that the system accepted publication.

Only website, username, kind, and opaque locator leave the encrypted catalog.
Item/vault names, field paths, passwords, OTP seeds, and keys are not published or
written to the shared index. Publication health stores a timestamp, generic status, and opaque IDs of vaults
whose catalogs still need refreshing. Files use private permissions and iOS data protection.

All no-interaction password and code requests return `userInteractionRequired`
before opening a vault. A selected suggestion authenticates in the presented
extension. Opening and searching 2ndPass’s picker does not open any vault or start
an authentication session. Item and vault names remain encrypted and are not shown.
Selecting a credential starts a fresh request session that authorizes one fill for
at most 60 seconds. The containing app may be locked or terminated. It never reuses the containing app’s authentication
or a prior fill. Dismissal, cancellation, backgrounding, account changes, failures,
and expiry release the session. System authentication presentation
does not itself count as leaving the request.

The picker groups exact normalized-host matches under For This Website, with Other
Accounts below. Search uses cached usernames and websites. Arrow keys select, Return
fills, and Escape cancels. Choosing an unrelated account requires confirmation that
names both sites. Empty searches and failed credential resolution have explicit explanations.
Errors offer Retry and Choose Another Account; setup instructions point to 2ndPass’s
AutoFill settings without relying on an unsupported extension-to-app launch route.

Immediately before filling, the extension re-resolves the identifier against the
authenticated catalog. It does not trust cached usernames or references. Passwords
and codes are never displayed or copied to the clipboard. On iOS, text insertion
provides Username, Password, and Code actions under the same authentication policy.
Codes are generated after authentication and checked for expiration immediately
before completion; an expired result requires a fresh authenticated Retry.

## Storage and refresh

The app, CLI, and extension share device-local App Group `MopV7` checkpoints and the
non-synchronizable hardware key namespace. Account changes invalidate offline access
and clear suggestions. Removed/stale suggestions cannot bypass catalog resolution.
Offline filling uses the last verified catalog and cannot establish remote freshness.
System suggestions and the picker reveal websites and usernames before authentication;
item/vault names remain encrypted. Identical website/username pairs in separate
vaults appear as separate entries without decrypted labels.

This version fills existing passwords and verification codes. Passkeys, saving new
credentials, and generating passwords inside AutoFill are not implemented. Disabling
the provider clears Apple’s store; enable it again and refresh suggestions in 2ndPass.
An invalid derived metadata cache is rebuilt from authenticated catalogs. Filesystem
permission failures remain errors and are never bypassed during repair.

## Provisioning and building

Both App IDs need AutoFill Credential Provider and the App Group
`group.com.koehn.mop`. The extension ID is `com.koehn.mop.AutoFill`; grant it the
same CloudKit container (`iCloud.com.koehn.mop`) and existing Keychain group
`<AppIdentifierPrefix>com.koehn.mop`. Regenerate both profiles after enabling these
capabilities. Keep the app's existing identifier/group so existing keys remain
accessible. The Mac extension is sandboxed and uses the hardened runtime. The packaged Mac
app and CLI do not enable App Sandbox; iOS/iPadOS apply their platform sandbox.
The Keychain access group authorizes identity access, the App Group shares local
files, and CloudKit entitlements authorize container access. These are distinct
capabilities. The extension intentionally has access to the same hardware-bound
device identity, so its code is part of the vault's trusted computing base.

Non-exportable device private keys do not prevent an authorized extension or
sufficiently privileged malware from using keys during an unlocked operation.
Decrypted item keys and the filled password/code reach normal memory. Once
AuthenticationServices delivers the credential, the OS and destination app/site
control its subsequent use; fresh fill authentication does not encrypt that
plaintext destination.

The `Mop` Xcode scheme builds and embeds MopAutoFill on both platforms. The separate
MopAutoFill scheme supports the Mac packaging script. For that script, supply
`MOP_AUTOFILL_PROVISION_PROFILE` as well as `MOP_PROVISION_PROFILE` and
`MOP_SIGN_IDENTITY`. Packaging validates the required capabilities, signs the
extension before its containing app, and verifies both signatures. For a custom
Mac bundle ID, packaging derives the `.AutoFill` suffix and `group.` identifier
from `MOP_BUNDLE_ID`.

## Device acceptance

Unsigned builds and unit tests cannot validate system registration, provisioning,
Keychain sharing or biometric presentation. Before release, use signed builds on
an iPhone/iPad and Mac to check:

- Enable provider, unlock 2ndPass, and see website/username suggestions in Safari.
- Verify TOTP suggestions in a code field, including a login without a password.
  Selecting a code must present 2ndPass authentication before filling, even after
  a recent app unlock or code fill. Cancel the prompt and verify nothing fills.
- Open the code picker and verify only code accounts appear, with working search.
- Fill codes before and after a TOTP rollover and compare with 2ndPass’s current code.
- Open and search the picker with 2ndPass locked or terminated; verify usernames
  and websites appear without authentication. Select an account, authenticate in
  the extension, and verify it fills without opening or unlocking the containing app.
- Select a password suggestion and verify 2ndPass requires authentication before filling.
  Repeat immediately after an app unlock and after a successful fill. Cancel and
  confirm neither username nor password is filled. Choose “2ndPass…” and verify its
  picker lists accounts without a prompt, then authenticates once when filling.
- Cancel system authentication and confirm no fields are filled; then retry.
- On iOS, long-press a text field and choose AutoFill → Passwords. Verify 2ndPass
  appears, its list can be searched, and Username/Password/Code inserts only the
  chosen value after authentication. Cancelling must leave the field unchanged.
- Cancel authentication and retry; dismiss the extension during authentication.
- Fill offline, update a password/username, rename/trash/delete items and vaults,
  refresh 2ndPass, and confirm old suggestions cannot fill removed credentials.
- Switch/sign out of the Apple Account and verify suggestions/offline access clear.
- Disable/re-enable the provider and repopulate by unlocking 2ndPass.
- Upgrade an existing installation and verify its app and CLI identities still work.

An invalid local AutoFill metadata index is rebuilt on the next successful
authenticated catalog refresh. This includes stale locator formats and malformed
JSON; the extension continues to reject them until the app refreshes. Rebuilding
does not modify vaults, secrets, device keys, or trust checkpoints. Other vaults'
suggestions return as their catalogs are refreshed. Filesystem permission and
access failures remain errors and are not bypassed as part of cache repair.

Additional acceptance: browse for more than 60 seconds before choosing and verify
a fresh authentication session starts on selection. Switch apps or dismiss during
authentication and verify nothing fills from the invalidated session.
Check Return/Escape/arrow keys, VoiceOver, text sizing, contrast, no-results search,
and confirmation before choosing an unrelated site. Test disabled/enabled provider
states and publication failure independently from a successful vault save.

## Device-bound passkeys in `local`

The extension implements Secure Enclave ES256 WebAuthn registration and assertion,
with user verification for every operation. Creation requires acknowledging permanent
device loss and recommends registering another independent passkey on another device.
The passkey remains device-bound; it is never synced or backed up. Only credentials
matching the exact requested relying party and allowed credential IDs are offered.

BE and BS are both zero. Apple has documented a credential-provider restriction
requiring those flags to be true, so physical-device acceptance is not yet established.
The implementation never lies about backups to bypass that restriction. See
[the compatibility limitation and acceptance suite](LOCAL-VAULT.md#device-bound-passkeys).
