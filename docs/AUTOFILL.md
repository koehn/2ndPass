# Password and TOTP AutoFill

Mop includes a native credential provider extension for iOS/iPadOS 18+ and macOS
15+. Enable Mop in the system AutoFill/password-provider settings, then open and
unlock Mop. Each authenticated catalog refresh publishes login websites,
usernames and opaque password/code credential identifiers to Mop's Apple credential identity
store. Mop also writes the same metadata fields plus credential kind to a shared local index;
the extension reads that index for its searchable picker without unlocking. It
does not depend on Apple returning its stored suggestions to the extension.
Only undeleted Login items with a usable typed username/email and valid HTTP(S)
website are indexed. Password suggestions require a primary typed Password field.
Code suggestions require a primary typed OTP field, but do not require a password.
The `otp` field takes priority; otherwise exactly one OTP field is required.
Ambiguous OTP layouts are excluded from code suggestions without affecting passwords. The standard `username` and `password` fields take priority
over extra fields. Username takes priority over a contact email; email is used
when no nonempty Username field exists. Without standard field names, multiple
distinct usernames or passwords need an explicit primary field. The item view
explains any field-layout exclusion. Multiple websites are supported; URL paths, queries,
item titles, passwords, OTP seeds and vault keys are not indexed. The shared
index uses private file permissions and iOS file protection; its contents are
available to Mop and its extension without a vault-unlock prompt.

All password and OTP suggestions return `userInteractionRequired` from
`provideCredentialWithoutUserInteraction`, before opening a vault or decrypting
any secret. The system then presents Mop’s selected-credential interface, which
creates a fresh service and requests biometrics or device-owner authentication.
Selecting a suggestion is never treated as proof of authentication. The extension
verifies the selected identifier against the authenticated catalog before reading
its value. Cancelling the prompt leaves the field unchanged; the service locks
after every request. Recent app unlocks or fills do not bypass this requirement.

Username-only insertion uses the same authenticated credential resolution as
password insertion; it never inserts a username directly from the shared index.
Website and username metadata remain visible in suggestions and the searchable
picker before authentication. Every action that fills a value requires authentication.

Choosing “Mop…” opens the searchable account picker. Selecting an account there
authenticates through LocalAuthentication (biometrics or the system's device-owner
fallback), since AutoFill does not authenticate on behalf of a presented extension.
No CLI or running containing app is needed. The extension locks after completion,
failure, cancellation or dismissal. App and CLI authentication are unchanged.

On iOS, the text-field menu's AutoFill → Passwords action uses the separate text
insertion API. Mop advertises `ProvidesTextToInsert` and presents its searchable
login list with Username, Password and Code actions as applicable. Choosing an action authenticates,
revalidates the credential, and inserts only that value into the focused field.
Passwords and codes are never shown in the list or copied to the clipboard.
The code picker lists only eligible code accounts; search and website prioritization
work like the password picker. Codes are generated after authentication at fill time,
using the saved algorithm, digit count and period. Invalid seeds or expired results
fail without inserting anything; Mop does not wait for the next TOTP period.

## Storage and refresh

The app, CLI and extension use the same device-local App Group `MopV6` directory and non-synchronizable hardware key namespace. Verified encrypted checkpoints, private journals and trust pins are scoped by container, environment, account, database and actual owner. There is no exported synchronized account anchor or software private key. An exclusive local lease prevents overlapping writers.

Suggestions refresh after authenticated app catalog reads/edits. The extension resolves a selected locator against the last verified local catalog and requires fresh authentication for each fill, then releases key handles and locks. It does not establish remote freshness while offline. Observed account-change notifications invalidate the offline binding and clear suggestions. Old ciphertext is retained rather than silently deleted. A copied suggestion cannot bypass catalog membership or decryption checks.

Websites and usernames are deliberately available to the system without unlocking
Mop. Passwords and OTP seeds remain encrypted on disk; the extension decrypts only after Mop authentication for delivery to system AutoFill.
Apple manages the metadata
store, excludes it from device backups and clears it when the provider is disabled.
This version provides existing passwords and TOTP codes. Passkeys and saving or
generating new credentials through AutoFill are not implemented.
Existing password index rows upgrade automatically on refresh; password identifiers
remain stable and codes use a separate identifier namespace. No vault migration is needed.

## Provisioning and building

Both App IDs need AutoFill Credential Provider and the App Group
`group.com.koehn.mop`. The extension ID is `com.koehn.mop.AutoFill`; grant it the
same CloudKit container (`iCloud.com.koehn.mop`) and existing Keychain group
`<AppIdentifierPrefix>com.koehn.mop`. Regenerate both profiles after enabling these
capabilities. Keep the app's existing identifier/group so existing keys remain
accessible. The Mac extension is sandboxed and uses the hardened runtime.

The Mop Xcode scheme builds and embeds MopAutoFill on both platforms. The separate
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

- Enable provider, unlock Mop, and see website/username suggestions in Safari.
- Verify TOTP suggestions in a code field, including a login without a password.
  Selecting a code must present Mop authentication before filling, even after
  a recent app unlock or code fill. Cancel the prompt and verify nothing fills.
- Open the code picker and verify only code accounts appear, with working search.
- Fill codes before and after a TOTP rollover and compare with Mop’s current code.
- Browse/search the extension while Mop is locked or terminated, without a prompt.
- Select a password suggestion and verify Mop requires authentication before filling.
  Repeat immediately after an app unlock and after a successful fill. Cancel and
  confirm neither username nor password is filled. Choose “Mop…” and verify its
  picker also requires authentication before filling.
- Cancel system authentication and confirm no fields are filled; then retry.
- On iOS, long-press a text field and choose AutoFill → Passwords. Verify Mop
  appears, its list can be searched, and Username/Password/Code inserts only the
  chosen value after authentication. Cancelling must leave the field unchanged.
- Cancel authentication and retry; dismiss the extension during authentication.
- Fill offline, update a password/username, rename/trash/delete items and vaults,
  refresh Mop, and confirm old suggestions cannot fill removed credentials.
- Switch/sign out of the Apple Account and verify suggestions/offline access clear.
- Disable/re-enable the provider and repopulate by unlocking Mop.
- Upgrade an existing installation and verify its app and CLI identities still work.

An invalid local AutoFill metadata index is rebuilt on the next successful
authenticated catalog refresh. This includes stale locator formats and malformed
JSON; the extension continues to reject them until the app refreshes. Rebuilding
does not modify vaults, secrets, device keys, or trust checkpoints. Other vaults'
suggestions return as their catalogs are refreshed. Filesystem permission and
access failures remain errors and are not bypassed as part of cache repair.
