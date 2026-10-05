# 2ndPass branding and Apple identity

Use **2ndPass** in the interface and prose, pronounce it “Second Pass”, and use
`2ndpass.app` for the product domain. The command is `sp`; new secret
references are `sp://vault/item/[section/]field`. URI schemes must start
with a letter. Existing `mop://` references remain accepted, including environment
variables and templates; copying a reference emits the new spelling.

## Existing installations

The signed app is now `2ndPass.app`. Build/install it using the existing team and
profiles, then verify access before retiring an older Mop.app or its CLI link.
The installer does not delete the older app. Use `command -v sp` to check the
new command. Existing `MOP_*` build and runtime environment variables remain
supported under their original names. Update shell commands to `sp` and secret
references to `sp://`. The installer accepts a signed app containing the older
`2ndpass` helper when upgrading. Old command symlinks are not installed as aliases;
remove an obsolete link if you no longer need it.

The following deliberately retain their original names:

- Bundle ID `com.koehn.mop` and AutoFill ID `com.koehn.mop.AutoFill`.
- CloudKit container `iCloud.com.koehn.mop`, App Groups, and Keychain access groups.
- Device-key service names, local storage directories, preferences, cloud
  record/subscription identifiers, cryptographic domains, and backup format markers.
- Swift modules, Xcode project/schemes, and internal Info.plist configuration keys.
- Dated security-audit evidence.

The GitHub repository is now [koehn/2ndPass](https://github.com/koehn/2ndPass).

Stable application/container/access-group identifiers preserve the platform
identity across product renames. Branding alone must not silently
change identifiers or imply format compatibility. The extension display name is 2ndPass
AutoFill even though the build target is still MopAutoFill.

## Developer account and possible future identifiers

No new Apple Developer account or team is needed. Display names do not need to
match bundle IDs or the product domain. Reusing the current identifiers is the
recommended path for existing installations.

For a deliberate new application identity, `app.2ndpass` and
`app.2ndpass.AutoFill` are possible reverse-domain identifiers, subject to Apple's
registration checks. Register/configure them under the same team and regenerate
profiles. App Groups, Keychain access, CloudKit containers, and migration must be
planned together; changing a string alone does not move vaults or hardware keys.
Once a build has been uploaded to App Store Connect, its bundle ID cannot be
changed in that app record. A new ID requires a separate app record.

Apple references: [changing a bundle identifier](https://developer.apple.com/documentation/xcode/changing-the-bundle-identifier),
[Keychain access groups](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps),
and [configuring iCloud](https://developer.apple.com/documentation/xcode/configuring-icloud-services).
