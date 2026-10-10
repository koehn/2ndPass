# Clean preview sync cutover

The GUI, CLI, AutoFill and background callbacks use the shared V3 account coordinator and a separate store at `ContentPreview3/Content3.sqlite`. Vault zones are `MopContent3-UUID`; coordination uses `MopCoordination3`. Trust services and device identities have separate V3 namespaces. The new clients do not migrate or synchronize old vault formats.

## Bring existing data forward

1. Keep the previous preview build available. Use that build to export each existing vault as an encrypted portable archive. Retain its archive key separately. Review the local inventory before export: the exporter cannot certify that a disconnected device has every remote item.
2. Open the new build and explicitly restore each archive into a new vault. CLI users can use `sp vault restore-backup FILE --key-file KEY --name NAME --restore-id FRESH-UUID`; retain the destination UUID to resume an interrupted import.
3. Verify the imported items, history, trash, attachments and transferable credentials. Hardware-bound private credentials retain their existing portability limits.
4. Enroll other devices using the new build. Unlock an existing owner to authorize admission. Membership and initial download progress are separate; content arrives automatically after access is granted.

Old local stores, Keychain entries and cloud vaults remain untouched. Do not copy or rename an old database into the new store path. No automatic reset, deletion, mixed-version synchronization or in-place migration is provided. Keep archives and the previous build until the new clients pass disposable-vault acceptance.

Local saves are durable immediately. Prepared signed changes may transfer while locked; key creation, comparison and rotation wait for an authorized unlock. Normal delivery does not require Refresh. `sp vault sync` remains a diagnostic wake and optional receipt wait, not a delivery prerequisite. Receipt expiry means unknown, never confirmed delivery.

Production activation requires cryptographic review, schema validation and signed physical macOS/iOS testing. Software tests and simulator runs do not satisfy those gates. Background delivery occurs when the operating system permits execution, without a fixed deadline.

Production connections are disabled unless `MopAppSupport` is compiled with `MOP_CONTENT_SYNC_V3_REVIEWED`. Leave this condition absent until schema validation, independent cryptographic review and physical-client acceptance are recorded. This flag is not enabled by this change.
