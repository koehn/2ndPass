# Importing password-manager data

Choose **Import…** in the Mac File menu or the app’s New menu. Select a source
file and destination vault, review the records and warnings, then import.
Existing items are never replaced. Duplicates and conflicts are skipped.
Use **Review Selection** after excluding records; use **Refresh Preview** if the
vault changed while reviewing. An owner or editor must be online to import.

Supported sources:

| Source | Export |
| --- | --- |
| Apple Passwords / Safari | Password CSV (extract the CSV from a Safari ZIP first) |
| Chrome | Password CSV |
| Bitwarden | CSV or unencrypted JSON; prefer JSON for cards, identities, and SSH keys |
| 1Password | CSV or 1PUX version 3; prefer 1PUX for richer items and fields |
| LastPass | Generic password/secure-note CSV |

Use the source selector if detection fails. CSV must have a header and use UTF-8.
2ndPass handles quoted commas, quotes, and multiline values. It preserves password
whitespace. Password-manager export formats vary; unknown columns and structured
values are retained as concealed source data where possible. Invalid records
and unsupported features are reported. Passkeys and password history are not migrated. 1PUX file attachments and Document items are imported when the referenced file bytes are present.
Keep access to the source manager until every warning has been resolved.

Logins, passwords, secure notes, API credentials, databases, SSH keys, cards,
identities, and documents use 2ndPass's item templates. Source folders/collections become tags in
the selected vault. Favorites and archive state are retained when exported.
Archived entries do not appear in normal lists or AutoFill; use the Archived
filter and edit an item to unarchive it. Cards and identities have no system
AutoFill integration, and SSH items do not provide an SSH agent. Recovery codes
are concealed multiline values; copying does not mark a code used.

An import is published as one encrypted revision. There is **no field-count
limit**. The encrypted revision metadata and non-attachment fields must fit within 16 MiB; attachment ciphertext is stored separately. Input files and decoded
archive data are limited to 64 MiB; source files may contain up to 10,000 records.
If the selected batch exceeds vault capacity, choose fewer items or another
vault. A failure before publication leaves the vault unchanged. If the server
may have committed despite a lost response, refresh to reconcile before retrying.

Update 2ndPass on every connected device before using the new item types or metadata.
Affected revisions contain a signed capability marker. Older clients reject
those revisions rather than silently discarding metadata. Current v7 encrypted backups/recovery retain the new fields. This is not an
old-format reader: v6 and earlier vaults require a compatible older client and
are not migrated. Create a v7 vault and import a supported source export.

## Command line

```sh
2ndpass item import export.csv --vault personal --dry-run
2ndpass item import export.1pux --vault personal --yes
2ndpass item import export.json --vault personal --format bitwarden-json --dry-run --json
```

Formats: `auto`, `apple-csv`, `chrome-csv`, `bitwarden-csv`, `1password-csv`,
`lastpass-csv`, `bitwarden-json`, `1pux`. Interactive import asks for confirmation;
noninteractive import requires `--yes`. Reports include titles, record numbers,
status, and warnings, but no field values. Warnings identify source field names, category names/IDs, structural property types, and attachment failures. Treat titles, filenames, and field names as personal information.
Exit status 0 means success (including duplicates), 2 means records need attention,
and 1 means import failed or its publication outcome is uncertain.
`2ndpass vault import` still imports trusted encrypted 2ndPass checkpoints.

## Handling export files

Source exports contain unencrypted secrets. 2ndPass reads them using coordinated,
security-scoped access and does not stage plaintext copies. Import review state
is not persisted and is cleared on lock, backgrounding, cancellation, or completion.
Swift/Foundation text parsing creates memory copies that cannot be reliably wiped;
2ndPass drops references when the operation ends and wipes owned byte buffers where
possible. 2ndPass never deletes the source file: check the results, then delete it
manually, including copies made outside 2ndPass.

Source-specific matching first uses exported stable item identity when available.
When both records have source identities, different identities mean different
items—even when their titles, websites, usernames, and contents are identical.
Otherwise, logins match exact usernames and overlapping website URLs (scheme/host
case and default ports normalized, paths and queries retained). Other items match
type and title. Recently Deleted and archived items are excluded from matching.
Archived source rows also bypass matching; importing them again creates additional
archived items with numeric name suffixes. Distinct logins with the same title
receive numeric name suffixes. Matching data is skipped as a duplicate; different
content is reported as a conflict. Reimporting unchanged active source items adds nothing.
Matching includes earlier accepted rows in the same file, not just existing vault
items. Each duplicate/conflict reports the matching destination item or earlier
row and the matching rule. Duplicates have equal nonempty field paths, types and
contents, item type, favorite/archive status, and tags. Conflicts list differing
fields and metadata without revealing values. Distinct source items with the
same title receive numeric suffixes, such as `Terminal (2)`.

Format references: [Apple](https://developer.apple.com/documentation/safariservices/importing-data-exported-from-safari),
[1Password CSV](https://support.1password.com/export/),
[1PUX](https://support.1password.com/1pux-format/),
[Bitwarden](https://bitwarden.com/help/export-your-data/).

## Attachments

Attachment fields can be added to any item. Choose the Attachment field type,
then Choose File in the item editor; choose Save File to export it. The Document
template creates a standalone item with an attachment. Files remain concealed
and are never rendered as text or automatically opened.

The complete filename and binary contents are encrypted with a per-field key.
Attachment ciphertext is stored as a separate immutable CloudKit asset. Signed
revisions contain its digest, size, and device/recovery key envelopes, so swapping
or corrupting the asset fails verification. Attachment bytes do not count against
the **16 MiB revision limit**. Each file is currently limited to **8 MiB**.

In **Settings → Advanced → Attachments on this device**, choose **On demand**
(the default) or **During sync**. The preference is local to this device and shared
with its CLI; it is not synced through iCloud. Downloads cache encrypted bytes;
opening/exporting a file decrypts it after authentication. Cached files work
offline. Switching to on-demand keeps already downloaded files. AutoFill never
loads external attachment bytes, regardless of this setting.

Uploads complete before publishing a revision referencing them. Membership
removal and recovery rotate attachment encryption along with other records;
adding a member rewraps keys without downloading the file. These operations and
backup export may need attachments downloaded regardless of the preference.
Encrypted backups include every referenced blob, including Recently Deleted
items, and are bounded to 256 MiB. Import comparison may also download attachments
to compare their contents. Failed downloads stop operations that require them.

Inline attachment records within the supported v7 format remain readable. The next content or
membership revision moves their ciphertext into separate assets. Historical
revisions/backups are unchanged. Update every client before writing the new
`attachment-blobs-1` capability. Production CloudKit schema must include the new
`MopV7Attachment` record type before release.

Deleting an attachment removes its reference from subsequent revisions. Historical
blobs are retained for recovery; automatic history/blob garbage collection is not
yet implemented. Removing an account from this device clears its attachment cache.

1PUX attachments are matched by document ID and filename inside `files/`.
Missing, ambiguous, oversized, or size-mismatched files are reported by name and
skipped. Credentials in the same item remain importable. File contents are read
in memory and checked against ZIP checksums; import never extracts files to disk.
The 64 MiB decoded-import limit includes referenced file contents. Bitwarden JSON
contains attachment metadata but no file bytes, so those files must be added
separately. Exporting a file writes an unencrypted copy to the chosen destination.

```sh
2ndpass item attachment add proof.pdf --vault personal --item "Account" --field proof
2ndpass item attachment export secondpass://personal/Account/proof --output ./proof.pdf
```

The CLI export refuses to overwrite an existing file and creates the destination
with owner-only permissions. Adding an attachment requires an existing item and
a new field name; the editor can replace an existing attachment.

## Bank accounts and addresses

Bank Account and Address field types store named components as concealed JSON
objects. They have labeled editors and retain unknown imported properties.
1PUX addresses are preserved on any item; category 101's banking fields are
grouped by source section. Bitwarden address and bank-account components are
mapped to the same keys. Leading zeroes in account numbers and postal codes are
preserved. Existing items are not rewritten by this parser update.

See [Import type mappings](IMPORT-MAPPINGS.md) for the exact implemented mappings
and recommendations for other source categories and field types. All clients
must support `compound-fields-1` before opening revisions with the new types.
