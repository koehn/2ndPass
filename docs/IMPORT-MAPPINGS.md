# Import type mappings

Bank Account and Address are compound **field types**, usable on any item. Both
are concealed. Values are JSON objects; account numbers, routing numbers, postal
codes, and other textual identifiers retain leading zeroes and whitespace.
Editors show named components and preserve unknown source properties, including
nested data, when another component changes. Revisions containing these fields
require `compound-fields-1`; update all clients before using them.

## Implemented compound-field mappings

| Source | Mop field | Components |
| --- | --- | --- |
| 1PUX `value.address`, on any category | Address | `street`, `city`, `state`, `zip`, `country`, plus every other property |
| 1PUX Bank Account category `101` | Bank Account, one per source section containing banking details | `bankName`, `owner`, `accountType`, `accountNo`, `routingNo`, `iban`, `swift`, `telephonePin`, `branchPhone` |
| 1PUX structured `value.bankAccount`, when present | Bank Account | Entire source object |
| Bitwarden identity address | Address | `address1/2/3` → `street/street2/street3`; `postalCode` → `zip`; city/state/country preserved |
| Bitwarden `bankAccount` object, when present | Bank Account | `nameOnAccount` → `owner`; `accountNumber` → `accountNo`; `routingNumber` → `routingNo`; `swiftCode` → `swift`; `pin` → `telephonePin`; `bankContactPhone` → `branchPhone`; other properties preserved |

1PUX bank account fields with duplicate IDs are retained separately rather than
overwriting one another. Multiple addresses remain separate fields. Bank
accounts retain the Custom item type until an item-category mapping is chosen.
No country-specific bank-number or postal-code rules are imposed.

## Recommended item mappings for review

These are recommendations for a later import/migration change, not additional
automatic conversions in this update. Prefer the explicit source category and
source identity over guessing from an item's title.

| Source category | Existing Mop item type | Conditions and retained details |
| --- | --- | --- |
| Login, Password, Secure Note, Card, Identity, Database, SSH Key, API Credential, Document | Corresponding Mop type | Already mapped directly |
| Bank Account (`101`) | Custom + Bank Account field | Keep banking data together; a bank account is not a payment card |
| Passport (`106`), Driver License (`103`), Outdoor License (`104`), Social Security Number (`108`) | Identity | Preserve original category in encrypted metadata; identifiers stay concealed with their original labels |
| Membership (`105`), Rewards Program (`107`) | Identity | Retain organization, member name, number, dates, and category; do not reinterpret every number as a government ID |
| Email Account (`111`) | Login | Map username/password explicitly; preserve mail-server settings separately; only actual web URLs become Website fields |
| Server (`110`) | Login | Use for account credentials; preserve hostname, protocol, port and other connection settings; do not invent an HTTPS URL |
| Wireless Router (`109`) | Password; Login if explicitly an administrator login | Retain SSID/security settings; a Wi-Fi key is not a website password |
| Software License (`100`) | Secure Note | Keep license key concealed; retain product/version/licensee separately |
| Medical Record (`113`) | Secure Note | Keep medical identifiers and details concealed |
| Unknown category | Custom | Retain its source category ID and report the fallback |

## Recommended remaining field mappings for review

| Imported field | Mop field type | Rule |
| --- | --- | --- |
| Explicit username/password designation | Username / Password | Prefer designation over translated labels |
| `string`, `menu`, `gender` | Text | Preserve the original string; concealed/guarded input stays Concealed |
| `concealed`, PIN, security answer, license key, government ID | Concealed | Only actual passwords become Password and get password scoring |
| `url`, `email`, `phone` | Website / Email / Phone | Use the declared type; retain email provider metadata separately |
| `date`, `monthYear` | Date / Expiration (month/year) | Preserve date precision; never invent a day for a month/year |
| `creditCardNumber` | Card number | Keep string formatting and leading zeroes |
| Bank-account components / `address` | Bank Account / Address | Implemented above |
| TOTP | OTP | Only supported configurations generate codes; retain other configurations concealed with a specific warning |
| SSH key | Private key plus public key/fingerprint | Existing mapping; keep every additional source property |
| File reference | Attachment | Resolve bytes from 1PUX; report named failures |
| Item reference | Text containing a clearly labeled source reference, pending a link feature | Do not turn an opaque source ID into a functioning Mop reference |
| Unknown structured value | Concealed JSON | Preserve it and report field/section/type structure, without scalar secret values |

Scope template IDs by category: for example, `type` can mean card brand, passport
type, or account type. Use the declared source value type first, a
category-specific field-ID mapping second, and labels only as a cautious fallback.
Do not split a full name into guessed first/last names or convert identifiers to
numbers. If a component is already present, keep both values or ask for a
conflict decision instead of overwriting.

## Existing imported items

A migration should match records using the encrypted source identity, preview
item-type and field changes, preserve every value, and commit the selected changes
as one revision. Merely switching an item's template is insufficient to combine
its old flattened address or bank fields. Ambiguous matches should remain for
manual review. Normal re-import continues to skip conflicts; it does not perform
this migration.

Sources: [1Password's 1PUX specification](https://support.1password.com/1pux-format/)
and [Bitwarden's 1PUX importer and bank-field mapping](https://github.com/bitwarden/clients/blob/main/libs/importer/src/importers/onepassword/onepassword-1pux-importer.ts).
