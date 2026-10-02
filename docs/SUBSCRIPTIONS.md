# Subscription evidence (reporting preview)

The GUI and `sp` report subscription status. No command, recovery operation, vault
permission, or Free/Pro limit is enforced. Purchase UI and production publication
are disabled in default builds. Do not enable them for release until the paid
offering and enforcement are ready.

## Configuration

Create one auto-renewable **one-year** product `com.koehn.mop.pro.yearly` in one Pro
subscription group for the `com.koehn.mop` App Store app. Configure availability,
localization, pricing, and subscription review information in App Store Connect.
Family Sharing and permanent unlocks are unsupported. Prices come from StoreKit.

Set these sealed host Info.plist build settings for an approved testing build:

- `MOP_APP_APPLE_ID`: the positive numeric App Store app ID (not the bundle ID).
- `MOP_SUBSCRIPTION_PURCHASES=YES`: enables GUI purchase/restore controls.
- `MOP_SUBSCRIPTION_PUBLICATION=YES`: enables production evidence publication and CLI reading.

The defaults are an empty ID and `NO` for both flags. Runtime configuration fails
closed to status unavailable if publication or purchases are enabled without an
ID. CLI packaging validates the ID and accepts the same build-time environment
settings; these are sealed into its bundle, not runtime bypasses. Direct-distribution
packaging rejects purchase enablement. Release GUIs require a verified StoreKit app transaction for the host bundle.
Developer ID GUIs without one explain that purchases require the App Store version.

Signed CloudKit Development builds skip automatic checks and production publication.
Explicit CLI inspection returns `developmentExempt`, never a pretend purchase.
For local StoreKit UI testing, create an Xcode StoreKit configuration containing
the annual product, select it on the Run scheme, and enable the purchase build
setting. Injected purchasing adapters exercise purchase outcomes in unit tests.
Sandbox, TestFlight, and Xcode StoreKit evidence cannot be published into Production.

## CloudKit deployment

Before enabling publication, create and deploy this schema in the existing
`iCloud.com.koehn.mop` container using CloudKit Console:

- Private custom zone: `mop-subscription-v1` (created per account by the app).
- Record type: `MopSubscriptionEvidence`.
- `payload`: Bytes containing JSON with Apple-signed transaction and renewal JWS.
- `expiration`: Date/Time (informational; never grants active status).
- `signedAt`: Date/Time (informational).
- `status`: String (informational snapshot at publication).
- Enable the record query/index configuration required for querying this type
  with a true predicate, including the `recordName` queryable system index.

Initialize the schema in Development, deploy the record type and indexes to
Production, and verify private record fetches using signed builds. Records are
content-addressed and immutable. Concurrent devices append evidence; consumers
verify signatures and compare Apple-signed transaction and renewal dates. There
are no public records, CKShare records, or vault dependencies in this store.

New purchases use an opaque, deterministic UUID derived from the CloudKit user
record ID and container. Both GUI and CLI require that token in transactions.
Changing iCloud accounts does not transfer purchases. Restore of a purchase bound
to another iCloud account fails verification; use the original account.

## CLI and caching

`sp subscription status [--json] [--offline]` explicitly inspects status. JSON
contains `status`, `source`, `expiration`, and `lastVerified`. Dates use ISO 8601
or JSON null when unknown. Operational commands report on stderr after parsing; help, version,
completion, and `device identity` are exempt. Reporting does not change stdout or
command exit codes. Existing commands with `--offline` use no subscription network
request. The total evidence lookup/verification deadline is two seconds.

The macOS-only verifier uses Apple's App Store Server Library, bundled Apple G2/G3
trust roots, the host bundle ID, numeric app ID, and Production environment. Both
transaction and renewal signatures are verified independently before interpreting
claims. There are no server credentials. Certificate verification runs offline;
refund knowledge comes from refreshed signed transaction evidence.

Caches contain signed evidence and are partitioned by container/environment and
validated against the local iCloud identity fingerprint and CloudKit account.
Account changes invalidate them. The CLI re-verifies cached evidence on every use;
active/grace status ends at the verified deadline, with no courtesy extension.
Missing connectivity or failed verification means unavailable unless valid cached
evidence exists. GUI publication has a separate durable pending file; after restart
it reacquires StoreKit-verified evidence before retrying, rather than trusting local
JSON. Failed publication retains pending evidence and retries every minute and on
refresh. The GUI never overwrites the CLI's verified cache.

## Validation and limitations

Unit tests use isolated purchase and signature adapters for state transitions,
account binding, expiry/grace, stale updates, outages, timeouts, cache invalidation,
and publication retries. A real-library test rejects unsigned evidence; unsigned
fixtures do not establish compatibility with live Apple signatures.

Before release, use signed builds to validate a real production purchase,
publication, cross-device CLI consumption, account switching, renewal, refund,
and grace handling. Sandbox testing validates the UI but cannot produce production
evidence. These checks require the configured App Store product, numeric app ID,
appropriate signed entitlements/profiles, and deployed CloudKit schema.

There is no licensing server. Renewals and refunds reach CloudKit only after a GUI
refresh. Cached evidence cannot prove that a later refund has not occurred. This
reporting preview does not solve unpaid CLI access.
