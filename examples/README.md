# Screenshot demo vault

Import **demo-showcase.1pux** with Auto-detect or 1PUX for the full showcase:
26 fictional entries covering all nine item templates (login, password, API
credential, secure note, database, SSH key, payment card, identity, and document).
Includes tags, favorites, an archived entry, source dates, OTP, recovery codes,
card fields, a compound address, contact details, and a small text attachment.
SSH key material is deliberately invalid; the payment card uses a public test
number. All credentials are fictional and all web addresses use `.example`.

**demo-credentials.csv** is a simpler 20-item alternative. Import with Auto-detect
or Bitwarden CSV (the format has changed from the original 1Password CSV).
It includes login, standalone password, and secure-note items, plus OTP and
additional custom fields. CSV does not preserve the richer card, identity,
SSH, database, API, and document types; use the archive to demonstrate those.

Import one file into a fresh demo vault. The files overlap, so importing both or
reimporting over the original CSV can produce duplicate/conflict warnings.
Nothing in these files should be used as a real credential.
