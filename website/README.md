# 2ndPass public website

A portable Eleventy site: Markdown content, Nunjucks layouts, local CSS/JavaScript,
and the existing app logo. Output is plain HTML with no application server, runtime
API, external fonts, analytics, or third-party scripts.

## Build and preview

Install Node.js 22+, Python 3.10+, and [just](https://just.systems/). From the repository root:

```sh
just site-install
just site-build
just site-serve
```

Open http://localhost:8080. Eleventy rebuilds when source files change. Stop it with
Ctrl-C. Build output goes to `website/dist/` and is ignored by Git. Without just:

```sh
cd website
npm ci --ignore-scripts
npm run build
npm run dev
```

The production build checks local links, anchors, missing assets, and duplicate IDs.
`npm run check` checks existing output. Dependencies are pinned in `package-lock.json`.

## Edit the site

| File | Purpose |
| --- | --- |
| `src/index.njk` | Landing page and feature overview |
| `src/docs.md` | User documentation and command examples |
| `src/security.md` | Security model, boundaries, and validation status |
| `src/privacy.md` | Website/app data collection policy and service boundaries |
| `src/faq.md` | Project origin and frequently asked questions |
| `src/_includes/base.njk` | Shared head, navigation, and footer |
| `src/_includes/guide.njk` | Documentation layout and table of contents |
| `src/_data/site.json` | Public URL and navigation |
| `src/assets/site.css` | Responsive styling |
| `src/assets/site.js` | Optional copy buttons; content works without JavaScript |
| `src/assets/logo.png` | Copy of the approved `assets/Mop.png` logo |

Markdown pages begin with YAML front matter. Keep the table-of-contents IDs in sync
with headings: `## First vault` becomes `#first-vault`. Markdown is not processed as
a template, so CLI placeholders such as `{{ sp://… }}` remain literal.
Each page has an explicit `.html` URL to avoid relying on directory-index rewrites.
Use root hosting for the public domain. Prefix uploads are useful for staging;
canonical URLs, the sitemap, and the error page assume the domain root. Adapt those
before making a subdirectory deployment canonical.

The security copy follows the repository's `docs/SECURITY.md`, `docs/VAULT-V7.md`,
and validation records. `vault.html` and `vault-validation.html` are generated from
the canonical v7 documents by `src/_data/vaultDocuments.js`; update that manifest
when publishing a newer validation record. Their linked profiling data is also
included in the build. When publishing new profiling files, explicitly review and add
their output paths to `PUBLIC_PROFILING` in `deploy.py`; arbitrary JSONL logs are
not permitted for deployment. Run `python3 website/test_deploy.py` from the
repository root to check that boundary. Update public claims when implementation or acceptance
status changes. The origin FAQ separates the creator's judgment from the linked
funding announcement and news reporting, reviewed September 27, 2026.

## Deploy to S3

Use an **existing, dedicated bucket** and configured AWS CLI credentials with write
access to its public-site prefix. The recipes do not create infrastructure, change
bucket policy/ACLs, or make objects public.

```sh
# Inspect the exact commands; makes no AWS calls.
just site-deploy-dry-run my-site-bucket

# Upload at the root.
just site-deploy my-site-bucket

# Optional prefix and optional CloudFront invalidation.
just site-deploy my-site-bucket preview
just site-deploy my-site-bucket '' E123EXAMPLEDIST
```

For `2ndpass.app`, use **HTTPS**: `.app` domains require it in browsers. An S3 website
endpoint alone does not provide HTTPS. A typical setup is a private S3 bucket behind
CloudFront with Origin Access Control, a certificate for the domain, DNS pointing to
CloudFront, and `index.html` as the default root object. Configure a custom error
response for both 403 and 404 using `/404.html` and HTTP status 404. Do not rewrite
missing URLs to `index.html` as if this were a single-page application.

Only `website/dist/` is uploaded. Assets are uploaded first with a one-hour cache;
HTML is uploaded afterward with `Cache-Control: no-cache`. Existing objects are not
deleted, so deliberately remove retired pages yourself. Optional invalidation runs
after upload and is subject to CloudFront's usual pricing. A dry run prints the plan
without uploading or invalidating anything. Source files and npm dependencies are
never deployment inputs.

## App build recipes

`just --list` includes CLI/macOS builds, packaging, installation, Swift tests, iOS
builds, simulator tests, archives, and exports. These wrap the existing repository
scripts and preserve their signing requirements. Export the documented `MOP_*`
settings first; the justfile does not load a `.env` file automatically. See the root
README and `docs/MOBILE.md` for provisioning and `MOP_BUILD_NUMBER` requirements.
