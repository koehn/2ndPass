set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# Show available recipes.
default:
    @just --list

# Install the public site's locked Eleventy dependencies (Node 22+).
site-install:
    npm --prefix website ci --ignore-scripts

# Build and check the static public site in website/dist.
site-build:
    npm --prefix website run build

# Check generated links, fragments, and assets.
site-check:
    npm --prefix website run check

# Preview the site with live rebuilding at http://localhost:8080.
site-serve:
    npm --prefix website run dev

# Build and print the S3 deployment commands without contacting AWS.
site-deploy-dry-run bucket prefix="" distribution="": site-build
    python3 website/deploy.py "$1" --prefix "$2" --distribution "$3" --dry-run

# Upload to an existing S3 bucket; optionally invalidate CloudFront.
site-deploy bucket prefix="" distribution="": site-build
    python3 website/deploy.py "$1" --prefix "$2" --distribution "$3"

# Compile the release CLI (vault access requires a provisioned app bundle).
cli-build:
    CLANG_MODULE_CACHE_PATH=/tmp/mop-clang-cache SWIFTPM_MODULECACHE_OVERRIDE=/tmp/mop-swift-cache swift build --disable-sandbox -c release --product sp

# Package and sign the universal CLI using MOP_SIGN_IDENTITY and MOP_CLI_PROVISION_PROFILE.
cli-package:
    bash scripts/package-cli.sh

# Build, sign, and install the separate CLI (MOP_INSTALL_ROOT overrides the prefix).
cli-install: cli-package
    bash scripts/install-cli.sh

# Compile the macOS app.
app-build:
    swift build -c release --product MopApp

# Package and sign the macOS app using exported MOP_* settings.
app-package:
    bash scripts/package.sh

# Build, sign, and install the sandboxed macOS app without the CLI.
app-install: app-package
    bash scripts/install.sh

# Run the Swift unit tests.
app-test:
    swift test

# Build iOS/iPadOS simulator and device targets without signing.
ios-build:
    bash scripts/mobile.sh build

# Run mobile UI tests on available iPhone/iPad simulators.
ios-test:
    bash scripts/mobile.sh test

# Create a signed iOS archive; export MOP_BUILD_NUMBER and signing settings first.
ios-archive:
    bash scripts/mobile.sh archive

# Export the archive selected by MOP_BUILD_NUMBER using Apple/ExportOptions.plist.
ios-export:
    bash scripts/mobile.sh export
