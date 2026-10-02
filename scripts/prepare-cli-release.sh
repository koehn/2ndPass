#!/bin/bash
# Notarize a signed universal CLI, then produce its archive and Homebrew cask.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# == 2 ]] || { echo 'Usage: scripts/prepare-cli-release.sh VERSION HTTPS_ARCHIVE_URL' >&2; exit 2; }
version=$1
url=$2
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release version" >&2; exit 2; }
: "${MOP_NOTARY_PROFILE:?Set MOP_NOTARY_PROFILE to a notarytool Keychain profile.}"
app="$PWD/dist/cli/2ndPass CLI.app"
codesign --verify --strict "$app"
[[ $("$app/Contents/MacOS/sp" --version) == "$version" ]] || { echo 'CLI version mismatch' >&2; exit 2; }
lipo -verify_arch arm64 x86_64 "$app/Contents/MacOS/sp"
# A cask release must use Developer ID signing, not development signing.
codesign -d --verbose=2 "$app" 2>&1 | grep -q '^Authority=Developer ID Application:'
stage=$(mktemp -d "$PWD/dist/.cli-release.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
ditto -c -k --keepParent "$app" "$stage/notarize.zip"
xcrun notarytool submit "$stage/notarize.zip" --keychain-profile "$MOP_NOTARY_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute "$app"
chmod -R a+rX dist/cli
archive="$PWD/dist/secondpass-cli-$version-macos-universal.zip"
ditto -c -k --keepParent dist/cli "$stage/release.zip"
python3 scripts/prepare-cli-cask.py "$version" "$url" "$stage/release.zip" --output "$stage/secondpass-cli.rb"
mv "$stage/release.zip" "$archive"
mkdir -p dist/Casks
mv "$stage/secondpass-cli.rb" dist/Casks/secondpass-cli.rb
echo "Release archive: $archive"
echo 'Cask: dist/Casks/secondpass-cli.rb (publish in your tap after uploading the archive)'
