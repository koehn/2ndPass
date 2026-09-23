#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
product=mop
bundle_name=Mop
bundle_id=${MOP_BUNDLE_ID:-net.koehn.mop}
if [[ ${1:-} == --check && $# == 1 ]]; then
    product=mop-enclave-check
    bundle_name=MopEnclaveCheck
    bundle_id=${MOP_BUNDLE_ID:-net.koehn.mop.enclave-check}
elif [[ $# != 0 ]]; then
    echo 'Usage: scripts/package.sh [--check]' >&2
    exit 2
fi
: "${MOP_SIGN_IDENTITY:?Set MOP_SIGN_IDENTITY to your Apple signing identity (not ad-hoc).}"
: "${MOP_PROVISION_PROFILE:?Set MOP_PROVISION_PROFILE to an explicit macOS provisioning profile for this bundle ID.}"
if [[ "$MOP_SIGN_IDENTITY" == - ]]; then
    echo 'Ad-hoc signing is unsupported. Set MOP_SIGN_IDENTITY to your Apple signing identity.' >&2
    exit 8
fi
if [[ ! -f "$MOP_PROVISION_PROFILE" ]]; then
    printf 'Provisioning profile not found: %s\nSet MOP_PROVISION_PROFILE to the downloaded .provisionprofile file.\n' "$MOP_PROVISION_PROFILE" >&2
    exit 8
fi
mkdir -p dist
stage=$(mktemp -d "$PWD/dist/.package.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
app="$stage/$bundle_name.app"
mkdir -p "$app/Contents/MacOS"
security cms -D -i "$MOP_PROVISION_PROFILE" > "$stage/profile.plist"
python3 scripts/signing-config.py "$stage/profile.plist" "$bundle_id" "$product" "$app/Contents/Info.plist" "$stage/entitlements.plist"
cp "$MOP_PROVISION_PROFILE" "$app/Contents/embedded.provisionprofile"
swift build -c release --product "$product"
bin_dir=$(swift build -c release --show-bin-path)
cp "$bin_dir/$product" "$app/Contents/MacOS/$product"
if [[ "$product" == mop ]]; then
    swift build -c release --product MopApp
    cp "$bin_dir/MopApp" "$app/Contents/MacOS/MopApp"
    /usr/libexec/PlistBuddy -c 'Set :CFBundleExecutable MopApp' "$app/Contents/Info.plist"
    # Sign the CLI helper with the same identity, CloudKit container, and Keychain group.
    codesign --force --sign "$MOP_SIGN_IDENTITY" --identifier "$bundle_id" --options runtime --timestamp \
        --entitlements "$stage/entitlements.plist" "$app/Contents/MacOS/mop"
fi
codesign --force --sign "$MOP_SIGN_IDENTITY" --options runtime --timestamp \
    --entitlements "$stage/entitlements.plist" "$app"
codesign --verify --strict "$app"
if [[ "$product" == mop ]]; then
    "$app/Contents/MacOS/mop" device identity
    mkdir -p "$stage/share/man/man1" "$stage/share/bash-completion/completions" \
        "$stage/share/zsh/site-functions" "$stage/share/fish/vendor_completions.d"
    cp docs/man/mop.1 "$stage/share/man/man1/mop.1"
    "$app/Contents/MacOS/mop" completion bash > "$stage/share/bash-completion/completions/mop"
    "$app/Contents/MacOS/mop" completion zsh > "$stage/share/zsh/site-functions/_mop"
    "$app/Contents/MacOS/mop" completion fish > "$stage/share/fish/vendor_completions.d/mop.fish"
    for resource in man/man1/mop.1 bash-completion/completions/mop zsh/site-functions/_mop fish/vendor_completions.d/mop.fish; do
        mkdir -p "dist/share/$(dirname "$resource")"
        chmod 644 "$stage/share/$resource"
        mv -f "$stage/share/$resource" "dist/share/$resource"
    done
fi
# Preserve an existing bundle until the replacement has passed signature validation.
if [[ -e "dist/$bundle_name.app" ]]; then
    [[ -d "dist/$bundle_name.app" && ! -L "dist/$bundle_name.app" ]] || exit 7
    mv "dist/$bundle_name.app" "$stage/previous.app"
fi
mv "$app" "dist/$bundle_name.app"
echo "Signed application: $PWD/dist/$bundle_name.app"
