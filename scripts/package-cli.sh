#!/bin/bash
set -euo pipefail
umask 077
export CLANG_MODULE_CACHE_PATH=${CLANG_MODULE_CACHE_PATH:-/tmp/mop-clang-cache}
export SWIFTPM_MODULECACHE_OVERRIDE=${SWIFTPM_MODULECACHE_OVERRIDE:-/tmp/mop-swift-cache}
cd "$(dirname "$0")/.."
product=sp
bundle_name="2ndPass CLI"
bundle_id="${MOP_BUNDLE_ID:-com.koehn.mop}.CLI"
if [[ $# != 0 ]]; then echo "Usage: scripts/package-cli.sh" >&2; exit 2; fi
: "${MOP_SIGN_IDENTITY:?Set MOP_SIGN_IDENTITY to your Apple signing identity (not ad-hoc).}"
: "${MOP_CLI_PROVISION_PROFILE:?Set MOP_CLI_PROVISION_PROFILE to an explicit macOS provisioning profile for this bundle ID.}"
if [[ "$MOP_SIGN_IDENTITY" == - ]]; then
    echo 'Ad-hoc signing is unsupported. Set MOP_SIGN_IDENTITY to your Apple signing identity.' >&2
    exit 8
fi
if [[ ! -f "$MOP_CLI_PROVISION_PROFILE" ]]; then
    printf 'Provisioning profile not found: %s\nSet MOP_CLI_PROVISION_PROFILE to the downloaded .provisionprofile file.\n' "$MOP_CLI_PROVISION_PROFILE" >&2
    exit 8
fi
mkdir -p dist/cli
stage=$(mktemp -d "$PWD/dist/cli/.package.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
app="$stage/$bundle_name.app"
mkdir -p "$app/Contents/MacOS"
security cms -D -i "$MOP_CLI_PROVISION_PROFILE" > "$stage/profile.plist"
python3 scripts/signing-config.py "$stage/profile.plist" "$bundle_id" "$product" "$app/Contents/Info.plist" "$stage/entitlements.plist"
cp "$MOP_CLI_PROVISION_PROFILE" "$app/Contents/embedded.provisionprofile"
swift build --disable-sandbox --arch arm64 --arch x86_64 -c release --product "$product"
bin_dir=$(swift build --disable-sandbox --arch arm64 --arch x86_64 -c release --show-bin-path)
cp "$bin_dir/$product" "$app/Contents/MacOS/$product"
mkdir -p "$app/Contents/Resources"
cp -R "$bin_dir/2ndpass_MopSubscriptionVerification.bundle" "$app/Contents/Resources/"
cp -R "$bin_dir/zxcvbn_zxcvbn.bundle" "$app/Contents/Resources/"
cp .build/checkouts/zxcvbn-swift/LICENSE "$app/Contents/Resources/zxcvbn-LICENSE.txt"
codesign --force --sign "$MOP_SIGN_IDENTITY" --options runtime --timestamp \
    --entitlements "$stage/entitlements.plist" "$app"
codesign --verify --strict "$app"
if [[ "$product" == sp ]]; then
    "$app/Contents/MacOS/sp" device identity
    mkdir -p "$stage/share/man/man1" "$stage/share/bash-completion/completions" \
        "$stage/share/zsh/site-functions" "$stage/share/fish/vendor_completions.d"
    cp docs/man/sp.1 "$stage/share/man/man1/sp.1"
    "$app/Contents/MacOS/sp" completion bash > "$stage/share/bash-completion/completions/sp"
    "$app/Contents/MacOS/sp" completion zsh > "$stage/share/zsh/site-functions/_sp"
    "$app/Contents/MacOS/sp" completion fish > "$stage/share/fish/vendor_completions.d/sp.fish"
    for resource in man/man1/sp.1 bash-completion/completions/sp zsh/site-functions/_sp fish/vendor_completions.d/sp.fish; do
        mkdir -p "dist/cli/share/$(dirname "$resource")"
        chmod 644 "$stage/share/$resource"
        mv -f "$stage/share/$resource" "dist/cli/share/$resource"
    done
fi
# Preserve an existing bundle until the replacement has passed signature validation.
if [[ -e "dist/cli/$bundle_name.app" ]]; then
    [[ -d "dist/cli/$bundle_name.app" && ! -L "dist/cli/$bundle_name.app" ]] || exit 7
    mv "dist/cli/$bundle_name.app" "$stage/previous.app"
fi
mv "$app" "dist/cli/$bundle_name.app"
cp scripts/install-cli.sh dist/cli/install-cli.sh
cp LICENSE dist/cli/LICENSE
echo "Signed CLI: $PWD/dist/cli/$bundle_name.app"
echo 'Install with: dist/cli/install-cli.sh'
