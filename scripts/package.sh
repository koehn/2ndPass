#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
product=2ndpass
bundle_name=2ndPass
bundle_id=${MOP_BUNDLE_ID:-com.koehn.mop}
if [[ $# != 0 ]]; then echo "Usage: scripts/package.sh" >&2; exit 2; fi
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
: "${MOP_AUTOFILL_PROVISION_PROFILE:?Set MOP_AUTOFILL_PROVISION_PROFILE to the macOS AutoFill extension provisioning profile.}"
export MOP_AUTOFILL=1
mkdir -p dist
stage=$(mktemp -d "$PWD/dist/.package.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
app="$stage/$bundle_name.app"
mkdir -p "$app/Contents/MacOS"
security cms -D -i "$MOP_PROVISION_PROFILE" > "$stage/profile.plist"
python3 scripts/signing-config.py "$stage/profile.plist" "$bundle_id" "$product" "$app/Contents/Info.plist" "$stage/entitlements.plist"
# Validate both profiles before compiling. The extension needs its own App ID.
if [[ ! -f "$MOP_AUTOFILL_PROVISION_PROFILE" ]]; then
    printf 'AutoFill provisioning profile not found: %s\n' "$MOP_AUTOFILL_PROVISION_PROFILE" >&2
    exit 8
fi
security cms -D -i "$MOP_AUTOFILL_PROVISION_PROFILE" > "$stage/extension-profile.plist"
python3 scripts/signing-config.py "$stage/extension-profile.plist" "$bundle_id.AutoFill" MopAutoFill \
    "$stage/extension-info.plist" "$stage/extension-entitlements.plist"
cp "$MOP_PROVISION_PROFILE" "$app/Contents/embedded.provisionprofile"
swift build -c release --product "$product"
bin_dir=$(swift build -c release --show-bin-path)
cp "$bin_dir/$product" "$app/Contents/MacOS/$product"
if [[ "$product" == 2ndpass ]]; then
    swift build -c release --product MopApp
    cp "$bin_dir/MopApp" "$app/Contents/MacOS/MopApp"
    /usr/libexec/PlistBuddy -c 'Set :CFBundleExecutable MopApp' "$app/Contents/Info.plist"
    mkdir -p "$app/Contents/Resources"
    # SwiftPM resources used by the UI and password-strength estimator.
    cp -R "$bin_dir/2ndpass_MopUI.bundle" "$app/Contents/Resources/"
    cp -R "$bin_dir/zxcvbn_zxcvbn.bundle" "$app/Contents/Resources/"
    cp .build/checkouts/zxcvbn-swift/LICENSE "$app/Contents/Resources/zxcvbn-LICENSE.txt"
    cp assets/Mop.icns "$app/Contents/Resources/Mop.icns"
    /usr/libexec/PlistBuddy -c 'Add :CFBundleIconFile string Mop.icns' "$app/Contents/Info.plist"
    # Sign the CLI helper with the same identity, CloudKit container, and Keychain group.
    codesign --force --sign "$MOP_SIGN_IDENTITY" --identifier "$bundle_id" --options runtime --timestamp \
        --entitlements "$stage/entitlements.plist" "$app/Contents/MacOS/2ndpass"
fi
# Build the native extension for both Mac architectures and sign it before the app.
xcodebuild -project Apple/Mop.xcodeproj -scheme MopAutoFill -configuration Release \
    -destination 'generic/platform=macOS' -derivedDataPath "$PWD/.build/autofill" \
    CODE_SIGNING_ALLOWED=NO MOP_HOST_BUNDLE_ID="$bundle_id" \
    PRODUCT_BUNDLE_IDENTIFIER="$bundle_id.AutoFill" \
    MOP_CLOUD_ENVIRONMENT="${MOP_CLOUD_ENVIRONMENT:-Production}" build
mkdir -p "$app/Contents/PlugIns"
cp -R .build/autofill/Build/Products/Release/MopAutoFill.appex "$app/Contents/PlugIns/"
extension="$app/Contents/PlugIns/MopAutoFill.appex"
cp "$MOP_AUTOFILL_PROVISION_PROFILE" "$extension/Contents/embedded.provisionprofile"
python3 - "$app/Contents/Info.plist" "$extension/Contents/Info.plist" <<'PYINFO'
import plistlib, sys
with open(sys.argv[1], 'rb') as source:
    host_info = plistlib.load(source)
with open(sys.argv[2], 'rb') as source:
    extension_info = plistlib.load(source)
for key in ('CFBundleVersion', 'CFBundleShortVersionString'):
    extension_info[key] = host_info[key]
with open(sys.argv[2], 'wb') as destination:
    plistlib.dump(extension_info, destination)
PYINFO
codesign --force --sign "$MOP_SIGN_IDENTITY" --options runtime --timestamp \
    --entitlements "$stage/extension-entitlements.plist" "$extension"
codesign --verify --strict "$extension"
codesign --force --sign "$MOP_SIGN_IDENTITY" --options runtime --timestamp \
    --entitlements "$stage/entitlements.plist" "$app"
codesign --verify --strict "$app"
if [[ "$product" == 2ndpass ]]; then
    "$app/Contents/MacOS/2ndpass" device identity
    mkdir -p "$stage/share/man/man1" "$stage/share/bash-completion/completions" \
        "$stage/share/zsh/site-functions" "$stage/share/fish/vendor_completions.d"
    cp docs/man/2ndpass.1 "$stage/share/man/man1/2ndpass.1"
    "$app/Contents/MacOS/2ndpass" completion bash > "$stage/share/bash-completion/completions/2ndpass"
    "$app/Contents/MacOS/2ndpass" completion zsh > "$stage/share/zsh/site-functions/_2ndpass"
    "$app/Contents/MacOS/2ndpass" completion fish > "$stage/share/fish/vendor_completions.d/2ndpass.fish"
    for resource in man/man1/2ndpass.1 bash-completion/completions/2ndpass zsh/site-functions/_2ndpass fish/vendor_completions.d/2ndpass.fish; do
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
# Notify Launch Services after replacing the bundle at the same path. Otherwise
# Finder and the Dock can retain icon metadata from the previous build.
touch "dist/$bundle_name.app"
if ! /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f "$PWD/dist/$bundle_name.app"; then
    echo 'Warning: macOS application registration could not be refreshed.' >&2
fi
echo "Signed application: $PWD/dist/$bundle_name.app"
