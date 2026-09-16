#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
product=mop
if [[ ${1:-} == --check && $# == 1 ]]; then
    product=mop-enclave-check
elif [[ $# != 0 ]]; then
    echo 'Usage: scripts/package.sh [--check]' >&2
    exit 2
fi
swift build -c release --product "$product"
bin_dir=$(swift build -c release --show-bin-path)
mkdir -p dist
stage=$(mktemp -d "$PWD/dist/.package.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
cp "$bin_dir/$product" "$stage/$product"
# Local ad-hoc signing needs no certificate, developer account, or provisioning.
codesign --force --sign - --options runtime --timestamp=none "$stage/$product"
codesign --verify --strict "$stage/$product"
if [[ "$product" == mop ]]; then
    mkdir -p "$stage/share/man/man1" "$stage/share/bash-completion/completions" \
        "$stage/share/zsh/site-functions" "$stage/share/fish/vendor_completions.d"
    cp docs/man/mop.1 "$stage/share/man/man1/mop.1"
    "$stage/mop" completion bash > "$stage/share/bash-completion/completions/mop"
    "$stage/mop" completion zsh > "$stage/share/zsh/site-functions/_mop"
    "$stage/mop" completion fish > "$stage/share/fish/vendor_completions.d/mop.fish"
    for resource in man/man1/mop.1 bash-completion/completions/mop zsh/site-functions/_mop fish/vendor_completions.d/mop.fish; do
        mkdir -p "dist/share/$(dirname "$resource")"
        chmod 644 "$stage/share/$resource"
        mv -f "$stage/share/$resource" "dist/share/$resource"
    done
fi
mv -f "$stage/$product" "$PWD/dist/$product"
echo "Local executable: $PWD/dist/$product"
