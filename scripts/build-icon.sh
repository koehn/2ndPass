#!/bin/bash
# Build all macOS icon representations from the approved artwork.
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:?Usage: scripts/build-icon.sh OUTPUT.icns}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/Mop.iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" assets/Mop.png --out "$stage/Mop.iconset/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" assets/Mop.png --out "$stage/Mop.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$stage/Mop.iconset" -o "$output"
