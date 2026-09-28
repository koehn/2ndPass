#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
project=Apple/Mop.xcodeproj
build_dir="$PWD/.build/mobile"
case "${1:-build}" in
  build)
    xcodebuild -project "$project" -scheme Mop -destination 'generic/platform=iOS Simulator' \
      -derivedDataPath "$build_dir" CODE_SIGNING_ALLOWED=NO build-for-testing
    xcodebuild -project "$project" -scheme Mop -configuration Release -destination 'generic/platform=iOS' \
      -derivedDataPath "$build_dir" CODE_SIGNING_ALLOWED=NO build
    ;;
  test)
    if [[ -n ${MOP_SIMULATOR_DESTINATION:-} ]]; then
      destinations=("$MOP_SIMULATOR_DESTINATION")
    else
      device_ids=$(xcrun simctl list devices available --json | python3 -c '
import json,sys
all_devices=[d for devices in json.load(sys.stdin)["devices"].values() for d in devices]
for prefix in ("iPhone", "iPad"):
    candidates=[d for d in all_devices if d["name"].startswith(prefix)]
    if not candidates: raise SystemExit("Install an iOS simulator runtime and create an iPhone and iPad in Xcode.")
    print(candidates[0]["udid"])
')
      destinations=()
      while IFS= read -r id; do destinations+=("platform=iOS Simulator,id=$id"); done <<< "$device_ids"
    fi
    for destination in "${destinations[@]}"; do
      xcodebuild -project "$project" -scheme Mop -destination "$destination" \
        -derivedDataPath "$build_dir" -parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO test
    done
    ;;
  archive)
    : "${MOP_BUILD_NUMBER:?Set MOP_BUILD_NUMBER to a new positive TestFlight build number.}"
    [[ "$MOP_BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid build number.' >&2; exit 2; }
    mkdir -p dist/mobile
    xcodebuild -project "$project" -scheme Mop -configuration Release -destination 'generic/platform=iOS' \
      -archivePath "$PWD/dist/mobile/2ndPass-$MOP_BUILD_NUMBER.xcarchive" \
      CURRENT_PROJECT_VERSION="$MOP_BUILD_NUMBER" archive
    ;;
  export)
    : "${MOP_BUILD_NUMBER:?Set MOP_BUILD_NUMBER to the archived build number.}"
    [[ "$MOP_BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]] || exit 2
    xcodebuild -exportArchive -archivePath "$PWD/dist/mobile/2ndPass-$MOP_BUILD_NUMBER.xcarchive" \
      -exportOptionsPlist Apple/ExportOptions.plist -exportPath "$PWD/dist/mobile/export-$MOP_BUILD_NUMBER"
    ;;
  *) echo 'Usage: scripts/mobile.sh [build|test|archive|export]' >&2; exit 2 ;;
esac
