#!/bin/bash
# Install only the sandboxed GUI. Developer tools have their own installer.
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
[[ $# -le 1 ]] || { echo 'Usage: scripts/install.sh [signed-2ndPass.app]' >&2; exit 2; }
source_app=${1:-"$PWD/dist/2ndPass.app"}
applications=${MOP_APPLICATIONS_DIR:-/Applications}
app="$applications/2ndPass.app"
[[ -f "$source_app/Contents/MacOS/MopApp" && ! -e "$source_app/Contents/MacOS/sp" ]] || exit 7
codesign --verify --strict "$source_app"
# Compare signed identifiers before replacing an existing app.
identifier() { codesign -d --verbose=2 "$1" 2>&1 | sed -n -e '/^Identifier=/p' -e '/^TeamIdentifier=/p'; }
identity=$(identifier "$source_app")
[[ "$identity" == *TeamIdentifier=* && "$identity" != *TeamIdentifier=not\ set* ]] || exit 8
if [[ -e "$app" || -L "$app" ]]; then
    [[ -d "$app" && ! -L "$app" ]] || exit 7
    codesign --verify --strict "$app"
    [[ $(identifier "$app") == "$identity" ]] || exit 8
fi
needs_privilege=false
ancestor="$applications"
while [[ ! -e "$ancestor" ]]; do ancestor=$(dirname "$ancestor"); done
[[ -w "$ancestor" ]] || needs_privilege=true
install_command() { if [[ "$needs_privilege" == true ]]; then sudo "$@"; else "$@"; fi; }
if [[ "$needs_privilege" == true ]]; then sudo -v; fi
install_command mkdir -p "$applications"
stage=$(install_command mktemp -d "$applications/.mop-install.XXXXXXXX")
installed=false
published=false
cleanup() {
    if [[ "$installed" == false ]]; then
        if [[ "$published" == true ]]; then install_command rm -rf "$app"; fi
        if [[ -d "$stage/previous.app" ]]; then install_command mv "$stage/previous.app" "$app"; fi
    fi
    install_command rm -rf "$stage"
}
trap cleanup EXIT
install_command chmod 755 "$stage"
install_command cp -R "$source_app" "$stage/2ndPass.app"
install_command chmod -R a+rX "$stage/2ndPass.app"
codesign --verify --strict "$stage/2ndPass.app"
if [[ -e "$app" ]]; then install_command mv "$app" "$stage/previous.app"; fi
install_command mv "$stage/2ndPass.app" "$app"
published=true
codesign --verify --strict "$app"
installed=true
echo "Installed application: $app"
echo 'Install developer tools separately with scripts/install-cli.sh.'
