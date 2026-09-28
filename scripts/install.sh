#!/bin/bash
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
[[ $# -le 1 ]] || { echo 'Usage: scripts/install.sh [signed-2ndPass.app]' >&2; exit 2; }
source_app=${1:-"$PWD/dist/2ndPass.app"}
prefix=${MOP_INSTALL_ROOT:-/usr/local}
applications=${MOP_APPLICATIONS_DIR:-/Applications}
app="$applications/2ndPass.app"
bin_dir="$prefix/bin"
lib_dir="$prefix/lib/2ndpass"
target="$app/Contents/MacOS/2ndpass"
link="$bin_dir/2ndpass"
[[ -d "$source_app" && -f "$source_app/Contents/embedded.provisionprofile" && -f "$source_app/Contents/MacOS/2ndpass" ]] || { echo 'Run scripts/package.sh first.' >&2; exit 7; }
codesign --verify --strict "$source_app"
identity=$("$source_app/Contents/MacOS/2ndpass" device identity)
source_share="$(dirname "$source_app")/share"
resources=(man/man1/2ndpass.1 bash-completion/completions/2ndpass zsh/site-functions/_2ndpass fish/vendor_completions.d/2ndpass.fish)
# Refuse collisions before changing any installed file or requesting privileges.
if [[ -e "$app" || -L "$app" ]]; then
    [[ -d "$app" && ! -L "$app" && -x "$target" ]] || { echo 'Refusing to replace an unrelated application.' >&2; exit 7; }
    codesign --verify --strict "$app"
    [[ $("$target" device identity) == "$identity" ]] || { echo 'Installed app has a different signing identity.' >&2; exit 7; }
fi
for resource in "${resources[@]}"; do
    [[ -f "$source_share/$resource" ]] || { echo 'Packaged manpage/completions missing. Run scripts/package.sh first.' >&2; exit 7; }
    destination="$prefix/share/$resource"
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -L "$destination" && $(readlink "$destination") == "$lib_dir/share/$resource" ]] || {
            echo 'Refusing to replace an unrelated manpage or completion.' >&2; exit 7;
        }
    fi
    relative="share/$resource"
    while [[ "$relative" != . ]]; do
        [[ ! -L "$lib_dir/$relative" ]] || exit 7
        relative=$(dirname "$relative")
    done
done
if [[ -e "$link" || -L "$link" ]]; then
    [[ -L "$link" ]] || { echo 'Refusing to replace an unrelated executable.' >&2; exit 7; }
    previous=$(readlink "$link")
    [[ "$previous" == "$target" || "$previous" == "$lib_dir/2ndPass.app/Contents/MacOS/2ndpass" || "$previous" == "$lib_dir/2ndpass" || "$previous" == "$HOME/Applications/2ndPass.app/Contents/MacOS/2ndpass" ]] || exit 7
fi
if [[ -e "$lib_dir" || -L "$lib_dir" ]]; then
    [[ ! -L "$lib_dir" && -f "$lib_dir/.mop-install" ]] || exit 7
    [[ $(cat "$lib_dir/.mop-install") == net.koehn.mop ]] || exit 7
fi
# Authenticate as the invoking user; elevate only filesystem installation commands.
needs_privilege=false
install_command() {
    if [[ "$needs_privilege" == true ]]; then sudo "$@"; else "$@"; fi
}
for directory in "$applications" "$bin_dir" "$lib_dir" "$prefix/share"; do
    ancestor="$directory"
    while [[ ! -e "$ancestor" ]]; do ancestor=$(dirname "$ancestor"); done
    if [[ ! -w "$ancestor" ]]; then needs_privilege=true; break; fi
done
if [[ "$needs_privilege" == true ]]; then
    echo 'Administrator access is needed to install in /Applications and /usr/local.'
    sudo -v
fi
install_command mkdir -p "$applications" "$bin_dir" "$lib_dir"
install_command chmod 755 "$lib_dir"
printf '%s\n' net.koehn.mop | install_command tee "$lib_dir/.mop-install" >/dev/null
stage=$(install_command mktemp -d "$applications/.mop-install.XXXXXXXX")
installed=false
published=false
cleanup() {
    # Restore the previous app if publishing or validation failed.
    if [[ "$installed" == false ]]; then
        if [[ "$published" == true ]]; then install_command rm -rf "$app"; fi
        if [[ -d "$stage/previous.app" ]]; then install_command mv "$stage/previous.app" "$app"; fi
    fi
    install_command rm -rf "$stage"
}
trap cleanup EXIT
install_command chmod 755 "$stage"
install_command cp -R "$source_app" "$stage/2ndPass.app"
# Packaging uses a private umask; the installed app must be readable by all users.
install_command chmod -R a+rX "$stage/2ndPass.app"
codesign --verify --strict "$stage/2ndPass.app"
for resource in "${resources[@]}"; do
    install_command mkdir -p "$prefix/share/$(dirname "$resource")" "$lib_dir/share/$(dirname "$resource")"
    install_command install -m 644 "$source_share/$resource" "$lib_dir/share/$resource"
done
if [[ -e "$app" ]]; then install_command mv "$app" "$stage/previous.app"; fi
install_command mv "$stage/2ndPass.app" "$app"
published=true
codesign --verify --strict "$app"
[[ $("$target" device identity) == "$identity" ]]
for resource in "${resources[@]}"; do
    install_command ln -sfn "$lib_dir/share/$resource" "$prefix/share/$resource"
done
printf '%s\n' net.koehn.mop | install_command tee "$lib_dir/.mop-install" >/dev/null
install_command ln -sfn "$target" "$link"
"$link" device identity
installed=true
echo "Installed application: $app"
echo "Installed CLI: $link"
echo "Manpage: $prefix/share/man/man1/2ndpass.1"
echo "Completions: $prefix/share/{bash-completion/completions,zsh/site-functions,fish/vendor_completions.d}"
echo 'No shell startup files were modified. Ensure the CLI directory is on PATH.'
