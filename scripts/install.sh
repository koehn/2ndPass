#!/bin/bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
[[ $# -le 1 ]] || { echo 'Usage: scripts/install.sh [signed-Mop.app]' >&2; exit 2; }
source_app=${1:-"$PWD/dist/Mop.app"}
prefix=${MOP_INSTALL_ROOT:-"$HOME/.local"}
bin_dir="$prefix/bin"
lib_dir="$prefix/lib/mop"
target="$lib_dir/Mop.app/Contents/MacOS/mop"
link="$bin_dir/mop"
[[ -d "$source_app" && -f "$source_app/Contents/embedded.provisionprofile" && -f "$source_app/Contents/MacOS/mop" ]] || { echo 'Run scripts/package.sh first.' >&2; exit 7; }
codesign --verify --strict "$source_app"
"$source_app/Contents/MacOS/mop" device identity
source_share="$(dirname "$source_app")/share"
resources=(man/man1/mop.1 bash-completion/completions/mop zsh/site-functions/_mop fish/vendor_completions.d/mop.fish)
# Preflight every destination before replacing the executable or any resource.
for resource in "${resources[@]}"; do
    [[ -f "$source_share/$resource" ]] || { echo 'Packaged manpage/completions missing. Run scripts/package.sh first.' >&2; exit 7; }
    destination="$prefix/share/$resource"
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -L "$destination" && $(readlink "$destination") == "$lib_dir/share/$resource" ]] || {
            echo 'Refusing to replace an unrelated manpage or completion.' >&2; exit 7;
        }
    fi
    # Do not write through symlinks inside the private installation directory.
    relative="share/$resource"
    while [[ "$relative" != . ]]; do
        [[ ! -L "$lib_dir/$relative" ]] || exit 7
        relative=$(dirname "$relative")
    done
done
if [[ -e "$link" || -L "$link" ]]; then
    [[ -L "$link" ]] || { echo 'Refusing to replace an unrelated executable.' >&2; exit 7; }
    previous=$(readlink "$link")
    [[ "$previous" == "$target" || "$previous" == "$lib_dir/mop" || "$previous" == "$HOME/Applications/Mop.app/Contents/MacOS/mop" ]] || exit 7
fi
if [[ -e "$lib_dir" || -L "$lib_dir" ]]; then
    [[ ! -L "$lib_dir" && -f "$lib_dir/.mop-install" ]] || exit 7
    [[ $(cat "$lib_dir/.mop-install") == net.koehn.mop ]] || exit 7
fi
mkdir -p "$bin_dir" "$lib_dir"
for resource in "${resources[@]}"; do
    mkdir -p "$prefix/share/$(dirname "$resource")" "$lib_dir/share/$(dirname "$resource")"
done
chmod 700 "$lib_dir"
stage=$(mktemp -d "$lib_dir/.install.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
cp -R "$source_app" "$stage/Mop.app"
codesign --verify --strict "$stage/Mop.app"
for resource in "${resources[@]}"; do
    mkdir -p "$stage/share/$(dirname "$resource")"
    cp "$source_share/$resource" "$stage/share/$resource"
    chmod 644 "$stage/share/$resource"
done
if [[ -e "$lib_dir/Mop.app" || -L "$lib_dir/Mop.app" ]]; then
    [[ -d "$lib_dir/Mop.app" && ! -L "$lib_dir/Mop.app" ]] || exit 7
    mv "$lib_dir/Mop.app" "$stage/previous.app"
fi
mv "$stage/Mop.app" "$lib_dir/Mop.app"
for resource in "${resources[@]}"; do
    mv -f "$stage/share/$resource" "$lib_dir/share/$resource"
    ln -sfn "$lib_dir/share/$resource" "$prefix/share/$resource"
done
printf '%s\n' net.koehn.mop > "$lib_dir/.mop-install"
ln -sfn "$target" "$link"
echo "Installed $link. Add $bin_dir to PATH."
echo "Manpage: $prefix/share/man/man1/mop.1"
echo "Completions: $prefix/share/{bash-completion/completions,zsh/site-functions,fish/vendor_completions.d}"
echo 'See README.md for shell activation; no shell startup files were modified.'
