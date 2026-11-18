#!/usr/bin/env bash
# Run from a workstation: ship scripts/, config/, and lua/ as they are in the workspace to a server over ssh, then run the installer there.
# The server needs no access to this repo, and once the WAF is installed it runs update-*.sh, which refuses rather than rotating a secret it cannot read.
# Usage: scripts/deploy.sh user@host
set -euo pipefail

target="${1:?usage: $0 user@host}"
ROOT="${ROOT:-}"
dest="$ROOT/opt/nginx-waf"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source-path=SCRIPTDIR source=lib/log.sh
source scripts/lib/log.sh

# Both steps share one ssh connection, so a password login asks for the ssh password only once.
ssh_opts=(-o ControlMaster=auto -o "ControlPath=${TMPDIR:-/tmp}/nginx-waf-ssh-%C" -o ControlPersist=60)
trap 'ssh "${ssh_opts[@]}" -O exit "$target" >/dev/null 2>&1 || true' EXIT

info "Deploying scripts/, config/, and lua/ to $target:$dest"
info "Connecting to $target over ssh; type the ssh password of the remote user if ssh asks for it"
tmp="$(tar -cf - scripts config lua | ssh "${ssh_opts[@]}" "$target" 'd="$(mktemp -d)" && tar -x -C "$d" && echo "$d"')"
info "Uploaded the files to $target:$tmp"

info "Running the installer as root on $target; type the sudo password of the remote user if sudo asks for it"
# A fresh copy drops files deleted from the repo, and cp (not mv) gives them the destination's SELinux label.
ssh "${ssh_opts[@]}" -t "$target" "sudo -p '[sudo] password for %u on %h: ' sh -c '
set -e
info() { printf \"[%s] INFO: %s\\n\" \"\$(date +%H:%M:%S)\" \"\$*\"; }
info \"Copying the files to $dest\"
rm -rf $dest/scripts $dest/config $dest/lua
mkdir -p $dest
cp -r $tmp/scripts $tmp/config $tmp/lua $dest/
chown -R root:root $dest
rm -rf $tmp
if grep -qx ID=ubuntu $ROOT/etc/os-release; then p=deb; else p=rpm; fi
if [ -f $ROOT/etc/nginx/lua/waf-local-overrides.lua ]; then s=update; else s=install; fi
info \"Running \$s-\$p.sh\"
$dest/scripts/\$s-\$p.sh
'"
info "Deploy to $target finished"
