#!/usr/bin/env bash
# Run from a workstation: ship scripts/, config/, and lua/ as they are in the workspace to a server over ssh, then run the installer there.
# The server needs no access to this repo, and once the WAF is installed it runs update-*.sh, which refuses rather than rotating a secret it cannot read.
# Usage: scripts/deploy.sh user@host
set -euo pipefail

target="${1:?usage: $0 user@host}"
ROOT="${ROOT:-}"
dest="$ROOT/opt/nginx-waf"
cd "$(dirname "${BASH_SOURCE[0]}")/.."

tmp="$(tar -cf - scripts config lua | ssh "$target" 'd="$(mktemp -d)" && tar -x -C "$d" && echo "$d"')"

# A fresh copy drops files deleted from the repo, and cp (not mv) gives them the destination's SELinux label.
ssh -t "$target" "sudo sh -c '
set -e
rm -rf $dest/scripts $dest/config $dest/lua
mkdir -p $dest
cp -r $tmp/scripts $tmp/config $tmp/lua $dest/
chown -R root:root $dest
rm -rf $tmp
if grep -qx ID=ubuntu $ROOT/etc/os-release; then p=deb; else p=rpm; fi
if [ -f $ROOT/etc/nginx/lua/waf-local-overrides.lua ]; then s=update; else s=install; fi
$dest/scripts/\$s-\$p.sh
'"
