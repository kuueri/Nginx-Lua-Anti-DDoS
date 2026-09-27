#!/usr/bin/env bash
# Update Nginx-Lua-Anti-DDoS on Ubuntu: re-sync waf.lua with upstream and reapply config/.
# Requires an existing nginx with the Lua module (libnginx-mod-http-lua) and a prior run of install-ubuntu.sh.
# apt keeps nginx and libnginx-mod-http-lua on the same ABI, so unlike RPM no module rebuild is needed.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

grep -qx 'ID=ubuntu' "$ROOT/etc/os-release" || die "this script supports Ubuntu only"
sync_waf
