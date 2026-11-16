#!/usr/bin/env bash
# Update Nginx-Lua-Anti-DDoS on Ubuntu: re-sync waf.lua with upstream and reapply config/.
# Requires an existing nginx and a prior run of install-ubuntu.sh.
# Ubuntu 24.04 no longer ships libnginx-mod-http-lua, so like update-rpm.sh it builds the ndk/lua modules from source when nginx lacks them or an nginx upgrade left them behind.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

install_build_deps() {
	local dep missing=()
	for dep in build-essential git wget tar libpcre2-dev zlib1g-dev libssl-dev; do
		dpkg-query -W -f='${Status}' "$dep" 2>/dev/null | grep -q 'install ok installed' || missing+=("$dep")
	done
	[ "${#missing[@]}" -gt 0 ] || return 0
	log "Installing build dependencies: ${missing[*]}"
	apt-get update -q
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}"
}

# apt has no per-package hook, so dpkg reruns this script after every package run.
# The run changes nothing unless an nginx upgrade left the modules behind or the WAF files differ.
# The hook runs as root without SUDO_USER, so it gets the resolved BUILD_DIR explicitly.
install_update_hook() {
	local hook="$ROOT/etc/apt/apt.conf.d/99nginx-waf"
	local scripts
	scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	if ! hook_is_safe "$(dirname "$scripts")"; then
		rm -f -- "$hook"
		return 0
	fi
	mkdir -p "$(dirname "$hook")"
	printf 'DPkg::Post-Invoke { "/usr/bin/env BUILD_DIR=%s %s/update-ubuntu.sh || true"; };\n' "$BUILD_DIR" "$scripts" >"$hook"
}

grep -qx 'ID=ubuntu' "$ROOT/etc/os-release" || die "this script supports Ubuntu only"
log "Starting WAF update"
ensure_modules
sync_waf
install_update_hook
