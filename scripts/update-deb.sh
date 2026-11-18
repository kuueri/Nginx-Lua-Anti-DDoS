#!/usr/bin/env bash
# Update Nginx-Lua-Anti-DDoS on Ubuntu: re-sync waf.lua with upstream and reapply config/.
# Requires an existing nginx and a prior run of install-deb.sh.
# Ubuntu 24.04 no longer ships libnginx-mod-http-lua, so like update-rpm.sh it builds the ndk/lua modules from source when nginx lacks them or an nginx upgrade left them behind.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

install_build_deps() {
	local dep missing=()
	for dep in build-essential git wget tar libpcre2-dev zlib1g-dev libssl-dev; do
		dpkg-query -W -f='${Status}' "$dep" 2>/dev/null | grep -q 'install ok installed' || missing+=("$dep")
	done
	if [ "${#missing[@]}" -eq 0 ]; then
		info "All build dependencies are installed"
		return 0
	fi
	info "Installing build dependencies with apt-get: ${missing[*]}"
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
	printf 'DPkg::Post-Invoke { "/usr/bin/env BUILD_DIR=%s %s/update-deb.sh || true"; };\n' "$BUILD_DIR" "$scripts" >"$hook"
	info "Installed the update hook at $hook"
}

grep -qx 'ID=ubuntu' "$ROOT/etc/os-release" || die "this script supports Ubuntu only"
info "Starting WAF update on Ubuntu"
ensure_modules
sync_waf
install_update_hook
info "WAF update finished"
