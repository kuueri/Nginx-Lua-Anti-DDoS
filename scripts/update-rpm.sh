#!/usr/bin/env bash
# Update Nginx-Lua-Anti-DDoS on RPM-based systems (Rocky, RHEL, AlmaLinux), whose ndk/lua dynamic modules are built from source.
# Requires an existing nginx and a prior run of install-rpm.sh.
# When nginx has no Lua module, or an nginx upgrade left it on the old version, lib/common.sh builds it first, then syncs the WAF files.
# It also installs a dnf hook that reruns it after every nginx package upgrade.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

install_build_deps() {
	local dep missing=()
	for dep in gcc make git wget tar pcre2-devel zlib-devel openssl-devel; do
		rpm -q "$dep" >/dev/null 2>&1 || missing+=("$dep")
	done
	if [ "${#missing[@]}" -eq 0 ]; then
		info "All build dependencies are installed"
		return 0
	fi
	info "Installing build dependencies with dnf: ${missing[*]}"
	dnf install -y -q "${missing[@]}"
}

# dnf reruns this script right after any nginx package changes, so an upgrade never waits on a person to rebuild the modules.
# The hook runs as root without SUDO_USER, so it gets the resolved BUILD_DIR explicitly.
install_update_hook() {
	local plugin=python3-dnf-plugin-post-transaction-actions
	local action="$ROOT/etc/dnf/plugins/post-transaction-actions.d/nginx-waf.action"
	local scripts
	scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	if ! hook_is_safe "$(dirname "$scripts")"; then
		rm -f -- "$action"
		return 0
	fi
	if ! rpm -q "$plugin" >/dev/null 2>&1; then
		info "Installing $plugin for the update hook"
		if ! dnf install -y -q "$plugin"; then
			warn "cannot install $plugin; run update-rpm.sh by hand after every nginx upgrade"
			return 0
		fi
	fi
	mkdir -p "$(dirname "$action")"
	printf 'nginx*:in:/usr/bin/env BUILD_DIR=%s %s/update-rpm.sh\n' "$BUILD_DIR" "$scripts" >"$action"
	info "Installed the update hook at $action"
}

grep -qE '^ID(_LIKE)?=.*(rhel|fedora)' "$ROOT/etc/os-release" || die "this script supports RPM-based systems (RHEL family) only"
info "Starting WAF update on an RPM-based system"
ensure_modules
sync_waf
install_update_hook
info "WAF update finished"
