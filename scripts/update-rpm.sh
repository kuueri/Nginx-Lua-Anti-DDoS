#!/usr/bin/env bash
# Update Nginx-Lua-Anti-DDoS on RPM-based systems (Rocky, RHEL, AlmaLinux) whose ndk/lua dynamic modules are built from source.
# Requires an existing nginx with the Lua module and a prior run of install-rpm.sh.
# When an nginx upgrade leaves the modules on the old version they are rebuilt first, then lib/common.sh syncs the WAF files.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Rebuild module dipicu otomatis kalau versi module != versi nginx (mis. setelah dnf upgrade nginx).
# Di bawah sudo, $HOME = /root, jadi pakai home user asli (SUDO_USER) supaya cocok dgn lokasi build manual.
_BUILD_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
BUILD_DIR="${BUILD_DIR:-${_BUILD_HOME:-$HOME}/build/nginx-lua}"
LUAJIT_LIB="${LUAJIT_LIB:-/usr/local/luajit/lib}"
LUAJIT_INC="${LUAJIT_INC:-/usr/local/luajit/include/luajit-2.1}"

rebuild_modules() {
	local ver src modules_path
	ver="$("$NGINX_BIN" -v 2>&1 | sed -n 's#.*nginx/##p')"
	[ -n "$ver" ] || { log "ERROR: cannot detect nginx version"; exit 1; }
	log "Detected nginx $ver"

	if [ ! -d "$BUILD_DIR/ngx_devel_kit" ] || [ ! -d "$BUILD_DIR/lua-nginx-module" ]; then
		log "ERROR: module sources missing in $BUILD_DIR (ngx_devel_kit, lua-nginx-module)"
		exit 1
	fi

	modules_path="$("$NGINX_BIN" -V 2>&1 | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p')"
	modules_path="${modules_path:-/etc/nginx/modules}"

	src="$BUILD_DIR/nginx-$ver"
	if [ ! -d "$src" ]; then
		log "Downloading nginx $ver source"
		wget -qO "$BUILD_DIR/nginx-$ver.tar.gz" "https://nginx.org/download/nginx-$ver.tar.gz"
		tar -xzf "$BUILD_DIR/nginx-$ver.tar.gz" -C "$BUILD_DIR"
	fi

	log "Rebuilding ndk/lua modules for nginx $ver"
	(
		cd "$src"
		export LUAJIT_LIB LUAJIT_INC
		log "Configuring build"
		./configure \
			--with-compat \
			--with-ld-opt="-Wl,-rpath,$LUAJIT_LIB" \
			--add-dynamic-module="$BUILD_DIR/ngx_devel_kit" \
			--add-dynamic-module="$BUILD_DIR/lua-nginx-module"
		log "Compiling modules"
		make modules
		log "Installing modules to $modules_path"
		install -m 0644 objs/ndk_http_module.so     "$modules_path/"
		install -m 0644 objs/ngx_http_lua_module.so "$modules_path/"
		# Relabel SELinux: .so kebawa label home dari $BUILD_DIR, tanpa ini nginx (httpd_t) gagal load.
		if command -v restorecon >/dev/null; then
			log "Restoring SELinux context on modules"
			restorecon -F "$modules_path/ndk_http_module.so" "$modules_path/ngx_http_lua_module.so" \
				|| log "WARN: restorecon failed (continuing)"
		fi
	)
	log "Module rebuild complete"
}

# ponytail: pakai `nginx -t` sebagai detektor mismatch — reuse cek versi bawaan nginx, gak perlu parse .so
ensure_modules() {
	local out
	log "Checking nginx config and module compatibility"
	if out="$(nginx_test 2>&1)"; then
		log "Config OK; modules match nginx"
		return 0
	fi
	# Rebuild hanya untuk error "version NNNN instead of MMMM"; error lain (mis. waf.lua) diabaikan di sini.
	if grep -qE 'version [0-9]+ instead of [0-9]+' <<<"$out"; then
		log "Module version mismatch detected; rebuilding"
		rebuild_modules
	else
		log "nginx -t failed but not a module mismatch; leaving it to the WAF update step"
	fi
}

grep -qE '^ID(_LIKE)?=.*(rhel|fedora)' "$ROOT/etc/os-release" || die "this script supports RPM-based systems (RHEL family) only"
log "Starting WAF update"
ensure_modules
sync_waf
