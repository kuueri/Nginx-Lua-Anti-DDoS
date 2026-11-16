# shellcheck shell=bash
# Shared by update-deb.sh and update-rpm.sh: logging, a pid-safe nginx -t, the Lua module build, and the WAF file sync.
# Sourcing it also checks for root and nginx, so callers stop before touching anything.
# ROOT prefixes every system path so tests can run the scripts against a scratch tree.

CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../config" && pwd)"
ROOT="${ROOT:-}"
NGINX_BIN="${NGINX_BIN:-nginx}"
# The fork's own copy of upstream, pinned by the last reviewed merge: upstream changes several times a week, and nginx -t never compiles waf.lua, so a breaking change would go live unseen.
# To move on, read upstream's precompile_waf_*_table changes, mirror them in tests/test-rules.lua, and merge the upstream commit once that test passes.
URL="${URL:-file://${CONFIG_DIR%/config}/lua/anti_ddos_challenge.lua}"
PID_FILE="$ROOT/run/nginx.pid"
BACKUP_DIR="$ROOT/var/backups/nginx-waf/$(date +%Y%m%d%H%M%S)"
PLACEHOLDER_SECRET="CHANGE_ME_TO_LONG_RANDOM_SECRET"
WAF_FILE="etc/nginx/lua/waf.lua"
OVERRIDES_FILE="etc/nginx/lua/waf-local-overrides.lua"
BAN_FILE="etc/nginx/lua/waf-ban.lua"
HTTP_CONF="etc/nginx/conf.d/waf.conf"
FILES=("$WAF_FILE" "$OVERRIDES_FILE" "$BAN_FILE" "$HTTP_CONF")
WORK_DIR=""

log() {
	printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

die() {
	log "ERROR: $*"
	exit 1
}

# Copy preserving mode, creating the destination's parent directories.
copy() {
	mkdir -p "$(dirname "$2")"
	cp -p -- "$1" "$2"
}

# `nginx -t` creates an empty pid file when nginx is stopped.
# Created from a root shell it lacks the httpd_var_run_t label, so on SELinux hosts the systemd-run nginx (httpd_t) gets "open() /run/nginx.pid failed (13: Permission denied)" and the start times out.
# Removing the empty file lets nginx create a correctly labeled one on start.
# Pass -T to also print the loaded config.
nginx_test() {
	local rc=0
	"$NGINX_BIN" "${1:--t}" || rc=$?
	[ -s "$PID_FILE" ] || rm -f -- "$PID_FILE"
	return "$rc"
}

restore_files() {
	local f
	for f in "${FILES[@]}"; do
		if [ -f "$BACKUP_DIR/$f" ]; then
			copy "$BACKUP_DIR/$f" "$ROOT/$f"
		else
			rm -f -- "$ROOT/$f"
		fi
	done
}

# nginx -V gives the paths even while the config fails, which nginx -T cannot.
nginx_build_opt() {
	"$NGINX_BIN" -V 2>&1 | sed -n "s/.*--$1=\([^ ]*\).*/\1/p"
}

modules_path() {
	local p
	p="$(nginx_build_opt modules-path)"
	echo "${p:-/etc/nginx/modules}"
}

main_conf_path() {
	local p prefix
	p="$(nginx_build_opt conf-path)"
	prefix="$(nginx_build_opt prefix)"
	echo "${p:-${prefix:-/usr/local/nginx}/conf/nginx.conf}"
}

# True while nginx cannot run Lua: its config fails on a Lua directive, or it passes without loading the Lua module.
# The output is captured before grep -q reads it: grep -q exits on the first match, and under pipefail the SIGPIPE to nginx would turn a found module into a missing one.
lua_module_missing() {
	local out dump build
	if out="$(nginx_test 2>&1)"; then
		dump="$(nginx_test -T 2>/dev/null)" || true
		build="$("$NGINX_BIN" -V 2>&1)" || true
		! grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_lua_module\.so;' <<<"$dump" &&
			! grep -qE -- '--add-module=[^ ]*(lua-nginx-module|ngx_lua)' <<<"$build"
	else
		grep -qF 'unknown directive "lua_' <<<"$out"
	fi
}

# Load the ndk and lua modules from $1 at the top of the main config, and with $2 also set lua_package_path in its http block.
# nginx.conf goes back as it was when nginx -t then fails.
load_lua_module() {
	local conf backup
	conf="$(main_conf_path)"
	backup="$BACKUP_DIR/nginx.conf.before-lua"
	log "Loading the Lua module from $1 in $conf"
	install -d -m 0700 "$BACKUP_DIR"
	copy "$conf" "$backup"
	sed -i -e "1i load_module $1/ndk_http_module.so;" -e "1i load_module $1/ngx_http_lua_module.so;" "$conf"
	if [ -n "${2:-}" ] && ! grep -q 'lua_package_path' "$conf"; then
		sed -i -E "0,/^[[:space:]]*http[[:space:]]*\{/s##&\n    lua_package_path \"$2\";#" "$conf"
	fi
	if ! nginx_test; then
		copy "$backup" "$conf"
		die "nginx -t fails with the Lua module loaded; restored $conf"
	fi
}

# Build tree for the source-built ndk/lua modules; distro packages for them are missing or stale (Ubuntu 24.04 dropped libnginx-mod-http-lua).
# A root-owned build tree in /usr/local/src wins, because only such a tree is safe for the root package-manager hook to build from.
# An older manual build in the sudo user's home is still used; a first build goes to /usr/local/src.
if [ -z "${BUILD_DIR:-}" ]; then
	_BUILD_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
	BUILD_DIR="${_BUILD_HOME:-$HOME}/build/nginx-lua"
	if [ -d /usr/local/src/nginx-lua ] || [ ! -d "$BUILD_DIR" ]; then BUILD_DIR=/usr/local/src/nginx-lua; fi
fi
LUAJIT_LIB="${LUAJIT_LIB:-/usr/local/luajit/lib}"
LUAJIT_INC="${LUAJIT_INC:-/usr/local/luajit/include/luajit-2.1}"
LUA_LIB_DIR="/usr/local/lib/lua"
SOURCES=(openresty/luajit2 vision5/ngx_devel_kit openresty/lua-nginx-module openresty/lua-resty-core openresty/lua-resty-lrucache)

# Builds only what is missing, so a rebuild after an nginx upgrade reuses everything else.
# The calling script defines install_build_deps for its package manager.
build_lua_module() {
	local ver src modules_path repo
	ver="$("$NGINX_BIN" -v 2>&1 | sed -n 's#.*nginx/##p')"
	[ -n "$ver" ] || die "cannot detect nginx version"
	log "Detected nginx $ver"

	install_build_deps
	install -d -m 0755 "$BUILD_DIR"
	for repo in "${SOURCES[@]}"; do
		if [ ! -d "$BUILD_DIR/${repo#*/}" ]; then
			log "Downloading $repo"
			git clone -q --depth=1 "https://github.com/$repo.git" "$BUILD_DIR/${repo#*/}"
		fi
	done

	if [ ! -e "$ROOT$LUAJIT_LIB/libluajit-5.1.so" ]; then
		log "Building LuaJIT into ${LUAJIT_LIB%/lib}"
		make -C "$BUILD_DIR/luajit2" -j"$(nproc)" PREFIX="${LUAJIT_LIB%/lib}"
		make -C "$BUILD_DIR/luajit2" install PREFIX="${LUAJIT_LIB%/lib}" DESTDIR="$ROOT"
	fi
	# lua-nginx-module refuses to start without resty.core.
	if [ ! -e "$ROOT$LUA_LIB_DIR/resty/core.lua" ]; then
		log "Installing lua-resty-core and lua-resty-lrucache into $LUA_LIB_DIR"
		make -C "$BUILD_DIR/lua-resty-core" install PREFIX=/usr/local DESTDIR="$ROOT"
		make -C "$BUILD_DIR/lua-resty-lrucache" install PREFIX=/usr/local DESTDIR="$ROOT"
	fi

	modules_path="$(modules_path)"
	mkdir -p "$modules_path"
	src="$BUILD_DIR/nginx-$ver"
	if [ ! -d "$src" ]; then
		log "Downloading nginx $ver source"
		wget -qO "$BUILD_DIR/nginx-$ver.tar.gz" "https://nginx.org/download/nginx-$ver.tar.gz"
		tar -xzf "$BUILD_DIR/nginx-$ver.tar.gz" -C "$BUILD_DIR"
	fi

	log "Building ndk/lua modules for nginx $ver"
	(
		cd "$src" || exit 1
		export LUAJIT_LIB LUAJIT_INC
		# A fresh objs/ keeps objects from an older configure, such as one without OpenSSL, out of the build.
		rm -rf objs
		log "Configuring build"
		# Without OpenSSL the lua module has no ngx.hmac_sha1, which upstream calls on every request.
		./configure \
			--with-compat \
			--with-http_ssl_module \
			--with-ld-opt="-Wl,-rpath,$LUAJIT_LIB" \
			--add-dynamic-module="$BUILD_DIR/ngx_devel_kit" \
			--add-dynamic-module="$BUILD_DIR/lua-nginx-module"
		log "Compiling modules"
		make modules
		log "Installing modules to $modules_path"
		install -m 0644 objs/ndk_http_module.so "$modules_path/"
		install -m 0644 objs/ngx_http_lua_module.so "$modules_path/"
		# Relabel SELinux: .so kebawa label home dari $BUILD_DIR, tanpa ini nginx (httpd_t) gagal load.
		if command -v restorecon >/dev/null; then
			log "Restoring SELinux context on modules"
			restorecon -F "$modules_path/ndk_http_module.so" "$modules_path/ngx_http_lua_module.so" ||
				log "WARN: restorecon failed (continuing)"
		fi
	)
	log "Module build complete"
}

# lua-nginx-module registers hmac_sha1 only when built with OpenSSL, so a module of ours without that name was built without it.
lua_module_without_ssl() {
	local so
	so="$(modules_path)/ngx_http_lua_module.so"
	[ -f "$so" ] && ! grep -qa 'hmac_sha1' "$so"
}

# ponytail: pakai `nginx -t` sebagai detektor mismatch — reuse cek versi bawaan nginx, gak perlu parse .so
ensure_modules() {
	local out
	log "Checking nginx config and module compatibility"
	out="$(nginx_test 2>&1)" || true
	# Rebuild only for "version NNNN instead of MMMM"; other errors (e.g. in waf.lua) are ignored here.
	if grep -qE 'version [0-9]+ instead of [0-9]+' <<<"$out"; then
		log "Module version mismatch detected; rebuilding"
		build_lua_module
		# A reload keeps the old nginx binary, which cannot load modules built for the upgraded one, so only a restart picks them up.
		nginx_test || die "nginx -t still fails after the module rebuild"
		log "Restarting nginx on the rebuilt modules"
		systemctl restart nginx
	elif lua_module_without_ssl; then
		log "The Lua module was built without OpenSSL and lacks ngx.hmac_sha1; rebuilding"
		build_lua_module
		nginx_test || die "nginx -t fails after the module rebuild"
		log "Restarting nginx on the rebuilt modules"
		systemctl restart nginx
	elif lua_module_missing; then
		log "nginx has no Lua module; building it from source in $BUILD_DIR"
		build_lua_module
		load_lua_module "$(modules_path)" "$LUA_LIB_DIR/?.lua;;"
	else
		log "Lua module present"
	fi
}

# Owner the root update hook trusts; tests run unprivileged and pass their own uid.
HOOK_UID="${HOOK_UID:-0}"

# The hook runs this tree as root, so any account that can write to it, or to a parent directory, would gain root on the next nginx upgrade.
# Every entry must belong to HOOK_UID and not be group- or world-writable; parents may also belong to root, and sticky ones such as /tmp may be world-writable.
writable_by_root_only() {
	local p
	p="$(realpath -e -- "$1" 2>/dev/null)" || return 1
	[ -z "$(find "$p" \( ! -uid "$HOOK_UID" -o \( ! -type l -perm /022 \) \) -print -quit)" ] || return 1
	while [ "$p" != / ]; do
		p="$(dirname -- "$p")"
		[ -z "$(find "$p" -maxdepth 0 \( \( ! -uid 0 ! -uid "$HOOK_UID" \) -o \( -perm /022 ! -perm -1000 \) \) -print)" ] || return 1
	done
}

# True when the package-manager hook may run the repo copy at $1 and BUILD_DIR as root.
hook_is_safe() {
	writable_by_root_only "$1" && writable_by_root_only "$BUILD_DIR" && return 0
	log "WARN: not installing the update hook, because it would run $1 and $BUILD_DIR as root; both, with every parent, must be owned by root and not group- or world-writable (e.g. BUILD_DIR=/usr/local/src/nginx-lua)"
	return 1
}

# Download upstream waf.lua, reapply config/, and reload nginx only when a file changed.
# A failed nginx -t puts every file back.
sync_waf() {
	local stage secret f conf main_conf changed=0

	WORK_DIR="$(mktemp -d)"
	trap 'rm -rf -- "$WORK_DIR"' EXIT
	stage="$WORK_DIR/stage"

	log "Downloading upstream WAF"
	mkdir -p "$stage/etc/nginx/lua" "$stage/etc/nginx/conf.d"
	curl -fsSL "$URL" -o "$stage/$WAF_FILE"
	cp -- "$CONFIG_DIR/waf-local-overrides.lua" "$stage/$OVERRIDES_FILE"
	cp -- "$CONFIG_DIR/waf-ban.lua" "$stage/$BAN_FILE"
	cp -- "$CONFIG_DIR/nginx-waf.conf" "$stage/$HTTP_CONF"

	# The installed secret wins, so visitors' auth cookies survive updates.
	# WAF_SECRET is only the fallback the install scripts pass on the first install.
	if grep -q "$PLACEHOLDER_SECRET" "$stage/$OVERRIDES_FILE"; then
		secret="$(sed -n 's/^localized_global\.secret = "\(.*\)"$/\1/p' "$ROOT/$OVERRIDES_FILE" 2>/dev/null || true)"
		if [ -z "$secret" ] || [ "$secret" = "$PLACEHOLDER_SECRET" ]; then
			secret="${WAF_SECRET:-}"
		fi
		[ -n "$secret" ] || die "WAF is not installed yet; run install-deb.sh or install-rpm.sh first"
		# Escape sed's replacement metacharacters so a hand-set secret from a manual setup carries over verbatim.
		sed -i "s/$PLACEHOLDER_SECRET/$(printf '%s' "$secret" | sed 's/[\/&]/\\&/g')/" "$stage/$OVERRIDES_FILE"
	fi
	# LuaJIT's JIT needs executable memory, which SELinux denies nginx while httpd_execmem is off, and every worker request then aborts with
	# "Lua VM crashed, reason: runtime code generation failed". jit.off() in init_by_lua runs in the master before the workers fork, so it covers them all.
	# The check runs here as unconfined root, because nginx's own domain may not read the SELinux booleans.
	if [ "$(getenforce 2>/dev/null)" = Enforcing ] && getsebool httpd_execmem 2>/dev/null | grep -q -- '--> off$'; then
		log "SELinux denies nginx executable memory (httpd_execmem off); turning the LuaJIT JIT off"
		printf '\njit.off()\n' >>"$stage/$OVERRIDES_FILE"
	fi
	# The overrides file holds the secret; only the nginx master (root) reads it via init_by_lua_file.
	chmod 0600 "$stage/$OVERRIDES_FILE"
	# Workers load waf.lua as the unprivileged nginx user on their first request.
	chmod 0644 "$stage/$WAF_FILE" "$stage/$BAN_FILE" "$stage/$HTTP_CONF"

	for f in "${FILES[@]}"; do
		cmp -s "$stage/$f" "$ROOT/$f" || changed=1
	done
	if [ "$changed" -eq 0 ]; then
		log "WAF already up to date; nothing to do"
		return 0
	fi

	log "Backing up current files to $BACKUP_DIR"
	install -d -m 0700 "$BACKUP_DIR"
	for f in "${FILES[@]}"; do
		if [ -f "$ROOT/$f" ]; then
			copy "$ROOT/$f" "$BACKUP_DIR/$f"
		fi
	done

	log "Installing WAF files"
	for f in "${FILES[@]}"; do
		copy "$stage/$f" "$ROOT/$f"
	done

	log "Testing nginx config"
	if ! conf="$(nginx_test -T)"; then
		restore_files
		die "nginx -t failed; restored previous files from $BACKUP_DIR"
	fi
	# Without waf.conf nginx -t still passes, but upstream then runs on its public default secret and lacks the antiddos shared dict it stores state in.
	# So when nginx.conf has no conf.d include, the include for waf.conf goes into its http block.
	# The file header of nginx -T is the check, because a manual setup can load the overrides from nginx.conf itself while waf.conf, with access_by_lua_file, stays unloaded.
	if ! grep -qxF "# configuration file $ROOT/$HTTP_CONF:" <<<"$conf"; then
		main_conf="$(main_conf_path)"
		if [ ! -f "$main_conf" ]; then
			restore_files
			die "cannot find the main nginx config at $main_conf; restored previous files from $BACKUP_DIR"
		fi
		log "Adding 'include /$HTTP_CONF;' to the http block of $main_conf"
		copy "$main_conf" "$BACKUP_DIR/nginx.conf"
		# A manual setup may hold waf.conf's directives inline, and nginx -t fails on a second lua_shared_dict, so the include replaces them.
		sed -i -E '/^[[:space:]]*(lua_shared_dict[[:space:]]+(antiddos|antiddos_blocked|ddos_counter|jspuzzle_tracker|waf_strikes)[[:space:]]|init_by_lua_file[[:space:]]+\/etc\/nginx\/lua\/waf-local-overrides\.lua;|(access|rewrite|log)_by_lua_file[[:space:]]+\/etc\/nginx\/lua\/waf(-ban)?\.lua;)/d' "$main_conf"
		# After lua_package_path when the module setup added one, so the Lua path stays first in the http block.
		if grep -qE '^[[:space:]]*lua_package_path[[:space:]]' "$main_conf"; then
			sed -i -E "0,/^[[:space:]]*lua_package_path[[:space:]].*$/s##&\n    include /$HTTP_CONF;#" "$main_conf"
		else
			sed -i -E "0,/^[[:space:]]*http[[:space:]]*\{/s##&\n    include /$HTTP_CONF;#" "$main_conf"
		fi
		if ! conf="$(nginx_test -T)" || ! grep -qxF "# configuration file $ROOT/$HTTP_CONF:" <<<"$conf"; then
			copy "$BACKUP_DIR/nginx.conf" "$main_conf"
			restore_files
			die "cannot make nginx load /$HTTP_CONF from the http block of $main_conf; restored previous files from $BACKUP_DIR"
		fi
	fi

	log "Reloading nginx"
	systemctl reload-or-restart nginx
	log "WAF files installed; previous versions (if any) are in $BACKUP_DIR"
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v "$NGINX_BIN" >/dev/null || die "nginx not found; install nginx first"
