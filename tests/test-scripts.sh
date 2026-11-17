#!/usr/bin/env bash
# Run the Ubuntu and RPM install/update scripts against scratch roots with stubbed system commands.
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts"
T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT
platform=""
R=""

fail() {
	echo "FAIL [$platform]: $*" >&2
	exit 1
}

mkdir -p "$T/bin"
tee "$T/bin/id" >/dev/null <<'EOF'
#!/bin/sh
echo 0
EOF
# Like real nginx, -t and -T leave an empty pid file behind when nginx is stopped, and -T prints the loaded config.
# NGINX_NO_CONFD stands for an nginx.conf without the conf.d include, so only an explicit waf.conf include loads it.
# $ROOT/mismatch stands for modules built for an older nginx, until the make stub "rebuilds" them.
# Without a load_module line for the Lua module in nginx.conf, a loaded waf.conf fails like real nginx does.
tee "$T/bin/nginx" >/dev/null <<'EOF'
#!/bin/sh
c="$ROOT/etc/nginx/nginx.conf"
case "$1" in
-v) echo "nginx version: nginx/1.2.3" >&2; exit 0 ;;
-V) echo "configure arguments: --prefix=/etc/nginx --conf-path=$c --modules-path=$ROOT/modules" >&2; exit 0 ;;
esac
mkdir -p "$ROOT/run"; : >>"$ROOT/run/nginx.pid"
if [ -e "$ROOT/mismatch" ]; then echo 'nginx: [emerg] module "ngx_http_lua_module.so" version 1002002 instead of 1002003' >&2; exit 1; fi
[ -z "$NGINX_FAIL" ] || exit 1
waf=
if [ -e "$ROOT/etc/nginx/conf.d/waf.conf" ] && { [ -z "$NGINX_NO_CONFD" ] || grep -qF 'include /etc/nginx/conf.d/waf.conf;' "$c" 2>/dev/null; }; then waf=1; fi
if [ -n "$waf" ] && ! grep -q 'ngx_http_lua_module.so;' "$c" 2>/dev/null; then
	echo 'nginx: [emerg] unknown directive "lua_shared_dict" in /etc/nginx/conf.d/waf.conf:1' >&2; exit 1
fi
if [ -n "$waf" ] && grep -qE '^[[:space:]]*lua_shared_dict antiddos ' "$c" 2>/dev/null; then
	echo "nginx: [emerg] lua_shared_dict \"antiddos\" is already defined as \"antiddos\" in $c" >&2; exit 1
fi
[ "$1" = -T ] || exit 0
echo "# configuration file $c:"; cat "$c" 2>/dev/null
if [ -n "$waf" ]; then
	for f in "$ROOT"/etc/nginx/conf.d/*.conf; do echo "# configuration file $f:"; cat "$f"; done
fi
EOF
tee "$T/bin/systemctl" >/dev/null <<'EOF'
#!/bin/sh
echo "$*" >>"$ROOT/systemctl.log"
EOF
tee "$T/bin/make" >/dev/null <<'EOF'
#!/bin/sh
rm -f "$ROOT/mismatch"
EOF
tee "$T/bin/dpkg-query" >/dev/null <<'EOF'
#!/bin/sh
echo 'install ok installed'
EOF
tee "$T/bin/git" >/dev/null <<'EOF'
#!/bin/sh
for dir; do :; done
mkdir -p "$dir"
EOF
# rpm and dpkg-query report every package as installed, so the test never reaches the real dnf or apt; restorecon must not relabel scratch files.
printf '#!/bin/sh\n' | tee "$T/bin/rpm" "$T/bin/restorecon" >/dev/null
# SE_MODE and SE_EXECMEM stand for the host's SELinux mode and httpd_execmem boolean, so the host running the tests does not leak in.
tee "$T/bin/getenforce" >/dev/null <<'EOF'
#!/bin/sh
echo "${SE_MODE:-Disabled}"
EOF
tee "$T/bin/getsebool" >/dev/null <<'EOF'
#!/bin/sh
echo "httpd_execmem --> ${SE_EXECMEM:-on}"
EOF
chmod +x "$T/bin/getenforce" "$T/bin/getsebool"
chmod +x "$T"/bin/*

# A first build finds the nginx source already unpacked, so it never downloads it.
# The configure stub writes the modules itself, and only a build with OpenSSL gets the hmac_sha1 name, as in the real lua module.
tee "$T/configure" >/dev/null <<'EOF'
#!/bin/sh
mkdir -p objs
: >objs/ndk_http_module.so
case " $* " in *" --with-http_ssl_module "*) echo hmac_sha1 ;; esac >objs/ngx_http_lua_module.so
EOF
chmod +x "$T/configure"
mkdir -p "$T/build/nginx-1.2.3"
cp "$T/configure" "$T/build/nginx-1.2.3/configure"

run() {
	PATH="$T/bin:$PATH" ROOT="$R" URL="file://$T/upstream.lua" BUILD_DIR="${BUILD_DIR:-$T/build}" bash "$SCRIPTS/$1" 2>"$T/out.log"
}

secret() {
	sed -n 's/^localized_global\.secret = "\(.*\)"$/\1/p' "$R/etc/nginx/lua/waf-local-overrides.lua"
}

reloads() {
	wc -l <"$R/systemctl.log"
}

for platform in deb rpm; do
	R="$T/root-$platform"
	mkdir -p "$R/etc/nginx"
	printf 'events {}\nhttp {\n}\n' >"$R/etc/nginx/nginx.conf"
	touch "$R/systemctl.log"
	if [ "$platform" = deb ]; then
		echo 'ID=ubuntu' >"$R/etc/os-release"
	else
		printf 'ID="rocky"\nID_LIKE="rhel centos fedora"\n' >"$R/etc/os-release"
	fi
	printf -- '-- upstream v1\n' >"$T/upstream.lua"

	lm="load_module $R/modules/ndk_http_module.so;
load_module $R/modules/ngx_http_lua_module.so;"

	# Update before install refuses instead of installing without a secret.
	# It first gives the stock nginx a Lua module built from source, with load_module lines and lua_package_path in nginx.conf.
	if run "update-$platform.sh"; then fail "update ran before install"; fi
	grep -q 'run install-deb.sh or install-rpm.sh first' "$T/out.log" || fail "update did not point to the installer: $(cat "$T/out.log")"
	[ ! -e "$R/etc/nginx/lua/waf.lua" ] || fail "update installed files before install"
	[ -f "$R/modules/ngx_http_lua_module.so" ] || fail "Lua module was not built: $(cat "$T/out.log")"
	[ "$(head -n 2 "$R/etc/nginx/nginx.conf")" = "$lm" ] || fail "Lua module not loaded in nginx.conf: $(cat "$T/out.log" "$R/etc/nginx/nginx.conf")"
	grep -qF 'lua_package_path "/usr/local/lib/lua/?.lua;;";' "$R/etc/nginx/nginx.conf" || fail "lua_package_path not set"

	# Install generates a secret, installs upstream verbatim, reloads nginx, and leaves no empty pid file.
	run "install-$platform.sh" || fail "install exited non-zero: $(cat "$T/out.log")"
	s1="$(secret)"
	[[ "$s1" =~ ^[0-9a-f]{64}$ ]] || fail "secret not generated: '$s1'"
	cmp -s "$T/upstream.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua differs from upstream"
	[ "$(stat -c %a "$R/etc/nginx/lua/waf-local-overrides.lua")" = 600 ] || fail "overrides file is not 0600"
	[ ! -e "$R/run/nginx.pid" ] || fail "nginx -t left an empty pid file behind"
	[ "$(reloads)" -eq 1 ] || fail "install did not reload nginx once"
	cmp -s "${SCRIPTS%/scripts}/config/waf-stats.lua" "$R/etc/nginx/lua/waf-stats.lua" || fail "install did not install waf-stats.lua"
	grep -qx 'access_by_lua_file /etc/nginx/lua/waf.lua;' "$R/etc/nginx/conf.d/waf.conf" || fail "install did not turn the WAF on for every site"

	# Re-running install with no upstream change is a no-op and keeps the secret.
	run "install-$platform.sh" || fail "install rerun exited non-zero: $(cat "$T/out.log")"
	grep -q 'already up to date' "$T/out.log" || fail "install rerun did not report up to date"
	[ "$(secret)" = "$s1" ] || fail "install rerun rotated the secret"
	[ "$(reloads)" -eq 1 ] || fail "install rerun reloaded nginx"
	[ "$(grep -c 'ngx_http_lua_module.so;' "$R/etc/nginx/nginx.conf")" -eq 1 ] || fail "Lua module loaded twice"
	grep -q 'Lua module present' "$T/out.log" || fail "install rerun did not find the loaded Lua module"

	# An upstream change that fails nginx -t is rolled back.
	cp "$T/upstream.lua" "$T/upstream.v1.lua"
	echo '-- upstream v2' >>"$T/upstream.lua"
	if NGINX_FAIL=1 run "update-$platform.sh"; then fail "failed nginx -t did not abort the update"; fi
	cmp -s "$T/upstream.v1.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua was not rolled back"
	[ "$(reloads)" -eq 1 ] || fail "failed update reloaded nginx"

	# The same upstream change with a valid config is applied and keeps the secret.
	run "update-$platform.sh" || fail "update exited non-zero: $(cat "$T/out.log")"
	cmp -s "$T/upstream.lua" "$R/etc/nginx/lua/waf.lua" || fail "update did not install the new waf.lua"
	[ "$(secret)" = "$s1" ] || fail "update rotated the secret"
	[ "$(reloads)" -eq 2 ] || fail "update did not reload nginx"

	# An nginx.conf without the conf.d include gets one explicit waf.conf include in its http block, and a rerun adds no second one.
	echo '-- upstream v3' >>"$T/upstream.lua"
	NGINX_NO_CONFD=1 run "update-$platform.sh" || fail "update without the conf.d include exited non-zero: $(cat "$T/out.log")"
	cmp -s "$T/upstream.lua" "$R/etc/nginx/lua/waf.lua" || fail "update without the conf.d include did not install waf.lua"
	[ "$(grep -c 'include /etc/nginx/conf.d/waf.conf;' "$R/etc/nginx/nginx.conf")" -eq 1 ] || fail "waf.conf include not added to nginx.conf: $(cat "$R/etc/nginx/nginx.conf")"
	[ "$(grep -A1 'lua_package_path' "$R/etc/nginx/nginx.conf" | tail -n 1)" = '    include /etc/nginx/conf.d/waf.conf;' ] || fail "waf.conf include does not follow lua_package_path: $(cat "$R/etc/nginx/nginx.conf")"
	[ "$(reloads)" -eq 3 ] || fail "update with the added include did not reload nginx"
	echo '-- upstream v4' >>"$T/upstream.lua"
	NGINX_NO_CONFD=1 run "update-$platform.sh" || fail "rerun with the waf.conf include exited non-zero: $(cat "$T/out.log")"
	[ "$(grep -c 'include /etc/nginx/conf.d/waf.conf;' "$R/etc/nginx/nginx.conf")" -eq 1 ] || fail "waf.conf include added twice"

	# A manual setup with waf.conf's directives indented inline in nginx.conf, and waf.conf itself unloaded, gets them swapped for the include.
	printf '%s\nevents {}\nhttp {\n    lua_package_path "/usr/local/lib/lua/?.lua;;";\n    lua_shared_dict antiddos 70m;\n    lua_shared_dict jspuzzle_tracker 70m;\n    init_by_lua_file /etc/nginx/lua/waf-local-overrides.lua;\n    server {\n        access_by_lua_file /etc/nginx/lua/waf.lua;\n        listen 80;\n    }\n}\n' "$lm" >"$R/etc/nginx/nginx.conf"
	echo '-- upstream v4b' >>"$T/upstream.lua"
	NGINX_NO_CONFD=1 run "update-$platform.sh" || fail "update over inline WAF directives exited non-zero: $(cat "$T/out.log")"
	[ "$(grep -c 'include /etc/nginx/conf.d/waf.conf;' "$R/etc/nginx/nginx.conf")" -eq 1 ] || fail "waf.conf include not added over inline WAF directives: $(cat "$R/etc/nginx/nginx.conf")"
	! grep -qE 'lua_shared_dict|init_by_lua_file|access_by_lua_file' "$R/etc/nginx/nginx.conf" || fail "inline WAF directives left in nginx.conf: $(cat "$R/etc/nginx/nginx.conf")"
	grep -qF 'listen 80;' "$R/etc/nginx/nginx.conf" || fail "server block lost with the inline WAF directives"
	[ "$(reloads)" -eq 5 ] || fail "update over inline WAF directives did not reload nginx"

	# Without an http block the include has nowhere to go, so the update is rolled back and nginx.conf stays as it was.
	cp "$T/upstream.lua" "$T/upstream.v4.lua"
	echo '-- upstream v5' >>"$T/upstream.lua"
	printf '%s\nevents {}\n' "$lm" >"$R/etc/nginx/nginx.conf"
	if NGINX_NO_CONFD=1 run "update-$platform.sh"; then fail "update succeeded although nginx.conf has no http block"; fi
	grep -qF 'cannot make nginx load' "$T/out.log" || fail "update did not explain the failed include: $(cat "$T/out.log")"
	cmp -s "$T/upstream.v4.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua was not rolled back after the failed include"
	[ "$(cat "$R/etc/nginx/nginx.conf")" = "$lm"$'\nevents {}' ] || fail "nginx.conf changed although the include failed"
	[ "$(reloads)" -eq 5 ] || fail "update reloaded nginx without waf.conf loaded"
	printf '%s\nevents {}\nhttp {\n}\n' "$lm" >"$R/etc/nginx/nginx.conf"

	# Modules left behind by an nginx upgrade are rebuilt and picked up by a restart, and the package manager reruns the update after nginx upgrades.
	# The hook is only installed while the tree it runs as root is writable by its owner alone, so this runs a private copy owned by the test user.
	h="$T/hook-$platform"
	b="$h/build"
	mkdir -p "$b/nginx-1.2.3"
	cp -r "$SCRIPTS" "$SCRIPTS/../config" "$h/"
	cp "$T/configure" "$b/nginx-1.2.3/configure"
	touch "$R/mismatch"
	chmod -R go-w "$h"
	SCRIPTS="$h/scripts" HOOK_UID="$(id -u)" BUILD_DIR="$b" run "update-$platform.sh" || fail "update with stale modules exited non-zero: $(cat "$T/out.log")"
	[ ! -e "$R/mismatch" ] || fail "stale modules were not rebuilt"
	grep -qx 'restart nginx' "$R/systemctl.log" || fail "nginx was not restarted on the rebuilt modules"
	if [ "$platform" = rpm ]; then
		hook="$R/etc/dnf/plugins/post-transaction-actions.d/nginx-waf.action"
		want="nginx*:in:/usr/bin/env BUILD_DIR=$b $h/scripts/update-rpm.sh"
	else
		hook="$R/etc/apt/apt.conf.d/99nginx-waf"
		want="DPkg::Post-Invoke { \"/usr/bin/env BUILD_DIR=$b $h/scripts/update-deb.sh || true\"; };"
	fi
	grep -qxF "$want" "$hook" || fail "update hook missing or wrong: $(cat "$T/out.log" "$hook" 2>&1)"

	# A build tree that others can write to would hand them root, so the hook is removed instead.
	chmod g+w "$b/nginx-1.2.3/configure"
	SCRIPTS="$h/scripts" HOOK_UID="$(id -u)" BUILD_DIR="$b" run "update-$platform.sh" || fail "update with a writable build tree exited non-zero: $(cat "$T/out.log")"
	grep -q 'WARN: not installing the update hook' "$T/out.log" || fail "writable build tree did not block the update hook"
	[ ! -e "$hook" ] || fail "update hook kept although the build tree is group-writable"

	# A Lua module built without OpenSSL lacks ngx.hmac_sha1, which upstream calls on every request, so it is rebuilt with OpenSSL and nginx restarts.
	restarts="$(grep -cx 'restart nginx' "$R/systemctl.log")"
	: >"$R/modules/ngx_http_lua_module.so"
	run "update-$platform.sh" || fail "update with a Lua module without OpenSSL exited non-zero: $(cat "$T/out.log")"
	grep -q 'hmac_sha1' "$R/modules/ngx_http_lua_module.so" || fail "Lua module was not rebuilt with OpenSSL: $(cat "$T/out.log")"
	[ "$(grep -cx 'restart nginx' "$R/systemctl.log")" -eq $((restarts + 1)) ] || fail "nginx was not restarted on the module rebuilt with OpenSSL"
	run "update-$platform.sh" || fail "rerun after the OpenSSL rebuild exited non-zero: $(cat "$T/out.log")"
	grep -q 'Lua module present' "$T/out.log" || fail "a module with OpenSSL was rebuilt again"

	# SELinux with httpd_execmem off makes every LuaJIT trace crash the worker, so only such a host gets jit.off(), once, with its secret kept.
	s1="$(secret)"
	! grep -qx 'jit.off()' "$R/etc/nginx/lua/waf-local-overrides.lua" || fail "jit.off() installed without SELinux denying executable memory"
	SE_MODE=Enforcing SE_EXECMEM=off run "update-$platform.sh" || fail "update with httpd_execmem off exited non-zero: $(cat "$T/out.log")"
	[ "$(grep -cx 'jit.off()' "$R/etc/nginx/lua/waf-local-overrides.lua")" -eq 1 ] || fail "jit.off() not installed once while httpd_execmem is off"
	[ "$(secret)" = "$s1" ] || fail "turning the JIT off rotated the secret"
	SE_MODE=Enforcing SE_EXECMEM=off run "update-$platform.sh" || fail "rerun with httpd_execmem off exited non-zero: $(cat "$T/out.log")"
	[ "$(grep -cx 'jit.off()' "$R/etc/nginx/lua/waf-local-overrides.lua")" -eq 1 ] || fail "jit.off() added twice"
	SE_MODE=Enforcing SE_EXECMEM=on run "update-$platform.sh" || fail "update with httpd_execmem on exited non-zero: $(cat "$T/out.log")"
	! grep -qx 'jit.off()' "$R/etc/nginx/lua/waf-local-overrides.lua" || fail "jit.off() kept after httpd_execmem was turned on"
done

# A hand-set secret from a manual setup carries over verbatim, sed metacharacters included.
manual='a/b&c\\d'
printf 'localized_global.secret = "%s"\n' "$manual" >"$R/etc/nginx/lua/waf-local-overrides.lua"
run "update-$platform.sh" || fail "update with a hand-set secret exited non-zero: $(cat "$T/out.log")"
[ "$(secret)" = "$manual" ] || fail "hand-set secret not kept: '$(secret)'"

# deploy.sh ships the workspace scripts/, config/, and lua/ through a local ssh stub, replaces stale files, and installs.
platform=deploy
R="$T/root-deploy"
mkdir -p "$R/etc/nginx" "$R/opt/nginx-waf/config" "$T/repo"
echo 'ID=ubuntu' >"$R/etc/os-release"
printf 'events {}\nhttp {\n}\n' >"$R/etc/nginx/nginx.conf"
touch "$R/systemctl.log" "$R/opt/nginx-waf/config/stale"
tee "$T/bin/ssh" >/dev/null <<'EOF'
#!/bin/sh
for cmd; do :; done
exec sh -c "$cmd"
EOF
tee "$T/bin/sudo" >/dev/null <<'EOF'
#!/bin/sh
exec "$@"
EOF
printf '#!/bin/sh\n' >"$T/bin/chown"
chmod +x "$T/bin/ssh" "$T/bin/sudo" "$T/bin/chown"
cp -r "$SCRIPTS" "$SCRIPTS/../config" "$SCRIPTS/../lua" "$T/repo/"
deploy() {
	PATH="$T/bin:$PATH" ROOT="$R" URL="file://$T/upstream.lua" BUILD_DIR="$T/build" bash "$T/repo/scripts/deploy.sh" host 2>"$T/out.log"
}
deploy || fail "deploy exited non-zero: $(cat "$T/out.log")"
[ ! -e "$R/opt/nginx-waf/config/stale" ] || fail "deploy kept a file deleted from the repo"
cmp -s "$T/repo/config/nginx-waf.conf" "$R/opt/nginx-waf/config/nginx-waf.conf" || fail "deploy did not ship config/"
[[ "$(secret)" =~ ^[0-9a-f]{64}$ ]] || fail "deploy did not run the installer"
echo "localized_global.secret = 'unreadable'" >"$R/etc/nginx/lua/waf-local-overrides.lua"
if deploy; then fail "deploy rotated a secret it could not read"; fi
grep -q "'unreadable'" "$R/etc/nginx/lua/waf-local-overrides.lua" || fail "deploy overwrote an unreadable secret"

echo "PASS"
