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
# NGINX_NO_CONFD leaves conf.d out of that config, and NGINX_SITE adds a site that runs the WAF.
# $ROOT/mismatch stands for modules built for an older nginx, until the make stub "rebuilds" them.
tee "$T/bin/nginx" >/dev/null <<'EOF'
#!/bin/sh
case "$1" in
-v) echo "nginx version: nginx/1.2.3" >&2; exit 0 ;;
-V) echo "configure arguments: --modules-path=$ROOT/modules" >&2; exit 0 ;;
esac
mkdir -p "$ROOT/run"; : >>"$ROOT/run/nginx.pid"
if [ -e "$ROOT/mismatch" ]; then echo 'nginx: [emerg] module "ngx_http_lua_module.so" version 1002002 instead of 1002003' >&2; exit 1; fi
[ -z "$NGINX_FAIL" ] || exit 1
[ "$1" = -T ] || exit 0
if [ -z "$NGINX_NO_CONFD" ]; then
	for f in "$ROOT"/etc/nginx/conf.d/*.conf; do echo "# configuration file $f:"; cat "$f"; done
fi
if [ -n "$NGINX_SITE" ]; then printf '    access_by_lua_file /etc/nginx/lua/waf.lua;\n'; fi
EOF
tee "$T/bin/systemctl" >/dev/null <<'EOF'
#!/bin/sh
echo "$*" >>"$ROOT/systemctl.log"
EOF
tee "$T/bin/make" >/dev/null <<'EOF'
#!/bin/sh
rm -f "$ROOT/mismatch"
EOF
# rpm reports the dnf plugin as installed, so the test never reaches the real dnf; restorecon must not relabel scratch files.
printf '#!/bin/sh\n' | tee "$T/bin/rpm" "$T/bin/restorecon" >/dev/null
chmod +x "$T"/bin/*

run() {
	PATH="$T/bin:$PATH" ROOT="$R" URL="file://$T/upstream.lua" bash "$SCRIPTS/$1" 2>"$T/out.log"
}

secret() {
	sed -n 's/^localized_global\.secret = "\(.*\)"$/\1/p' "$R/etc/nginx/lua/waf-local-overrides.lua"
}

reloads() {
	wc -l <"$R/systemctl.log"
}

for platform in ubuntu rpm; do
	R="$T/root-$platform"
	mkdir -p "$R/etc"
	touch "$R/systemctl.log"
	if [ "$platform" = ubuntu ]; then
		echo 'ID=ubuntu' >"$R/etc/os-release"
	else
		printf 'ID="rocky"\nID_LIKE="rhel centos fedora"\n' >"$R/etc/os-release"
	fi
	printf -- '-- upstream v1\n' >"$T/upstream.lua"

	# Update before install refuses instead of installing without a secret.
	if run "update-$platform.sh"; then fail "update ran before install"; fi
	grep -q 'run install-ubuntu.sh or install-rpm.sh first' "$T/out.log" || fail "update did not point to the installer: $(cat "$T/out.log")"
	[ ! -e "$R/etc/nginx/lua/waf.lua" ] || fail "update installed files before install"

	# Install generates a secret, installs upstream verbatim, reloads nginx, and leaves no empty pid file.
	run "install-$platform.sh" || fail "install exited non-zero: $(cat "$T/out.log")"
	s1="$(secret)"
	[[ "$s1" =~ ^[0-9a-f]{64}$ ]] || fail "secret not generated: '$s1'"
	cmp -s "$T/upstream.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua differs from upstream"
	[ "$(stat -c %a "$R/etc/nginx/lua/waf-local-overrides.lua")" = 600 ] || fail "overrides file is not 0600"
	[ ! -e "$R/run/nginx.pid" ] || fail "nginx -t left an empty pid file behind"
	[ "$(reloads)" -eq 1 ] || fail "install did not reload nginx once"
	grep -q 'WARN: no site runs the WAF yet' "$T/out.log" || fail "install did not warn that no site runs the WAF"

	# Re-running install with no upstream change is a no-op and keeps the secret.
	run "install-$platform.sh" || fail "install rerun exited non-zero: $(cat "$T/out.log")"
	grep -q 'already up to date' "$T/out.log" || fail "install rerun did not report up to date"
	[ "$(secret)" = "$s1" ] || fail "install rerun rotated the secret"
	[ "$(reloads)" -eq 1 ] || fail "install rerun reloaded nginx"

	# An upstream change that fails nginx -t is rolled back.
	cp "$T/upstream.lua" "$T/upstream.v1.lua"
	echo '-- upstream v2' >>"$T/upstream.lua"
	if NGINX_FAIL=1 run "update-$platform.sh"; then fail "failed nginx -t did not abort the update"; fi
	cmp -s "$T/upstream.v1.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua was not rolled back"
	[ "$(reloads)" -eq 1 ] || fail "failed update reloaded nginx"

	# The same upstream change with a valid config is applied, keeps the secret, and does not warn once a site runs the WAF.
	NGINX_SITE=1 run "update-$platform.sh" || fail "update exited non-zero: $(cat "$T/out.log")"
	cmp -s "$T/upstream.lua" "$R/etc/nginx/lua/waf.lua" || fail "update did not install the new waf.lua"
	[ "$(secret)" = "$s1" ] || fail "update rotated the secret"
	[ "$(reloads)" -eq 2 ] || fail "update did not reload nginx"
	! grep -q 'WARN: no site runs the WAF yet' "$T/out.log" || fail "update warned although a site runs the WAF"

	# An nginx.conf that does not include conf.d passes nginx -t without loading waf.conf, so the update is rolled back.
	cp "$T/upstream.lua" "$T/upstream.v2.lua"
	echo '-- upstream v3' >>"$T/upstream.lua"
	if NGINX_NO_CONFD=1 run "update-$platform.sh"; then fail "update succeeded although nginx does not load waf.conf"; fi
	grep -qF "add 'include /etc/nginx/conf.d/*.conf;'" "$T/out.log" || fail "update did not explain the missing conf.d include: $(cat "$T/out.log")"
	cmp -s "$T/upstream.v2.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua was not rolled back after the conf.d check"
	[ "$(reloads)" -eq 2 ] || fail "update reloaded nginx without waf.conf loaded"

	# RPM: modules left behind by an nginx upgrade are rebuilt and picked up by a restart, and dnf reruns the update after every nginx upgrade.
	# The hook is only installed while the tree it runs as root is writable by its owner alone, so this runs a private copy owned by the test user.
	if [ "$platform" = rpm ]; then
		h="$T/hook"
		b="$h/build"
		mkdir -p "$b/ngx_devel_kit" "$b/lua-nginx-module" "$b/nginx-1.2.3/objs" "$R/modules"
		cp -r "$SCRIPTS" "$SCRIPTS/../config" "$h/"
		touch "$b/nginx-1.2.3/objs/ndk_http_module.so" "$b/nginx-1.2.3/objs/ngx_http_lua_module.so" "$R/mismatch"
		printf '#!/bin/sh\n' >"$b/nginx-1.2.3/configure"
		chmod -R go-w "$h"
		chmod +x "$b/nginx-1.2.3/configure"
		SCRIPTS="$h/scripts" HOOK_UID="$(id -u)" BUILD_DIR="$b" run update-rpm.sh || fail "update with stale modules exited non-zero: $(cat "$T/out.log")"
		[ -f "$R/modules/ngx_http_lua_module.so" ] || fail "rebuilt modules were not installed"
		grep -qx 'restart nginx' "$R/systemctl.log" || fail "nginx was not restarted on the rebuilt modules"
		action="$R/etc/dnf/plugins/post-transaction-actions.d/nginx-waf.action"
		grep -qxF "nginx*:in:/usr/bin/env BUILD_DIR=$b $h/scripts/update-rpm.sh" "$action" || fail "dnf hook missing or wrong: $(cat "$T/out.log" "$action" 2>&1)"

		# A build tree that others can write to would hand them root, so the hook is removed instead.
		chmod g+w "$b/nginx-1.2.3/configure"
		SCRIPTS="$h/scripts" HOOK_UID="$(id -u)" BUILD_DIR="$b" run update-rpm.sh || fail "update with a writable build tree exited non-zero: $(cat "$T/out.log")"
		grep -q 'WARN: not installing the dnf hook' "$T/out.log" || fail "writable build tree did not block the dnf hook"
		[ ! -e "$action" ] || fail "dnf hook kept although the build tree is group-writable"
	fi
done

# A hand-set secret from a manual setup carries over verbatim, sed metacharacters included.
manual='a/b&c\\d'
printf 'localized_global.secret = "%s"\n' "$manual" >"$R/etc/nginx/lua/waf-local-overrides.lua"
run "update-$platform.sh" || fail "update with a hand-set secret exited non-zero: $(cat "$T/out.log")"
[ "$(secret)" = "$manual" ] || fail "hand-set secret not kept: '$(secret)'"

# deploy.sh ships the workspace scripts/ and config/ through a local ssh stub, replaces stale files, and installs.
platform=deploy
R="$T/root-deploy"
mkdir -p "$R/etc" "$R/opt/nginx-waf/config" "$T/repo"
echo 'ID=ubuntu' >"$R/etc/os-release"
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
cp -r "$SCRIPTS" "$SCRIPTS/../config" "$T/repo/"
deploy() {
	PATH="$T/bin:$PATH" ROOT="$R" URL="file://$T/upstream.lua" bash "$T/repo/scripts/deploy.sh" host 2>"$T/out.log"
}
deploy || fail "deploy exited non-zero: $(cat "$T/out.log")"
[ ! -e "$R/opt/nginx-waf/config/stale" ] || fail "deploy kept a file deleted from the repo"
cmp -s "$T/repo/config/nginx-waf.conf" "$R/opt/nginx-waf/config/nginx-waf.conf" || fail "deploy did not ship config/"
[[ "$(secret)" =~ ^[0-9a-f]{64}$ ]] || fail "deploy did not run the installer"
echo "localized_global.secret = 'unreadable'" >"$R/etc/nginx/lua/waf-local-overrides.lua"
if deploy; then fail "deploy rotated a secret it could not read"; fi
grep -q "'unreadable'" "$R/etc/nginx/lua/waf-local-overrides.lua" || fail "deploy overwrote an unreadable secret"

echo "PASS"
