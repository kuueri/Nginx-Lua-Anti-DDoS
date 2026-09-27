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
# Like real nginx, -t leaves an empty pid file behind when nginx is stopped.
tee "$T/bin/nginx" >/dev/null <<'EOF'
#!/bin/sh
if [ "$1" = -t ]; then mkdir -p "$ROOT/run"; : >>"$ROOT/run/nginx.pid"; fi
[ -z "$NGINX_FAIL" ]
EOF
tee "$T/bin/systemctl" >/dev/null <<'EOF'
#!/bin/sh
echo "$*" >>"$ROOT/systemctl.log"
EOF
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
	printf 'localized.WAF_POST_Request_table = {\n}\nlocalized.query_string_sort_table = {\n' >"$T/upstream.lua"

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

	# Re-running install with no upstream change is a no-op and keeps the secret.
	run "install-$platform.sh" || fail "install rerun exited non-zero: $(cat "$T/out.log")"
	grep -q 'already up to date' "$T/out.log" || fail "install rerun did not report up to date"
	[ "$(secret)" = "$s1" ] || fail "install rerun rotated the secret"
	[ "$(reloads)" -eq 1 ] || fail "install rerun reloaded nginx"

	# An upstream change that fails nginx -t is rolled back, and the default-rule drift is flagged.
	cp "$T/upstream.lua" "$T/upstream.v1.lua"
	sed -i '1a { "^.*$", ".*new-rule.*" },' "$T/upstream.lua"
	if NGINX_FAIL=1 run "update-$platform.sh"; then fail "failed nginx -t did not abort the update"; fi
	grep -q 'WARN: upstream changed its default WAF_\* rules' "$T/out.log" || fail "drift warning missing"
	cmp -s "$T/upstream.v1.lua" "$R/etc/nginx/lua/waf.lua" || fail "waf.lua was not rolled back"
	[ "$(reloads)" -eq 1 ] || fail "failed update reloaded nginx"

	# The same upstream change with a valid config is applied and keeps the secret.
	run "update-$platform.sh" || fail "update exited non-zero: $(cat "$T/out.log")"
	cmp -s "$T/upstream.lua" "$R/etc/nginx/lua/waf.lua" || fail "update did not install the new waf.lua"
	[ "$(secret)" = "$s1" ] || fail "update rotated the secret"
	[ "$(reloads)" -eq 2 ] || fail "update did not reload nginx"
done

# A hand-set secret from a manual setup carries over verbatim, sed metacharacters included.
manual='a/b&c\\d'
printf 'localized_global.secret = "%s"\n' "$manual" >"$R/etc/nginx/lua/waf-local-overrides.lua"
run "update-$platform.sh" || fail "update with a hand-set secret exited non-zero: $(cat "$T/out.log")"
[ "$(secret)" = "$manual" ] || fail "hand-set secret not kept: '$(secret)'"

echo "PASS"
