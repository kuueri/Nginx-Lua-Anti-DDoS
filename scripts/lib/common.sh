# shellcheck shell=bash
# Shared by update-ubuntu.sh and update-rpm.sh: logging, a pid-safe nginx -t, and the WAF file sync.
# Sourcing it also checks for root and nginx, so callers stop before touching anything.
# ROOT prefixes every system path so tests can run the scripts against a scratch tree.

CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../config" && pwd)"
ROOT="${ROOT:-}"
NGINX_BIN="${NGINX_BIN:-nginx}"
URL="${URL:-https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/raw/refs/heads/master/lua/anti_ddos_challenge.lua}"
PID_FILE="$ROOT/run/nginx.pid"
BACKUP_DIR="$ROOT/var/backups/nginx-waf/$(date +%Y%m%d%H%M%S)"
PLACEHOLDER_SECRET="CHANGE_ME_TO_LONG_RANDOM_SECRET"
WAF_FILE="etc/nginx/lua/waf.lua"
OVERRIDES_FILE="etc/nginx/lua/waf-local-overrides.lua"
HTTP_CONF="etc/nginx/conf.d/waf.conf"
FILES=("$WAF_FILE" "$OVERRIDES_FILE" "$HTTP_CONF")
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
nginx_test() {
	local rc=0
	"$NGINX_BIN" -t || rc=$?
	[ -s "$PID_FILE" ] || rm -f -- "$PID_FILE"
	return "$rc"
}

# ponytail: section located by two upstream line markers; if upstream renames them, the drift warning goes silent.
waf_defaults() {
	sed -n '/^localized\.WAF_POST_Request_table = {/,/^localized\.query_string_sort_table = {/p' "$1"
}

# Download upstream waf.lua, reapply config/, and reload nginx only when a file changed.
# A failed nginx -t puts every file back.
sync_waf() {
	local stage secret f changed=0

	WORK_DIR="$(mktemp -d)"
	trap 'rm -rf -- "$WORK_DIR"' EXIT
	stage="$WORK_DIR/stage"

	log "Downloading upstream WAF"
	mkdir -p "$stage/etc/nginx/lua" "$stage/etc/nginx/conf.d"
	curl -fsSL "$URL" -o "$stage/$WAF_FILE"
	cp -- "$CONFIG_DIR/waf-local-overrides.lua" "$stage/$OVERRIDES_FILE"
	cp -- "$CONFIG_DIR/nginx-waf.conf" "$stage/$HTTP_CONF"

	# The installed secret wins, so visitors' auth cookies survive updates.
	# WAF_SECRET is only the fallback the install scripts pass on the first install.
	if grep -q "$PLACEHOLDER_SECRET" "$stage/$OVERRIDES_FILE"; then
		secret="$(sed -n 's/^localized_global\.secret = "\(.*\)"$/\1/p' "$ROOT/$OVERRIDES_FILE" 2>/dev/null || true)"
		if [ -z "$secret" ] || [ "$secret" = "$PLACEHOLDER_SECRET" ]; then
			secret="${WAF_SECRET:-}"
		fi
		[ -n "$secret" ] || die "WAF is not installed yet; run install-ubuntu.sh or install-rpm.sh first"
		# Escape sed's replacement metacharacters so a hand-set secret from a manual setup carries over verbatim.
		sed -i "s/$PLACEHOLDER_SECRET/$(printf '%s' "$secret" | sed 's/[\/&]/\\&/g')/" "$stage/$OVERRIDES_FILE"
	fi
	# The overrides file holds the secret; only the nginx master (root) reads it via init_by_lua_file.
	chmod 0600 "$stage/$OVERRIDES_FILE"
	# Workers load waf.lua as the unprivileged nginx user on their first request.
	chmod 0644 "$stage/$WAF_FILE" "$stage/$HTTP_CONF"

	# Local WAF_* tables replace the upstream defaults instead of extending them, so an upstream change there needs a manual review.
	if [ -f "$ROOT/$WAF_FILE" ] && [ "$(waf_defaults "$ROOT/$WAF_FILE")" != "$(waf_defaults "$stage/$WAF_FILE")" ]; then
		log "WARN: upstream changed its default WAF_* rules; review config/waf-local-overrides.lua, which replaces them"
	fi

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
	if ! nginx_test; then
		for f in "${FILES[@]}"; do
			if [ -f "$BACKUP_DIR/$f" ]; then
				copy "$BACKUP_DIR/$f" "$ROOT/$f"
			else
				rm -f -- "$ROOT/$f"
			fi
		done
		die "nginx -t failed; restored previous files from $BACKUP_DIR"
	fi

	log "Reloading nginx"
	systemctl reload-or-restart nginx
	log "WAF files installed; previous versions (if any) are in $BACKUP_DIR"
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v "$NGINX_BIN" >/dev/null || die "nginx not found; install nginx with the Lua module first"
