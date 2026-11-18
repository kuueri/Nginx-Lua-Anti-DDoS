# shellcheck shell=bash
# Leveled log lines shared by every script: INFO and WARN go to stdout, ERROR to stderr, each with the time.
# WARN is yellow only on a terminal and without NO_COLOR (https://no-color.org), so log files and pipes get plain text.
# errtrace and the ERR trap report a command that stops a script under set -e, so no step fails silently.
# The trap reports only in the top-level shell, because a failure inside ( ... ) or $( ... ) also fails the enclosing command and would print twice; the INFO line before it names the step.

info() {
	printf '[%s] INFO: %s\n' "$(date +%H:%M:%S)" "$*"
}

warn() {
	local on="" off=""
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		on=$'\033[33m'
		off=$'\033[0m'
	fi
	printf '%s[%s] WARN: %s%s\n' "$on" "$(date +%H:%M:%S)" "$*" "$off"
}

error() {
	printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

die() {
	error "$*"
	exit 1
}

on_error() {
	local rc=$?
	[ "$BASH_SUBSHELL" -gt 0 ] || error "the step above failed with exit code $rc ($(basename -- "${BASH_SOURCE[1]:-$0}") line ${BASH_LINENO[0]:-?})"
}

set -o errtrace
trap on_error ERR
