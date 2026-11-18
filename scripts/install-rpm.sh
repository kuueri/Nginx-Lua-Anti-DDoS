#!/usr/bin/env bash
# First-time install of Nginx-Lua-Anti-DDoS on RPM-based systems, for an nginx that already loads the source-built ndk/lua modules.
# It creates the per-server secret, then lets update-rpm.sh install the files, so re-running it behaves like an update.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/log.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/log.sh"

info "Generating a per-server secret; the update keeps an already installed secret instead"
# The secret signs visitors' auth cookies, so each server gets its own and it never lives in the repo.
# update-rpm.sh ignores this value when a secret is already installed.
WAF_SECRET="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
export WAF_SECRET

"$(dirname "${BASH_SOURCE[0]}")/update-rpm.sh"
