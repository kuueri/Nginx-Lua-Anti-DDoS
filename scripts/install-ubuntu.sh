#!/usr/bin/env bash
# First-time install of Nginx-Lua-Anti-DDoS on Ubuntu, for an nginx that already has the Lua module (libnginx-mod-http-lua).
# It creates the per-server secret, then lets update-ubuntu.sh install the files, so re-running it behaves like an update.
set -euo pipefail

# The secret signs visitors' auth cookies, so each server gets its own and it never lives in the repo.
# update-ubuntu.sh ignores this value when a secret is already installed.
WAF_SECRET="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
export WAF_SECRET

"$(dirname "${BASH_SOURCE[0]}")/update-ubuntu.sh"
