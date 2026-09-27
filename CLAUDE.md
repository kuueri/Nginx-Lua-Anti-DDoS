# Workspace

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Bash scripts that install and update the upstream [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) WAF on Ubuntu and RPM servers.
`README.md` covers layout, deployment, and usage.

## Commands

```bash
shellcheck -x scripts/*.sh scripts/lib/*.sh tests/*.sh		# lint, kept at zero findings; -x follows the lib/common.sh source
bash tests/test-scripts.sh									# whole suite, prints PASS
lua tests/test-rules.lua									# local WAF rules against sample requests, prints PASS
```

`tests/test-scripts.sh` runs one sequential scenario per platform and stops at the first `FAIL [platform]: ...`.
There is no per-case runner; to focus on one platform, narrow its `for platform in ubuntu rpm` loop.

The test works on a scratch root: every script prefixes system paths with `ROOT`, stub `id`, `nginx`, and `systemctl` sit first on `PATH`, and upstream is served from `URL=file://...`.
Real nginx behaviour (Lua runtime, SELinux, systemd) is only observable on a target server.

## Architecture

- Call chain: `install-<platform>.sh` → `update-<platform>.sh` → `sync_waf` in `scripts/lib/common.sh`.
  - `install-*` only generates a secret and exports it as `WAF_SECRET`, so re-running it is an update.
  - `update-ubuntu.sh` is a platform check plus `sync_waf`, because apt keeps nginx and `libnginx-mod-http-lua` on the same ABI.
  - `update-rpm.sh` first runs `ensure_modules`: an `nginx -t` failing with `version N instead of M` triggers `rebuild_modules`, which recompiles the source-built ndk/lua modules from `$BUILD_DIR` for the installed nginx version.
- `common.sh` is sourced, and sourcing it runs the root and nginx preflight.
- `sync_waf` stages the files listed in `FILES`, compares them with the installed copies, and only on a change backs up, installs, runs `nginx_test`, then reloads or rolls every file back.
  A new installed file joins that cycle by being added to `FILES` and staged at the same relative path under `$stage`.
- Paths are relative (`etc/nginx/...`) and always joined as `"$ROOT/$f"`, which is what makes the scratch-root test possible.

## Gotchas

- Run `nginx -t` through `nginx_test`.
  A bare `nginx -t` while nginx is stopped leaves an empty `/run/nginx.pid`, which on SELinux hosts blocks the next `systemctl start` with `Permission denied` and a 90 s timeout.
- Upstream reads `localized_global.*` set by `init_by_lua_file`, and each `WAF_*` table in `config/waf-local-overrides.lua` replaces the upstream default table wholesale.
  Upstream matches URI rules against the raw path and query rules against each value re-escaped by `ngx.escape_uri`, so query patterns spell `:` and `/` as `%%3A` and `%%2F`; `tests/test-rules.lua` mirrors that matching.
  The POST table stays empty because upstream's `WAF_Post_Requests` matches value patterns against the argument name.
  `waf_defaults` spots upstream default changes between the `localized.WAF_POST_Request_table = {` and `localized.query_string_sort_table = {` line markers.
- Secret precedence: the secret already installed on the server, then `WAF_SECRET`, otherwise the update refuses.
  The repo file keeps the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder.
- `config/nginx-waf.conf` carries WAF directives only.
  `lua_package_path` and `load_module` belong to the module setup (`nginx.conf` on RPM), and a second copy makes `nginx -t` fail on duplicates.
