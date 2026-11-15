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
    - `update-rpm.sh` first runs `ensure_modules`: an `nginx -t` failing with `version N instead of M` triggers `rebuild_modules`, which recompiles the source-built ndk/lua modules from `$BUILD_DIR` for the installed nginx version, then restarts nginx, because a reload keeps the old binary.
    - `update-rpm.sh` ends with `install_dnf_hook`, a dnf4 `post-transaction-actions` file that reruns it with an explicit `BUILD_DIR` after any `nginx*` package upgrade; it lives in the update rather than the install so `deploy.sh` reaches servers that are already installed.
      Because the hook runs as root, `writable_by_root_only` refuses it (and deletes an old one) unless the repo copy and `BUILD_DIR`, with every parent, belong to `HOOK_UID` (root; tests pass their own uid) and are not group- or world-writable.
- `common.sh` is sourced, and sourcing it runs the root and nginx preflight.
- `sync_waf` stages the files listed in `FILES`, compares them with the installed copies, and only on a change backs up, installs, runs `nginx_test`, then reloads or rolls every file back.
  A new installed file joins that cycle by being added to `FILES` and staged at the same relative path under `$stage`.
- Paths are relative (`etc/nginx/...`) and always joined as `"$ROOT/$f"`, which is what makes the scratch-root test possible.

## Gotchas

- Run `nginx -t` through `nginx_test`.
  A bare `nginx -t` while nginx is stopped leaves an empty `/run/nginx.pid`, which on SELinux hosts blocks the next `systemctl start` with `Permission denied` and a 90 s timeout.
- Upstream reads `localized_global.*` set by `init_by_lua_file`, and each `WAF_*` table in `config/waf-local-overrides.lua` replaces the upstream default table wholesale.
  Upstream compiles every rule into a PCRE regex for `ngx.re.find`, and its only Lua-pattern translation is `%.` to `.`, so rules use regex escapes (`\.`), never Lua ones (`%-`, `%/`).
  URI rules match the raw path unanchored and case-insensitively, query rules match each decoded value as `^(?i)<pattern>$` (hence the `(?s).*` ... `.*` wrapping), and header rules match raw values unanchored and case-sensitively (hence `(?i)`).
  `tests/test-rules.lua` mirrors that compilation and runs the regexes through Perl, because stock Lua has no PCRE; every rule must block at least one case.
  The POST table stays empty because any rule there makes upstream read every POST body, uploads included, into a Lua string.
- `URL` in `common.sh` pins upstream to one commit, because `nginx -t` never compiles `waf.lua` (`access_by_lua_file` loads on the first request).
  Bumping it means mirroring upstream's `precompile_waf_*_table` changes in `tests/test-rules.lua` first.
- `sync_waf` checks `nginx -T`, not just `nginx -t`: a config without the `conf.d` include passes `-t` while upstream runs on its public default secret, so a missing `init_by_lua_file` line rolls the update back.
- Secret precedence: the secret already installed on the server, then `WAF_SECRET`, otherwise the update refuses.
  The repo file keeps the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder.
- `config/nginx-waf.conf` carries WAF directives only.
  `lua_package_path` and `load_module` belong to the module setup (`nginx.conf` on RPM), and a second copy makes `nginx -t` fail on duplicates.
