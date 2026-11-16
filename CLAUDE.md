# Workspace

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Bash scripts that install and update the upstream [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) WAF on Ubuntu and RPM servers.
`README.md` covers layout, deployment, and usage.

## Commands

```bash
shellcheck -x scripts/*.sh scripts/lib/*.sh tests/*.sh		# lint, kept at zero findings; -x follows the lib/common.sh source
bash tests/test-scripts.sh									# whole suite, prints PASS
lua tests/test-rules.lua									# local WAF rules against sample requests, prints PASS
lua tests/test-ban.lua										# config/waf-ban.lua against a stub ngx, prints PASS
```

`tests/test-scripts.sh` runs one sequential scenario per platform and stops at the first `FAIL [platform]: ...`.
There is no per-case runner; to focus on one platform, narrow its `for platform in ubuntu rpm` loop.

The test works on a scratch root: every script prefixes system paths with `ROOT`, stub `id`, `nginx`, and `systemctl` sit first on `PATH`, and upstream is served from `URL=file://...`.
Real nginx behaviour (Lua runtime, SELinux, systemd) is only observable on a target server.

## Architecture

- Call chain: `install-<platform>.sh` → `update-<platform>.sh` → `sync_waf` in `scripts/lib/common.sh`.
    - `install-*` only generates a secret and exports it as `WAF_SECRET`, so re-running it is an update.
    - Both update scripts run `ensure_modules`, then `sync_waf`, then `install_update_hook`; each platform script only defines `install_build_deps` and `install_update_hook`.
    - `ensure_modules` (in `common.sh`): an `nginx -t` failing with `version N instead of M`, or `lua_module_missing`, triggers `build_lua_module`, because distro packages are missing (Ubuntu 24.04 dropped `libnginx-mod-http-lua`) or stale.
      `lua_module_missing` means the config fails on `unknown directive "lua_`, or passes with no `load_module ... ngx_http_lua_module.so` in `nginx -T` and no Lua in `nginx -V`.
      `build_lua_module` installs only missing build packages and git sources, builds LuaJIT and lua-resty-core when absent, and compiles the ndk/lua modules from `$BUILD_DIR` for the installed nginx version.
      It configures with `--with-http_ssl_module`, because without OpenSSL the lua module has no `ngx.hmac_sha1` and upstream then fails every request with 500; `lua_module_without_ssl` (no `hmac_sha1` string in our `.so`) triggers a rebuild and restart, and the overrides file asserts `ngx.hmac_sha1` so nginx rejects such a module at config load.
      After a version mismatch nginx restarts, because a reload keeps the old binary; a missing module gets `load_lua_module`, which prepends `load_module` lines and adds `lua_package_path` to the main config from `nginx -V --conf-path`, restoring it when `nginx -t` fails.
    - `install_update_hook` reruns the update with an explicit `BUILD_DIR` after nginx upgrades: a dnf4 `post-transaction-actions` file for `nginx*` on RPM, a dpkg `Post-Invoke` in `/etc/apt/apt.conf.d/99nginx-waf` after every package run on Ubuntu.
      It lives in the update rather than the install so `deploy.sh` reaches servers that are already installed.
      Because the hook runs as root, `hook_is_safe` refuses it (and deletes an old one) unless the repo copy and `BUILD_DIR`, with every parent, belong to `HOOK_UID` (root; tests pass their own uid) and are not group- or world-writable.
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
- `sync_waf` checks `nginx -T`, not just `nginx -t`: a config without the `conf.d` include passes `-t` while upstream runs on its public default secret.
  When the `init_by_lua_file` line is missing, it inserts `include /etc/nginx/conf.d/waf.conf;` into the main config from `nginx -V --conf-path`, after its `lua_package_path` line or else after the first `http {`, and rolls that file back with the others if nginx still does not load it.
- Secret precedence: the secret already installed on the server, then `WAF_SECRET`, otherwise the update refuses.
  The repo file keeps the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder.
- `config/nginx-waf.conf` turns the WAF on for every site with `access_by_lua_file` in the `http` block, so an install needs no site edits.
  API and OAI-PMH paths skip only the JavaScript challenge via `master_switch = 3` and `master_switch_custom_hosts` in the overrides; upstream runs `WAF_Checks()` before `check_master_switch()`, so the WAF rules still apply there.
  The bypass entries are Lua patterns on `scheme://host/path?query`, anchored with `^https?://[^/]+/` so a query string cannot match them; `tests/test-rules.lua` checks each one.
- `anti_ddos()` runs before `check_master_switch()` and, with upstream's default "I am Under Attack" setting, rewrites `master_switch` on every request: 2 (no challenge) while at most 100 IPs are banned, 1 (challenge everywhere, bypass paths included) above that.
  So `master_switch = 3` and its bypass paths are a fallback only; during an attack only `user_agent_whitelist_table` matches skip the challenge.
  WAF rule hits return 403 without a ban; bans come from floods, challenge failures, and forged proxy headers.
- `user_agent_blacklist_table` replaces upstream's list without `curl` and `python`, and with `OAI-SearchBot` instead of `OAI-`, because the upstream list returned 403 to OAI-PMH and REST clients on every path; `tests/test-rules.lua` checks it as the `uablock` kind.
- `user_agent_whitelist_table` (Googlebot, Bingbot, Turnitin) gets no Lua-to-PCRE shim at all: upstream joins the entries into one regex for `ngx.re.find`.
  Use mode 3 and plain PCRE; modes 1 and 4 lowercase the whole pattern, which turns `\S` into `\s`.
- Upstream bans any request that carries `X-Forwarded-For` from an address outside `proxy_header_table` as proxy impersonation, for 24 hours, in a shared dict that survives reloads.
  Behind the realip module that is every visitor, because `$remote_addr` is already the public client, so `waf-ban.lua` clears the header in the rewrite phase when `$realip_remote_addr` differs from `$remote_addr`.
  Bans placed before that fix only clear with a restart, not a reload.
- `config/waf-ban.lua` runs as both `rewrite_by_lua_file` and `log_by_lua_file` (one file, branched on `ngx.get_phase()`), because nginx allows one `rewrite_by_lua*` per context.
  The log phase counts a 403 only when the rewrite phase ran (`ngx.ctx` flag, so a site's earlier `return 403` is skipped) and `upstream_status` is unset (so DSpace's own 403s are skipped); 5 in 10 minutes put a `ban:` key in `lua_shared_dict waf_strikes` for 1 hour, and private addresses never count, so a misconfigured realip cannot ban the reverse proxy.
- `config/nginx-waf.conf` carries WAF directives only.
  `lua_package_path` and `load_module` belong to the module setup (`nginx.conf` on RPM), and a second copy makes `nginx -t` fail on duplicates.
