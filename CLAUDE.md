# Workspace

A fork of [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) that adds Bash scripts to install and update the upstream WAF on Ubuntu and RPM servers, plus local rules.
`README.md` covers layout, deployment, and usage.

## Commands

```bash
shellcheck -x scripts/*.sh scripts/lib/*.sh tests/*.sh		# lint, kept at zero findings; -x follows the lib/common.sh source
bash tests/test-scripts.sh									# whole suite, prints PASS
lua tests/test-rules.lua									# local WAF rules against sample requests, prints PASS
lua tests/test-ban.lua										# config/waf-ban.lua against a stub ngx, prints PASS
lua tests/test-stats.lua									# config/waf-stats.lua against a stub ngx, prints PASS
```

`tests/test-scripts.sh` runs one sequential scenario per platform, then one for `deploy.sh`, and stops at the first `FAIL [platform]: ...`.
There is no per-case runner; to focus on one platform, narrow its `for platform in deb rpm` loop.

The test works on a scratch root: every script prefixes system paths with `ROOT`, stubs for the system commands sit first on `PATH`, and the upstream file is served from `URL=file://...`.
Real nginx behaviour (Lua runtime, SELinux, systemd) is only observable on a target server.

## Architecture

- Call chain: `deploy.sh` (workstation, over ssh) → `install-<platform>.sh` → `update-<platform>.sh` → `ensure_modules`, `sync_waf`, `install_update_hook`.
    - `deploy.sh` ships `scripts/`, `config/`, and `lua/` to `/opt/nginx-waf`, then runs the install script, or the update script once `/etc/nginx/lua/waf-local-overrides.lua` exists.
    - `install-*` only generates a secret and exports it as `WAF_SECRET`, so re-running it is an update.
    - Each update script defines only `install_build_deps` and `install_update_hook` for its package manager; the rest lives in `scripts/lib/common.sh`, and sourcing it runs the root and nginx preflight.
- `ensure_modules` takes the first match, because distro Lua modules are missing (Ubuntu 24.04 dropped `libnginx-mod-http-lua`) or stale:
    1. `nginx -t` fails with `version N instead of M` after an nginx upgrade: `build_lua_module`, then a restart, because a reload keeps the old binary.
    2. `lua_module_without_ssl` (no `hmac_sha1` string in our `.so`): rebuild and restart, because upstream calls `ngx.hmac_sha1` on every request.
    3. `lua_module_missing` (the config fails on `unknown directive "lua_`, or passes with no `load_module ... ngx_http_lua_module.so` in `nginx -T` and no Lua in `nginx -V`): `build_lua_module`, then `load_lua_module` prepends `load_module` lines and adds `lua_package_path` to the main config from `nginx -V --conf-path`, restoring it when `nginx -t` fails.
- `build_lua_module` builds only what is missing in `$BUILD_DIR` (packages, git sources, LuaJIT, lua-resty-core) and configures with `--with-http_ssl_module`.
- `install_update_hook` reruns the update with an explicit `BUILD_DIR` after nginx upgrades: a dnf4 `post-transaction-actions` file for `nginx*` on RPM, a dpkg `Post-Invoke` in `/etc/apt/apt.conf.d/99nginx-waf` after every package run on Ubuntu.
  It lives in the update rather than the install so `deploy.sh` reaches servers that are already installed.
  Because the hook runs as root, `hook_is_safe` refuses it (and deletes an old one) unless the repo copy and `BUILD_DIR`, with every parent, belong to `HOOK_UID` (root; tests pass their own uid) and are not group- or world-writable.
- `sync_waf` stages the files listed in `FILES`, compares them with the installed copies, and only on a change backs up, installs, runs `nginx_test -T`, then reloads or rolls every file back.
  A new installed file joins that cycle by being added to `FILES` and staged at the same relative path under `$stage`.
  It looks for the `# configuration file /etc/nginx/conf.d/waf.conf:` header in the dump, because a config without that include passes `nginx -t` while upstream runs on its public default secret.
  When the header is missing, it deletes inline WAF directives from the main config, since a second `lua_shared_dict` fails `nginx -t`, and inserts `include /etc/nginx/conf.d/waf.conf;` after `lua_package_path` or else after the first `http {`.
- Paths are relative (`etc/nginx/...`) and always joined as `"$ROOT/$f"`, which is what makes the scratch-root test possible.

## Upstream

- `lua/anti_ddos_challenge.lua` is the pin: `URL` in `common.sh` defaults to it, because `nginx -t` never compiles `waf.lua` (`access_by_lua_file` loads it on the first request), so an unreviewed upstream change would go live unseen.
  Before merging a newer upstream commit, mirror its `precompile_waf_*_table` changes in `tests/test-rules.lua`.
- Upstream files (`lua/`, `debian/`, `rpm/`, `.github/`, `CHANGELOG`) stay as upstream wrote them, so merges stay conflict-free.
- Every push, pull request, and issue goes to `kuueri/Nginx-Lua-Anti-DDoS` only: push with `git push origin dev:master`, and pass `--repo kuueri/Nginx-Lua-Anti-DDoS` to `gh`.
  `C0nw0nk/Nginx-Lua-Anti-DDoS` is read-only for this repo: the `upstream` remote exists for `git fetch upstream` alone and has its push URL set to `DISABLED`, and `gh` in a fork targets the parent repo unless told otherwise.
- Upstream reads `localized_global.*` set by `init_by_lua_file`, and each table in `config/waf-local-overrides.lua` replaces the upstream default table wholesale.
- Before editing an entry in `config/waf-local-overrides.lua` or `config/nginx-waf.conf`, read the comment above it: it records how upstream treats that entry (rule syntax, challenge bypass, User-Agent lists, the empty POST table, bans).
- Every rule and bypass entry needs a case in `tests/test-rules.lua`, which mirrors upstream's compilation and runs the regexes through Perl.
- Upstream bans live in shared dicts, which survive a reload; only a restart clears them.

## Gotchas

- Run `nginx -t` through `nginx_test`: a bare `nginx -t` while nginx is stopped leaves an empty `/run/nginx.pid`, which on SELinux hosts blocks the next `systemctl start` with `Permission denied` and a 90 s timeout.
- Secret precedence: the secret already installed on the server, then `WAF_SECRET`, otherwise the update refuses; the repo keeps the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder.
- With SELinux Enforcing and `httpd_execmem` off, LuaJIT aborts every request with `runtime code generation failed`, which `nginx -t` never shows, so `sync_waf` appends `jit.off()` to the staged overrides.
  The check runs in Bash as root because `httpd_t` may not read SELinux booleans, and `jit.off()` suffices because upstream's FFI use is pointer casts only, which need no executable memory.
- `config/nginx-waf.conf` carries WAF directives only and turns the WAF on for every site with `access_by_lua_file` in the `http` block.
  `lua_package_path` and `load_module` belong to the main config (`load_lua_module`) or the distro's module setup, and a second copy fails `nginx -t` on duplicates.
- `config/waf-ban.lua` runs as both `rewrite_by_lua_file` and `log_by_lua_file`, branched on `ngx.get_phase()`, because nginx allows one `rewrite_by_lua*` per context.
- Policy: crawlers, scrapers, AI agents, and Turnitin are allowed with strict limits, and only attack payloads lead to a ban.
  Every 403 from the access phase counts toward the `waf-ban.lua` ban, so `user_agent_blacklist_table` is empty: upstream's other 403 sources are the WAF rule tables and Tor blocking (`.onion` only).
  The log phase never counts a User-Agent matching `AI_AGENTS` or `CRAWLERS` (`bot`, `crawl`, `spider`, `slurp`, `turnitin`, `facebookexternalhit`), because crawlers follow links with payloads planted elsewhere; generic clients such as `curl` still get banned for payloads.
  The rewrite phase gives each `AI_AGENTS` family (plain lowercase substrings of the User-Agent) one shared budget across all addresses, `AI_LIMIT` per `AI_WINDOW`, and answers the excess with 429, which the ban ignores.
