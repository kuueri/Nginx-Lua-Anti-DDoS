# Workspace

Cyber defense fork of [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) deploying nginx WAF rules and exponential IP banning on Ubuntu and RPM.

- **Fail-closed defense:** close bypasses across raw/decoded URIs, query names/values, headers, cookies, and bodies; treat unexpected rule errors as blocks; keep root hooks tamper-proof.
- **Minimum latency:** keep request hot paths **tight**—O(1) `lua_shared_dict` lookups, per-worker caching (`package.loaded.waf_ban_cache`), linear regexes, zero blocking I/O, and zero unnecessary allocations on `access`/`log`/banned-IP fast paths (assume `jit.off()` on SELinux Enforcing hosts).

## Verification

```bash
shellcheck -x scripts/*.sh scripts/lib/*.sh tests/*.sh
bash tests/test-scripts.sh
lua tests/test-rules.lua
lua tests/test-ban.lua
lua tests/test-stats.lua
python3 -I tests/test-linear.py
```

Keep `shellcheck` at zero findings and every test printing `PASS`.
`tests/test-scripts.sh` uses a scratch `ROOT` with stubbed `PATH` and `URL=file://...`; narrow its `for platform in deb rpm` loop for one platform.
Real nginx, LuaJIT, SELinux, and systemd behavior is observable only on a target server.

## Fork & Upstream

- Target `kuueri/Nginx-Lua-Anti-DDoS` for every push (`git push origin dev:master`).
- Keep upstream paths (`lua/`, `debian/`, `rpm/`, `.github/`, `CHANGELOG`) unmodified.
- `lua/anti_ddos_challenge.lua` is pinned (`nginx -t` never compiles `waf.lua`); mirror upstream `precompile_waf_*_table` changes in `tests/test-rules.lua` before merging.

## WAF & Runtime Invariants

- Read the comment above any entry in `config/waf-local-overrides.lua` or `config/nginx-waf.conf` before editing; each Lua override table replaces upstream wholesale.
- Upstream wraps query value patterns as `^(?i)<pattern>$`: group top-level `|` alternatives, keep every rule linear (upstream treats PCRE errors as no match), and verify with `tests/test-rules.lua` and `tests/test-linear.py` (128 KB).
  Keep `XML_RULE` tag scans in `config/waf-ban.lua` bounded at `<` or `>` and verify linearity with `tests/test-linear.py`.
- `WAF_URI_Request_table` runs on both raw `request_uri` (upstream) and decoded `$uri` (`waf-ban.lua`); URI rules must hold on both paths.
- `config/waf-ban.lua` branches on `ngx.get_phase()` (`rewrite`, `access`, `log`): exit early before allocations, rely on upstream `exit_status = false` to set `ngx.ctx.waf_access_passed`, wrap `ngx.exit` in `access` and record rewrite-phase 403s before `ngx.exit` (so `error_page 403` internal redirects that wipe `ngx.ctx` or return `444` still count bans and stats), isolate `waf_bans` from `waf_strikes`, claim bans atomically via `bans:add`, and skip body/cookie/AI checks on `ngx.req.is_internal()`.
- `config/waf-stats.lua` persists attack, ban, and per-category counters (`waf_stats 1m`) asynchronously from worker 0 to `/var/lib/nginx/waf/stats.txt` every 30 s and on graceful shutdown (`add` on load preserves live values across reloads); each rule in `config/waf-local-overrides.lua` carries its category as element 3, and upstream 403s are classified lazily in the `log` phase only.
- Allow crawlers, scrapers, AI agents, and Turnitin under limits and ban only on attack payloads (`user_agent_blacklist_table` stays empty).
- Keep `config/nginx-waf.conf` free of `load_module`/`lua_package_path` (duplicates fail `nginx -t`) and keep `waf_login` opt-in without `limit_req_status`; add any new `lua_shared_dict` name to the cleanup regex in `scripts/lib/common.sh` (`sync_waf`).

## Script & Deployment Traps

- Prefix system paths as `"$ROOT/$f"` (relative `f`, e.g. `etc/nginx/...`) for scratch-root tests.
- Add newly installed files to `FILES` and stage them at `"$stage/$f"` in `scripts/lib/common.sh` for backup, diff-check, `nginx -t`, and rollback.
- Run `nginx -t` only via `nginx_test` (bare `nginx -t` while stopped leaves an empty `/run/nginx.pid` that blocks `systemctl start` on SELinux).
- Secret precedence: installed server secret > `WAF_SECRET` > refuse; keep `CHANGE_ME_TO_LONG_RANDOM_SECRET` in the repo.
- Keep the SELinux `httpd_execmem` check in root Bash (`sync_waf` appends `jit.off()` when Enforcing with `httpd_execmem` off), because `httpd_t` cannot read SELinux booleans.
- Keep `install_update_hook` in the update path and enforce `hook_is_safe` (owner `HOOK_UID`, non-group/world-writable across repo, `BUILD_DIR`, and parents).
- Keep functions silent inside `$( ... )` (`scripts/lib/log.sh` ERR trap), and keep the remote `sh -c` messages in `scripts/deploy.sh` free of single quotes.
