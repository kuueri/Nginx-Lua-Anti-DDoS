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
python3 -I tests/test-linear.py							# every WAF rule against adversarial 8 KB and 128 KB input in PCRE2, prints PASS
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
- Every script sources `scripts/lib/log.sh` (`common.sh` does it for the update scripts): `info` and `warn` print to stdout, `error` and `die` to stderr, as `[HH:MM:SS] LEVEL: message`; `warn` is yellow only when stdout is a terminal and `NO_COLOR` is unset, which the tests check through a Python `pty`, since `script(1)` is not always installed.
  Its `errtrace` ERR trap prints one ERROR for a command that stops a script under `set -e`, only in the top-level shell, because a failure inside `( ... )` also fails the enclosing command; contexts that test a status (`if`, `||`) never trigger it.
  So functions must never log from inside a `$( ... )` whose output a caller captures, and the tests capture stdout and stderr together in `out.log`.
- `deploy.sh` announces each ssh and sudo password prompt, gives sudo a `-p` prompt (the test's sudo stub skips it), and runs both ssh steps over one `ControlMaster` connection so a password login asks once.
  The remote `sh -c` script cannot source `log.sh`, so it defines its own `info`; its messages must not contain a single quote.

## Upstream

- `lua/anti_ddos_challenge.lua` is the pin: `URL` in `common.sh` defaults to it, because `nginx -t` never compiles `waf.lua` (`access_by_lua_file` loads it on the first request), so an unreviewed upstream change would go live unseen.
  Before merging a newer upstream commit, mirror its `precompile_waf_*_table` changes in `tests/test-rules.lua`.
- Upstream files (`lua/`, `debian/`, `rpm/`, `.github/`, `CHANGELOG`) stay as upstream wrote them, so merges stay conflict-free.
- Every push, pull request, and issue goes to `kuueri/Nginx-Lua-Anti-DDoS` only: push with `git push origin dev:master`, and pass `--repo kuueri/Nginx-Lua-Anti-DDoS` to `gh`.
  `C0nw0nk/Nginx-Lua-Anti-DDoS` is read-only for this repo: the `upstream` remote exists for `git fetch upstream` alone and has its push URL set to `DISABLED`, and `gh` in a fork targets the parent repo unless told otherwise.
- Upstream reads `localized_global.*` set by `init_by_lua_file`, and each table in `config/waf-local-overrides.lua` replaces the upstream default table wholesale.
- Before editing an entry in `config/waf-local-overrides.lua` or `config/nginx-waf.conf`, read the comment above it: it records how upstream treats that entry (rule syntax, challenge bypass, User-Agent lists, the empty POST table, bans).
- Every rule and bypass entry needs a case in `tests/test-rules.lua`, which mirrors upstream's compilation and runs the regexes through Perl.
- Upstream wraps each query value pattern as `^(?i)<pattern>$`, so a top-level `|` breaks the anchors and alternatives need a group.
  A rule must also stay linear, because upstream treats a regex error, such as the PCRE match limit on a long value, as no match.
  `tests/test-linear.py` checks it, query rules at 128 KB, because `waf-ban.lua` also runs them on body fields.
- Upstream bans live in shared dicts, which survive a reload; only a restart clears them.

## Gotchas

- Run `nginx -t` through `nginx_test`: a bare `nginx -t` while nginx is stopped leaves an empty `/run/nginx.pid`, which on SELinux hosts blocks the next `systemctl start` with `Permission denied` and a 90 s timeout.
- Secret precedence: the secret already installed on the server, then `WAF_SECRET`, otherwise the update refuses; the repo keeps the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder.
- With SELinux Enforcing and `httpd_execmem` off, LuaJIT aborts every request with `runtime code generation failed`, which `nginx -t` never shows, so `sync_waf` appends `jit.off()` to the staged overrides.
  The check runs in Bash as root because `httpd_t` may not read SELinux booleans, and `jit.off()` suffices because upstream's FFI use is pointer casts only, which need no executable memory.
- `config/nginx-waf.conf` carries WAF directives only and turns the WAF on for every site with `access_by_lua_file` in the `http` block.
  `lua_package_path` and `load_module` belong to the main config (`load_lua_module`) or the distro's module setup, and a second copy fails `nginx -t` on duplicates.
- `config/waf-ban.lua` runs as `rewrite_by_lua_file`, `access_by_lua_file`, and `log_by_lua_file`, branched on `ngx.get_phase()`, because nginx allows one `*_by_lua*` per phase and context.
  The access phase runs upstream's `/etc/nginx/lua/waf.lua` through a per-worker `loadfile` cached in `package.loaded.waf_ban_cache` and sets `ngx.ctx.waf_access_passed` when it returns, so the log phase ignores content-phase 403s (`autoindex off`) but still counts a `deny`, which runs before Lua access handlers.
  It relies on upstream's default `exit_status = false`, which returns instead of calling `ngx.exit(ngx.OK)`; `tests/test-ban.lua` stubs upstream through that cache.
- Upstream parses only the first 100 query arguments and headers (the `ngx.req` defaults), so the rewrite phase of `waf-ban.lua` answers 403, uncounted, when either comes back `truncated`.
- Upstream matches `WAF_URI_Request_table` against the raw `request_uri`, which `%2e` defeats, so the rewrite phase of `waf-ban.lua` matches the same rules against the decoded, normalized `$uri` and its 403 counts toward a ban.
  A URI rule must therefore hold on both paths; `tests/test-ban.lua` stubs `ngx.re.find` with Lua patterns, so its rules use only syntax both share.
- The same rewrite phase checks query argument names (always blocked), cookie names and values (`WAF_cookie_block`), and urlencoded, multipart, and JSON bodies with the query rules, bodies up to `BODY_LIMIT` (128 KB), because the query rules hit the PCRE match limit on 1 MB values without PCRE JIT and a regex error there blocks rather than passes.
  XML bodies get `XML_RULE` in `waf-ban.lua` instead, which `tests/test-linear.py` does not load, so its tag scans stop at `<` or `>` to stay linear.
  `WAF_cookie_block`, `WAF_cookie_skip`, `WAF_body_block` (false logs only), and `WAF_body_skip` in the overrides are read only by `waf-ban.lua`, and these checks skip internal redirects, so a `try_files` fallback to `/index.php` cannot check a body twice or past the skip list.
- Upstream's default `content_type_fix = true` resends every allowed request to the backend as a HEAD subrequest, which doubled Tomcat's page renders on DSpace, so the overrides set it to false.
- Policy: crawlers, scrapers, AI agents, and Turnitin are allowed with strict limits, and only attack payloads lead to a ban.
  Every 403 from the access phase or the rewrite-phase rule checks counts toward the `waf-ban.lua` ban, so `user_agent_blacklist_table` is empty: upstream's other 403 sources are the WAF rule tables and Tor blocking (`.onion` only).
  The log phase counts a User-Agent matching `AI_AGENTS` or `CRAWLERS` (`bot`, `crawl`, `spider`, `slurp`, `turnitin`, `facebookexternalhit`) under `crawl:<ip>` against `CRAWLER_LIMIT` (50) per `CRAWLER_WINDOW` (600 s), because crawlers follow links with payloads planted elsewhere, yet anyone can send such a User-Agent; generic clients such as `curl` still get banned at 5.
  The rewrite phase gives each `AI_AGENTS` family (plain lowercase substrings of the User-Agent) one shared budget across all addresses, `AI_LIMIT` per `AI_WINDOW`, and answers the excess with 429, which the ban ignores.
- The `waf_login` zone in `config/nginx-waf.conf` is opt-in per site with `limit_req zone=waf_login burst=5 nodelay;`, because a `limit_req` in `http` would also reach unrelated servers such as DSpace's 19123 proxy.
  It sets no `limit_req_status`, because DSpace sets one in `http` and a duplicate fails `nginx -t`, and DSpace's login locations, which have their own `limit_req`, do not inherit it.

## Documentation

- Not every change needs documentation. Put each fact in the one place where its reader looks for it:

    | Fact                                                         | Place                                     |
    | ------------------------------------------------------------ | ----------------------------------------- |
    | What the operator sees, configures, or runs                  | `README.md`                               |
    | A constraint or trap that the code does not show to an agent | `CLAUDE.md`                               |
    | How upstream treats one config entry                         | The comment above that entry in `config/` |
    | Why a change was made                                        | The commit message                        |
    | The exact behavior of a rule or script                       | A case in `tests/`                        |
    | A server-specific value, a one-off finding, or a debug log   | Nowhere in the repo                       |

- Keep each addition to the shortest text that keeps its full meaning: the condition, the number, and the reason.
  Do not repeat a fact that another place already holds. Point to that place instead.
