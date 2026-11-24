# Nginx WAF

This repository is a cybersecurity defense fork of [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) by Conor McKnight ([C0nw0nk](https://github.com/C0nw0nk)).
It adds deployment scripts for `deb` and `rpm` Linux systems, local WAF rules, and exponential in-memory IP banning.
For upstream details, read the [upstream README](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS#readme).

## Requirements

- An installed nginx server. The scripts do not install nginx.
- Root access on the target server.

The scripts do not require an existing nginx Lua module.
If nginx lacks a Lua module, the update script builds one from source.

## Layout

| Path                                       | Purpose                                                                 |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `lua/anti_ddos_challenge.lua`              | Pinned upstream WAF, installed as `/etc/nginx/lua/waf.lua`              |
| `config/nginx-waf.conf`                    | `http` block snippet that enables the WAF on all sites                  |
| `config/waf-local-overrides.lua`           | Local secret and WAF rule tables                                        |
| `config/waf-ban.lua`                       | Fast-path ban check, extra request checks, and exponential IP banning   |
| `config/waf-stats.lua`                     | WAF counters as JSON on `http://127.0.0.1:9180/ddos_stats`              |
| `scripts/deploy.sh`                        | Copies repo files over `ssh` and runs the install or update script      |
| `scripts/install-deb.sh`, `install-rpm.sh` | First install: generates the server secret, then runs the update script |
| `scripts/update-deb.sh`, `update-rpm.sh`   | Update: builds the Lua module if needed, then installs WAF files        |
| `scripts/lib/common.sh`                    | Shared module build, file sync, backup, rollback, and reload logic      |
| `tests/`                                   | Automated tests for scripts, rules, linearity, bans, and stats          |
| `debian/`, `rpm/`, `.github/`, `CHANGELOG` | Unmodified upstream packaging and CI files                              |

## Deploy

Run this command from the repository root:

```bash
scripts/deploy.sh user@server
```

The command copies `scripts/`, `config/`, and `lua/` to `/opt/nginx-waf` on the target server.
On a new server, it runs the install script.
On an installed server, it runs the update script.
The target server needs only `ssh` and `sudo` access for `user`.
It does not need direct access to this git repository.

Both remote steps reuse one `ssh` connection, so `ssh` asks for a password only once.
The deploy script announces each `ssh` or `sudo` password prompt before it runs:

```text
[08:57:01] INFO: Connecting to user@server over ssh; type the ssh password of the remote user if ssh asks for it
user@server's password:
[08:57:04] INFO: Running the installer as root on user@server; type the sudo password of the remote user if sudo asks for it
[sudo] password for user on server:
```

Each script prints one line per step with a timestamp and a level:

- `INFO` on stdout: a step starts or finishes normally.
- `WARN` on stdout (yellow on a terminal): the script continues, but the operator must review the notice.
- `ERROR` on stderr: the script stops and restores the previous files.

Set `NO_COLOR=1` to disable terminal color on `WARN` lines.
Output to a file or pipe has no color.

To copy the files manually, place all three directories into one root-owned directory on the server:

```bash
scp -r scripts config lua user@server:/tmp/nginx-waf/
ssh user@server
sudo mkdir -p /opt/nginx-waf
sudo cp -r /tmp/nginx-waf/scripts /tmp/nginx-waf/config /tmp/nginx-waf/lua /opt/nginx-waf/
sudo chown -R root:root /opt/nginx-waf
```

Keep `/opt/nginx-waf` on the server because later updates and package-manager hooks read from it.

## Install and update

| Package type         | First install                                | Update                                      |
| -------------------- | -------------------------------------------- | ------------------------------------------- |
| `deb` (`apt`/`dpkg`) | `sudo /opt/nginx-waf/scripts/install-deb.sh` | `sudo /opt/nginx-waf/scripts/update-deb.sh` |
| `rpm` (`dnf`)        | `sudo /opt/nginx-waf/scripts/install-rpm.sh` | `sudo /opt/nginx-waf/scripts/update-rpm.sh` |

The install script generates a per-server secret and calls the update script.
The update script performs these steps:

1. It checks the nginx Lua module and builds it from source when any of these conditions holds:
    - An nginx upgrade left the module on an older binary version. The script then restarts nginx.
    - The module lacks OpenSSL support for `ngx.hmac_sha1`. The script then restarts nginx.
    - nginx has no Lua module. The script adds `load_module` and `lua_package_path` to the main `nginx.conf`, and restores it if `nginx -t` fails.
2. It stages the WAF files:
    - `lua/anti_ddos_challenge.lua` verbatim as `/etc/nginx/lua/waf.lua`.
    - `config/waf-local-overrides.lua` with the server secret, `config/waf-ban.lua`, `config/waf-stats.lua`, and `config/nginx-waf.conf`.
    - If SELinux runs in Enforcing mode and `httpd_execmem` is off, the script appends `jit.off()` to the staged overrides file.
      Without `jit.off()`, LuaJIT stops worker processes because SELinux blocks executable memory generation.
3. If the staged files match the installed files, the script skips to step 6.
4. It backs up the installed files to `/var/backups/nginx-waf/<timestamp>/` and copies the staged files into place.
   If nginx does not load `waf.conf`, the script removes duplicate inline WAF directives from `nginx.conf` and adds `include /etc/nginx/conf.d/waf.conf;`.
   If `nginx -t` fails, the script restores the previous files and `nginx.conf`.
5. It reloads nginx.
6. It installs the package-manager hook.

The module build uses `/usr/local/src/nginx-lua` for LuaJIT, `lua-resty-core`, and the nginx modules.
The update script installs only missing build packages through the system package manager.

### nginx upgrades

After an nginx package upgrade, source-built modules no longer match the new nginx binary.
The update script rebuilds those modules from `BUILD_DIR` and restarts nginx.
It also installs a package-manager hook to run the update script automatically after upgrades:

- On `rpm` systems (`dnf4`): a `post-transaction-actions` hook runs `update-rpm.sh` after nginx package upgrades.
- On `deb` systems: a `dpkg` `Post-Invoke` hook in `/etc/apt/apt.conf.d/99nginx-waf` runs `update-deb.sh` after package runs.

Because the hook runs as root, the script installs it only when `/opt/nginx-waf`, `BUILD_DIR`, and every parent directory meet both conditions:

- Root owns the directory.
- Neither group nor others can write to the directory.

If either condition fails, the script removes any old hook and prints a warning.
To fix a build directory owned by a regular user, move it and lock its permissions:

```bash
sudo mv ~/build/nginx-lua /usr/local/src/nginx-lua
sudo chown -R root:root /usr/local/src/nginx-lua
sudo chmod -R go-w /usr/local/src/nginx-lua
```

If the `dnf4` plugin is unavailable on an `rpm` system, the script prints a warning.
In that case, run `update-rpm.sh` manually after each nginx upgrade.

## WAF behavior

### Global scope

The installed `waf.conf` sets `rewrite_by_lua_file`, `access_by_lua_file`, and `log_by_lua_file` to `/etc/nginx/lua/waf-ban.lua` in the `http` block.
This activates the WAF on all sites without editing individual site configs.

To disable the WAF on one `location`, add both `rewrite_by_lua_block { return }` and `access_by_lua_block { return }` to that `location`.
Overriding only the access handler leaves the rewrite-phase checks active.

### WAF rules

`config/waf-local-overrides.lua` defines the local rule tables.
A request that matches a rule receives `403`.
The rules inspect these attack classes across request components:

| Attack                             | Inspected surfaces                                                                     |
| ---------------------------------- | -------------------------------------------------------------------------------------- |
| SQL injection                      | Query values, query names, cookies, bodies, `Referer`, `User-Agent`, client IP headers |
| XSS                                | Query values, query names, cookies, bodies, `Referer`, `User-Agent`                    |
| Command injection                  | Query values, query names, cookies, bodies, Shellshock in all headers                  |
| File inclusion and path traversal  | Raw path, decoded path, query values, query names, cookies, bodies                     |
| SSRF                               | Query values, query names, cookies, bodies                                             |
| Code injection and deserialization | Query values, query names, cookies, bodies, all headers                                |
| XML external entities (XXE)        | Query values, query names, cookies, XML bodies                                         |
| Sensitive files and admin paths    | Raw path, decoded path                                                                 |

Path rules run twice: once against the raw path (upstream) and once against the decoded, normalized `$uri` (`waf-ban.lua`).
This blocks percent-encoded paths such as `/xmlrpc%2ephp` before backend servers decode them.

Upstream inspects only query values.
`waf-ban.lua` applies the same query rules to more surfaces:

- Every query argument name. A hit returns `403`.
- Every decoded cookie name and value when `WAF_cookie_block` is `true` (default).
  `WAF_cookie_skip` lists cookie name patterns to skip, such as opaque proxy session tokens.
- Request bodies up to 128 KB when `WAF_body_block` is `true` (default):
    - URL-encoded form fields.
    - Non-file multipart form fields.
    - JSON keys and values. `waf-ban.lua` scans unparseable JSON, JSON deeper than 100 levels, or JSON with over 1,000 entries as decoded text.
    - XML bodies (`xml` or `+xml` media types), checked with a dedicated linear XML rule for XXE, XInclude, XSLT, script tags, and template injection.
    - `text/plain` or untyped bodies that start with `{`, `[`, or `<`, scanned as JSON or XML.

URL-encoded, JSON, or XML bodies over 128 KB return `413`.
URL-encoded or multipart bodies with more than 1,000 fields also return `413`.
`text/plain` bodies over 128 KB stay unchecked.
Multipart uploads can exceed 128 KB because `waf-ban.lua` streams them in 1 MB chunks, skips file parts (`filename` parameter), and caps non-file field text at 128 KB.
Ambiguous multipart boundaries or duplicate `Content-Disposition` headers return `403`.

`WAF_body_skip` lists decoded `$uri` patterns whose bodies stay unchecked, such as rich-text editor endpoints.
To tune a new site without blocking, set `WAF_body_block` or `WAF_cookie_block` to `false`.
In log-only mode, hits write `Would block (log only)` to the error log and do not return `403` or `413`.
`WAF_POST_Request_table` stays empty so upstream never buffers large upload bodies into memory.

The WAF does not scan uploaded file contents.
Instead, path rules return `403` for script extensions (including double extensions) inside common upload directories listed in `config/waf-local-overrides.lua`.

Upstream parses only the first 100 query arguments and the first 100 headers.
`waf-ban.lua` rejects requests that exceed either limit with an uncounted `403`.

### Login rate limiting

`config/nginx-waf.conf` defines an opt-in `waf_login` rate-limit zone set to 10 POST requests per minute per address.
It covers common login endpoints defined in `$waf_login_key` inside `config/nginx-waf.conf`.
The zone stays inactive until a `server` or `location` block adds `limit_req zone=waf_login burst=5 nodelay;`.
Requests above the limit receive the site's `limit_req_status` (or nginx default `503`), which never counts toward a ban.

### Exponential IP bans

Upstream returns `403` on a WAF rule hit without banning the client address.
`waf-ban.lua` adds temporary, in-memory exponential banning with minimal latency:

- Bans live only in nginx shared memory (`waf_bans`), isolated from short-lived strike counters (`waf_strikes`).
  No external database or disk I/O runs on the request path.
  A reload keeps active bans and ban counts, while a full restart clears them.
- On every request, the rewrite phase checks `waf_bans` first and immediately returns `403` before running header logic or request parsers.
- The log phase counts WAF `403` responses per client address.
  After 5 hits in 10 minutes, the address receives a 1-hour ban.
- Each repeat ban doubles the duration: 1, 2, 4, 8, and up to 512 hours (tenth ban and later).
  The ban history expires 30 days after the last ban ends.
- Ban claiming uses an atomic shared-dict `add`, so parallel requests or HTTP/2 bursts ban an address only once.
- Private and loopback addresses are never banned.
- `403` responses from backend applications, earlier `return 403` rules, or content-phase checks (such as `autoindex off`) do not count.
  `deny` rules in a site location run before the Lua access handler and still count.
- Requests whose User-Agent matches `AI_AGENTS` or `CRAWLERS` require 50 hits in 10 minutes before a ban.
  Generic HTTP clients still trigger a ban at 5 hits.

Edit `LIMIT`, `WINDOW`, `BAN`, `CRAWLER_LIMIT`, `CRAWLER_WINDOW`, and `BAN_HISTORY_TTL` in `config/waf-ban.lua` to adjust these thresholds.

Upstream also applies a 24-hour ban for flood bursts (over 10,000 requests in 500 ms), failed JavaScript challenge floods, forbidden methods (`CONNECT`, `TRACE`), or forged proxy headers.
`config/waf-local-overrides.lua` allows `OPTIONS`, `PUT`, `PATCH`, and `DELETE` for REST APIs and delegates body size limits to nginx `client_max_body_size`.

### Stats

`config/waf-stats.lua` exposes live counters as JSON on loopback only:

```bash
ssh user@server 'curl -s http://127.0.0.1:9180/ddos_stats' | jq
```

The stats endpoint disables the rewrite and access WAF handlers, so polling it does not affect counters.

| Field                   | Meaning                                                |
| ----------------------- | ------------------------------------------------------ |
| `total_traffic_allowed` | Allowed requests in the current upstream window        |
| `total_traffic_blocked` | Blocked requests in the current upstream window        |
| `requests_blocked`      | Addresses currently blocked by upstream                |
| `requests_per_ip`       | Active request count per address in the current window |
| `js_puzzle_per_ip`      | Failed JavaScript challenges per address               |
| `blocked_ips_ttl`       | Remaining seconds for each upstream ban                |
| `waf_bans`              | Active bans currently stored in `waf_bans`             |
| `keys_listed`           | Number of keys read from `antiddos` (capped at 10,000) |

Key scans cap at 10,000 entries to bound shared-dict lock time.
The script serializes JSON directly so the module build does not depend on `cjson`.

### JavaScript challenge

Upstream enables the JavaScript challenge globally when it bans 100 or more addresses.
Non-browser API and OAI-PMH endpoints listed in `config/waf-local-overrides.lua` skip the automatic challenge while keeping WAF rules and flood protection active.
Whitelisted crawlers in `user_agent_whitelist_table` also skip the challenge.

### User-Agent policy

Crawlers, scrapers, and AI agents stay allowed under rate limits.
Only attack payloads trigger a ban, so `user_agent_blacklist_table` stays empty.
`waf-ban.lua` limits each AI agent family listed in `AI_AGENTS` to 10 requests per minute across all addresses and returns `429` with `Retry-After: 60`.
`429` responses never count toward a ban.
Edit `AI_LIMIT`, `AI_WINDOW`, and `AI_AGENTS` in `config/waf-ban.lua` to adjust this limit.

### Client address behind a proxy

Upstream reads `X-Forwarded-For` or `CF-Connecting-IP` only when the peer address appears in `proxy_header_table`.
If your reverse proxy uses another public address, define `localized_global.proxy_header_table` in `config/waf-local-overrides.lua`.

When nginx `realip` replaces the peer address with the client address, `waf-ban.lua` clears consumed `X-Forwarded-For` and `CF-Connecting-IP` headers so upstream does not mistake them for spoofed proxy headers.
For requests arriving from an unlisted private proxy address, `waf-ban.lua` clears only `CF-Connecting-IP`.
Without the `realip` module, `waf-ban.lua` clears no headers.

## Local rules

- Edit `config/waf-local-overrides.lua` and run `scripts/deploy.sh user@server` to deploy changes.
- Each table in `config/waf-local-overrides.lua` replaces the upstream default table completely.
- Keep `CHANGE_ME_TO_LONG_RANDOM_SECRET` as the placeholder in git.
  The install script writes the real secret only on the server.

## Upstream updates

`lua/anti_ddos_challenge.lua` pins the deployed upstream revision.
`nginx -t` does not compile `waf.lua`, so pinning prevents unreviewed upstream errors from reaching production.
Keep upstream files unchanged to avoid merge conflicts.

Configure the read-only `upstream` remote once:

```bash
git remote add upstream https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS.git
git remote set-url --push upstream DISABLED
```

To adopt a newer upstream commit:

1. Run `git fetch upstream` and inspect changes in upstream `precompile_waf_*_table` functions.
2. Mirror those compilation changes in `tests/test-rules.lua`.
3. Run `git merge <commit>` and run the full test suite.
4. Push the verified branch to your fork.

## Test

```bash
shellcheck -x scripts/*.sh scripts/lib/*.sh tests/*.sh
bash tests/test-scripts.sh
lua tests/test-rules.lua
lua tests/test-ban.lua
lua tests/test-stats.lua
python3 -I tests/test-linear.py
```

## Credits

The upstream WAF, JavaScript challenge, and rule engine are the work of Conor McKnight ([C0nw0nk/Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS)).
This fork adds deployment automation, local defense rules, and exponential IP banning.
To support the upstream author, use the Sponsor button on the upstream repository or the [upstream funding page](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/funding).

## License

MIT, see `LICENSE`.
