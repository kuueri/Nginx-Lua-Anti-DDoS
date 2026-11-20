# Nginx WAF

This repo is a fork of [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) by Conor McKnight ([C0nw0nk](https://github.com/C0nw0nk)).
Its scripts install and update the upstream WAF on Ubuntu and RPM-based servers, and add local rules to it.
For the upstream documentation, read the [upstream README](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS#readme).

## Requirements

- An installed nginx. The scripts do not install nginx.
- Root access on the server.

The scripts do not need a Lua module in nginx. If nginx has no Lua module, the update script builds one from source.
Ubuntu 24.04 no longer has the `libnginx-mod-http-lua` package, so this build also applies to Ubuntu.

## Layout

| Path                                       | Purpose                                                                 |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `lua/anti_ddos_challenge.lua`              | Upstream WAF, installed as `/etc/nginx/lua/waf.lua`                     |
| `config/nginx-waf.conf`                    | `http` block snippet that turns on the WAF for all sites                |
| `config/waf-local-overrides.lua`           | Local secret and WAF rules                                              |
| `config/waf-ban.lua`                       | Bans addresses after repeated WAF rule hits                             |
| `config/waf-stats.lua`                     | WAF stats as JSON on `http://127.0.0.1:9180/ddos_stats`                 |
| `scripts/deploy.sh`                        | Copies the repo files to a server over ssh, then installs or updates    |
| `scripts/install-deb.sh`, `install-rpm.sh` | First install: makes the server secret, then runs the update script     |
| `scripts/update-deb.sh`, `update-rpm.sh`   | Update: builds the Lua module if necessary, then installs the WAF files |
| `scripts/lib/common.sh`                    | Shared module build, file sync, backup, rollback, and reload            |
| `tests/`                                   | Tests for the scripts, the local rules, and `waf-ban.lua`               |
| `debian/`, `rpm/`, `.github/`, `CHANGELOG` | Upstream packaging and CI. The scripts do not use them.                 |

The `deb` scripts support Ubuntu. The `rpm` scripts support Rocky, RHEL, AlmaLinux, and other RHEL-family systems.

## Deploy

Run this command from this workspace:

```bash
scripts/deploy.sh user@server
```

The command copies `scripts/`, `config/`, and `lua/` to `/opt/nginx-waf` on the server.
On a new server, it then runs the install script. On an installed server, it runs the update script.
The server does not need access to this repo. It needs only ssh and sudo for `user`.

The command tells you before ssh or sudo can ask for a password:

```text
[08:57:01] INFO: Connecting to user@server over ssh; type the ssh password of the remote user if ssh asks for it
user@server's password:
[08:57:04] INFO: Running the installer as root on user@server; type the sudo password of the remote user if sudo asks for it
[sudo] password for user on server:
```

Both steps use one ssh connection, so ssh asks for the password only once.

Each script prints one line for each step, with the time and a level:

- `INFO` on stdout: a step starts or ends normally.
- `WARN` on stdout, in yellow on a terminal: the script continues, but you must know about it. Examples: the update hook is not installed, or the LuaJIT JIT is off.
- `ERROR` on stderr: the script stops. The line before it names the step that failed.
  The scripts restore the previous files before they stop.

To get `WARN` without color, set `NO_COLOR=1`. Output to a file or a pipe has no color.

To do the same steps manually, copy the three directories into one root-owned directory on the server:

```bash
scp -r scripts config lua user@server:/tmp/nginx-waf/
ssh user@server
sudo mkdir -p /opt/nginx-waf
sudo cp -r /tmp/nginx-waf/scripts /tmp/nginx-waf/config /tmp/nginx-waf/lua /opt/nginx-waf/
sudo chown -R root:root /opt/nginx-waf
```

Keep `/opt/nginx-waf` on the server. Each update and the package-manager hook use the files in it.

## Install and update

| Platform | First install                                | Update                                      |
| -------- | -------------------------------------------- | ------------------------------------------- |
| Ubuntu   | `sudo /opt/nginx-waf/scripts/install-deb.sh` | `sudo /opt/nginx-waf/scripts/update-deb.sh` |
| RPM      | `sudo /opt/nginx-waf/scripts/install-rpm.sh` | `sudo /opt/nginx-waf/scripts/update-rpm.sh` |

The install script runs the update script. The update script does these steps:

1. It checks the Lua module of nginx, and builds the module when one of these conditions is true:
    - An nginx upgrade left the module on the old version. The script then restarts nginx, because a reload keeps the old nginx binary.
    - The module has no OpenSSL support. Upstream needs `ngx.hmac_sha1`, and only a module with OpenSSL has it. The script then restarts nginx.
    - nginx has no Lua module. The script then adds `load_module` lines to the top of the main `nginx.conf`, and `lua_package_path` to its `http` block. If `nginx -t` then fails, the script restores `nginx.conf`.
2. It prepares the new WAF files:
    - `lua/anti_ddos_challenge.lua` without changes, as `/etc/nginx/lua/waf.lua`.
    - `config/waf-local-overrides.lua` with the secret of the server, `config/waf-ban.lua`, and `config/nginx-waf.conf`.
    - If SELinux is in Enforcing mode and the boolean `httpd_execmem` is off, `jit.off()` at the end of the overrides file.
      Without `jit.off()`, each request stops the worker with `Lua VM crashed, reason: runtime code generation failed`, because SELinux does not let nginx create executable memory for the LuaJIT JIT.
      With `jit.off()`, Lua runs without the JIT. The SELinux policy does not change.
3. When the new files are the same as the installed files, it goes to step 6.
4. It backs up the installed files to `/var/backups/nginx-waf/<timestamp>/`, then installs the new files.
   If nginx does not load `waf.conf`, it adds `include /etc/nginx/conf.d/waf.conf;` to the `http` block of the main `nginx.conf`.
   If `nginx.conf` already contains the WAF directives from a manual setup, the include replaces them.
   It restores the old files and `nginx.conf` when `nginx -t` fails, or when nginx still does not load `waf.conf`.
5. It reloads nginx.
6. It installs the package-manager hook. See [nginx upgrades](#nginx-upgrades).

The module build goes to `/usr/local/src/nginx-lua`. It contains LuaJIT, lua-resty-core, and the ndk and lua modules.
The update script installs only the build packages that are missing, with apt on Ubuntu and with dnf on RPM.

### nginx upgrades

After an nginx upgrade, the source-built ndk and lua modules stay on the old version. nginx then cannot reload or start.
The update script rebuilds the modules from `BUILD_DIR` and restarts nginx.
It also installs a package-manager hook that runs the update script immediately after a package upgrade. You do not need a cron job.

- RPM: a dnf `post-transaction-actions` hook runs `update-rpm.sh` after each nginx package upgrade.
- Ubuntu: apt has no hook for one package. A dpkg `Post-Invoke` hook in `/etc/apt/apt.conf.d/99nginx-waf` runs `update-deb.sh` after each package run.
  That run changes nothing when nginx and the WAF files did not change.

The hook builds and runs code as root.
So the script installs the hook only when these conditions are true for `/opt/nginx-waf`, `BUILD_DIR`, and each parent directory:

- Root owns them.
- Only root has write access to them.

Otherwise, the script removes an old hook and shows a warning.
A build by the scripts goes to `/usr/local/src/nginx-lua`, which meets these conditions.
An older manual build in `~/build/nginx-lua` does not. Move it one time, and the update script then uses the new path:

```bash
sudo mv ~/build/nginx-lua /usr/local/src/nginx-lua
sudo chown -R root:root /usr/local/src/nginx-lua
sudo chmod -R go-w /usr/local/src/nginx-lua
```

On RPM, the hook needs dnf4, as on Rocky, RHEL, and AlmaLinux 8 and 9.
If the script cannot install the dnf plugin, it shows a warning. Then you must run `update-rpm.sh` manually after each nginx upgrade.

## WAF behavior

### All sites

The installed `waf.conf` contains `access_by_lua_file /etc/nginx/lua/waf.lua;` in the `http` block.
Thus the WAF is active on all sites and paths immediately after the install. You do not edit the site configs.

To turn off the WAF for one `location`, add `access_by_lua_block { return }` to it. This handler replaces the handler from the `http` block.

### WAF rules

`config/waf-local-overrides.lua` contains the rules. A request that matches a rule gets `403`.
The rules check the request path, each decoded query value, and some header values:

| Attack                                                    | Checked in                                                          |
| --------------------------------------------------------- | ------------------------------------------------------------------- |
| SQL injection                                             | Query values, `Cookie`, `Referer`, `User-Agent`, `X-Forwarded-For`  |
| XSS                                                       | Query values, `Cookie`, `Referer`, `User-Agent`                     |
| Command injection                                         | Query values, and Shellshock in all headers                         |
| File inclusion and path traversal                         | Path, query values                                                  |
| SSRF                                                      | Query values                                                        |
| Java code injection (Log4Shell, SpEL) and deserialization | Query values, all headers                                           |
| PHP code injection and object injection                   | Query values, PHP tags in all headers, object injection in `Cookie` |
| XML external entities (XXE)                               | Query values                                                        |
| ASP, JSP, and ERB code injection                          | Query values                                                        |
| Sensitive files and admin paths                           | Path                                                                |

The path rules check the path twice: as the client sent it, and after nginx decodes `%XX` and resolves `..`.
So `/xmlrpc%2ephp` gets `403` like `/xmlrpc.php`, because nginx and Tomcat decode the path before they pick a file.

Upstream checks only the query values.
`waf-ban.lua` uses the query value rules on more parts of the request:

- The name of each query argument. A hit gets `403`.
- Each cookie value, after `waf-ban.lua` decodes it as PHP does.
  With `WAF_cookie_block = false`, a hit only writes a `Would block (log only)` line, because cookies often carry JSON or tokens.
  `WAF_cookie_skip` lists the cookie names whose values are not checked, for example the `sl-session` token of a SafeLine proxy.
- The request body, up to 128 KB:
    - each urlencoded field
    - each multipart field that is not a file
    - each JSON value, with the rules for its object key; JSON that does not parse, or that nests deeper than 100 levels or holds more than 1000 values, as one text

A urlencoded or multipart body with more than 1000 fields gets `413`.
A urlencoded or JSON body larger than 128 KB also gets `413`.
A multipart body larger than 128 KB is an upload, and `waf-ban.lua` does not check it.

With `WAF_body_block = false`, a body hit only writes a `Would block (log only)` line to the error log.
Set `WAF_body_block` to `true` after one week without false positives.
Then a body hit gets `403` and counts toward a ban.
`WAF_body_skip` lists the paths whose bodies are not checked, for example the WordPress editors, where HTML and SQL words are normal content.
Upstream's own POST table stays empty.
When a POST rule exists, upstream reads the whole body of each POST request into memory, uploads included.

The rules do not check uploaded files.
Instead, a request for a script in an upload directory (`wp-content/uploads`, `/files`, `/repository`, `/images/docs`, `/images/persons`) gets `403`, so an uploaded webshell cannot run.
The script extensions are `php` (also `php5` and similar), `phtml`, `phar`, `jsp`, `jspx`, `asp`, `aspx`, `cgi`, `pl`, and `sh`, also in double extensions such as `shell.php.jpg`.

CSRF checks need the `Origin` header, so the rules do not cover CSRF.

`config/nginx-waf.conf` defines the `waf_login` rate-limit zone: 10 login POSTs per minute for each address.
The zone has no effect on a site until the site adds `limit_req zone=waf_login burst=5 nodelay;` to its `server` block or its login `location`.
The zone counts POSTs to these paths, at the site root or one directory below it:

- WordPress: `wp-login.php`
- SLiMS: `index.php`, but not under `admin/` or `wp-admin/`
- DSpace: `password-login`, `rest/login`, and `server/api/authn/login`

A request above the limit gets `429` when the server sets `limit_req_status 429`, and `503` when it does not.
Neither response counts toward a ban.

Upstream checks only the first 100 query arguments and the first 100 headers.
`waf-ban.lua` rejects a request with more query arguments or more headers with `403`, and this `403` does not count toward a ban.

### Bans

A ban rejects all requests from one client address for a time.

The WAF rules apply to all requests. A request that matches a rule gets `403`, but upstream does not ban the address.
`waf-ban.lua` adds that ban:

- It counts the `403` responses from the WAF for each client address. The WAF sends `403` only for a request with an attack payload, because the User-Agent blacklist is empty.
- After 5 of them in 10 minutes, it bans the address for 1 hour.
- Each later ban of the same address is two times longer than the ban before it.
  So the next bans last 2 hours, 4 hours, 8 hours, and so on, with no maximum.
  The ban count is in the `waf_strikes` shared dict, so a reload keeps it and only an nginx restart clears it.
- It does not count a `403` from the application, for example DSpace, or from a `return 403` in the site config.
- It never bans private or loopback addresses, so it cannot ban a reverse proxy.
- It bans crawlers, AI agents, and Turnitin only after 50 of them in 10 minutes. These are User-Agents that contain `bot`, `crawl`, `spider`, `slurp`, `turnitin`, or `facebookexternalhit`, and the AI agent families.
  A crawler can follow a link with an attack payload that an attacker put on another site. The WAF rejects that request with `403`, and a few such links do not ban the crawler.
  Any client can send a crawler User-Agent, so the higher limit stops an attacker who uses one from probing the rules without end.
- It bans generic HTTP clients, for example `curl` and `python-requests`, when they send attack payloads.

To change these numbers, edit `LIMIT`, `WINDOW`, `BAN`, `CRAWLER_LIMIT`, and `CRAWLER_WINDOW` in `config/waf-ban.lua`.

Upstream bans an address for 24 hours for these causes:

- More than 10,000 requests in 500 ms.
- More than 1,000 failed JavaScript challenges in 1 second.
- A request method that upstream prohibits: `PATCH`, `PUT`, `DELETE`, `CONNECT`, or `TRACE`.
- A forged `X-Forwarded-For` or `CF-Connecting-IP` header.

Upstream also prohibits `OPTIONS`, but `config/waf-local-overrides.lua` removes it from that list.
Microsoft Office and some browsers send `OPTIONS` before they open a document link, so these readers got a 24-hour ban.
`OPTIONS` requests now go to the application.

Upstream and `waf-ban.lua` keep their bans in nginx shared memory. A reload keeps the bans. Only a restart of nginx removes them.

### Stats

`waf-stats.lua` shows the WAF counters as JSON. It is an adapted version of the example in the upstream wiki page [Anti-DDoS Stats and Metrics](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/Anti%E2%80%90DDoS-Stats-and-Metrics).
`config/nginx-waf.conf` serves it only on the loopback address, because the output lists client addresses:

```bash
ssh <server> 'curl -s http://127.0.0.1:9180/ddos_stats' | jq
```

Port 9180 is far from the DSpace ports (8080, 8787, 5432, and 19123).
The WAF does not run on this request, so the request does not change the stats.

| Field                   | Meaning                                                                     |
| ----------------------- | --------------------------------------------------------------------------- |
| `total_traffic_allowed` | Requests in the current upstream rate limit window, not since nginx started |
| `total_traffic_blocked` | Blocked requests in the current rate limit window                           |
| `requests_blocked`      | Addresses that upstream blocked in the current block duration               |
| `requests_per_ip`       | Requests of each active address in the current rate limit window            |
| `js_puzzle_per_ip`      | Failed JavaScript challenges of each address                                |
| `blocked_ips_ttl`       | Seconds until the upstream ban of each address ends                         |
| `waf_bans`              | Addresses that `waf-ban.lua` bans now                                       |
| `keys_listed`           | Keys read from the `antiddos` shared dict, at most 10,000                   |

The 10,000 limit is necessary because nginx locks the shared dict while it lists the keys, and the WAF waits for that lock.
The endpoint makes the JSON itself, because the Lua module that `build_lua_module` builds has no `cjson` library.
The counters are in shared memory, so a restart of nginx sets them to zero.

### JavaScript challenge

The JavaScript challenge is automatic. Upstream turns on the challenge for all paths when it bans 100 or more addresses.
When upstream bans fewer than 100 addresses, no request gets the challenge.

API clients and OAI-PMH harvesters are not browsers. They cannot solve the JavaScript challenge.
During an attack, they get the challenge too, because no path skips it.
Only the User-Agent whitelist skips the challenge, for Googlebot, Bingbot, and Turnitin.

### User-Agent lists

Crawlers, scrapers, AI agents, and Turnitin can access the sites, with strict limits. Only an attack payload causes a ban.
So `localized_global.user_agent_blacklist_table` is empty. It replaces the upstream list, which rejected `curl`, `python`, `ChatGPT`, `GPTBot`, `OAI-`, empty User-Agents, and others with `403`.
Each `403` counts toward a ban, so the upstream list would ban these clients.

The nginx config of each site can limit crawlers with `limit_req`.
AI agents get a strict limit in all sites. `waf-ban.lua` limits each AI agent family to 10 requests per minute, for all addresses together.
For example, all `ChatGPT-User` requests share one limit. A request above the limit gets `429` with `Retry-After: 60`. A `429` does not count toward a ban.
`AI_AGENTS` in `config/waf-ban.lua` lists the families, for example `gptbot`, `chatgpt-user`, `claude-user`, and `perplexitybot`.
To change the limit, edit `AI_LIMIT` and `AI_WINDOW` in the same file.

Googlebot, Bingbot, and the Turnitin crawler skip the blacklist and the challenge, also during an attack. Google Scholar uses Googlebot.
`localized_global.user_agent_whitelist_table` matches their User-Agents. The WAF rules still apply to them.
A client can fake its User-Agent. With a fake crawler User-Agent, the client also skips the challenge.

### Client address behind a proxy

Upstream can get the client address from `X-Forwarded-For` or `CF-Connecting-IP`.
It does this only when the request comes from an address in its `proxy_header_table`.
The default list contains loopback, private ranges, and Cloudflare.
If your reverse proxy or load balancer has a different public address, set `localized_global.proxy_header_table` in `config/waf-local-overrides.lua`.
That table replaces the default list.
Without it, all visitors share the address of the proxy and its rate limits.

If nginx uses `set_real_ip_from` and `real_ip_header X-Forwarded-For`, nginx already replaces the proxy address with the client address.
Upstream then sees a public address together with `X-Forwarded-For`. Upstream calls this proxy impersonation and bans the visitor for 24 hours.
To prevent this, `waf-ban.lua` removes `X-Forwarded-For` from requests where the realip module changed the address.
Upstream then uses the client address from nginx. A request from an address that `set_real_ip_from` does not list keeps its header.

## Local rules

- To change a rule, edit `config/waf-local-overrides.lua`. Then run `scripts/deploy.sh user@server`.
- Each table in that file **replaces** the upstream default table. It does not add to it. Keep the upstream defaults that you still need.
  The upstream defaults change only when you merge a newer upstream commit.
- Keep the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder in the repo.
  The first install makes the real secret. The secret is only in `/etc/nginx/lua/waf-local-overrides.lua` on the server.

## Upstream updates

`lua/anti_ddos_challenge.lua` is the file of the upstream commit that this fork last merged.
The fork does not follow upstream `master` for two reasons:

- Upstream changes several times each week.
- `nginx -t` does not compile `waf.lua`. Thus a defective upstream change can go live without a warning.

Keep the upstream files unchanged, so that a merge has no conflicts.
In a new clone, add the `upstream` remote one time. The second command disables push to it:

```bash
git remote add upstream https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS.git
git remote set-url --push upstream DISABLED
```

To use a newer upstream commit, do these steps:

1. Run `git fetch upstream`, and read the changes in the upstream `precompile_waf_*_table` functions.
2. Copy those changes into `tests/test-rules.lua`.
3. Run `git merge <commit>`, then run the tests.
4. When the tests pass, push the merge to this fork.

## Test

```bash
shellcheck -x scripts/*.sh scripts/lib/*.sh tests/*.sh
bash tests/test-scripts.sh
lua tests/test-rules.lua
lua tests/test-ban.lua
lua tests/test-stats.lua
```

## Credits

The WAF, its JavaScript challenge, and its rule engine are the work of Conor McKnight ([C0nw0nk/Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS)).
This fork adds only the install scripts, the local rules, and `waf-ban.lua`.
To support the upstream author, use the Sponsor button of this repo or the [upstream funding page](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/funding).

## License

MIT, see `LICENSE`.
