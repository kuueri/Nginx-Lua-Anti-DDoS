# Nginx WAF

This is a fork of [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) by Conor McKnight ([C0nw0nk](https://github.com/C0nw0nk)).
Its scripts install and update the upstream WAF on Ubuntu and RPM-based servers, and add local rules to it.
The upstream documentation is in the [upstream README](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS#readme).

## Requirements

- An installed nginx. The scripts do not install nginx.
- Root access.

If nginx has no Lua module, the scripts build it from source. Ubuntu 24.04 no longer has the `libnginx-mod-http-lua` package.
The scripts do these steps:

1. They install the missing build packages: with apt on Ubuntu, with dnf on RPM (Rocky, RHEL, AlmaLinux).
2. They build LuaJIT, lua-resty-core, and the ndk and lua modules in `/usr/local/src/nginx-lua`.
   The modules use OpenSSL, because upstream needs `ngx.hmac_sha1`. A module without OpenSSL from an older run gets a rebuild.
3. They add `load_module` lines to the top of the main `nginx.conf`, and `lua_package_path` to its `http` block.
4. If `nginx -t` then fails, they restore `nginx.conf`.

## Layout

| Path                             | Purpose                                                          |
| -------------------------------- | ---------------------------------------------------------------- |
| `lua/anti_ddos_challenge.lua`    | Upstream WAF, installed as `/etc/nginx/lua/waf.lua`              |
| `config/nginx-waf.conf`          | `http` block snippet that turns the WAF on for all sites         |
| `config/waf-local-overrides.lua` | Local secret and WAF rules, installed in `/etc/nginx/lua/`       |
| `config/waf-ban.lua`             | Blocks addresses after repeated WAF rule hits                    |
| `scripts/install-*.sh`           | First install: makes the server secret, then runs the update     |
| `scripts/update-*.sh`            | Update: copies `waf.lua` from `lua/` and applies `config/`       |
| `scripts/lib/common.sh`          | Shared module build, sync, backup, rollback, and reload logic    |
| `tests/test-scripts.sh`          | Runs every script against a scratch root with stub commands      |
| `tests/test-rules.lua`           | Checks the local rules against sample requests, as upstream does |

## Deploy

Run this command from this workspace:

```bash
scripts/deploy.sh user@server
```

The command copies `scripts/`, `config/`, and `lua/` without changes to `/opt/nginx-waf` on the server.
On a new server, it then runs the installer. On an installed server, it runs the update script.
The server does not need access to this repo. It needs only ssh and sudo for `user`.

To do the same steps manually, copy `scripts/`, `config/`, and `lua/` into one root-owned directory on the server:

```bash
scp -r scripts config lua user@server:/tmp/nginx-waf/
ssh user@server
sudo mkdir -p /opt/nginx-waf
sudo cp -r /tmp/nginx-waf/scripts /tmp/nginx-waf/config /tmp/nginx-waf/lua /opt/nginx-waf/
sudo chown -R root:root /opt/nginx-waf
```

Keep the copy on the server. Each update reads `config/` again.

## Install and update

| Platform | First install                                   | Update                                         |
| -------- | ----------------------------------------------- | ---------------------------------------------- |
| Ubuntu   | `sudo /opt/nginx-waf/scripts/install-ubuntu.sh` | `sudo /opt/nginx-waf/scripts/update-ubuntu.sh` |
| RPM      | `sudo /opt/nginx-waf/scripts/install-rpm.sh`    | `sudo /opt/nginx-waf/scripts/update-rpm.sh`    |

Each run does these steps:

1. It copies `lua/anti_ddos_challenge.lua` without changes to `/etc/nginx/lua/waf.lua`.
2. It installs `config/waf-local-overrides.lua` and `config/nginx-waf.conf`. It keeps the secret of the server.
3. It backs up the old files to `/var/backups/nginx-waf/<timestamp>/`. It reloads nginx only when a file changed.
4. If nginx does not load `waf.conf`, it adds `include /etc/nginx/conf.d/waf.conf;` to the `http` block of the main `nginx.conf`.
   If `nginx.conf` already contains the WAF directives from a manual setup, the include replaces them.
   It restores the old files and `nginx.conf` when `nginx -t` fails or when nginx still does not load `waf.conf`.
5. If SELinux is in Enforcing mode and the boolean `httpd_execmem` is off, it adds `jit.off()` to the installed overrides file.
   SELinux then does not let nginx create executable memory, and the LuaJIT JIT needs it. Without `jit.off()`, each request stops the worker with `Lua VM crashed, reason: runtime code generation failed`.
   Lua then runs without the JIT. The SELinux policy does not change.

### Upstream commit

`lua/anti_ddos_challenge.lua` is the file of the upstream commit that this fork last merged.
The fork does not follow upstream `master` for two reasons:

- Upstream changes several times each week.
- `nginx -t` does not compile `waf.lua`. A defective upstream change can thus go live without a warning.

Keep the upstream files unchanged, so that a merge has no conflicts.
To use a newer commit, do these steps:

1. Run `git fetch upstream` and read the changes in the upstream `precompile_waf_*_table` functions.
2. Copy those changes into `tests/test-rules.lua`.
3. Run `git merge <commit>`, then run the tests.
4. When the tests pass, push the merge.

The `upstream` remote has no push URL, so changes go only to this fork.

### nginx upgrades

After an nginx upgrade, the source-built ndk and lua modules stay on the old version. nginx then cannot reload or start.
The update script rebuilds the modules from `BUILD_DIR` and restarts nginx.
It also installs a package-manager hook that runs the update script immediately after a package upgrade. You do not need a cron job.

- RPM: a dnf `post-transaction-actions` hook runs `update-rpm.sh` after each nginx package upgrade.
- Ubuntu: apt has no hook for one package. A dpkg `Post-Invoke` hook in `/etc/apt/apt.conf.d/99nginx-waf` runs `update-ubuntu.sh` after each package run.
  That run changes nothing when nginx and the WAF files did not change.

The hook builds and runs code as root. The script installs the hook only when root owns `/opt/nginx-waf`, `BUILD_DIR`, and each parent directory.
Only root can have write access to them.
A build by the scripts goes to `/usr/local/src/nginx-lua`, which meets these conditions.
An older manual build in `~/build/nginx-lua` does not. Move it once, and the update script then uses the new path:

```bash
sudo mv ~/build/nginx-lua /usr/local/src/nginx-lua
sudo chown -R root:root /usr/local/src/nginx-lua
sudo chmod -R go-w /usr/local/src/nginx-lua
```

On RPM, the hook needs dnf4, as on Rocky, RHEL, and AlmaLinux 8 and 9.
If the script cannot install the dnf plugin, it shows a warning. Then you must run `update-rpm.sh` manually after each nginx upgrade.

## WAF on all sites

The installed `waf.conf` contains `access_by_lua_file /etc/nginx/lua/waf.lua;` in the `http` block.
The WAF is thus active on all sites and paths immediately after the install. You do not edit the site configs.

The WAF rules apply to all requests. A request that matches a rule gets `403`.
Upstream does not block the address for that. `waf-ban.lua` does:

- It counts the `403` responses from the WAF for each client address.
- After 5 of them in 10 minutes, it blocks the address for 1 hour. All requests from that address then get `403`.
- It does not count a `403` from the application, for example DSpace, or from a `return 403` in the site config.
- It never blocks private or loopback addresses, so a reverse proxy cannot be blocked.

To change these numbers, edit `LIMIT`, `WINDOW`, and `BAN` in `config/waf-ban.lua`.

Upstream also blocks an address for 24 hours for these causes:

- More than 10,000 requests in 500 ms.
- More than 1,000 failed JavaScript challenges in 1 second.
- A forged `X-Forwarded-For` or `CF-Connecting-IP` header.

The block applies to the client address, not to the address of the reverse proxy.

The JavaScript challenge is automatic. Upstream turns it on only when more than 100 addresses are blocked. Then the challenge applies to all paths.
When 100 or fewer addresses are blocked, no request gets the challenge.

API clients and OAI-PMH harvesters are not browsers. They cannot solve the JavaScript challenge.
`localized_global.master_switch_custom_hosts` in `config/waf-local-overrides.lua` lists the paths that skip the challenge:

- DSpace: `/oai/`, `/rest/`, `/server/api/`, `/server/oai/`
- WordPress: `/wp-json/`
- SLiMS: `/api/v1/`, `/oai.php`, `/oai2.php`

The WAF rules still apply to these paths. Only the challenge does not.
To add a path, add an entry with the same form to that table.
This list is used only when the challenge stays in mode 3. The automatic challenge during an attack ignores the list.

`localized_global.user_agent_blacklist_table` blocks some User-Agents with `403` on all paths, these paths included.
It is the upstream list without `curl` and `python`, because OAI-PMH harvesters and REST clients use these User-Agents.
The upstream entry `OAI-` also blocked `OAI-Harvester`, so the list uses `OAI-SearchBot` instead.

Googlebot, Bingbot, and the Turnitin crawler skip the blacklist and the challenge, also during an attack. Google Scholar uses Googlebot.
`localized_global.user_agent_whitelist_table` matches their User-Agents. The WAF rules still apply to them.
A client can fake its User-Agent. With a fake crawler User-Agent, the client also skips the challenge.

To turn the WAF off for one `location`, add `access_by_lua_block { return }` to it. This handler replaces the handler from the `http` block.

Upstream can get the client address from `X-Forwarded-For` or `CF-Connecting-IP`.
It does this only when the request comes from an address in its `proxy_header_table`.
The default list contains loopback, private ranges, and Cloudflare.
If your reverse proxy or load balancer has a different public address, set `localized_global.proxy_header_table` in `config/waf-local-overrides.lua`.
That table replaces the default list.
Without it, all visitors share the address of the proxy and its rate limits.

If nginx uses `set_real_ip_from` and `real_ip_header X-Forwarded-For`, nginx already replaces the proxy address with the client address.
Upstream then sees a public address together with `X-Forwarded-For`. Upstream calls this proxy impersonation and blocks the visitor for 24 hours.
To prevent this, `waf-ban.lua` removes `X-Forwarded-For` from requests where the realip module changed the address.
Upstream then uses the client address from nginx. A request from an address that `set_real_ip_from` does not list keeps its header.

## Local rules

- To change a rule, edit `config/waf-local-overrides.lua`. Then copy it to the server and run the update script.
- Each `WAF_*` table in that file **replaces** the upstream default table. It does not add to it. Keep the upstream defaults that you still need.
  The upstream defaults change only when you merge a newer upstream commit.
- Keep the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder in the repo.
  The first install makes the real secret. The secret is only in `/etc/nginx/lua/waf-local-overrides.lua` on the server.

## Test

```bash
bash tests/test-scripts.sh
lua tests/test-rules.lua
lua tests/test-ban.lua
```

## Credits

The WAF, its JavaScript challenge, and its rule engine are the work of Conor McKnight ([C0nw0nk/Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS)).
This fork adds only the install scripts, the local rules, and `waf-ban.lua`.
To support the upstream author, use the Sponsor button of this repo or the [upstream funding page](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/funding).

## License

MIT, see `LICENSE`.
