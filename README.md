# Nginx WAF

These scripts install and update [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) on Ubuntu and RPM-based servers.
They add local rules to the upstream script.

## Requirements

- nginx with a working Lua module. The scripts do not install nginx.
    - Ubuntu: `apt install nginx libnginx-mod-http-lua`.
    - RPM (Rocky, RHEL, AlmaLinux): build the ndk and lua dynamic modules from source in `~/build/nginx-lua`.
      Load them with `load_module` lines at the top of `nginx.conf`.
      Set `lua_package_path` to lua-resty-core in the `http` block.
- The line `include /etc/nginx/conf.d/*.conf;` in the `http` block of `nginx.conf`. The stock Ubuntu and RPM configs have this line.
  The scripts install `waf.conf` in that directory. They stop when nginx does not load it.
- Root access.

## Layout

| Path                             | Purpose                                                          |
| -------------------------------- | ---------------------------------------------------------------- |
| `config/nginx-waf.conf`          | `http` block snippet, installed as `/etc/nginx/conf.d/waf.conf`  |
| `config/waf-local-overrides.lua` | Local secret and WAF rules, installed in `/etc/nginx/lua/`       |
| `scripts/install-*.sh`           | First install: makes the server secret, then runs the update     |
| `scripts/update-*.sh`            | Update: copies `waf.lua` from upstream and applies `config/`     |
| `scripts/lib/common.sh`          | Shared sync, backup, rollback, and reload logic                  |
| `tests/test-scripts.sh`          | Runs every script against a scratch root with stub commands      |
| `tests/test-rules.lua`           | Checks the local rules against sample requests, as upstream does |

## Deploy

Run this command from this workspace:

```bash
scripts/deploy.sh user@server
```

The command copies `scripts/` and `config/` without changes to `/opt/nginx-waf` on the server.
On a new server, it then runs the installer. On an installed server, it runs the update script.
The server does not need access to this repo. It needs only ssh and sudo for `user`.

To do the same steps manually, copy `scripts/` and `config/` into one root-owned directory on the server:

```bash
scp -r scripts config user@server:/tmp/nginx-waf/
ssh user@server
sudo mkdir -p /opt/nginx-waf
sudo cp -r /tmp/nginx-waf/scripts /tmp/nginx-waf/config /opt/nginx-waf/
sudo chown -R root:root /opt/nginx-waf
```

Keep the copy on the server. Each update reads `config/` again.

## Install and update

| Platform | First install                                   | Update                                         |
| -------- | ----------------------------------------------- | ---------------------------------------------- |
| Ubuntu   | `sudo /opt/nginx-waf/scripts/install-ubuntu.sh` | `sudo /opt/nginx-waf/scripts/update-ubuntu.sh` |
| RPM      | `sudo /opt/nginx-waf/scripts/install-rpm.sh`    | `sudo /opt/nginx-waf/scripts/update-rpm.sh`    |

Each run does these steps:

1. It downloads `anti_ddos_challenge.lua` without changes to `/etc/nginx/lua/waf.lua`. The source is the upstream commit that `scripts/lib/common.sh` pins.
2. It installs `config/waf-local-overrides.lua` and `config/nginx-waf.conf`. It keeps the secret of the server.
3. It backs up the old files to `/var/backups/nginx-waf/<timestamp>/`. It reloads nginx only when a file changed.
4. It restores the old files when `nginx -t` fails or when nginx does not load `waf.conf`.
5. It shows a warning when no site runs the WAF.

### Upstream commit

The scripts pin one upstream commit for two reasons:

- Upstream changes several times each week.
- `nginx -t` does not compile `waf.lua`. A defective upstream change can thus go live without a warning.

To use a newer commit, do these steps:

1. Read the changes in the upstream `precompile_waf_*_table` functions.
2. Copy those changes into `tests/test-rules.lua`.
3. Run `lua tests/test-rules.lua`.
4. When the test passes, write the new commit in `URL` in `scripts/lib/common.sh`.

### nginx upgrades on RPM

After an nginx upgrade, the source-built ndk and lua modules stay on the old version. nginx then cannot reload or start.
`update-rpm.sh` rebuilds the modules from `BUILD_DIR` and restarts nginx.
It also installs a dnf `post-transaction-actions` hook. This hook runs `update-rpm.sh` immediately after each nginx package upgrade. You do not need a cron job.

The hook builds and runs code as root. The script installs the hook only when root owns `/opt/nginx-waf`, `BUILD_DIR`, and each parent directory.
Only root can have write access to them.
Keep the module sources in `/usr/local/src/nginx-lua`, not in a home directory. `update-rpm.sh` uses that path when it exists:

```bash
sudo mv ~/build/nginx-lua /usr/local/src/nginx-lua
sudo chown -R root:root /usr/local/src/nginx-lua
sudo chmod -R go-w /usr/local/src/nginx-lua
```

The hook needs dnf4, as on Rocky, RHEL, and AlmaLinux 8 and 9.
If the script cannot install the dnf plugin, it shows a warning. Then you must run `update-rpm.sh` manually after each nginx upgrade.

## Enable the WAF on a site

The scripts only load the WAF. To enable it, add this line to a `server` or `location` block:

```nginx
access_by_lua_file /etc/nginx/lua/waf.lua;
```

Do not add it to API endpoints for clients that are not browsers, for example `/wp-json/`, `/api/v1/`, `/oai/`, and `/rest/`.
These clients cannot solve the JavaScript challenge.

Upstream can get the client address from `X-Forwarded-For` or `CF-Connecting-IP`.
It does this only when the request comes from an address in its `proxy_header_table`.
The default list contains loopback, private ranges, and Cloudflare.
If your reverse proxy or load balancer has a different public address, set `localized_global.proxy_header_table` in `config/waf-local-overrides.lua`.
That table replaces the default list.
Without it, all visitors share the address of the proxy and its rate limits.

## Local rules

- To change a rule, edit `config/waf-local-overrides.lua`. Then copy it to the server and run the update script.
- Each `WAF_*` table in that file **replaces** the upstream default table. It does not add to it. Keep the upstream defaults that you still need.
  The upstream defaults change only when you pin a newer commit.
- Keep the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder in the repo.
  The first install makes the real secret. The secret is only in `/etc/nginx/lua/waf-local-overrides.lua` on the server.

## Test

```bash
bash tests/test-scripts.sh
lua tests/test-rules.lua
```
