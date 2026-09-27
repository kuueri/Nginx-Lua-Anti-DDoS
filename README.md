# Nginx WAF

Install and update [Nginx-Lua-Anti-DDoS](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS) on Ubuntu and RPM-based servers, with local rules layered on top of the upstream script.

## Requirements

- nginx with the Lua module already working. The scripts do not install nginx.
  - Ubuntu: `apt install nginx libnginx-mod-http-lua`.
  - RPM (Rocky, RHEL, AlmaLinux): ndk/lua dynamic modules built from source, see `docs/install-existing-nginx.md`.
- Root access.

## Layout

| Path                             | Purpose                                                            |
| -------------------------------- | ------------------------------------------------------------------ |
| `config/nginx-waf.conf`          | `http` block snippet, installed as `/etc/nginx/conf.d/waf.conf`    |
| `config/waf-local-overrides.lua` | Local secret and WAF rules, installed to `/etc/nginx/lua/`         |
| `scripts/install-*.sh`           | First install: creates the per-server secret, then runs the update |
| `scripts/update-*.sh`            | Update: syncs `waf.lua` from upstream and reapplies `config/`      |
| `scripts/lib/common.sh`          | Shared sync, backup, rollback, and reload logic                    |
| `tests/test-scripts.sh`          | Runs every script against a scratch root with stubbed commands     |
| `tests/test-rules.lua`           | Checks local rules against sample requests, matched like upstream  |
| `docs/`                          | Manual setup guides and per-app rules (Indonesian)                 |

## Deploy

Copy `scripts/` and `config/` to the server, side by side in a root-owned directory:

```bash
scp -r scripts config user@server:/tmp/nginx-waf/
ssh user@server
sudo mkdir -p /opt/nginx-waf
sudo cp -r /tmp/nginx-waf/scripts /tmp/nginx-waf/config /opt/nginx-waf/
sudo chown -R root:root /opt/nginx-waf
```

Keep the copy on the server, because every update reads `config/` again.

## Install and update

| Platform | First install                                   | Update                                         |
| -------- | ----------------------------------------------- | ---------------------------------------------- |
| Ubuntu   | `sudo /opt/nginx-waf/scripts/install-ubuntu.sh` | `sudo /opt/nginx-waf/scripts/update-ubuntu.sh` |
| RPM      | `sudo /opt/nginx-waf/scripts/install-rpm.sh`    | `sudo /opt/nginx-waf/scripts/update-rpm.sh`    |

Each run:

1. Downloads `anti_ddos_challenge.lua` from upstream `master` to `/etc/nginx/lua/waf.lua`, unmodified.
2. Installs `config/waf-local-overrides.lua` and `config/nginx-waf.conf`, keeping the server's secret.
3. Reloads nginx only when a file changed, after backing up the old files to `/var/backups/nginx-waf/<timestamp>/`.
4. Restores the old files if `nginx -t` fails.

`update-rpm.sh` also rebuilds the ndk/lua modules when an nginx upgrade leaves them on the old version.

Weekly update via cron:

```bash
echo '0 3 * * 0 root /opt/nginx-waf/scripts/update-rpm.sh' | sudo tee /etc/cron.d/nginx-waf-update
```

## Enable on a site

The scripts only load the WAF; turn it on per `server` or `location`:

```nginx
access_by_lua_file /etc/nginx/lua/waf.lua;
```

See `docs/app-rules-wordpress-slims-dspace.md` for which paths to protect or exempt.

## Local rules

- Edit `config/waf-local-overrides.lua`, copy it to the server, and run the update script.
- Each `WAF_*` table there **replaces** the upstream default table instead of extending it, so keep the upstream defaults you still want. The update script warns when upstream changes its defaults.
- Leave the `CHANGE_ME_TO_LONG_RANDOM_SECRET` placeholder in the repo. The real secret is generated on the first install and lives only in `/etc/nginx/lua/waf-local-overrides.lua` on the server.

## Test

```bash
bash tests/test-scripts.sh
lua tests/test-rules.lua
```
