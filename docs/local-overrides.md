# Mekanisme Update-Safe untuk `waf.lua`

Jangan edit `waf.lua` langsung untuk rule lokal.

Simpan `waf.lua` sebagai file upstream murni. Saat ada update dari upstream, file ini boleh ditimpa. Rule lokal disimpan di file override terpisah agar tidak hilang.

## Struktur File

| File                                     | Fungsi                                           |
| ---------------------------------------- | ------------------------------------------------ |
| `/etc/nginx/lua/waf.lua`                 | File upstream terbaru dari `Nginx-Lua-Anti-DDoS` |
| `/etc/nginx/lua/waf-local-overrides.lua` | Secret, setting, dan rule lokal                  |
| `/etc/nginx/conf.d/example.conf`         | Site config yang memanggil WAF                   |

## Cara Kerja

`waf.lua` membaca global table bernama `localized_global`.

Jika `localized_global.WAF_URI_Request_table` diset, maka table default di `waf.lua` akan diganti oleh table dari override.

Artinya:

| Perilaku                 | Dampak                                                       |
| ------------------------ | ------------------------------------------------------------ |
| Override table diset     | Table bawaan upstream diganti                                |
| Tidak ada merge otomatis | Rule bawaan perlu dicantumkan ulang jika masih ingin dipakai |
| Update `waf.lua`         | Rule lokal aman selama berada di `waf-local-overrides.lua`   |

## Buat File Override

```bash
sudo mkdir -p /etc/nginx/lua
sudo nano /etc/nginx/lua/waf-local-overrides.lua
```

Contoh isi:

```lua
localized_global = localized_global or {}

localized_global.secret = "CHANGE_ME_TO_LONG_RANDOM_SECRET"
localized_global.expire_time = 86400
localized_global.remote_addr = "auto"

localized_global.WAF_URI_Request_table = {
    {
        "^.*$",
        ".*%.htaccess.*",
    },
    {
        "^.*$",
        ".*config%.php.*",
    },
    {
        "^.*$",
        ".*configuration%.php.*",
    },
    {
        "^.*$",
        ".*%/cache.*",
    },
    {
        "^.*$",
        ".*%.[eE][nN][vV].*",
    },
    {
        "^.*$",
        ".*%/[.]git.*",
    },
    {
        "^.*$",
        ".*wp%-config%.php.*",
    },
    {
        "^.*$",
        ".*sysconfig.*%.inc%.php.*",
    },
    {
        "^.*$",
        ".*/solr/.*",
    },
}

localized_global.WAF_query_string_Request_table = {
    {
        "^.*$",
        ".*[Uu][Nn][Ii][Oo][Nn].*[Ss][Ee][Ll][Ee][Cc][Tt]%f[^%w_].*",
    },
    {
        "^.*$",
        ".*[Pp][Hh][Pp]%%3A%%2F%%2F.*",
    },
    {
        "^.*$",
        ".*[Dd][Aa][Tt][Aa]%%3A%%2F%%2F.*",
    },
    {
        "^.*$",
        ".*%.%.%%2F.*",
    },
}

localized_global.WAF_Header_Request_table = {
    {
        "^cookie$",
        ".*<[Ss][Cc][Rr][Ii][Pp][Tt].*",
    },
    {
        "^cookie$",
        ".*[Uu][Nn][Ii][Oo][Nn].*[Ss][Ee][Ll][Ee][Cc][Tt].*",
    },
}

localized_global.WAF_POST_Request_table = {}
```

Nilai query dicocokkan setelah di-escape oleh `ngx.escape_uri`, jadi `:` menjadi `%3A` dan `/` menjadi `%2F`. Filter POST dikosongkan karena upstream mencocokkan pola nilai dengan nama argumen. Detailnya ada di komentar `config/waf-local-overrides.lua`.

## Load Override di Nginx

Tambahkan di blok `http` sebelum `server` yang memakai `access_by_lua_file`:

```nginx
init_by_lua_file /etc/nginx/lua/waf-local-overrides.lua;
```

Contoh:

```nginx
http {
    lua_package_path "/usr/local/lib/lua/?.lua;;";

    lua_shared_dict antiddos 70m;
    lua_shared_dict antiddos_blocked 70m;
    lua_shared_dict ddos_counter 10m;
    lua_shared_dict jspuzzle_tracker 70m;

    init_by_lua_file /etc/nginx/lua/waf-local-overrides.lua;

    include /etc/nginx/conf.d/*.conf;
}
```

Site config tetap memanggil upstream `waf.lua`:

```nginx
server {
    listen 80;
    server_name example.com;

    access_by_lua_file /etc/nginx/lua/waf.lua;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## Update `waf.lua`

Backup dulu:

```bash
sudo cp /etc/nginx/lua/waf.lua "/etc/nginx/lua/waf.lua.$(date +%Y%m%d%H%M%S).bak"
```

Download versi terbaru:

```bash
sudo curl -fsSL \
  https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/raw/refs/heads/master/lua/anti_ddos_challenge.lua \
  -o /etc/nginx/lua/waf.lua
```

Validasi:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Update Otomatis dengan Script

Buat script:

```bash
sudo nano /usr/local/sbin/update-nginx-lua-waf
```

Isi:

```bash
#!/usr/bin/env bash
set -euo pipefail

WAF_FILE="/etc/nginx/lua/waf.lua"
URL="https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/raw/refs/heads/master/lua/anti_ddos_challenge.lua"
TMP_FILE="$(mktemp)"
BACKUP_FILE="${WAF_FILE}.$(date +%Y%m%d%H%M%S).bak"

curl -fsSL "$URL" -o "$TMP_FILE"

if cmp -s "$TMP_FILE" "$WAF_FILE"; then
  rm -f "$TMP_FILE"
  echo "No update."
  exit 0
fi

cp "$WAF_FILE" "$BACKUP_FILE"
install -m 0644 "$TMP_FILE" "$WAF_FILE"
rm -f "$TMP_FILE"

if nginx -t; then
  systemctl reload nginx
  echo "Updated waf.lua. Backup: $BACKUP_FILE"
else
  cp "$BACKUP_FILE" "$WAF_FILE"
  nginx -t || true
  echo "Update failed. Restored backup: $BACKUP_FILE" >&2
  exit 1
fi
```

Aktifkan:

```bash
sudo chmod +x /usr/local/sbin/update-nginx-lua-waf
sudo /usr/local/sbin/update-nginx-lua-waf
```

## Cron Mingguan

```bash
sudo tee /etc/cron.weekly/update-nginx-lua-waf >/dev/null <<'EOF'
#!/usr/bin/env bash
/usr/local/sbin/update-nginx-lua-waf
EOF

sudo chmod +x /etc/cron.weekly/update-nginx-lua-waf
```

## Checklist

| Cek                | Perintah                                                                            |
| ------------------ | ----------------------------------------------------------------------------------- |
| Override terbaca   | `sudo nginx -t`                                                                     |
| WAF upstream valid | `sudo nginx -t` setelah update                                                      |
| Rule lokal aman    | Jangan edit `/etc/nginx/lua/waf.lua`; edit `/etc/nginx/lua/waf-local-overrides.lua` |
| Rollback           | Pakai file `/etc/nginx/lua/waf.lua.*.bak`                                           |

## Catatan Penting

`localized_global.*` mengganti table default, bukan menambahkan isi ke table default. Untuk table seperti `WAF_URI_Request_table`, masukkan juga rule bawaan upstream yang masih ingin dipertahankan.
