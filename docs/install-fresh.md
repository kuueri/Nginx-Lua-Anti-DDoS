# Fresh Install Nginx dengan Lua Module

Gunakan ini jika server belum memiliki Nginx, atau Nginx existing boleh diganti.

## Ubuntu Server 24.04

Ubuntu punya paket Nginx Lua module di repository resmi.

### 1. Install

```bash
sudo apt update
sudo apt install -y nginx libnginx-mod-http-lua
sudo systemctl enable --now nginx
```

### 2. Cek Module

```bash
ls /etc/nginx/modules-enabled | grep -E 'lua|ndk'
sudo nginx -t
```

Jika belum aktif otomatis:

```bash
printf 'load_module modules/ndk_http_module.so;\n' \
  | sudo tee /etc/nginx/modules-enabled/10-mod-http-ndk.conf

printf 'load_module modules/ngx_http_lua_module.so;\n' \
  | sudo tee /etc/nginx/modules-enabled/50-mod-http-lua.conf

sudo nginx -t
sudo systemctl reload nginx
```

### 3. Validasi

```bash
sudo nginx -t
sudo systemctl status nginx --no-pager
```

Catatan:

| Kondisi                      | Rekomendasi                                           |
| ---------------------------- | ----------------------------------------------------- |
| Nginx dari repository Ubuntu | Pakai `libnginx-mod-http-lua`                         |
| Nginx dari repo `nginx.org`  | Jangan campur dengan module Ubuntu                    |
| Nginx custom                 | Pakai panduan existing Nginx dan build dynamic module |

## Rocky Linux 9

GetPageSpeed tidak dipakai karena `nginx-module-lua` membutuhkan subscription. Jalur gratis yang konsisten adalah build Nginx dari source dengan Lua module.

### 1. Bersihkan Repo GetPageSpeed Jika Pernah Dipasang

```bash
sudo dnf remove -y getpagespeed-extras-release
sudo rm -f /etc/yum.repos.d/getpagespeed*.repo
sudo dnf clean all
```

### 2. Install Dependency

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git wget tar pcre2-devel zlib-devel openssl-devel perl-devel
```

### 3. Build LuaJIT

```bash
cd /usr/local/src
sudo git clone --depth=1 https://github.com/openresty/luajit2.git
sudo make -C luajit2 -j"$(nproc)"
sudo make -C luajit2 install PREFIX=/usr/local/luajit
```

### 4. Download Source

```bash
cd /usr/local/src
sudo git clone --depth=1 https://github.com/simplresty/ngx_devel_kit.git
sudo git clone --depth=1 https://github.com/openresty/lua-nginx-module.git
sudo git clone --depth=1 https://github.com/openresty/lua-resty-core.git
sudo git clone --depth=1 https://github.com/openresty/lua-resty-lrucache.git

NGINX_VERSION=1.30.2
sudo wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
sudo tar -xzf "nginx-${NGINX_VERSION}.tar.gz"
cd "nginx-${NGINX_VERSION}"
```

### 5. Build dan Install Nginx

```bash
sudo env \
  LUAJIT_LIB=/usr/local/luajit/lib \
  LUAJIT_INC=/usr/local/luajit/include/luajit-2.1 \
  ./configure \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --modules-path=/etc/nginx/modules \
  --pid-path=/run/nginx.pid \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --with-threads \
  --with-compat \
  --with-ld-opt="-Wl,-rpath,/usr/local/luajit/lib" \
  --add-module=/usr/local/src/ngx_devel_kit \
  --add-module=/usr/local/src/lua-nginx-module \
  2>&1 | sudo tee /tmp/nginx-lua-configure.log

grep -i pcre /tmp/nginx-lua-configure.log
sudo make -j"$(nproc)"
sudo make install
```

Output yang diharapkan:

```text
checking for PCRE2 library ... found
```

### 6. Install Lua Runtime Library

```bash
sudo make -C /usr/local/src/lua-resty-core install PREFIX=/usr/local
sudo make -C /usr/local/src/lua-resty-lrucache install PREFIX=/usr/local
```

### 7. Buat Direktori

```bash
sudo mkdir -p /etc/nginx/conf.d /var/log/nginx
```

### 8. Buat Konfigurasi Minimal

```bash
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.default
```

Isi `/etc/nginx/nginx.conf`:

```nginx
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    lua_package_path "/usr/local/lib/lua/?.lua;;";

    include       mime.types;
    default_type  application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    sendfile on;
    keepalive_timeout 65;

    include /etc/nginx/conf.d/*.conf;
}
```

### 9. Buat Systemd Service

```bash
sudo tee /etc/systemd/system/nginx.service >/dev/null <<'EOF'
[Unit]
Description=Nginx with Lua module
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

### 10. Validasi

```bash
sudo nginx -V
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now nginx
sudo systemctl status nginx --no-pager
```

## Sumber

| Referensi                      | URL                                                                        |
| ------------------------------ | -------------------------------------------------------------------------- |
| Nginx source download          | https://nginx.org/en/download.html                                         |
| Nginx configure                | https://nginx.org/en/docs/configure.html                                   |
| lua-nginx-module               | https://github.com/openresty/lua-nginx-module                              |
| Ubuntu `libnginx-mod-http-lua` | https://packages.ubuntu.com/noble/libnginx-mod-http-lua                    |
| GetPageSpeed module            | https://nginx-extras.getpagespeed.com/modules/lua/ - subscription required |
