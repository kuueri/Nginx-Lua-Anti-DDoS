# Nginx Lua Module untuk Nginx Existing

Gunakan ini jika Nginx sudah terpasang dan ingin ditambah Lua module tanpa mengganti binary Nginx.

Contoh kondisi:

```bash
nginx -v
```

```text
nginx version: nginx/1.30.2
```

## Alur

| Langkah              | Hasil                                     |
| -------------------- | ----------------------------------------- |
| Cek `nginx -V`       | Tahu versi, config path, dan modules path |
| Build LuaJIT         | Runtime Lua tersedia                      |
| Build dynamic module | File `.so` untuk Nginx existing           |
| Copy `.so`           | Module tersedia di modules path           |
| Load module          | Nginx mengenali directive Lua             |
| `nginx -t`           | Konfigurasi valid                         |

## 1. Cek Nginx Existing

```bash
nginx -v
nginx -V 2>&1 | tee /tmp/nginx-build.txt
nginx -V 2>&1 | tr ' ' '\n' | grep -E '^--(prefix|conf-path|modules-path|with-compat)'
```

Catatan:

| Output                              | Makna                                       |
| ----------------------------------- | ------------------------------------------- |
| `nginx/1.30.2`                      | Source Nginx yang didownload harus `1.30.2` |
| `--modules-path=/etc/nginx/modules` | Copy module ke path tersebut                |
| `--with-compat`                     | Dynamic module lebih aman                   |

## 2. Install Dependency

Rocky Linux 9:

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git wget tar pcre2-devel zlib-devel openssl-devel perl-devel
```

Gunakan `pcre2-devel` untuk Nginx modern. Jangan pakai `pcre-devel` kecuali `nginx -V` jelas menunjukkan build PCRE1.

## 3. Build LuaJIT

```bash
BUILD_DIR="$HOME/build/nginx-lua"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

git clone --depth=1 https://github.com/openresty/luajit2.git
make -C luajit2 -j"$(nproc)"
sudo make -C luajit2 install PREFIX=/usr/local/luajit
```

## 4. Download Source

Sesuaikan `NGINX_VERSION` dengan output `nginx -v`.

```bash
cd "$BUILD_DIR"

git clone --depth=1 https://github.com/simplresty/ngx_devel_kit.git
git clone --depth=1 https://github.com/openresty/lua-nginx-module.git
git clone --depth=1 https://github.com/openresty/lua-resty-core.git
git clone --depth=1 https://github.com/openresty/lua-resty-lrucache.git

NGINX_VERSION=1.30.2
wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf "nginx-${NGINX_VERSION}.tar.gz"
cd "nginx-${NGINX_VERSION}"
```

## 5. Build Dynamic Module

```bash
export LUAJIT_LIB=/usr/local/luajit/lib
export LUAJIT_INC=/usr/local/luajit/include/luajit-2.1

./configure \
  --with-compat \
  --with-ld-opt="-Wl,-rpath,/usr/local/luajit/lib" \
  --add-dynamic-module="$BUILD_DIR/ngx_devel_kit" \
  --add-dynamic-module="$BUILD_DIR/lua-nginx-module" \
  2>&1 | tee /tmp/nginx-lua-configure.log

grep -i pcre /tmp/nginx-lua-configure.log
make modules
```

Output yang diharapkan:

```text
checking for PCRE2 library ... found
```

## 6. Copy Module

```bash
MODULES_PATH=$(nginx -V 2>&1 | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p')
PREFIX=$(nginx -V 2>&1 | sed -n 's/.*--prefix=\([^ ]*\).*/\1/p')

if [ -z "$MODULES_PATH" ]; then
  MODULES_PATH="${PREFIX:-/usr/local/nginx}/modules"
fi

sudo mkdir -p "$MODULES_PATH"
sudo install -m 0644 objs/ndk_http_module.so "$MODULES_PATH/"
sudo install -m 0644 objs/ngx_http_lua_module.so "$MODULES_PATH/"
```

## 7. Install Lua Runtime Library

```bash
sudo make -C "$BUILD_DIR/lua-resty-core" install PREFIX=/usr/local
sudo make -C "$BUILD_DIR/lua-resty-lrucache" install PREFIX=/usr/local
```

## 8. Load Module

Tambahkan di baris paling atas `/etc/nginx/nginx.conf`, sebelum blok `events`:

```nginx
load_module modules/ndk_http_module.so;
load_module modules/ngx_http_lua_module.so;
```

Tambahkan di dalam blok `http`:

```nginx
lua_package_path "/usr/local/lib/lua/?.lua;;";
```

## 9. Validasi

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Troubleshooting

| Error                             | Penyebab umum                         | Fix                                                                 |
| --------------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| `undefined symbol: pcre_malloc`   | Module terbuild dengan PCRE1          | Rebuild dengan `pcre2-devel`, `make clean`, lalu `make modules`     |
| `undefined symbol`                | Urutan module salah                   | Pastikan NDK diload sebelum Lua                                     |
| `module is not binary compatible` | Build args tidak cocok                | Rebuild module dengan args lengkap dari `nginx -V`                  |
| `libluajit... not found`          | Runtime linker tidak menemukan LuaJIT | Pastikan `--with-ld-opt="-Wl,-rpath,/usr/local/luajit/lib"` dipakai |

Perintah rebuild bersih:

```bash
cd "$BUILD_DIR/nginx-1.30.2"
make clean || true
rm -rf objs
```

Lalu ulangi dari langkah 5.

## Sumber

| Referensi             | URL                                            |
| --------------------- | ---------------------------------------------- |
| Nginx source download | https://nginx.org/en/download.html             |
| Nginx configure       | https://nginx.org/en/docs/configure.html       |
| Nginx `load_module`   | https://nginx.org/en/docs/ngx_core_module.html |
| lua-nginx-module      | https://github.com/openresty/lua-nginx-module  |
