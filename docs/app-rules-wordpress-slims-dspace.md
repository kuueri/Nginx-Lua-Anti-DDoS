# Rekomendasi WAF: WordPress, SLiMS, dan DSpace v6

Dokumen ini hanya berisi rekomendasi WAF aplikasi. Instalasi Nginx Lua dipisah ke:

| Skenario        | File                        |
| --------------- | --------------------------- |
| Nginx sudah ada | `install-existing-nginx.md` |
| Fresh install   | `install-fresh.md`          |

## Baseline

| Area            | Rekomendasi                                                    |
| --------------- | -------------------------------------------------------------- |
| Secret          | Ganti `localized.secret = "C0nw0nk"` dengan nilai acak panjang |
| Client IP       | Pakai `localized.remote_addr = "auto"` jika ada reverse proxy  |
| API dan webhook | Jangan diberi JavaScript challenge                             |
| Admin dan login | Pakai WAF, `limit_req`, dan opsional allowlist IP              |
| Static upload   | Blok eksekusi PHP atau script                                  |
| OAI-PMH         | Jangan challenge; batasi method dan rate                       |

## WordPress

| Path                                             | Rekomendasi                                                |
| ------------------------------------------------ | ---------------------------------------------------------- |
| `/`                                              | Pasang `access_by_lua_file`                                |
| `/wp-login.php`                                  | Pasang WAF dan `limit_req`                                 |
| `/wp-admin/`                                     | Pasang WAF; exclude `admin-ajax.php` jika dipakai frontend |
| `/wp-json/`                                      | Jangan challenge jika REST API dipakai                     |
| `/xmlrpc.php`                                    | Blok jika tidak dipakai                                    |
| `/wp-content/uploads/`                           | Blok eksekusi PHP                                          |
| `/wp-config.php`, `/readme.html`, `/license.txt` | Deny langsung                                              |

Contoh Nginx:

```nginx
limit_req_zone $binary_remote_addr zone=wp_login:10m rate=5r/m;

server {
    listen 80;
    server_name wp.example.com;
    root /var/www/wordpress;

    client_max_body_size 32m;

    location / {
        access_by_lua_file /etc/nginx/lua/waf.lua;
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ /\.(?!well-known/) {
        return 403;
    }

    location = /wp-login.php {
        limit_req zone=wp_login burst=10 nodelay;
        access_by_lua_file /etc/nginx/lua/waf.lua;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location = /xmlrpc.php {
        return 403;
    }

    location ^~ /wp-json/ {
        try_files $uri $uri/ /index.php?$args;
    }

    location = /wp-admin/admin-ajax.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location ~* ^/wp-admin/.*\.php$ {
        access_by_lua_file /etc/nginx/lua/waf.lua;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location ~* ^/wp-includes/.*\.php$ {
        return 403;
    }

    location ~* ^/wp-content/uploads/.*\.php$ {
        return 403;
    }

    location ~* ^/(wp-config\.php|readme\.html|license\.txt)$ {
        return 403;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
```

Tambahan URI rule:

```lua
{
    "^.*$",
    ".*wp%-content/uploads/.*%.php.*",
},
{
    "^.*$",
    ".*wp%-admin/includes.*",
},
{
    "^.*$",
    ".*wp%-includes/.*%.php.*",
},
{
    "^.*$",
    ".*readme%.html.*",
},
```

## SLiMS

| Path                                                                | Rekomendasi                                        |
| ------------------------------------------------------------------- | -------------------------------------------------- |
| `/` dan `/index.php`                                                | Pasang WAF                                         |
| `/admin/`                                                           | Pasang WAF, `limit_req`, dan opsional allowlist IP |
| `/api/v1/`                                                          | Jangan challenge jika dipakai integrasi            |
| `/oai.php`, `/oai2.php`                                             | Jangan challenge; batasi `GET`/`HEAD` dan rate     |
| `/files/`, `/repository/`                                           | Izinkan download; blok PHP execution               |
| `/install/`, `/upgrade/`                                            | Deny setelah instalasi selesai                     |
| `/sysconfig.inc.php`, `/sysconfig.local.inc.php`, `/ucnode.inc.php` | Deny langsung                                      |

Contoh Nginx:

```nginx
limit_req_zone $binary_remote_addr zone=slims_admin:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=slims_oai:10m rate=60r/m;

server {
    listen 80;
    server_name slims.example.com;
    root /var/www/slims;

    client_max_body_size 64m;

    location / {
        access_by_lua_file /etc/nginx/lua/waf.lua;
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ /\.(?!well-known/) {
        return 403;
    }

    location /admin/ {
        limit_req zone=slims_admin burst=20 nodelay;
        access_by_lua_file /etc/nginx/lua/waf.lua;
        try_files $uri $uri/ /index.php?$args;
    }

    location /api/v1/ {
        limit_req zone=slims_admin burst=30 nodelay;
        try_files $uri $uri/ /index.php?$args;
    }

    location ~* ^/admin/.*\.php$ {
        limit_req zone=slims_admin burst=20 nodelay;
        access_by_lua_file /etc/nginx/lua/waf.lua;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location ~ ^/(oai|oai2)\.php$ {
        limit_req zone=slims_oai burst=120 nodelay;
        limit_except GET HEAD { deny all; }
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location ~* ^/(files|repository)/.*\.php$ {
        return 403;
    }

    location ~* ^/(install|upgrade)(/|$) {
        return 403;
    }

    location ~* ^/(sysconfig(\.local)?\.inc\.php|ucnode\.inc\.php|composer\.(json|lock))$ {
        return 403;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
```

Tambahan URI rule:

```lua
{
    "^.*$",
    ".*sysconfig.*%.inc%.php.*",
},
{
    "^.*$",
    ".*ucnode%.inc%.php.*",
},
{
    "^.*$",
    ".*/install[/.].*",
},
{
    "^.*$",
    ".*/upgrade/.*",
},
{
    "^.*$",
    ".*/repository/.*%.php.*",
},
{
    "^.*$",
    ".*/files/.*%.php.*",
},
```

OAI-PMH query allowlist:

```lua
{
    "slims%.example%.com/oai2?%.php.*",
    {
        "verb",
        "metadataPrefix",
        "identifier",
        "from",
        "until",
        "set",
        "resumptionToken",
    },
},
```

## DSpace v6

| Path                           | Rekomendasi                                                              |
| ------------------------------ | ------------------------------------------------------------------------ |
| `/xmlui/`, `/jspui/`           | Jangan challenge seluruh repository publik jika crawler/indexing penting |
| `/xmlui/login`, `/jspui/login` | Pasang WAF dan rate limit                                                |
| `/xmlui/admin`, `/jspui/admin` | Pasang WAF dan rate limit                                                |
| `/oai/`                        | Jangan challenge; batasi `GET`/`HEAD` dan rate                           |
| `/rest/`                       | Jangan challenge; pakai auth, allowlist IP, atau rate limit              |
| `/sword/`, `/swordv2/`         | Batasi ke deposit client tepercaya                                       |
| `/solr/`                       | Jangan expose publik                                                     |

Contoh Nginx:

```nginx
limit_req_zone $binary_remote_addr zone=dspace_login:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=dspace_oai:10m rate=120r/m;
limit_req_zone $binary_remote_addr zone=dspace_rest:10m rate=60r/m;

upstream dspace_tomcat {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name dspace.example.com;

    location /xmlui/ {
        proxy_pass http://dspace_tomcat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location ~ ^/(xmlui|jspui)/(login|password-login|admin) {
        limit_req zone=dspace_login burst=20 nodelay;
        access_by_lua_file /etc/nginx/lua/waf.lua;
        proxy_pass http://dspace_tomcat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /oai/ {
        limit_req zone=dspace_oai burst=240 nodelay;
        limit_except GET HEAD { deny all; }
        proxy_pass http://dspace_tomcat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /rest/ {
        limit_req zone=dspace_rest burst=120 nodelay;
        proxy_pass http://dspace_tomcat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location ~ ^/(sword|swordv2)/ {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://dspace_tomcat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /solr/ {
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://dspace_tomcat;
    }
}
```

Tambahan URI rule:

```lua
{
    "^.*$",
    ".*/solr/.*",
},
{
    "^.*$",
    ".*/jolokia/.*",
},
{
    "^.*$",
    ".*/manager/.*",
},
{
    "^.*$",
    ".*/host%-manager/.*",
},
```

OAI-PMH query allowlist:

```lua
{
    "dspace%.example%.com/oai.*",
    {
        "verb",
        "metadataPrefix",
        "identifier",
        "from",
        "until",
        "set",
        "resumptionToken",
    },
},
```

## Sumber

| Referensi             | URL                                                                                   |
| --------------------- | ------------------------------------------------------------------------------------- |
| Nginx-Lua-Anti-DDoS   | https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS                                        |
| WordPress hardening   | https://developer.wordpress.org/advanced-administration/security/hardening/           |
| WordPress REST API    | https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/ |
| SLiMS documentation   | https://slims.web.id/web/pages/docs/                                                  |
| SLiMS 9 source tree   | https://github.com/slims/slims9_bulian                                                |
| DSpace 6 installation | https://wiki.lyrasis.org/display/DSDOC6x/Installing+DSpace                            |
