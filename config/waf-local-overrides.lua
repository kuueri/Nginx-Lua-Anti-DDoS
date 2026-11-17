localized_global = localized_global or {}

-- Upstream signs its cookies with ngx.hmac_sha1 on every request, and lua-nginx-module only has it when built with OpenSSL.
-- Failing here, in init_by_lua_file, makes nginx reject the config instead of answering every request with 500.
-- Plain Lua in tests/test-rules.lua has no ngx table, so the check only runs inside nginx.
assert(not ngx or ngx.hmac_sha1, "lua-nginx-module lacks ngx.hmac_sha1; rebuild it with --with-http_ssl_module")

-- install-*.sh swaps this placeholder for a per-server secret, so never commit a real one here.
localized_global.secret = "CHANGE_ME_TO_LONG_RANDOM_SECRET"
localized_global.expire_time = 86400
localized_global.remote_addr = "auto"

-- Upstream's default true sends every request that passes its checks to the backend a second time, as a HEAD subrequest, only to learn the Content-Type.
-- On DSpace that doubled Tomcat's page renders: 79,189 HEAD for 78,598 GET on 2026-11-17, against 535 HEAD on 2026-11-15 before the WAF.
-- Upstream's own advice for subrequest trouble is false, which only stops range-filter rules from matching by Content-Type; range filtering still runs.
localized_global.content_type_fix = false

-- Upstream's automatic "I am Under Attack" mode rewrites master_switch on every request: 2 (no challenge) while at most 100 IPs are banned, 1 (challenge on every path, these included) above that.
-- Mode 3 and these paths therefore only apply if that rewrite does not run; during an attack only whitelisted User-Agents skip the challenge.
-- Upstream runs the WAF rules before this switch, so these paths still get every WAF_* table below.
-- Each entry is a Lua pattern matched against scheme://host/path?query, anchored to the path so that ?x=/oai/ cannot skip the challenge.
localized_global.master_switch = 3
localized_global.master_switch_custom_hosts = {
	-- DSpace 6 OAI-PMH and REST
	{ 2, "^https?://[^/]+/oai/" },
	{ 2, "^https?://[^/]+/rest/" },
	-- DSpace 7 REST and OAI-PMH
	{ 2, "^https?://[^/]+/server/api/" },
	{ 2, "^https?://[^/]+/server/oai/" },
	-- WordPress REST
	{ 2, "^https?://[^/]+/wp%-json/" },
	-- SLiMS API and OAI-PMH
	{ 2, "^https?://[^/]+/api/v1/" },
	{ 2, "^https?://[^/]+/oai2?%.php" },
}

-- Upstream would block these User-Agents with 403 on every path, and waf-ban.lua counts every 403 toward a ban.
-- Policy: crawlers, scrapers, AI agents, and Turnitin may access the sites with strict limits, and only attack payloads lead to a ban.
-- So this empty table replaces upstream's default list (curl, python, ChatGPT, GPTBot, OAI-, empty User-Agent, ...), and a 403 then always means a WAF rule hit.
-- waf-ban.lua rate-limits AI agents with 429, and the site's nginx config can limit other crawlers.
localized_global.user_agent_blacklist_table = {}

-- Search engine and plagiarism crawlers skip the blacklist and the JavaScript challenge, so the sites stay indexed and checkable; Google Scholar crawls as Googlebot.
-- The patterns cover the desktop and smartphone User-Agents of Googlebot and Bingbot, and Turnitin's crawler.
-- Upstream joins them into one PCRE regex for ngx.re.find; mode 3 keeps a pattern as written, while modes 1 and 4 lowercase all of it, escapes such as \S included.
-- A client can fake its User-Agent; a match skips the challenge and the checks after it, but the WAF rules have already run.
localized_global.user_agent_whitelist_table = {
	{ [[compatible; Googlebot/2\.1; \+http://www\.google\.com/bot\.html\)]], 3 },
	{ [[compatible; bingbot/2\.0; \+http://www\.bing\.com/bingbot\.htm\)]], 3 },
	{ [[^Turnitin \(https://bit\.ly/2UvnfoQ\)]], 3 },
}

-- Upstream compiles every rule below into a PCRE regex for ngx.re.find.
-- Its only Lua-pattern translation is %. into ".", so rules use regex escapes such as \. and never Lua ones such as %- or %/.
-- [[...]] strings keep regex backslashes literal.

-- Upstream matches these case-insensitively and unanchored against the raw request path, before nginx decodes or normalizes it.
-- nginx and Tomcat decode %XX before they pick a file, so waf-ban.lua matches these rules again in the rewrite phase against $uri, the path after nginx decodes it and resolves "..".
-- So /%2eenv and shell%2ephp are blocked too, and \.\./ only ever matches the raw path, where ".." is not resolved yet.
localized_global.WAF_URI_Request_table = {
	{
		"^.*$",
		[[\.htaccess]],
	},
	-- Also covers wp-config.php and WordPress setup-config.php.
	{
		"^.*$",
		[[config\.php]],
	},
	{
		"^.*$",
		[[configuration\.php]],
	},
	-- Also blocks the CSS/JS that Autoptimize and W3 Total Cache serve from /wp-content/cache/, so drop it on sites that use them.
	{
		"^.*$",
		"/cache",
	},
	{
		"^.*$",
		[[\.env]],
	},
	{
		"^.*$",
		[[/\.git]],
	},
	{
		"^.*$",
		[[composer\.json]],
	},
	{
		"^.*$",
		[[composer\.lock]],
	},
	-- Upload directories of WordPress (wp-content/uploads) and SLiMS (files, repository): a script there can only be an uploaded webshell.
	-- Upstream never reads upload bodies, so this rule keeps such a file from running, with double extensions such as shell.php.jpg, path info such as x.jpg/y.php, and Tomcat's shell.jsp;.png.
	-- The extension must end the path or be followed by . ; / or %, so names such as report.plan.pdf pass; % stays last in the class, because upstream turns %. into ".".
	-- ^(?>...) locks the first upload directory, so a path that repeats it stays a linear scan.
	{
		"^.*$",
		[[^(?>.*?(?:wp-content/uploads|/repository|/files)/).*?\.(?:php\d?|phtml|phar|jspx?|aspx?|cgi|pl|sh)(?:[./;%]|$)]],
	},
	{
		"^.*$",
		"wp-admin/includes",
	},
	{
		"^.*$",
		[[wp-includes/.*\.php]],
	},
	{
		"^.*$",
		[[readme\.html]],
	},
	-- WordPress: WP_DEBUG_LOG writes here by default, exposing file paths and failed SQL queries.
	{
		"^.*$",
		[[wp-content/debug\.log]],
	},
	{
		"^.*$",
		[[sysconfig.*\.inc\.php]],
	},
	{
		"^.*$",
		[[ucnode\.inc\.php]],
	},
	-- Installer directory or script only, so content paths such as /installing-slims/ still pass.
	{
		"^.*$",
		"/install[/.]",
	},
	{
		"^.*$",
		"/upgrade/",
	},
	{
		"^.*$",
		"/solr/",
	},
	{
		"^.*$",
		"/jolokia/",
	},
	{
		"^.*$",
		"/manager/",
	},
	{
		"^.*$",
		"/host-manager/",
	},
	-- WordPress: xmlrpc.php (DDoS pingback amplification + login brute-force)
	-- Jetpack talks to WordPress.com through xmlrpc.php, so drop this rule on sites that use it.
	{
		"^.*$",
		[[xmlrpc\.php]],
	},
	-- SLiMS: database credential file
	{
		"^.*$",
		[[database\.php]],
	},
	-- Java/DSpace: servlet internals must never be web-served
	{
		"^.*$",
		"/WEB-INF/",
	},
	{
		"^.*$",
		"/META-INF/",
	},
	-- Spring Boot / DSpace: management endpoints must not be public
	{
		"^.*$",
		"/actuator/",
	},
	-- Generic path traversal on the raw (un-normalized) URI
	{
		"^.*$",
		[[\.\./]],
	},
	-- Tomcat drops ";params" from every path segment and resolves "..;" as "..", while nginx does neither.
	-- So /xmlui/..;/manager/html or /manager;x/html reach Tomcat paths that the rules above and nginx locations never see.
	-- A ";" followed by another "/" is blocked, because ";jsessionid=" only ever ends the path.
	{
		"^.*$",
		";.*/",
	},
}

-- Upstream decodes each query value and matches it against ^(?i)<pattern>$, so every pattern spans the whole value from (?s).* to .*.
-- (?s) lets "." cross a decoded %0A, which would otherwise stop the match and let the payload through.
-- Upstream also turns each space in a pattern into [ +%20]*, so patterns use \s instead.
-- Upstream uses an argument name only to pick rules, so waf-ban.lua also matches each name against these rules and answers a hit with 403; ?x'+union+select+1-- has no value at all.
-- The SQLi rules cover MySQL (SLiMS, WordPress) and PostgreSQL or Oracle (DSpace); POST and JSON bodies stay unchecked, see the POST table.
localized_global.WAF_query_string_Request_table = {
	-- SQLi, UNION-based. "select" must be a whole word, so catalogue searches such as "trade union selection" pass.
	-- (?>...) locks the first "union" to keep the match linear, because a match that hits the PCRE limit returns an error and upstream lets the request through.
	{
		"^.*$",
		[[(?s)(?>.*?(?<![a-z_])union(?![a-z0-9_])).*(?<![a-z_])select(?![a-z0-9_]).*]],
	},
	-- SQLi, boolean tautology such as ' or '1'='1 or 1 and 1=1.
	-- The operator must be followed by a quote or digit, so titles such as "Teachers' and students' perceptions" pass.
	{
		"^.*$",
		[[(?s)(?>.*?['"\d)]\s*(?:or|and|xor|\|\||&&)\s*\(?\s*['"\d]).*[=<>].*]],
	},
	-- SQLi, time-based and error-based functions, matched only with their opening parenthesis so "sleep quality" passes.
	{
		"^.*$",
		[[(?s).*(?<![a-z_])(?:(?:sleep|pg_sleep|benchmark|extractvalue|updatexml|load_file|group_concat|concat|concat_ws|name_const)\s*\(|char\s*\(\s*\d).*]],
	},
	-- SQLi, a quote closed by a comment or terminator, such as admin'-- or admin'#.
	{
		"^.*$",
		[[(?s).*['"]\s*(?:--(?:\s|$)|#|/\*|;).*]],
	},
	-- SQLi, subquery.
	{
		"^.*$",
		[[(?s).*\(\s*select(?![a-z0-9_]).*]],
	},
	-- SQLi, schema probing and file access.
	{
		"^.*$",
		[[(?s).*(?:information_schema|mysql\.user|pg_catalog|pg_shadow|sqlite_master|@@(?:version|datadir|hostname|basedir)|into\s+(?:out|dump)file|(?<![a-z_])(?:version|database|user|current_user|schema)\s*\(\s*\)|dbms_pipe|utl_http|utl_inaddr).*]],
	},
	-- SQLi through sort parameters, a common WordPress plugin hole: only word characters, spaces, comma, dot, and dash pass.
	-- The name is grouped because upstream wraps it as ^(?i)<name>$.
	{
		[[(?:order|orderby|order_by|sort|sort_by)]],
		[[(?s).*[^\w\s,.-].*]],
	},
	{
		"^.*$",
		[[(?s).*base64_(?:en|de)code.*]],
	},
	{
		"^.*$",
		[[(?s).*(?:php|data)://.*]],
	},
	-- Also covers the documented CVE-2025-55752 request shape, ?param=../WEB-INF/web.xml.
	{
		"^.*$",
		[[(?s).*\.\./.*]],
	},
	-- Log4Shell (CVE-2021-44228, Log4j 2.x): ${jndi:...} and obfuscated ${...:...} lookups
	-- A ${...} without ":" before its "}" is skipped whole and possessively, which suffices because a ${ nested inside it has no ":" before that "}" either.
	-- So the scan stays linear without a length cap that a long key, as in ${${aaa...:-j}ndi:...}, could outrun; the earlier .*\$\{[^}]*: form spent 10 s of PCRE JIT time on 8 KB of "${:".
	{
		"^.*$",
		[[(?s)(?:.*\$\{jndi|(?:(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+\})*+(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+:[^}]*+\}).*]],
	},
	-- The rules below, through ASP, must stay linear too: an unbounded scan nested inside another lets a long value hit the PCRE limit and pass.
	-- XSS, a tag that runs script or loads content. Browsers need the name right after "<", so "p<0.05" and "x < y" pass.
	{
		"^.*$",
		[[(?s).*</?(?:script|iframe|frame|frameset|object|embed|applet|svg|math|img|image|video|audio|source|body|style|link|meta|base|form|input|button|textarea|select|details|marquee|isindex|template)(?![a-z0-9_-]).*]],
	},
	-- XSS, an event handler after any tag, such as <x onclick=...>; (?>...) locks the first tag.
	{
		"^.*$",
		[[(?s)(?>.*?<[a-z]).*?[\s/"'\x60]on[a-z]{3,}\s*=.*]],
	},
	-- XSS, a script URL at the start of a value that a page may put into href or src.
	-- The scheme must be followed by code, such as alert( or //, so a title search such as "JavaScript: The Good Parts" passes.
	{
		"^.*$",
		[[(?s)[\x00-\x20]*(?:(?:javascript|vbscript|livescript)\s*:\s*(?:[^\s\w]|[\w$.]+\s*[(\x60=])|data\s*:\s*(?:text/html|image/svg[+\s]xml|application/(?:x-)?javascript)).*]],
	},
	-- Command injection, a shell separator or substitution, a common command, and then what only a shell line has next: its end, an operator, an option, a path, a digit, a quote, a URL, or a host.
	-- So titles such as "Animal behaviour; cat breeds" or "Table tennis; ping pong" pass.
	{
		"^.*$",
		[[(?s).*(?:[;|\n\x60]|&&|\$\()\s*(?:(?:/usr)?(?:/local)?/s?bin/)?(?:id|whoami|uname|cat|ls|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|php|ruby|ping|nslookup|dig|sleep|echo|chmod|rm|mkfifo|powershell|cmd|certutil|busybox|base64|telnet|tftp|ifconfig)(?:\s*$|\s*[|;&<>\x60)]|\s+[-/$.~\d'"]|\s+https?:|\s+[\w-]+\.[\w.-]*[a-z]{2,}).*]],
	},
	-- Command injection, strings that only an attack sends: a shell path, a /dev/tcp reverse shell, $IFS as a space, Shellshock, or a Windows shell with its switches.
	{
		"^.*$",
		[[(?s).*(?:/bin/(?:ba|da|z|k)?sh(?![a-z])|/dev/(?:tcp|udp)/|\$\{?ifs\}?|\(\)\s*\{\s*[:\w]+;|cmd(?:\.exe)?\s*/[ck]\s|powershell(?:\.exe)?\s+-(?:e|enc|c|nop|w)\b).*]],
	},
	-- SSRF, a URL to a loopback, private, link-local, or cloud metadata address, also as hex, decimal, octal, an IPv6 literal, or behind user@, or a scheme that only internal services speak.
	-- Public URLs, such as https://doi.org/... in a redirect parameter, pass.
	{
		"^.*$",
		[[(?s).*(?:(?:gopher|dict|file|ldaps?|tftp|netdoc)://|jar:(?:https?|file|ftp)://|://(?>[^/@?#\s]*@)?(?:\[[0-9a-f:.%]+\]|(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|0x[0-9a-f]+|\d{8,10}|0\d+(?:\.\d+){3}|10(?:\.\d+){3}|192\.168(?:\.\d+){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d+){2}|169\.254(?:\.\d+){2}|metadata\.google\.internal|100\.100\.100\.200)(?:[:/?#]|$))).*]],
	},
	-- Java deserialization, a serialized object as base64 (rO0AB), hex (aced0005), or raw bytes, or a JSON gadget type.
	-- The object must start the value or follow a non-base64 character, so an arbitrary token, such as an OAI resumptionToken, cannot match by chance.
	{
		"^.*$",
		[[(?s)(?:(?:.*[^a-z0-9+/])?(?:ro0ab|aced0005|\xac\xed\x00\x05)|.*(?:"@type"\s*:\s*"|jdbcrowsetimpl|templatesimpl|commons\.collections\.functors|ysoserial)).*]],
	},
	-- PHP object injection, a serialized object such as O:8:"stdClass":0:{} or O:+8:..., or a phar:// stream, whose metadata PHP unserializes.
	-- Serialized arrays and strings without an object pass.
	{
		"^.*$",
		[[(?s).*(?:(?<![a-z0-9_])[oc]:\+?\d{1,6}:"[^"]{1,200}":\d{1,6}:\{|phar://).*]],
	},
	-- ASP code injection, JSP and ERB template tags included: a <% tag, or the objects and calls that classic ASP webshells use.
	{
		"^.*$",
		[[(?s).*(?:<%|(?<![a-z0-9_])(?:response\.(?:write|binarywrite)|server\.(?:createobject|execute|transfer|mappath)|createobject\s*\(|wscript\.shell|scripting\.filesystemobject|adodb\.stream|executeglobal|(?:eval|execute)\s*\(?\s*request)).*]],
	},
}

-- Upstream matches header values raw, unanchored, and case-sensitively, so value patterns start with (?i).
localized_global.WAF_Header_Request_table = {
	-- XSS through headers that apps decode, store, or show: a cookie that PHP decodes, or a Referer or User-Agent in an admin log view; raw or percent-encoded.
	{
		"^(?:cookie|referer|user-agent)$",
		[[(?i)(?:<|%3c)/?(?:script|iframe|svg|img|body|object|embed|style|link|meta|base|form|input|details|math|video|audio)(?![a-z0-9_-])|^(?>.*?(?:<|%3c)[a-z]).*?(?:[\s/"'\x60+]|%2[0f27])on[a-z]{3,}\s*(?:=|%3d)]],
	},
	-- SQLi through headers that apps store or log: UNION SELECT and time-based or error-based functions.
	{
		"^(?:cookie|referer|user-agent|x-forwarded-for)$",
		[[(?i)^(?>.*?(?<![a-z_])union(?![a-z0-9_])).*(?<![a-z_])select(?![a-z0-9_])|(?<![a-z_])(?:sleep|pg_sleep|benchmark|extractvalue|updatexml)\s*\(]],
	},
	{
		"^x-forwarded-host$",
		[[(?:/|\\)]],
	},
	-- Log4Shell (CVE-2021-44228, Log4j 2.x): scan every header value for ${jndi:...} / ${...:...}
	-- The same linear scan as the query rule, anchored with ^ so that it runs once per value.
	{
		"^.*$",
		[[(?is)^(?:.*\$\{jndi|(?:(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+\})*+(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+:[^}]*+\})]],
	},
	-- Java deserialization through any header, such as a rememberMe cookie: a serialized object at the start of a value, case-sensitive like base64.
	{
		"^.*$",
		[[(?:^|[^A-Za-z0-9+/])(?:rO0AB|aced0005|ACED0005)]],
	},
	-- PHP object injection through cookies, which PHP decodes before an app unserializes them; raw or percent-encoded.
	{
		"^cookie$",
		[[(?i)(?<![a-z0-9_])[oc](?::|%3a)\+?\d{1,6}(?::|%3a)(?:"|%22).{1,200}?(?:"|%22)(?::|%3a)\d{1,6}(?::|%3a)(?:\{|%7b)]],
	},
	-- Shellshock (CVE-2014-6271): a function definition in any header, which a CGI script would hand to bash.
	{
		"^.*$",
		[[\(\s*\)\s*\{]],
	},
}

-- Any rule here makes upstream read every POST body, uploads included, into a Lua string, so the filter stays off.
-- waf-ban.lua checks bodies instead, with the settings below.
localized_global.WAF_POST_Request_table = {}

-- waf-ban.lua checks request bodies in the rewrite phase with WAF_query_string_Request_table; upstream never reads these two settings.
-- It checks each urlencoded field, each multipart field without a filename= parameter (PHP's test for a file), and a JSON body as one text after it decodes \uXXXX escapes, because no JSON library is built in.
-- It reads up to 128 KB, where every query rule stays clear of the PCRE match limit even without PCRE JIT; 1 MB values hit that limit.
-- A larger urlencoded or JSON body, or one with more than 1000 fields, gets 413, which never counts toward a ban; a larger multipart body is an upload and stays unchecked.
-- false only logs "Would block (log only) Request body prohibited" for 7 days of tuning; true answers a hit with 403, which counts toward a ban.
localized_global.WAF_body_block = false
-- Lua patterns for $uri, the decoded path, whose bodies stay unchecked, because editors save posts there and HTML or SQL words are normal content.
-- The WordPress classic and block editors, anchored at the site root so that no path info or subdirectory can borrow the exemption; a WordPress in a subdirectory needs its own entries.
localized_global.WAF_body_skip = {
	"^/wp%-admin/post%.php$",
	"^/wp%-json/wp/v2/",
}

-- waf-ban.lua also checks each Cookie value, URL-decoded as PHP decodes it, with WAF_query_string_Request_table; upstream never reads this setting.
-- Cookies carry tokens, base64, and JSON, and a JSON cookie such as {"color":"#ffffff"} already matches the SQLi comment rule, so false only logs "Would block (log only) Request cookie prohibited" for 7 days of tuning, like the body check.
-- true answers a hit with 403, which counts toward a ban.
localized_global.WAF_cookie_block = false

-- Upstream's default anti_ddos_table closes the connection and bans the address for 24 hours on PATCH, PUT, DELETE, CONNECT, OPTIONS, or TRACE.
-- Readers send OPTIONS too: Microsoft Office and some browsers ask with OPTIONS before they open a bitstream link, so OPTIONS leaves that list and reaches the application again.
-- PUT, PATCH, and DELETE stay banned, because only vulnerability scanners sent them in the DSpace access logs.
-- Upstream calls this function once per worker, after it builds its default table, so every other default stays as upstream ships it; field 26 of each entry is the method list.
localized_global.anti_ddos_table = function()
	local t = package.loaded["anti_ddos_config_store"].anti_ddos_table
	for _, site in ipairs(t) do
		for i = #site[26], 1, -1 do
			if site[26][i][1] == "OPTIONS" then
				table.remove(site[26], i)
			end
		end
	end
	return t
end
