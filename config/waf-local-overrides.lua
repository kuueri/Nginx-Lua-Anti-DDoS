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
-- A percent-encoded path such as /%2eenv slips past them, so files nginx serves itself also need a deny in the site's location rules.
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
	{
		"^.*$",
		[[wp-content/uploads/.*\.php]],
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
		[[/repository/.*\.php]],
	},
	{
		"^.*$",
		[[/files/.*\.php]],
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
}

-- Upstream matches header values raw, unanchored, and case-sensitively, so value patterns start with (?i).
localized_global.WAF_Header_Request_table = {
	{
		"^cookie$",
		"(?i)<script",
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
}

-- Any rule here makes upstream read every POST body, uploads included, into a Lua string, so the filter stays off.
localized_global.WAF_POST_Request_table = {}

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
