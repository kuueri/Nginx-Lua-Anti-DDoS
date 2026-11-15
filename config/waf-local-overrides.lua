localized_global = localized_global or {}

-- install-*.sh swaps this placeholder for a per-server secret, so never commit a real one here.
localized_global.secret = "CHANGE_ME_TO_LONG_RANDOM_SECRET"
localized_global.expire_time = 86400
localized_global.remote_addr = "auto"

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
	{
		"^.*$",
		[[(?s).*\$\{(?:jndi|[^}]*:[^}]*\}).*]],
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
	{
		"^.*$",
		[[(?i)\$\{(?:jndi|[^}]*:[^}]*\})]],
	},
}

-- Any rule here makes upstream read every POST body, uploads included, into a Lua string, so the filter stays off.
localized_global.WAF_POST_Request_table = {}
