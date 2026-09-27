localized_global = localized_global or {}

-- install-*.sh swaps this placeholder for a per-server secret, so never commit a real one here.
localized_global.secret = "CHANGE_ME_TO_LONG_RANDOM_SECRET"
localized_global.expire_time = 86400
localized_global.remote_addr = "auto"

-- Upstream matches these against the raw request path, before nginx decodes or normalizes it.
-- A percent-encoded path such as /%2eenv slips past them, so files nginx serves itself also need a deny in the site's location rules.
localized_global.WAF_URI_Request_table = {
	{
		"^.*$",
		".*%.htaccess.*",
	},
	-- Also covers wp-config.php and WordPress setup-config.php.
	{
		"^.*$",
		".*config%.php.*",
	},
	{
		"^.*$",
		".*configuration%.php.*",
	},
	-- Also blocks the CSS/JS that Autoptimize and W3 Total Cache serve from /wp-content/cache/, so drop it on sites that use them.
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
		".*composer%.[jJ][sS][oO][nN].*",
	},
	{
		"^.*$",
		".*composer%.[lL][oO][cC][kK].*",
	},
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
	-- WordPress: WP_DEBUG_LOG writes here by default, exposing file paths and failed SQL queries.
	{
		"^.*$",
		".*wp%-content/debug%.log.*",
	},
	{
		"^.*$",
		".*sysconfig.*%.inc%.php.*",
	},
	{
		"^.*$",
		".*ucnode%.inc%.php.*",
	},
	-- Installer directory or script only, so content paths such as /installing-slims/ still pass.
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
	-- WordPress: xmlrpc.php (DDoS pingback amplification + login brute-force)
	-- Jetpack talks to WordPress.com through xmlrpc.php, so drop this rule on sites that use it.
	{
		"^.*$",
		".*xmlrpc%.php.*",
	},
	-- SLiMS: database credential file
	{
		"^.*$",
		".*database%.php.*",
	},
	-- Java/DSpace: servlet internals must never be web-served
	{
		"^.*$",
		".*/WEB%-INF/.*",
	},
	{
		"^.*$",
		".*/META%-INF/.*",
	},
	-- Spring Boot / DSpace: management endpoints must not be public
	{
		"^.*$",
		".*/actuator/.*",
	},
	-- Generic path traversal on the raw (un-normalized) URI
	{
		"^.*$",
		".*%.%./.*",
	},
	-- Tomcat drops ";params" from every path segment and resolves "..;" as "..", while nginx does neither.
	-- So /xmlui/..;/manager/html or /manager;x/html reach Tomcat paths that the rules above and nginx locations never see.
	-- A ";" followed by another "/" is blocked, because ";jsessionid=" only ever ends the path.
	{
		"^.*$",
		".*;.*/.*",
	},
}

-- Upstream decodes each query value, then re-escapes it with ngx.escape_uri before matching.
-- Patterns therefore see ":" as %3A, "/" as %2F, "$" as %24, "{" as %7B, "}" as %7D, and a space as %20.
-- Letters, digits, and -._~!'()* stay literal.
localized_global.WAF_query_string_Request_table = {
	-- "select" must end a word, so catalogue searches such as "trade union selection" pass.
	{
		"^.*$",
		".*[Uu][Nn][Ii][Oo][Nn].*[Ss][Ee][Ll][Ee][Cc][Tt]%f[^%w_].*",
	},
	{
		"^.*$",
		".*[Cc][Oo][Nn][Cc][Aa][Tt][%%20]*%(.*",
	},
	{
		"^.*$",
		".*[Bb][Aa][Ss][Ee]64%_[Ee][Nn][Cc][Oo][Dd][Ee].*",
	},
	{
		"^.*$",
		".*[Bb][Aa][Ss][Ee]64%_[Dd][Ee][Cc][Oo][Dd][Ee].*",
	},
	{
		"^.*$",
		".*[Pp][Hh][Pp]%%3A%%2F%%2F.*",
	},
	{
		"^.*$",
		".*[Dd][Aa][Tt][Aa]%%3A%%2F%%2F.*",
	},
	-- Also covers the documented CVE-2025-55752 request shape, ?param=../WEB-INF/web.xml.
	{
		"^.*$",
		".*%.%.%%2F.*",
	},
	-- Log4Shell (CVE-2021-44228, Log4j 2.x): ${jndi:...} and obfuscated ${...:...} lookups
	{
		"^.*$",
		".*%%24%%7B[jJ][nN][dD][iI].*",
	},
	{
		"^.*$",
		".*%%24%%7B.-%%3A.-%%7D.*",
	},
}

-- Upstream matches header values raw.
localized_global.WAF_Header_Request_table = {
	{
		"^cookie$",
		".*<[Ss][Cc][Rr][Ii][Pp][Tt].*",
	},
	{
		"^cookie$",
		".*[Uu][Nn][Ii][Oo][Nn].*[Ss][Ee][Ll][Ee][Cc][Tt].*",
	},
	{
		"^x%-forwarded%-host$",
		".*[/%\\].*",
	},
	-- Log4Shell (CVE-2021-44228, Log4j 2.x): scan every header value for ${jndi:...} / ${...:...}
	{
		"^.*$",
		".*%${[jJ][nN][dD][iI].*",
	},
	{
		"^.*$",
		".*%${[^}]*%:[^}]*}.*",
	},
}

-- Upstream's WAF_Post_Requests matches value patterns against the escaped argument name for single-valued fields, so payloads in values pass unchecked.
-- Any rule here still makes it read every POST body, uploads included, into a Lua string.
-- The filter stays off until upstream fixes that.
localized_global.WAF_POST_Request_table = {}
