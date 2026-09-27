-- Check config/waf-local-overrides.lua against sample requests, matched the way upstream anti_ddos_challenge.lua matches them.
-- URI rules see the raw path without its query, header rules see raw values, and query rules see each decoded value re-escaped by ngx.escape_uri.
-- The POST table is not exercised because it stays empty, see the comment above it.
dofile(arg[0]:gsub("[^/]*$", "") .. "../config/waf-local-overrides.lua")
local g = localized_global

-- ngx.escape_uri(s, 2) keeps letters, digits, and -._~!'()* and turns every other byte into uppercase %XX.
local function escape(s)
	return (s:gsub("[^%w%-%._~!'()*]", function(c)
		return string.format("%%%02X", c:byte())
	end))
end

local function hit(rules, name, value)
	for _, r in ipairs(rules) do
		if name:find(r[1]) and value:find(r[2]) then
			return true
		end
	end
	return false
end

local check = {
	uri = function(path)
		return path ~= "/" and hit(g.WAF_URI_Request_table, "example.com", path)
	end,
	query = function(value)
		return hit(g.WAF_query_string_Request_table, "q", escape(value))
	end,
	header = function(name, value)
		return hit(g.WAF_Header_Request_table, name, value)
	end,
}

local cases = {
	{ true, "uri", "/.env" },
	{ true, "uri", "/.git/config" },
	{ true, "uri", "/wp-config.php.bak" },
	{ true, "uri", "/wp-admin/setup-config.php" },
	{ true, "uri", "/wp-content/debug.log" },
	{ true, "uri", "/wp-content/uploads/2025/01/shell.php" },
	{ true, "uri", "/xmlrpc.php" },
	{ true, "uri", "/wp-admin/install.php" },
	{ true, "uri", "/install/index.php" },
	{ true, "uri", "/config/database.php" },
	{ true, "uri", "/sysconfig.local.inc.php" },
	{ true, "uri", "/solr/search/select" },
	{ true, "uri", "/xmlui/..;/manager/html" },
	{ true, "uri", "/manager;x/html" },
	{ true, "uri", "/xmlui/%2e%2e;/admin/" },
	{ true, "uri", "/server/actuator;/env" },
	{ false, "uri", "/" },
	{ false, "uri", "/xmlui/handle/123456789/1;jsessionid=0A1B2C" },
	{ false, "uri", "/bitstream/handle/123456789/1/report.pdf" },
	{ false, "uri", "/installing-slims-on-ubuntu/" },
	{ false, "uri", "/wp-content/themes/twentytwentyfive/style.css" },
	{ true, "query", "1 union select 1,2" },
	{ true, "query", "-1 UNION ALL SELECT" },
	{ true, "query", "concat(0x7e,version())" },
	{ true, "query", "concat (user())" },
	{ true, "query", "base64_decode(x)" },
	{ true, "query", "php://filter/convert.base64-encode/resource=index" },
	{ true, "query", "data://text/plain;base64,PD9waHA=" },
	{ true, "query", "../../../../etc/passwd" },
	{ true, "query", "../WEB-INF/web.xml" },
	{ true, "query", "${jndi:ldap://x/a}" },
	{ true, "query", "${${lower:j}ndi:ldap://x/a}" },
	{ false, "query", "trade union selection" },
	{ false, "query", "sejarah perpustakaan indonesia" },
	{ false, "query", "2025-01-31" },
	{ true, "header", "user-agent", "${jndi:ldap://x/a}" },
	{ true, "header", "cookie", "a=<script>alert(1)</script>" },
	{ true, "header", "x-forwarded-host", "evil.example/x" },
	{ false, "header", "cookie", "wordpress_logged_in_abc=admin%7C1700000000" },
	{ false, "header", "user-agent", "Mozilla/5.0 (X11; Linux x86_64)" },
}

local failed = 0
for _, c in ipairs(cases) do
	if check[c[2]](c[3], c[4]) ~= c[1] then
		failed = failed + 1
		print(
			string.format(
				"FAIL %s %q%s: expected %s",
				c[2],
				c[3],
				c[4] and " " .. string.format("%q", c[4]) or "",
				c[1] and "block" or "pass"
			)
		)
	end
end
assert(#g.WAF_POST_Request_table == 0, "WAF_POST_Request_table must stay empty")
if failed > 0 then
	os.exit(1)
end
print("PASS")
