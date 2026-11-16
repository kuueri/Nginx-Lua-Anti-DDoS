-- Check config/waf-local-overrides.lua against sample requests, matched the way upstream anti_ddos_challenge.lua matches them.
-- Upstream compiles each rule into a PCRE regex for ngx.re.find; stock Lua has no PCRE, so Perl runs the compiled regexes here.
-- Every rule must block at least one case, so a rule that compiles but can never match fails the check.
-- The POST table is not exercised because it stays empty, see the comment above it.
dofile(arg[0]:gsub("[^/]*$", "") .. "../config/waf-local-overrides.lua")
local g = localized_global

-- Upstream's precompile_waf_*_table: the only Lua-pattern translation is %. into ".".
local function shim(p)
	return (p:gsub("^%%%.%%*", ".*"):gsub("%%%.%%*%$", ".*"):gsub("%%%.", "."))
end

local function bare(p)
	return (p:gsub("[%^%$]", ""))
end

local rules = { uri = {}, query = {}, header = {} }
for _, r in ipairs(g.WAF_URI_Request_table) do
	table.insert(rules.uri, { src = r[2], key = "^(?i)" .. bare(shim(r[1])) .. "$", val = "(?i)" .. shim(r[2]) })
end
for _, r in ipairs(g.WAF_query_string_Request_table) do
	local v = shim(r[2]):gsub("%%_", "_")
	v = (v == ".*" or v == "^.*$") and ".*" or v:gsub(" ", "[ +%%20]*")
	table.insert(
		rules.query,
		{ src = r[2], key = "^(?i)" .. bare(shim(r[1]):gsub("%%_", "_")) .. "$", val = "^(?i)" .. v .. "$" }
	)
end
for _, r in ipairs(g.WAF_Header_Request_table) do
	table.insert(rules.header, { src = r[2], raw = r[1], clean = bare(shim(r[1])), val = shim(r[2]) })
end
-- The User-Agent whitelist gets no shim: modes 1 and 4 become "((?i)<lowercased pattern>)", the others "(<pattern>)".
-- For this kind, "block" in the cases means the crawler skips the challenge.
rules.ua = {}
for _, r in ipairs(g.user_agent_whitelist_table) do
	local mode = r[2] or 1
	local val = (mode == 1 or mode == 4) and "((?i)" .. r[1]:lower() .. ")" or "(" .. r[1] .. ")"
	table.insert(rules.ua, { src = r[1], val = val })
end
-- The blacklist compiles the same way, and "block" means a 403 on every path.
rules.uablock = {}
for _, r in ipairs(g.user_agent_blacklist_table) do
	local mode = r[2] or 1
	local val = (mode == 1 or mode == 4) and "((?i)" .. r[1]:lower() .. ")" or "(" .. r[1] .. ")"
	table.insert(rules.uablock, { src = r[1], val = val })
end

-- The first pass only records every regex and subject; Perl matches them all at once, and the second pass reads the results.
local asked, index, results = {}, {}, nil
local function re(subject, regex)
	local k = regex .. "\0" .. subject
	if not index[k] then
		table.insert(asked, { regex, subject })
		index[k] = #asked
	end
	return results == nil or results[index[k]] == "1"
end

local match = {
	uri = function(r, path)
		return path ~= "/" and re("https://example.com" .. path, r.key) and re(path, r.val)
	end,
	query = function(r, value, name)
		return re(name or "q", r.key) and re(value, r.val)
	end,
	header = function(r, name, value)
		return (name == r.clean or name == r.raw or re(name, r.raw)) and re(value, r.val)
	end,
	ua = function(r, value)
		return re(value, r.val)
	end,
	uablock = function(r, value)
		return re(value, r.val)
	end,
}

local cases = {
	{ true, "uri", "/.env" },
	{ true, "uri", "/.htaccess" },
	{ true, "uri", "/.git/config" },
	{ true, "uri", "/wp-config.php.bak" },
	{ true, "uri", "/wp-admin/setup-config.php" },
	{ true, "uri", "/configuration.php" },
	{ true, "uri", "/wp-content/cache/page.html" },
	{ true, "uri", "/composer.json" },
	{ true, "uri", "/composer.lock" },
	{ true, "uri", "/wp-content/debug.log" },
	{ true, "uri", "/wp-content/uploads/2025/01/shell.php" },
	{ true, "uri", "/wp-admin/includes/admin.php" },
	{ true, "uri", "/wp-includes/version.php" },
	{ true, "uri", "/readme.html" },
	{ true, "uri", "/xmlrpc.php" },
	{ true, "uri", "/wp-admin/install.php" },
	{ true, "uri", "/install/index.php" },
	{ true, "uri", "/upgrade/index.php" },
	{ true, "uri", "/config/database.php" },
	{ true, "uri", "/sysconfig.local.inc.php" },
	{ true, "uri", "/ucnode.inc.php" },
	{ true, "uri", "/repository/shell.php" },
	{ true, "uri", "/files/shell.php" },
	{ true, "uri", "/solr/search/select" },
	{ true, "uri", "/jolokia/list" },
	{ true, "uri", "/host-manager/html" },
	{ true, "uri", "/xmlui/WEB-INF/web.xml" },
	{ true, "uri", "/META-INF/context.xml" },
	{ true, "uri", "/actuator/health" },
	{ true, "uri", "/static/../../etc/passwd" },
	{ true, "uri", "/xmlui/..;/manager/html" },
	{ true, "uri", "/manager;x/html" },
	{ true, "uri", "/xmlui/%2e%2e;/admin/" },
	{ true, "uri", "/server/actuator;/env" },
	{ false, "uri", "/" },
	{ false, "uri", "/about/" },
	{ false, "uri", "/environmental-science/" },
	{ false, "uri", "/xmlui/handle/123456789/1;jsessionid=0A1B2C" },
	{ false, "uri", "/bitstream/handle/123456789/1/report.pdf" },
	{ false, "uri", "/installing-slims-on-ubuntu/" },
	{ false, "uri", "/wp-content/themes/twentytwentyfive/style.css" },
	{ false, "uri", "/wp-content/uploads/2025/01/photo.jpg" },
	{ true, "query", "1 union select 1,2" },
	{ true, "query", "-1 UNION ALL SELECT" },
	{ true, "query", "1/**/UnIoN/**/SeLeCt/**/1" },
	{ true, "query", "1\nunion\nselect 1" },
	{ true, "query", "1union select 1" },
	{ true, "query", "' or '1'='1" },
	{ true, "query", "admin' or 1=1-- -" },
	{ true, "query", "1\nAND\n1=2" },
	{ true, "query", "admin'-- " },
	{ true, "query", "admin'#" },
	{ true, "query", "1 AND BENCHMARK(5000000,MD5(1))" },
	{ true, "query", "1;select pg_sleep(5)" },
	{ true, "query", "1 and ascii(char(97))>1" },
	{ true, "query", "concat(0x7e,version())" },
	{ true, "query", "concat (user())" },
	{ true, "query", "' AND (SELECT SUBSTRING(user_pass,1,1) FROM wp_users WHERE ID=1)='a" },
	{ true, "query", "1 AND 1=(SELECT COUNT(*) FROM information_schema.tables)" },
	{ true, "query", "1 into outfile '/var/www/x.php'" },
	{ true, "query", "1 and dbms_pipe.receive_message('a',5)=1" },
	{ true, "query", "title,(select sleep(5))", "orderby" },
	{ true, "query", "(CASE WHEN 1=1 THEN title ELSE date END)", "orderby" },
	{ true, "query", "desc;", "order" },
	{ true, "query", "base64_decode(x)" },
	{ true, "query", "base64_encode(x)" },
	{ true, "query", "php://filter/convert.base64-encode/resource=index" },
	{ true, "query", "data://text/plain;base64,PD9waHA=" },
	{ true, "query", "../../../../etc/passwd" },
	{ true, "query", "../WEB-INF/web.xml" },
	{ true, "query", "${jndi:ldap://x/a}" },
	{ true, "query", "${${lower:j}ndi:ldap://x/a}" },
	{ false, "query", "trade union selection" },
	{ false, "query", "sejarah perpustakaan indonesia" },
	{ false, "query", "2025-01-31" },
	{ false, "query", "Teachers' and students' perceptions of e-learning" },
	{ false, "query", "O'Reilly and Associates" },
	{ false, "query", "Syafi'i and fiqh" },
	{ false, "query", "don't -- just do it" },
	{ false, "query", "select committee report" },
	{ false, "query", "sleep quality among students" },
	{ false, "query", "benchmarking library services" },
	{ false, "query", "user experience (UX) design" },
	{ false, "query", "C# programming" },
	{ false, "query", "pengaruh motivasi 1990 and 2000" },
	{ false, "query", '"climate change" AND title:(water OR air)' },
	{ false, "query", 'title:("machine learning") AND dateIssued:[2010 TO 2020]' },
	{ false, "query", "https://example.com/wp-admin/edit.php?orderby=title&order=asc", "redirect_to" },
	{ false, "query", "DESC", "order" },
	{ false, "query", "menu_order title", "orderby" },
	{ false, "query", "price-desc", "orderby" },
	{ false, "query", "dc.date.issued_dt", "sort_by" },
	{ false, "query", "O'Brien (1)", "order_id" },
	{ true, "header", "user-agent", "${jndi:ldap://x/a}" },
	{ true, "header", "cookie", "a=<script>alert(1)</script>" },
	{ true, "header", "cookie", "wp_lang=1 union select 1" },
	{ true, "header", "x-forwarded-for", "1.2.3.4' AND SLEEP(5)-- -" },
	{ true, "header", "x-forwarded-host", "evil.example/x" },
	{ false, "header", "cookie", "wordpress_logged_in_abc=admin%7C1700000000" },
	{ false, "header", "cookie", "SenayanMember=abc123; SenayanAdmin=def456" },
	{ false, "header", "user-agent", "Mozilla/5.0 (X11; Linux x86_64)" },
	{ false, "header", "referer", "https://lib.example.ac.id/index.php?keywords=trade+union+selection" },
	{ false, "header", "x-forwarded-for", "203.0.113.7, 10.0.0.1" },
	{ true, "ua", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" },
	{
		true,
		"ua",
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	},
	{ true, "ua", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" },
	{
		true,
		"ua",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/130.0.0.0 Safari/537.36",
	},
	{
		false,
		"ua",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
	},
	{ false, "ua", "Googlebot" },
	{ false, "ua", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com.evil.example/bot.html)" },
	{ true, "ua", "Turnitin (https://bit.ly/2UvnfoQ)" },
	{ false, "ua", "Mozilla/5.0 Turnitin (https://bit.ly/2UvnfoQ)" },
	{ true, "uablock", "" },
	{ true, "uablock", "Kodi/21.2 (X11; Linux x86_64) Ubuntu/24.04 App_Bitness/64 Version/21.2-(21.2.0)-Git:20250204" },
	{ true, "uablock", "XBMC/12.0 (Linux)" },
	{ true, "uablock", "WinHttp-Autoproxy-Service/5.1" },
	{ true, "uablock", "Mozilla/4.5 (compatible; HTTrack 3.0x; Windows 98)" },
	{ true, "uablock", "libwww-perl/6.72" },
	{
		true,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
	},
	{
		true,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	},
	{ true, "uablock", "DeepseekBot/1.0" },
	{
		true,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
	},
	{ true, "uablock", "Mozilla/5.0 (compatible) AI2Bot (+https://www.allenai.org/crawler)" },
	{ false, "uablock", "curl/8.5.0" },
	{ false, "uablock", "python-requests/2.32.3" },
	{ false, "uablock", "OAI-Harvester/1.0" },
	{ false, "uablock", "Turnitin (https://bit.ly/2UvnfoQ)" },
	{
		false,
		"uablock",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	},
}

local function hits(c)
	local found = {}
	for _, r in ipairs(rules[c[2]]) do
		if match[c[2]](r, c[3], c[4]) then
			table.insert(found, r)
		end
	end
	return found
end

for _, c in ipairs(cases) do
	hits(c)
end

local function hex(s)
	return (s:gsub(".", function(ch)
		return string.format("%02x", ch:byte())
	end))
end

local tmp = os.tmpname()
local f = assert(io.open(tmp, "w"))
for _, a in ipairs(asked) do
	f:write(hex(a[1]), "\t", hex(a[2]), "\n")
end
f:close()
local perl = assert(
	io.popen(
		[[perl -ne 'chomp; my ($r, $s) = map { pack "H*", $_ } split /\t/, $_, -1; my $m = eval { $s =~ /$r/ ? 1 : 0 }; print defined $m ? $m : "E", "\n"' < ]]
			.. tmp
	)
)
results = {}
for line in perl:lines() do
	table.insert(results, line)
end
perl:close()
os.remove(tmp)
assert(#results == #asked, "perl returned " .. #results .. " results for " .. #asked .. " regexes")

local failed = 0
local seen = {}
for i, a in ipairs(asked) do
	if results[i] == "E" and not seen[a[1]] then
		seen[a[1]] = true
		failed = failed + 1
		print(string.format("FAIL regex does not compile: %s", a[1]))
	end
end

local used = {}
for _, c in ipairs(cases) do
	local found = hits(c)
	for _, r in ipairs(found) do
		used[r] = true
	end
	if (#found > 0) ~= c[1] then
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
for kind, list in pairs(rules) do
	for _, r in ipairs(list) do
		if not used[r] then
			failed = failed + 1
			print(string.format("FAIL %s rule blocks no case: %s", kind, r.src))
		end
	end
end

-- Upstream's check_master_switch matches each bypass pattern with string.find against scheme://host/path?query, so plain Lua runs it here.
local bypass_cases = {
	{ true, "https://repo.example.ac.id/oai/request?verb=Identify" },
	{ true, "https://repo.example.ac.id/rest/items" },
	{ true, "https://repo.example.ac.id/server/api/core/items" },
	{ true, "https://repo.example.ac.id/server/oai/request?verb=ListRecords" },
	{ true, "https://wp.example.com/wp-json/wp/v2/posts" },
	{ true, "http://lib.example.ac.id/api/v1/biblio" },
	{ true, "http://lib.example.ac.id/oai2.php?verb=Identify" },
	{ false, "https://repo.example.ac.id/" },
	{ false, "https://repo.example.ac.id/handle/123456789/1" },
	{ false, "https://repo.example.ac.id/handle/1?next=/oai/" },
	{ false, "https://wp.example.com/?rest_route=/wp-json/" },
}
local bypass_used = {}
for _, c in ipairs(bypass_cases) do
	local hit = false
	for _, h in ipairs(g.master_switch_custom_hosts) do
		if c[2]:find(h[2]) then
			hit = h[1] == 2
			bypass_used[h] = true
			break
		end
	end
	if hit ~= c[1] then
		failed = failed + 1
		print(string.format("FAIL bypass %q: expected %s", c[2], c[1] and "bypass" or "challenge"))
	end
end
for _, h in ipairs(g.master_switch_custom_hosts) do
	if not bypass_used[h] then
		failed = failed + 1
		print(string.format("FAIL bypass pattern matches no case: %s", h[2]))
	end
end

assert(g.master_switch == 3, "master_switch must be 3 so the bypass list applies")
assert(#g.WAF_POST_Request_table == 0, "WAF_POST_Request_table must stay empty")
if failed > 0 then
	os.exit(1)
end
print("PASS")
