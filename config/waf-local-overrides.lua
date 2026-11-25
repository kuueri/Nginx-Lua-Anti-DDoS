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
-- So /%2eenv and shell%2ephp are blocked too, and the traversal rule only ever matches the raw path, where ".." is not resolved yet.
localized_global.WAF_URI_Request_table = {
	{
		"^.*$",
		[[\.htaccess]],
		"scanner",
	},
	-- Also covers wp-config.php and WordPress setup-config.php.
	{
		"^.*$",
		[[config\.php]],
		"scanner",
	},
	{
		"^.*$",
		[[configuration\.php]],
		"scanner",
	},
	-- Also blocks the CSS/JS that Autoptimize and W3 Total Cache serve from /wp-content/cache/, so drop it on sites that use them.
	-- The trailing slash lets page slugs that start with "cache" through.
	{
		"^.*$",
		"/cache/",
		"scanner",
	},
	{
		"^.*$",
		[[\.env]],
		"scanner",
	},
	{
		"^.*$",
		[[/\.git]],
		"scanner",
	},
	{
		"^.*$",
		[[composer\.json]],
		"scanner",
	},
	{
		"^.*$",
		[[composer\.lock]],
		"scanner",
	},
	-- Upload directories of WordPress (wp-content/uploads), INLISLite (uploaded_files), and SLiMS (files, repository, images/docs, images/persons): a script there can only be an uploaded webshell.
	-- Only SLiMS's two image upload directories count, because themes keep scripts such as timthumb.php under other images/ directories.
	-- Upstream never reads upload bodies, so this rule keeps such a file from running, with double extensions such as shell.php.jpg, path info such as x.jpg/y.php, and Tomcat's shell.jsp;.png.
	-- The extension must end the path or be followed by . ; / or %, so names such as report.plan.pdf pass; % stays last in the class, because upstream turns %. into ".".
	-- ^(?>...) locks the first upload directory, so a path that repeats it stays a linear scan.
	{
		"^.*$",
		[[^(?>.*?(?:wp-content/uploads|/uploaded_files|/repository|/files|/images/(?:docs|persons))/).*?\.(?:php\d?|pht(?:ml)?|phar|jspx?|aspx?|cgi|pl|sh)(?:[./;%]|$)]],
		"scanner",
	},
	-- SLiMS: database backups that the admin backup module writes under files/backup.
	{
		"^.*$",
		"/files/backup(?:[/;]|$)",
		"scanner",
	},
	-- Yii2 (INLISLite): local config files with database credentials and cookie validation keys, also as editor backups such as main-local.php~.
	{
		"^.*$",
		[[(?:main|params)-local\.php]],
		"scanner",
	},
	-- Yii2 and Laravel application logs, which expose paths, SQL, and session data.
	{
		"^.*$",
		"/(?:runtime|storage)/logs/",
		"scanner",
	},
	-- Yii2's Gii code generator, which writes PHP files when it is left enabled.
	{
		"^.*$",
		"/gii(?:[/;]|$)",
		"scanner",
	},
	{
		"^.*$",
		"wp-admin/includes",
		"scanner",
	},
	{
		"^.*$",
		[[wp-includes/.*\.php]],
		"scanner",
	},
	{
		"^.*$",
		[[readme\.html]],
		"scanner",
	},
	-- WordPress: WP_DEBUG_LOG writes here by default, exposing file paths and failed SQL queries.
	{
		"^.*$",
		[[wp-content/debug\.log]],
		"scanner",
	},
	{
		"^.*$",
		[[sysconfig.*\.inc\.php]],
		"scanner",
	},
	{
		"^.*$",
		[[ucnode\.inc\.php]],
		"scanner",
	},
	-- Installer directory or script only, so content paths such as /installing-slims/ still pass.
	-- These directory rules also match the bare name at the end of the path or before ";", because Tomcat drops ";x" and serves /jolokia;x as /jolokia, while /solar-energy/ still passes.
	{
		"^.*$",
		[[/install(?:[/.;]|$)]],
		"scanner",
	},
	{
		"^.*$",
		"/upgrade(?:[/;]|$)",
		"scanner",
	},
	{
		"^.*$",
		"/solr(?:[/;]|$)",
		"scanner",
	},
	{
		"^.*$",
		"/jolokia(?:[/;]|$)",
		"scanner",
	},
	{
		"^.*$",
		"/manager(?:[/;]|$)",
		"scanner",
	},
	{
		"^.*$",
		"/host-manager(?:[/;]|$)",
		"scanner",
	},
	-- WordPress: xmlrpc.php (DDoS pingback amplification + login brute-force)
	-- Jetpack talks to WordPress.com through xmlrpc.php, so drop this rule on sites that use it.
	{
		"^.*$",
		[[xmlrpc\.php]],
		"scanner",
	},
	-- SLiMS: database credential file
	{
		"^.*$",
		[[database\.php]],
		"scanner",
	},
	-- Java/DSpace: servlet internals must never be web-served
	{
		"^.*$",
		"/WEB-INF(?:[/;]|$)",
		"scanner",
	},
	{
		"^.*$",
		"/META-INF(?:[/;]|$)",
		"scanner",
	},
	-- Spring Boot / DSpace: management endpoints must not be public
	{
		"^.*$",
		"/actuator(?:[/;]|$)",
		"scanner",
	},
	-- Generic path traversal on the raw (un-normalized) URI, also with %2e for a dot and %2f, %5c, or \ for the slash, which a backend that gets the raw path decodes.
	{
		"^.*$",
		[[(?:\.|%2e){2}(?:/|%2f|%5c|\\)]],
		"lfi",
	},
	-- Tomcat drops ";params" from every path segment and resolves "..;" as "..", while nginx does neither.
	-- So /xmlui/..;/manager/html or /manager;x/html reach Tomcat paths that the rules above and nginx locations never see.
	-- A ";" followed by another "/" is blocked, because ";jsessionid=" only ever ends the path.
	{
		"^.*$",
		";.*/",
		"lfi",
	},
}

-- Upstream decodes each query value and matches it against ^(?i)<pattern>$, so every pattern spans the whole value from (?s).* to .*.
-- (?s) lets "." cross a decoded %0A, which would otherwise stop the match and let the payload through.
-- Upstream also turns each space in a pattern into [ +%20]*, so patterns use \s instead.
-- Upstream uses an argument name only to pick rules, so waf-ban.lua also matches each name against these rules and answers a hit with 403; ?x'+union+select+1-- has no value at all.
-- Upstream matches names against ^(?i)<name>$ without the s flag, so a catch-all name is (?s).*, or a decoded %0A in a name such as q[a%0Ab] would skip every rule for that value.
-- The SQLi rules cover MySQL (SLiMS, WordPress) and PostgreSQL or Oracle (DSpace); POST and JSON bodies stay unchecked, see the POST table.
localized_global.WAF_query_string_Request_table = {
	-- SQLi, UNION-based. "select" must be a whole word, so catalogue searches such as "trade union selection" pass.
	-- (?>...) locks the first "union" to keep the match linear, because a match that hits the PCRE limit returns an error and upstream lets the request through.
	{
		"(?s).*",
		[[(?s)(?>.*?(?<![a-z_])union(?![a-z0-9_])).*(?<![a-z_])select(?![a-z0-9_]).*]],
		"sqli",
	},
	-- SQLi, boolean tautology such as ' or '1'='1 or 1 and 1=1.
	-- The operator must be followed by a quote or digit, so titles such as "Teachers' and students' perceptions" pass.
	-- An inline comment counts as a space, as in ')/**/AND/**/('a'='a, which sqlmap sent to DSpace on 2026-11-18; (?:\s|/\*[^*]*+\*+/)*+ stays possessive to keep the scan linear, and \*+/ also closes /***/.
	-- Word operators need (?![a-z0-9_]) after them, because SQL lexes "or2" as an identifier, not "or 2", and otherwise base64 tokens such as an OAI resumptionToken holding 9oR2 before "=" match.
	-- The operand may sit in nested parentheses or carry a sign or !, and LIKE, RLIKE, REGEXP, BETWEEN, or IN ( compare as well as = < >.
	-- The second branch is a bare TRUE or FALSE operand, which must end the value or meet a quote, comment, or operator, so "Teachers' and true friends" passes.
	{
		"(?s).*",
		[[(?s)(?:(?>.*?['"\d)](?:\s|/\*[^*]*+\*+/)*+(?:(?:or|and|xor)(?![a-z0-9_])|\|\||&&)(?:\s|/\*[^*]*+\*+/)*+(?:\((?:\s|/\*[^*]*+\*+/)*+)*+(?:[+-]?['"\d]|![\s(]*\d)).*(?:[=<>]|(?<![a-z0-9_])(?:(?:like|rlike|regexp|between)(?![a-z0-9_])|in(?:\s|/\*[^*]*+\*+/)*+\())|.*['"\d)](?:\s|/\*[^*]*+\*+/)*+(?:or|and|xor)(?:\s|/\*[^*]*+\*+/)++(?:not(?:\s|/\*[^*]*+\*+/)++)?(?:true|false)(?:\s|/\*[^*]*+\*+/)*+(?:$|['");]|--|#|/\*|(?:and|or|xor)(?![a-z0-9_])|\|\||&&)).*]],
		"sqli",
	},
	-- SQLi, a whole value that is a numeric tautology without a comparison, such as 1 or 1, 1 or true, or 1 || 1, optionally ending in a comment.
	-- Both sides must hold the same number, so a search such as "1 or 2" passes.
	-- \1 refers to group 1, because upstream's ^(?i)...$ wrapping adds no group, and an inline comment counts as a space, as in 1/**/or/**/1.
	{
		"(?s).*",
		[[(?s)\s*-?(\d+)(?:\s|/\*[^*]*+\*+/)*+(?:(?:or|xor|and)(?:\s|/\*[^*]*+\*+/)*+(?:-?\1|true|false)|(?:\|\||&&)(?:\s|/\*[^*]*+\*+/)*+-?\d+)\s*(?:(?:--|#|/\*).*)?]],
		"sqli",
	},
	-- SQLi, time-based and error-based functions, matched only with their opening parenthesis so "sleep quality" passes.
	-- substr, substring, and mid count only with two numeric arguments, the blind SQLi probe shape, so "Substring (computer science)" passes.
	-- ascii( and ord( stay out, because titles such as "ASCII (...)" would match; the substr or mid call inside such a probe already matches.
	-- MySQL reads an inline comment as a space, as in SLEEP/**/(5), so the tautology rule's possessive comment token may sit before the parenthesis.
	{
		"(?s).*",
		[[(?s).*(?<![a-z_])(?:(?:sleep|pg_sleep(?:_for|_until)?|benchmark|extractvalue|updatexml|load_file|group_concat|concat|concat_ws|name_const|unhex|ifnull|make_set)(?:\s|/\*[^*]*+\*+/)*+\(|char(?:\s|/\*[^*]*+\*+/)*+\(\s*\d|(?:substr(?:ing)?|mid)(?:\s|/\*[^*]*+\*+/)*+\([^()]*,\s*\d+\s*,\s*\d+\s*\)).*]],
		"sqli",
	},
	-- SQLi, a quote closed by a comment or terminator, such as admin'-- or admin'#.
	-- After a double quote, # followed by 3 to 8 hex digits and a quote is a JSON color such as {"color":"#ffffff"}, and ";" must end the value or start a comment or SQL statement.
	-- A whole value that is a PHP serialized string, also behind Yii2's 64-hex HMAC, passes, because "; ends it by design; Yii2's signed _csrf cookie is a serialized array whose "; never meets those tails.
	{
		"(?s).*",
		[[(?s)(?!([0-9a-f]{64})?s:\d+:".*";$).*(?:'\s*(?:--(?:\s|$)|#|/\*|;)|"\s*(?:--(?:\s|$)|/\*|#(?![0-9a-f]{3,8}")|;\s*(?:$|--|#|/\*|(?:select|insert|update|delete|drop|alter|create|truncate|exec|declare|waitfor|set)\b))).*]],
		"sqli",
	},
	-- SQLi, column counting with ORDER BY n closed by a comment or terminator, such as subject' ORDER BY 1-- -, which sqlmap sent to DSpace on 2026-11-18.
	-- The comment must follow, so a search such as "Law and order by 1998 standards" passes.
	{
		"(?s).*",
		[[(?s).*(?<![a-z_])order(?:\s|/\*[^*]*+\*+/)++by(?:\s|/\*[^*]*+\*+/)++\d+(?:\s*,\s*\d+)*+(?:\s|/\*[^*]*+\*+/)*+(?:--|#|/\*|;).*]],
		"sqli",
	},
	-- SQLi, subquery.
	-- An inline comment counts as a space, and MySQL runs the body of a versioned comment, so (/*!50000SELECT*/1) and (/*!50000 SELECT*/1) open a subquery too.
	{
		"(?s).*",
		[[(?s).*\((?:(?:\s|/\*[^*]*+\*+/)*+select|\s*+/\*!\d*+\s*+select)(?![a-z0-9_]).*]],
		"sqli",
	},
	-- SQLi, schema probing and file access.
	-- An inline comment counts as a space, as in INTO/**/OUTFILE or USER/**/().
	{
		"(?s).*",
		[[(?s).*(?:information_schema|mysql\.user|pg_catalog|pg_shadow|sqlite_master|@@(?:version|datadir|hostname|basedir)|into(?:\s|/\*[^*]*+\*+/)+(?:out|dump)file|(?<![a-z_])(?:version|database|user|current_user|schema)(?:\s|/\*[^*]*+\*+/)*+\(\s*\)|dbms_pipe|utl_http|utl_inaddr).*]],
		"sqli",
	},
	-- SQLi, a stacked statement that changes data or schema after ";", such as 1; DROP TABLE user or 1; DELETE FROM eperson.
	-- The statement needs its object, so "Section 1; drop-in tutoring hours" passes.
	{
		"(?s).*",
		[[(?s).*;\s*(?:(?:drop|alter|truncate)(?:\s|/\*[^*]*+\*+/)++(?:table|database|schema|user|view|index)\b|delete(?:\s|/\*[^*]*+\*+/)++from(?:\s|/\*[^*]*+\*+/)++\w|insert(?:\s|/\*[^*]*+\*+/)++into(?:\s|/\*[^*]*+\*+/)++\w|update(?:\s|/\*[^*]*+\*+/)++\w+(?:\s|/\*[^*]*+\*+/)++set(?:\s|/\*[^*]*+\*+/)++\w).*]],
		"sqli",
	},
	-- SQLi through sort parameters, a common WordPress plugin hole: only word characters, spaces, comma, dot, and dash pass.
	-- The name is grouped because upstream wraps it as ^(?i)<name>$.
	-- PHP drops leading spaces from a name and turns "." and " " into "_", so " orderby", "order.by", and "order by" reach PHP as orderby and order_by.
	{
		[[\s*(?:order|sort)(?:[\s._]?by)?]],
		[[(?s).*[^\w\s,.-].*]],
		"sqli",
	},
	{
		"(?s).*",
		[[(?s).*base64_(?:en|de)code.*]],
		"rce",
	},
	-- PHP stream wrappers that include(), file_get_contents(), or fopen() open: code, archives, commands, and compressed files.
	{
		"(?s).*",
		[[(?s).*(?:php|data|zip|expect|glob|compress\.(?:zlib|bzip2))://.*]],
		"lfi",
	},
	-- Also covers the documented CVE-2025-55752 request shape, ?param=../WEB-INF/web.xml.
	-- A backslash separates path parts on Windows and in Java's File, and %2e or %2f left in a decoded value means an app decodes it a second time.
	{
		"(?s).*",
		[[(?s).*(?:\.|%2e){2}(?:[/\\]|%2f|%5c).*]],
		"lfi",
	},
	-- Local file inclusion by absolute path, because include() and file_get_contents() open /etc/passwd without any ../.
	-- The list holds the OS files that CRS rule 930120 (lfi-os-files.data) sees probed most.
	-- (?![a-z]) lets "etc/passwords" pass, and (?:\.?/)*+ catches /etc/./passwd and /etc//passwd, which PHP opens too.
	{
		"(?s).*",
		[[(?s)(?:(?:.*/)?etc/(?:\.?/)*+(?:passwd|shadow|group|hosts)(?![a-z])|.*(?:/proc/self/|win\.ini|boot\.ini)).*]],
		"lfi",
	},
	-- Log4Shell (CVE-2021-44228, Log4j 2.x): ${jndi:...} and obfuscated ${...:...} lookups
	-- A ${...} without ":" before its "}" is skipped whole and possessively, which suffices because a ${ nested inside it has no ":" before that "}" either.
	-- So the scan stays linear without a length cap that a long key, as in ${${aaa...:-j}ndi:...}, could outrun; the earlier .*\$\{[^}]*: form spent 10 s of PCRE JIT time on 8 KB of "${:".
	{
		"(?s).*",
		[[(?s)(?:.*\$\{jndi|(?:(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+\})*+(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+:[^}]*+\}).*]],
		"rce",
	},
	-- The rules below, through ASP, must stay linear too: an unbounded scan nested inside another lets a long value hit the PCRE limit and pass.
	-- XSS, a tag that runs script or loads content. Browsers need the name right after "<", so "p<0.05" and "x < y" pass.
	{
		"(?s).*",
		[[(?s).*</?(?:script|iframe|frame|frameset|object|embed|applet|svg|math|img|image|video|audio|source|body|style|link|meta|base|form|input|button|textarea|select|details|marquee|isindex|template)(?![a-z0-9_-]).*]],
		"xss",
	},
	-- XSS, an event handler after any tag, such as <x onclick=...>; (?>...) locks the first tag.
	-- A quote also opens it, because a quote can close the attribute an app echoes the value into, so a handler can follow without any tag.
	-- The handler may also follow that quote directly, as in "onfocus=alert(1), which the second branch misses because its locked quote is the only delimiter.
	{
		"(?s).*",
		[[(?s)(?:.*["'\x60]on[a-z]{3,}\s*=|(?>.*?(?:<[a-z]|["'\x60])).*?[\s/"'\x60]on[a-z]{3,}\s*=).*]],
		"xss",
	},
	-- XSS, a script URL at the start of a value that a page may put into href or src.
	-- The scheme must be followed by code, such as alert( or //, so a title search such as "JavaScript: The Good Parts" passes.
	-- The scheme may also follow a quote, "=", "(", "<", or ">", inside an attribute such as <a href="javascript:...">.
	-- A space is no such delimiter, so a search such as Crockford JavaScript: "the good parts" passes.
	-- The two-way alternation keeps the scan linear; the optional form (?:.*[...])?[\x00-\x20]* cost 35 ms on 8 KB of spaces.
	-- Browsers drop tabs and line breaks inside a URL, so java\tscript: runs too, and the scheme allows them between its letters.
	{
		"(?s).*",
		[[(?s)(?:[\x00-\x20]*+|.*["'\x60=(<>])(?:(?:j[\t\n\r]*+a[\t\n\r]*+v[\t\n\r]*+a|v[\t\n\r]*+b|l[\t\n\r]*+i[\t\n\r]*+v[\t\n\r]*+e)[\t\n\r]*+s[\t\n\r]*+c[\t\n\r]*+r[\t\n\r]*+i[\t\n\r]*+p[\t\n\r]*+t\s*:\s*(?:[^\s\w]|[\w$.]+\s*[(\x60=])|data\s*:\s*(?:text/html|image/svg[+\s]xml|application/(?:x-)?javascript)).*]],
		"xss",
	},
	-- Command injection, a shell separator or substitution, a common command, and then what only a shell line has next: its end, an operator, an option, a path, a digit, a quote, a URL, or a host.
	-- So titles such as "Animal behaviour; cat breeds" or "Table tennis; ping pong" pass.
	-- A single & also starts the next command, but titles use it too, as in "R & Python", "Anxiety & sleep", or "P&ID".
	-- So after a single &, which leaves group 1 unset, the conditional (?(1)...|...) asks for a stronger tail: a pipe or redirect, an option, a path, a quote, a URL, or a host.
	-- That lets "x&id" through, while "x&id|..." or "x&cat /etc/passwd" still match.
	-- A relative path counts only with a file extension, as in ;cat config/database.php, so "Dogs; cat food/treats" passes.
	{
		"(?s).*",
		[[(?s).*(?:([;|\n\x60]|&&|\$\()|&)\s*(?:(?:/usr)?(?:/local)?/s?bin/)?(?:id|whoami|uname|cat|ls|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|php|ruby|ping|nslookup|dig|sleep|echo|chmod|rm|mkfifo|powershell|cmd|certutil|busybox|base64|telnet|tftp|ifconfig)(?(1)(?:\s*$|\s*[|;&<>\x60)]|\s+[-/$.~\d'"]|\s+https?:|\s+[\w-]+\.[\w.-]*[a-z]{2,}|\s+[\w.-]+/[\w./-]*\.[a-z]{2,})|(?:\s*[|<>\x60]|\s+-{1,2}[a-z]|\s+[/$~'"]|\s+https?:|\s+[\w-]+\.[\w.-]*[a-z]{2,}|\s+[\w.-]+/[\w./-]*\.[a-z]{2,})).*]],
		"cmdi",
	},
	-- Command injection, strings that only an attack sends: a shell path, a /dev/tcp reverse shell, $IFS as a space, Shellshock, or a Windows shell with its switches.
	{
		"(?s).*",
		[[(?s).*(?:/bin/(?:ba|da|z|k)?sh(?![a-z])|/dev/(?:tcp|udp)/|\$\{?ifs\}?|\(\)\s*\{\s*[:\w]+;|cmd(?:\.exe)?\s*/[ck]\s|powershell(?:\.exe)?\s+-(?:e|enc|c|nop|w)\b).*]],
		"cmdi",
	},
	-- SSRF, a URL to a loopback, private, link-local, or cloud metadata address, also as hex, decimal, octal, an IPv6 literal, or behind user@, or a scheme that only internal services speak.
	-- Public URLs, such as https://doi.org/... in a redirect parameter, pass.
	-- A trailing dot, a 1 to 3 part IPv4 form such as 127.1 or 0x7f.1, and the bare address 0 reach the same host, while DNS names that resolve to private addresses stay out of reach.
	-- libcurl and inet_aton also read each part after the first as hex or octal, as in 127.0x0.1 or 169.0376.169.254, and the last @ ends the user part, as in http://a@b@127.0.0.1/.
	-- Java opens file:/path with one slash, so file: needs only one.
	{
		"(?s).*",
		[[(?s).*(?:(?:gopher|dict|ldaps?|tftp|netdoc)://|file:/|jar:(?:https?|file|ftp):/|://(?>[^/?#\s]*@)?(?:\[[0-9a-f:.%]+\]|(?:localhost\.?|127(?:\.(?:0x[0-9a-f]+|\d+)){1,3}\.?|0\.0\.0\.0\.?|0x[0-9a-f]+(?:\.(?:0x)?[0-9a-f]+)*\.?|\d{8,10}\.?|0\d*(?:\.(?:0x[0-9a-f]+|\d+)){0,3}\.?|10(?:\.(?:0x[0-9a-f]+|\d+)){1,3}\.?|192\.(?:168|0xa8|0250)(?:\.(?:0x[0-9a-f]+|\d+)){1,2}\.?|172\.(?:1[6-9]|2\d|3[01]|0x1[0-9a-f]|0[23][0-7])(?:\.(?:0x[0-9a-f]+|\d+)){1,2}\.?|169\.(?:254|0xfe|0376)(?:\.(?:0x[0-9a-f]+|\d+)){1,2}\.?|metadata\.google\.internal\.?|100\.100\.100\.200\.?)(?:[:/?#]|$))).*]],
		"ssrf",
	},
	-- Java deserialization, a serialized object as base64 (rO0AB), hex (aced0005), or raw bytes, or a JSON gadget type.
	-- The object must start the value or follow a non-base64 character, so an arbitrary token, such as an OAI resumptionToken, cannot match by chance.
	{
		"(?s).*",
		[[(?s)(?:(?:.*[^a-z0-9+/])?(?:ro0ab|aced0005|\xac\xed\x00\x05)|.*(?:"@type"\s*:\s*"|jdbcrowsetimpl|templatesimpl|commons\.collections\.functors|ysoserial)).*]],
		"rce",
	},
	-- PHP object injection, a serialized object such as O:8:"stdClass":0:{} or O:+8:..., or a phar:// stream, whose metadata PHP unserializes.
	-- Serialized arrays and strings without an object pass.
	-- The object may also follow a hex HMAC, as in Yii2's signed cookies, which unserialize what follows the 64 hex digits.
	{
		"(?s).*",
		[[(?s).*(?:(?:^|[^a-z0-9_]|[0-9a-f]{32})[oc]:\+?\d{1,6}:"[^"]{1,200}":\d{1,6}:\{|phar://).*]],
		"rce",
	},
	-- PHP code tags, an XML DOCTYPE or ENTITY declaration (XXE), and Java template injection.
	-- Java covers a Spring expression type reference such as ${T(java.lang.Runtime)} or ${(T(...)), reflection through getClass().forName(, new java.lang.ProcessBuilder or Runtime, Velocity's $class.inspect(, and FreeMarker's <#assign and Execute utility.
	-- <?xml passes, and "java.lang.Runtime" alone stays a valid repository search.
	{
		"(?s).*",
		[[(?s).*(?:<\?(?:php|=)|<!(?:doctype|entity)\s|[$#]\{\s*\(*\s*t\s*\(|(?:getclass\s*\(\s*\)\s*\.\s*forname|\.class\.forname|\.inspect)\s*\(|new\s+java\.lang\.(?:processbuilder|runtime)|<#assign\b|freemarker\.template\.utility\.).*]],
		"rce",
	},
	-- ASP code injection, JSP and ERB template tags included: a <% tag, or the objects and calls that classic ASP webshells use.
	{
		"(?s).*",
		[[(?s).*(?:<%|(?<![a-z0-9_])(?:response\.(?:write|binarywrite)|server\.(?:createobject|execute|transfer|mappath)|createobject\s*\(|wscript\.shell|scripting\.filesystemobject|adodb\.stream|executeglobal|(?:eval|execute)\s*\(?\s*request)).*]],
		"rce",
	},
}

-- Upstream matches header values raw, unanchored, and case-sensitively, so value patterns start with (?i).
localized_global.WAF_Header_Request_table = {
	-- XSS through headers that apps decode, store, or show: a cookie that PHP decodes, or a Referer or User-Agent in an admin log view; raw or percent-encoded.
	-- A quote also opens an event handler without any tag, because a log view may echo the value into an attribute.
	{
		"^(?:cookie|referer|user-agent)$",
		[[(?i)(?:<|%3c)/?(?:script|iframe|svg|img|body|object|embed|style|link|meta|base|form|input|details|math|video|audio)(?![a-z0-9_-])|^(?>.*?(?:<|%3c)[a-z]).*?(?:[\s/"'\x60+]|%2[0f27])on[a-z]{3,}\s*(?:=|%3d)|(?:["'\x60]|%2[27]|%60)(?:\s|\+|%20)*+on[a-z]{3,}\s*(?:=|%3d)]],
		"xss",
	},
	-- A script URL as the whole Referer, which an admin log view may turn into a link; browsers drop tabs and line breaks inside the scheme.
	{
		"^referer$",
		[[(?i)^\s*(?:j[\t\n\r ]*a[\t\n\r ]*v[\t\n\r ]*a|v[\t\n\r ]*b|l[\t\n\r ]*i[\t\n\r ]*v[\t\n\r ]*e)[\t\n\r ]*s[\t\n\r ]*c[\t\n\r ]*r[\t\n\r ]*i[\t\n\r ]*p[\t\n\r ]*t\s*:]],
		"xss",
	},
	-- SQLi through headers that apps store or log, client address headers included: UNION SELECT, time-based or error-based functions, and a subquery.
	-- An inline comment may sit before the parenthesis, as in SLEEP/**/(5), as in the query rule.
	{
		"^(?:cookie|referer|user-agent|x-forwarded-for|x-real-ip|client-ip)$",
		[[(?i)^(?>.*?(?<![a-z_])union(?![a-z0-9_])).*(?<![a-z_])select(?![a-z0-9_])|(?<![a-z_])(?:sleep|pg_sleep(?:_for|_until)?|benchmark|extractvalue|updatexml)(?:\s|/\*[^*]*+\*+/)*+\(|\((?:\s|/\*[^*]*+\*+/)*+select(?![a-z0-9_])]],
		"sqli",
	},
	{
		"^x-forwarded-host$",
		[[(?:/|\\)]],
		"protocol",
	},
	-- Log4Shell (CVE-2021-44228, Log4j 2.x): scan every header value for ${jndi:...} / ${...:...}
	-- The same linear scan as the query rule, anchored with ^ so that it runs once per value.
	{
		"^.*$",
		[[(?is)^(?:.*\$\{jndi|(?:(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+\})*+(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+:[^}]*+\})]],
		"rce",
	},
	-- Java deserialization through any header, such as a rememberMe cookie: a serialized object at the start of a value, case-sensitive like base64.
	{
		"^.*$",
		[[(?:^|[^A-Za-z0-9+/])(?:rO0AB|aced0005|ACED0005)]],
		"rce",
	},
	-- PHP object injection through cookies, which PHP decodes before an app unserializes them, or a phar:// stream; raw or percent-encoded, %2B for the + included.
	-- The object may also follow a hex HMAC, as in Yii2's signed cookies.
	{
		"^cookie$",
		[[(?i)(?:^|[^a-z0-9_]|[0-9a-f]{32})[oc](?::|%3a)(?:\+|%2b)?\d{1,6}(?::|%3a)(?:"|%22).{1,200}?(?:"|%22)(?::|%3a)\d{1,6}(?::|%3a)(?:\{|%7b)|phar(?::|%3a)(?:/|%2f){2}]],
		"rce",
	},
	-- PHP code tags, which a log viewer that includes the log file would run, and Java template injection as in the query rule, in any header.
	{
		"^.*$",
		[[(?i)<\?(?:php|=)|[$#]\{\s*\(*\s*t\s*\(|(?:getclass\s*\(\s*\)\s*\.\s*forname|\.class\.forname|\.inspect)\s*\(|new\s+java\.lang\.(?:processbuilder|runtime)|<#assign\b|freemarker\.template\.utility\.]],
		"rce",
	},
	-- Shellshock (CVE-2014-6271): a function definition in any header, which a CGI script would hand to bash.
	{
		"^.*$",
		[[\(\s*\)\s*\{]],
		"cmdi",
	},
}

-- Any rule here makes upstream read every POST body, uploads included, into a Lua string, so the filter stays off.
-- waf-ban.lua checks bodies instead, with the settings below.
localized_global.WAF_POST_Request_table = {}

-- waf-ban.lua checks request bodies in the rewrite phase with WAF_query_string_Request_table; upstream never reads these two settings.
-- It checks each urlencoded field, each multipart field without a filename= parameter (PHP's test for a file), and each JSON object key and each JSON value under its innermost object key, unquoted so that {"color":"#ffffff"} passes, with its own parser because no JSON library is built in.
-- JSON that does not parse, nests deeper than 100 levels, or holds more than 1000 keys and values is checked as one text after its escapes are decoded.
-- An xml or +xml body gets one XML rule in waf-ban.lua instead, because Atom and SOAP tags such as <link> and attributes such as online= match the query XSS rules; a text/plain or untyped body is checked as JSON or XML when it starts with {, [, or <.
-- It reads up to 128 KB, where every query rule stays clear of the PCRE match limit even without PCRE JIT; 1 MB values hit that limit.
-- A larger urlencoded, JSON, or XML body, or a urlencoded or multipart body with more than 1000 fields, gets 413, which never counts toward a ban; a larger text/plain body stays unchecked.
-- A larger multipart body is an upload: its file parts are skipped and its other fields are still checked, up to 128 KB of field text, or 413.
-- true answers a hit with 403, which counts toward a ban; DSpace's log-only hits on 2026-11-23 were sqlmap-style payloads in /browse and /discover forms.
-- false only logs "Would block (log only) Request body prohibited", as a fallback for tuning a new site; prefer a WAF_body_skip entry for one false-positive path.
localized_global.WAF_body_block = true
-- Lua patterns for $uri, the decoded path, whose bodies stay unchecked, because editors save posts there and HTML or SQL words are normal content.
-- The WordPress classic and block editors, anchored at the site root so that no path info or subdirectory can borrow the exemption; a WordPress in a subdirectory needs its own entries.
localized_global.WAF_body_skip = {
	"^/wp%-admin/post%.php$",
	"^/wp%-json/wp/v2/",
}

-- waf-ban.lua also checks each Cookie name and value, URL-decoded as PHP decodes them, with WAF_query_string_Request_table; upstream never reads this setting.
-- true answers a hit with 403, which counts toward a ban; the rules spare Yii2 signed cookies, PHP serialized strings, and JSON colors, which cookies carry.
-- false only logs "Would block (log only) Request cookie prohibited", as a fallback for tuning; prefer a WAF_cookie_skip entry for one opaque token cookie.
localized_global.WAF_cookie_block = true
-- Lua patterns for cookie names that waf-ban.lua does not check, name and value, because they carry opaque tokens; upstream never reads this setting.
-- sl-session is the base64 session token of a SafeLine front proxy.
localized_global.WAF_cookie_skip = { "^sl%-session$" }

-- Upstream's default anti_ddos_table closes the connection and bans the address for 24 hours on PATCH, PUT, DELETE, CONNECT, OPTIONS, or TRACE.
-- REST clients (DSpace's Angular UI and REST API, SWORDv2, the WordPress REST API) send PUT, PATCH, and DELETE, and Microsoft Office sends OPTIONS before it opens a bitstream link, so only CONNECT and TRACE stay banned.
-- Field 5 bans a request of 1 MB or more and field 12 a small body announced with Expect: 100-continue, which REST and SWORD deposits send, so both are 0 and nginx's client_max_body_size governs body size.
-- Upstream also turns on the JavaScript challenge for all paths once 100 addresses are banned (field 24), which breaks non-browser OAI-PMH harvesters and API clients with a 200 HTML page.
-- Prepending a copy of the default entry with field 24 set to math.huge keeps the challenge off on the paths below (field 23 must stay 1, or upstream's default master_switch = 1 leaves the challenge always on) while keeping all WAF rules and flood checks active.
-- Upstream matches each Lua pattern with string.find against scheme://host/request_uri, so every pattern is anchored at the host, and SLiMS's p=oai must be a whole query argument, which a value such as ?x=://a/oai/ is not.
-- pairs() copies every field across the nil hole at field 32; upstream calls this function once per worker after it builds its default table.
localized_global.anti_ddos_table = function()
	local t = package.loaded["anti_ddos_config_store"].anti_ddos_table
	local allowed = { OPTIONS = true, PUT = true, PATCH = true, DELETE = true }
	for _, site in ipairs(t) do
		for i = #site[26], 1, -1 do
			if allowed[site[26][i][1]] then
				table.remove(site[26], i)
			end
		end
		site[5] = 0
		site[12] = 0
	end
	local out = {}
	for _, pattern in ipairs({
		"^https?://[^/]+/oai[/?]",
		"^https?://[^/]+/server/oai[/?]",
		"^https?://[^/]+/opac/oai",
		"^https?://[^/]+/[^/?]+/opac/oai",
		"^https?://[^?]+%?p=oai$",
		"^https?://[^?]+%?p=oai&",
		"^https?://[^?]+%?.-&p=oai$",
		"^https?://[^?]+%?.-&p=oai&",
		"^https?://[^/]+/server/api/",
		"^https?://[^/]+/swordv2/",
		"^https?://[^/]+/rest/",
		"^https?://[^/]+/wp%-json/",
		"^https?://[^/]+/[^/?]+/wp%-json/",
		"^https?://[^/]+/api/",
		"^https?://[^/]+/[^/?]+/api/",
	}) do
		local entry = {}
		for k, v in pairs(t[1]) do
			entry[k] = v
		end
		entry[1] = pattern
		entry[24] = math.huge
		out[#out + 1] = entry
	end
	for i = 1, #t do
		out[#out + 1] = t[i]
	end
	return out
end
