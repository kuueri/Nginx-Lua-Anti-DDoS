-- Run config/waf-ban.lua against a stub ngx, one rewrite and one log phase per request, as nginx does.
local script = arg[0]:gsub("[^/]*$", "") .. "../config/waf-ban.lua"

local now = 0
local store = {}
local dict = {
	get = function(_, k)
		local e = store[k]
		return e and (not e.exp or e.exp > now) and e.v or nil
	end,
	set = function(_, k, v, ttl)
		store[k] = { v = v, exp = ttl and now + ttl }
	end,
	delete = function(_, k)
		store[k] = nil
	end,
	incr = function(self, k, n, init, ttl)
		local v = self:get(k)
		if v == nil then
			store[k] = { v = init + n, exp = ttl and now + ttl }
		else
			store[k].v = v + n
		end
		return store[k].v
	end,
}

localized_global = {
	WAF_URI_Request_table = {
		{ "^.*$", [[/xmlrpc\.php]] },
		{ [[^https://other\.example/.*$]], "/private/" },
		{ "^.*$", "/MATCHLIMIT/" },
	},
	WAF_query_string_Request_table = {
		{ "^.*$", ".*union.*" },
		{ "order", ".*;.*" },
		{ "^.*$", ".*MATCHLIMIT.*" },
		{ "^.*$", '.*"#.*' },
		{ "^.*$", ".*esc[\f\b\n]esc.*" },
	},
	WAF_body_block = true,
	WAF_body_skip = { "^/wp%-admin/post%.php$" },
	WAF_cookie_block = true,
	WAF_cookie_skip = { "^sl%-session$" },
}
local temps = {}

local EXIT = {}
package.loaded["waf_ban_cache"] = {}

local function run()
	local ok, err = pcall(dofile, script)
	if not ok and err ~= EXIT then
		error(err, 0)
	end
end

local function start(ip, opts)
	opts = opts or {}
	local ctx, exited, cleared, header = {}, nil, {}, {}
	local function env(phase, status)
		_G.ngx = {
			shared = { waf_strikes = dict },
			var = {
				remote_addr = ip,
				realip_remote_addr = not opts.realip_nil and (opts.realip or ip) or nil,
				upstream_status = opts.upstream,
				http_user_agent = opts.ua,
				scheme = "https",
				host = opts.host or "example.com",
				request_uri = opts.raw or opts.uri or "/",
				uri = opts.uri or "/",
				content_type = opts.ctype,
				http_cookie = opts.cookie,
				content_length = opts.body and not opts.chunked and tostring(#opts.body) or nil,
			},
			re = {
				find = function(s, p)
					if p:find("MATCHLIMIT", 1, true) and s:find("boom", 1, true) then
						return nil, nil, "pcre2_match() failed: -47"
					end
					if p:find("doctype", 1, true) then
						for _, w in ipairs({ "<!doctype", "<!entity", "class=", "<?php", "${jndi", "<script" }) do
							if s:lower():find(w, 1, true) then
								return 1
							end
						end
						return nil
					end
					return s:lower():find((p:gsub("%(%?i%)", ""):gsub("\\%.", "%%."):lower()))
				end,
			},
			decode_args = function(s, max)
				local t, n = {}, 0
				for pair in s:gmatch("[^&]+") do
					n = n + 1
					if n > max then
						break
					end
					local k, eq, v = pair:match("^([^=]*)(=?)(.*)$")
					v = eq == ""
						or v:gsub("%+", " "):gsub("%%(%x%x)", function(h)
							return string.char(tonumber(h, 16))
						end)
					if t[k] == nil then
						t[k] = v
					elseif type(t[k]) == "table" then
						table.insert(t[k], v)
					else
						t[k] = { t[k], v }
					end
				end
				return t
			end,
			unescape_uri = function(s)
				return (
					s:gsub("%+", " "):gsub("%%(%x%x)", function(h)
						return string.char(tonumber(h, 16))
					end)
				)
			end,
			header = header,
			HTTP_TOO_MANY_REQUESTS = 429,
			STDERR = 0,
			req = {
				is_internal = function()
					return opts.internal == true
				end,
				read_body = function() end,
				get_body_data = function()
					return not opts.file and opts.body or nil
				end,
				get_body_file = function()
					if opts.file and opts.body then
						local path = os.tmpname()
						local f = assert(io.open(path, "wb"))
						f:write(opts.body)
						f:close()
						table.insert(temps, path)
						return path
					end
				end,
				clear_header = function(h)
					cleared[h] = true
				end,
				get_uri_args = function()
					return opts.args or {}, opts.truncated == "args" and "truncated" or nil
				end,
				get_headers = function()
					return {}, opts.truncated == "headers" and "truncated" or nil
				end,
			},
			ctx = ctx,
			status = status,
			HTTP_FORBIDDEN = 403,
			WARN = 5,
			get_phase = function()
				return phase
			end,
			exit = function(code)
				exited = code
				error(EXIT)
			end,
			log = function() end,
		}
	end
	if not opts.site_return then
		env("rewrite")
		run()
		if not exited and not opts.site_deny then
			package.loaded["waf_ban_cache"].upstream = function()
				if opts.status == 403 and not opts.autoindex and not opts.upstream then
					ngx.exit(403)
				end
			end
			env("access")
			run()
		end
	end
	local status = exited or opts.status or 200
	return status, function()
		env("log", status)
		run()
	end, cleared, header
end

local function request(ip, opts)
	local status, log, cleared, header = start(ip, opts)
	log()
	return status, cleared, header
end

local failed = 0
local function check(ok, msg)
	if not ok then
		failed = failed + 1
		print("FAIL " .. msg)
	end
end

local pub = "203.0.113.10"
for i = 1, 4 do
	check(request(pub, { status = 403 }) == 403, "WAF hit " .. i .. " is not passed through as 403")
end
check(request(pub) == 200, "4 WAF hits must not ban")
check(request(pub, { status = 403 }) == 403, "5th WAF hit is not 403")
check(request(pub) == 403, "5 WAF hits within the window must ban")
now = now + 3599
check(request(pub) == 403, "ban must last 1 hour")
now = now + 2
check(request(pub) == 200, "ban must end after 1 hour")
for _, hours in ipairs({ 2, 4, 8, 16 }) do
	for _ = 1, 5 do
		request(pub, { status = 403 })
	end
	now = now + hours * 3600 - 1
	check(request(pub) == 403, "repeat ban must last " .. hours .. " hours")
	now = now + 2
	check(request(pub) == 200, "repeat ban must end after " .. hours .. " hours")
end

local slow = "203.0.113.11"
for _ = 1, 4 do
	request(slow, { status = 403 })
end
now = now + 601
request(slow, { status = 403 })
check(request(slow) == 200, "hits spread over more than 10 minutes must not ban")

local dspace = "203.0.113.12"
for _ = 1, 10 do
	request(dspace, { status = 403, upstream = "403" })
end
check(request(dspace) == 200, "403 from DSpace must not count")

local site = "203.0.113.13"
for _ = 1, 10 do
	request(site, { status = 403, site_return = true })
end
check(request(site) == 200, "403 from a site 'return 403' before the rewrite handler must not count")

for _, ip in ipairs({ "192.168.19.7", "10.1.2.3", "172.16.15.230", "172.31.0.1", "127.0.0.1", "::1", "fd00::1" }) do
	for _ = 1, 10 do
		request(ip, { status = 403 })
	end
	check(request(ip) == 200, "private address " .. ip .. " must never be banned")
end
for _ = 1, 5 do
	request("172.32.0.1", { status = 403 })
end
check(request("172.32.0.1") == 403, "172.32.0.1 is public and must be banned")

local _, cleared = request("203.0.113.20", { realip = "192.168.19.7" })
check(cleared["X-Forwarded-For"], "X-Forwarded-For must be cleared when realip replaced the address")
_, cleared = request("203.0.113.21")
check(not cleared["X-Forwarded-For"], "X-Forwarded-For must stay when realip did not replace the address")
_, cleared = request("203.0.113.22", { realip = "172.68.10.1" })
check(
	cleared["X-Forwarded-For"] and cleared["CF-Connecting-IP"],
	"X-Forwarded-For and CF-Connecting-IP must be cleared when realip replaced the address"
)
_, cleared = request("203.0.113.23", { realip_nil = true })
check(next(cleared) == nil, "no proxy header may be cleared without the realip module")
_, cleared = request("192.168.19.7", { realip = "192.168.19.7" })
check(
	cleared["CF-Connecting-IP"] and not cleared["X-Forwarded-For"],
	"a private proxy address must lose CF-Connecting-IP and keep X-Forwarded-For"
)

local listing = "203.0.113.24"
for _ = 1, 10 do
	request(listing, { status = 403, autoindex = true })
end
check(request(listing) == 200, "a content-phase 403 after upstream passed, such as autoindex off, must not count")
local trap = "203.0.113.25"
for _ = 1, 5 do
	request(trap, { status = 403, site_deny = true })
end
check(request(trap) == 403, "an access-phase deny before upstream must count toward a ban")

local burst = "203.0.113.26"
local logs = {}
for i = 1, 10 do
	local _, log = start(burst, { status = 403 })
	logs[i] = log
end
for _, log in ipairs(logs) do
	log()
end
check(store["bans:" .. burst].v == 1, "one HTTP/2 burst of 10 hits must ban once, not twice")
check(store["bans:" .. burst].exp ~= nil, "the ban history must expire")
local above = "203.0.113.27"
store["hit:" .. above] = { v = 7, exp = now + 600 }
request(above, { status = 403 })
check(request(above) == 403, "a hit count already above the limit must still ban")
local repeat_ip = "203.0.113.28"
store["bans:" .. repeat_ip] = { v = 20, exp = now + 2592000 }
for _ = 1, 5 do
	request(repeat_ip, { status = 403 })
end
now = now + 512 * 3600 - 1
check(request(repeat_ip) == 403, "a repeat ban must last up to its 512-hour cap")
now = now + 2
check(request(repeat_ip) == 200, "a repeat ban must end after its 512-hour cap")

-- Crawlers, AI agents, and Turnitin are not banned for a few payload hits, e.g. links planted with SQLi; the 403 itself stays.
-- 50 payload hits within 10 minutes ban them, because anyone can send a crawler User-Agent; a generic HTTP client is banned at 5.
now = now + 3600
local crawler_n = 0
for _, crawler in ipairs({
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Turnitin (https://bit.ly/2UvnfoQ)",
	"Mozilla/5.0 (compatible; PlagyBot/1.0)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claude-user@anthropic.com)",
}) do
	crawler_n = crawler_n + 1
	local addr = "203.0.113." .. (80 + crawler_n)
	for _ = 1, 10 do
		request(addr, { ua = crawler, status = 403 })
	end
	check(request(addr, { ua = crawler }) ~= 403, "crawler was banned for 10 payload hits: " .. crawler)
end
local patient = "203.0.113.70"
local patient_ua = "Mozilla/5.0 (compatible; PlagyBot/1.0)"
for _ = 1, 49 do
	request(patient, { ua = patient_ua, status = 403 })
end
check(request(patient, { ua = patient_ua }) == 200, "49 crawler payload hits must not ban")
request(patient, { ua = patient_ua, status = 403 })
check(request(patient, { ua = patient_ua }) == 403, "50 crawler payload hits within 10 minutes must ban")
local spread = "203.0.113.71"
for _ = 1, 49 do
	request(spread, { ua = patient_ua, status = 403 })
end
now = now + 601
request(spread, { ua = patient_ua, status = 403 })
check(request(spread, { ua = patient_ua }) == 200, "crawler payload hits spread over more than 10 minutes must not ban")
for _, client in ipairs({ "curl/8.5.0", "python-requests/2.32.3" }) do
	local addr = client:sub(1, 4) == "curl" and "203.0.113.41" or "203.0.113.42"
	for _ = 1, 5 do
		request(addr, { ua = client, status = 403 })
	end
	check(request(addr, { ua = client }) == 403, "generic client with 5 payload hits must be banned: " .. client)
end

-- AI agents share one budget per agent family across all addresses, answered with 429, which never counts toward a ban.
local chatgpt =
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
local claude =
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claude-user@anthropic.com)"
local browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
now = now + 3600
for i = 1, 10 do
	check(
		request("203.0.113.30", { ua = chatgpt }) == 200,
		"ChatGPT-User request " .. i .. " within the limit was refused"
	)
end
local status, _, header = request("203.0.113.31", { ua = chatgpt })
check(status == 429, "11th ChatGPT-User request in a minute, from another address, must get 429")
check(header["Retry-After"] == 60, "429 must carry Retry-After: 60")
check(request("203.0.113.30", { ua = claude }) == 200, "Claude-User must have its own budget")
for _ = 2, 10 do
	request("203.0.113.30", { ua = claude })
end
check(request("203.0.113.30", { ua = claude }) == 429, "11th Claude-User request in a minute must get 429")
check(request("203.0.113.30", { ua = browser }) == 200, "a browser on the same address must not be limited")
for _ = 1, 20 do
	request("203.0.113.32", { ua = chatgpt })
end
check(request("203.0.113.32", { ua = browser }) == 200, "429 from the AI limit must not count toward a ban")
now = now + 61
check(request("203.0.113.31", { ua = chatgpt }) == 200, "the AI limit must reset after a minute")
now = now + 61
for i = 1, 10 do
	request("203.0.113.34", { ua = chatgpt })
	check(
		request("203.0.113.34", { ua = chatgpt, internal = true }) == 200,
		"the internal redirect of ChatGPT-User request " .. i .. " must not use the budget"
	)
end
check(request("203.0.113.34", { ua = chatgpt }) == 429, "the 11th external ChatGPT-User request must get 429")
check(
	request("203.0.113.33", { ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" }) == 200,
	"Googlebot is no AI agent"
)

for _, kind in ipairs({ "args", "headers" }) do
	check(request("203.0.113.50", { truncated = kind }) == 403, "more than 100 " .. kind .. " must get 403")
end
for _ = 1, 10 do
	request("203.0.113.51", { truncated = "args" })
end
check(request("203.0.113.51") == 200, "403 for more than 100 args or headers must not count toward a ban")

local encoded = "203.0.113.60"
for i = 1, 5 do
	check(
		request(encoded, { raw = "/xmlrpc%2ephp", uri = "/xmlrpc.php" }) == 403,
		"encoded path hit " .. i .. " that only matches after decoding must get 403"
	)
end
check(request(encoded) == 403, "5 hits on the decoded path must ban")
check(request("203.0.113.61", { uri = "/xmlrpc.html" }) == 200, "a decoded path that matches no rule must pass")
check(request("203.0.113.62", { uri = "/boom" }) == 403, "a regex error on the decoded path must block")
check(request("203.0.113.61", { uri = "/private/x" }) == 200, "a URI rule for another host must not apply")
check(
	request("203.0.113.61", { host = "other.example", uri = "/private/x" }) == 403,
	"a URI rule for this host must apply"
)

local form = "application/x-www-form-urlencoded"
local mp = "multipart/form-data; boundary=XyZ"
local over = string.rep("a", 131073)
local n = 0
local function body(opts)
	n = n + 1
	return request("198.51.100." .. n, opts)
end
local function part(head, value)
	return "--XyZ\r\n" .. head .. "\r\n\r\n" .. value .. "\r\n"
end
local field_q = 'Content-Disposition: form-data; name="q"'
check(body({ ctype = form, body = "q=1+union+select+2" }) == 403, "a urlencoded field with a payload must get 403")
check(body({ ctype = form .. "; charset=UTF-8", body = "q=hello+world" }) == 200, "a clean urlencoded body must pass")
check(body({ ctype = form, body = "order=title;drop" }) == 403, "a rule for the order field must apply to it")
check(body({ ctype = form, body = "q=a;b" }) == 200, "a rule for the order field must not apply to other fields")
check(body({ ctype = form, body = "q=boom" }) == 403, "a regex error must block, not let the body through")
check(body({ ctype = form, body = string.rep("a=1&", 1001) }) == 413, "more than 1000 fields must get 413")
check(body({ ctype = form, body = "q=union", file = true }) == 403, "a body buffered to a temp file must be checked")
check(body({ ctype = form, body = over }) == 413, "a urlencoded body over 128 KB must get 413")
check(body({ ctype = form, body = over, chunked = true }) == 413, "a chunked body over 128 KB must get 413")
check(
	body({ ctype = "application/json", body = '{"q":"un\\u0069on"}' }) == 403,
	"a JSON body must be checked after its \\u escapes are decoded"
)
check(body({ ctype = "application/json", body = '{"q":"hello"}' }) == 200, "a clean JSON body must pass")
check(
	body({ ctype = "application/json", body = '{"color":"#ffffff","n":-1.5e3,"ok":true,"z":null,"e":{},"a":[]}' })
		== 200,
	"JSON values must be checked without the quotes around them"
)
check(
	body({ ctype = "application/json", body = '{"order":"title;drop"}' }) == 403,
	"a rule for a field name must apply to the JSON value of that key"
)
check(
	body({ ctype = "application/json", body = '{"a":["ok",{"q":"x\\"un\\u0069on\\""}]}' }) == 403,
	"a nested JSON string with escapes must be checked"
)
check(body({ ctype = "application/json", body = '{"x union y":1}' }) == 403, "a JSON key with a payload must get 403")
check(
	body({ ctype = "application/json", body = '{"q":"un\\u0069on"' }) == 403,
	"malformed JSON must be checked as one text"
)
check(
	body({ ctype = "application/json", body = '{"q":"#"} "#' }) == 403,
	"JSON with trailing data must be checked as one text"
)
check(
	body({ ctype = "application/json", body = ("["):rep(101) .. '"#"' .. ("]"):rep(101) }) == 403,
	"JSON nested deeper than 100 levels must be checked as one text"
)
check(
	body({ ctype = "application/json", body = "[" .. ("1,"):rep(1000) .. "1]" }) == 200,
	"JSON with more than 1000 values must be checked as one text, not refused"
)
check(
	body({ ctype = "application/json", body = '["#",' .. ("1,"):rep(1000) .. "1]" }) == 403,
	"JSON with more than 1000 values must still be checked"
)
check(
	body({ ctype = "text/plain", body = "q=union" }) == 200,
	"a body type that PHP and Tomcat do not parse is not checked"
)
check(
	body({ ctype = "application/json", body = '{"q":"esc\\fesc"}' }) == 403
		and body({ ctype = "application/json", body = '{"q":"esc\\besc"}' }) == 403,
	"JSON \\f and \\b escapes must decode to form feed and backspace"
)
check(
	body({ ctype = "application/json", body = '{"q":"esc\\\\nesc"}' }) == 200,
	"an escaped backslash before n must stay a backslash, not become a newline"
)
check(
	body({ ctype = "application/json", body = '{"q":"a\\fb"}' }) == 200
		and body({ ctype = "application/json", body = '{"x union y":{}}' }) == 403
		and body({ ctype = "application/json", body = '{"x union y":{"a":1}}' }) == 403
		and body({ ctype = "application/json", body = '{"x union y":[]}' }) == 403,
	"outer JSON object keys on empty or nested objects/arrays must be checked"
)
check(body({
	ctype = "application/atom+xml",
	body = '<entry xmlns="http://www.w3.org/2005/Atom"><link href="https://example.org/1"/><source><title>ok</title></source><item online="true"/></entry>',
}) == 200, "valid Atom and SOAP XML with <link>, <source>, and online= attributes must pass")
check(
	body({ ctype = "application/xml", body = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a/>' }) == 403,
	"XML body with DOCTYPE/ENTITY XXE must get 403"
)
check(
	body({ ctype = "text/xml", body = '<java><object class="java.lang.ProcessBuilder"/></java>' }) == 403,
	"XMLDecoder payload in XML body must get 403"
)
check(body({ ctype = "application/xml", body = over }) == 413, "an XML body over 128 KB must get 413")
check(
	body({ ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", body = over }) == 200,
	"a binary upload whose type name holds xml must stay unchecked"
)
check(
	body({ ctype = "text/plain", body = '{"q":"1 union select 2"}' }) == 403,
	"a text/plain JSON body with a payload must get 403"
)
check(
	body({ ctype = "text/plain", body = '<!DOCTYPE x [<!ENTITY a "b">]>' }) == 403,
	"a text/plain XML body with XXE must get 403"
)
check(body({ body = '{"q":"union"}' }) == 403, "a JSON body without a Content-Type must be checked")
check(
	body({ ctype = "text/plain", body = over }) == 200,
	"an unstructured text/plain body over 128 KB must stay unchecked"
)
check(request("198.51.100.220", { cookie = "union=1" }) == 403, "a cookie name with a payload must get 403")
check(
	request("198.51.100.221", { cookie = "un%69on=" }) == 403,
	"a percent-encoded cookie name with an empty value must get 403"
)
check(
	body({ ctype = mp, body = part(field_q, "1 union select 2") .. "--XyZ--\r\n" }) == 403,
	"a multipart field with a payload must get 403"
)
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a.sql"\r\nContent-Type: text/plain', "union")
		.. "--XyZ--\r\n",
}) == 200, "a multipart file must not be checked")
check(
	body({ ctype = mp, body = part(field_q .. '; xfilename="a"', "union") .. "--XyZ--\r\n" }) == 403,
	"only a filename parameter makes a multipart file, as in PHP"
)
check(
	body({ ctype = mp, body = part(field_q, "union") }) == 403,
	"a last field without a closing boundary must be checked"
)
check(
	body({ ctype = "multipart/form-data; boundary=Other", body = part(field_q, "union") }) == 403,
	"a multipart body whose boundary matches no part must be checked whole"
)
check(body({ ctype = mp, body = over }) == 413, "a multipart body over 128 KB without any part must get 413")
local clean_q = part(field_q, "x") .. "--XyZ--\r\n"
check(
	body({ ctype = 'multipart/form-data; x="boundary=FAKE"; boundary=XyZ', body = clean_q }) == 403,
	"a boundary that PHP and Tomcat read differently (quoted parameter) must get 403"
)
check(
	body({ ctype = "multipart/form-data; x_boundary=FAKE; boundary=XyZ", body = clean_q }) == 403,
	"a boundary that PHP and Tomcat read differently (prefixed parameter) must get 403"
)
check(
	body({ ctype = "multipart/form-data; boundary=XyZ; boundary=b", body = clean_q }) == 403,
	"two boundary parameters must get 403"
)
check(body({
	ctype = "multipart/form-data; boundary=XyZ ",
	body = part('Content-Disposition: form-data; name="order"', "title;drop") .. "--XyZ--\r\n",
}) == 403, "a boundary with trailing spaces must still be parsed and checked")
check(
	body({ ctype = mp .. "; charset=UTF-8", body = clean_q }) == 200,
	"a clean multipart body with more parameters must pass"
)
for _, head in ipairs({
	field_q .. '; x="; filename=a"',
	field_q .. "; x='; filename=a'",
	field_q .. '; x="\\"; filename=a"',
}) do
	check(
		body({ ctype = mp, body = part(head, "union") .. "--XyZ--\r\n" }) == 403,
		"a quoted filename= is no file parameter: " .. head
	)
end
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a.pdf"\r\n' .. field_q, "union") .. "--XyZ--\r\n",
}) == 403, "two Content-Disposition headers in one part must get 403")
local pdf = part(
	'Content-Disposition: form-data; name="f"; filename="thesis.pdf"\r\nContent-Type: application/pdf',
	("union "):rep(35000)
)
for _, file in ipairs({ false, true }) do
	local mode = file and "a temp file" or "memory"
	check(
		body({ ctype = mp, body = pdf .. part(field_q, "hello") .. "--XyZ--\r\n", file = file, chunked = file }) == 200,
		"a 200 KB upload with a clean field in " .. mode .. " must pass"
	)
	check(body({
		ctype = mp,
		body = part('Content-Disposition: form-data; name="f"; filename="a.pdf"', ("x"):rep(153600))
			.. part(field_q, "1 union select 2")
			.. "--XyZ--\r\n",
		file = file,
	}) == 403, "a payload after a 150 KB upload in " .. mode .. " must get 403")
	check(body({
		ctype = mp,
		body = part(field_q, "1 union select 2")
			.. part('Content-Disposition: form-data; name="f"; filename="a.pdf"', ("x"):rep(153600))
			.. "--XyZ--\r\n",
		file = file,
	}) == 403, "a payload before a 150 KB upload in " .. mode .. " must get 403")
end
check(
	body({ ctype = mp, body = part('Content-Disposition: form-data; name="pad"', over) .. "--XyZ--\r\n" }) == 413,
	"a non-file field over 128 KB must get 413"
)
check(
	body({ ctype = form, body = "q=union", uri = "/wp-admin/post.php" }) == 200,
	"a body on a skipped path must not be checked"
)
check(
	body({ ctype = form, body = "q=union", internal = true }) == 200,
	"an internal redirect must not check the body again"
)
localized_global.WAF_body_block = false
check(body({ ctype = form, body = "q=union" }) == 200, "log-only mode must not block")
check(body({ ctype = form, body = over }) == 200, "log-only mode must not answer 413")
localized_global.WAF_body_block = true
local attacker = "198.51.100.200"
for _ = 1, 5 do
	request(attacker, { ctype = form, body = "q=union" })
end
check(request(attacker) == 403, "5 body hits must ban")
local big = "198.51.100.201"
for _ = 1, 10 do
	request(big, { ctype = form, body = over })
end
check(request(big) == 200, "413 for a large body must not count toward a ban")

check(
	request("198.51.100.210", { args = { ["x' union select 1,2--"] = true } }) == 403,
	"a query argument name with a payload must get 403"
)
check(request("198.51.100.211", { args = { q = "union" } }) == 200, "query argument values are left to upstream")
check(
	request("198.51.100.212", { args = { union = true }, internal = true }) == 200,
	"an internal redirect must not check argument names again"
)
local named = "198.51.100.213"
for _ = 1, 5 do
	request(named, { args = { union = "1" } })
end
check(request(named) == 403, "5 argument name hits must ban")
check(body({ ctype = form, body = "1+union+select=2" }) == 403, "a urlencoded field name with a payload must get 403")
check(
	body({ ctype = mp, body = part('Content-Disposition: form-data; name="union"', "x") .. "--XyZ--\r\n" }) == 403,
	"a multipart field name with a payload must get 403"
)
check(
	request("198.51.100.214", { cookie = "a=1; q=un%69on" }) == 403,
	"a decoded cookie value with a payload must get 403"
)
check(
	request("198.51.100.215", { cookie = "_ga=GA1.1.123.456; wp-settings-1=libraryContent%3Dbrowse; e=" }) == 200,
	"clean cookies must pass"
)
check(
	request("198.51.100.216", { cookie = "q=union", internal = true }) == 200,
	"an internal redirect must not check cookies again"
)
check(
	request("198.51.100.218", { cookie = "sl-session=union" }) == 200,
	"a cookie in WAF_cookie_skip must not be checked"
)
check(
	request("198.51.100.219", { cookie = "sl-session=x; sl-sessionx=union" }) == 403,
	"a cookie not in WAF_cookie_skip must still be checked"
)
localized_global.WAF_cookie_block = false
check(request("198.51.100.217", { cookie = "q=union" }) == 200, "cookie log-only mode must not block")
localized_global.WAF_cookie_block = true

for _, path in ipairs(temps) do
	os.remove(path)
end

if failed > 0 then
	os.exit(1)
end
print("PASS")
