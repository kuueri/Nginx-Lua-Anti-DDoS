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
	},
	WAF_query_string_Request_table = {
		{ "^.*$", ".*union.*" },
		{ "order", ".*;.*" },
		{ "^.*$", ".*MATCHLIMIT.*" },
	},
	WAF_body_block = true,
	WAF_body_skip = { "^/wp%-admin/post%.php$" },
	WAF_cookie_block = true,
}
local temps = {}

-- One request: rewrite phase, then the access-phase status (nil when the rewrite phase already exited), then the log phase.
local function request(ip, opts)
	opts = opts or {}
	local ctx, exited, cleared, header = {}, nil, false, {}
	local function env(phase, status)
		_G.ngx = {
			shared = { waf_strikes = dict },
			var = {
				remote_addr = ip,
				realip_remote_addr = opts.realip or ip,
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
					cleared = cleared or h == "X-Forwarded-For"
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
			end,
			log = function() end,
		}
	end
	if not opts.site_return then
		env("rewrite")
		dofile(script)
	end
	local status = exited or opts.status or 200
	env("log", status)
	dofile(script)
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
check(cleared, "X-Forwarded-For must be cleared when realip replaced the address")
_, cleared = request("203.0.113.21")
check(not cleared, "X-Forwarded-For must stay when realip did not replace the address")

-- Crawlers, AI agents, and Turnitin are never banned, even when a request carries a payload, e.g. a link planted with SQLi; the 403 itself stays.
-- A generic HTTP client with payloads is still banned.
now = now + 3600
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
	for _ = 1, 10 do
		request("203.0.113.40", { ua = crawler, status = 403 })
	end
	check(request("203.0.113.40", { ua = crawler }) ~= 403, "crawler was banned for payload hits: " .. crawler)
end
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
	body({ ctype = "text/plain", body = "q=union" }) == 200,
	"a body type that PHP and Tomcat do not parse is not checked"
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
check(body({ ctype = mp, body = over }) == 200, "a multipart body over 128 KB is an upload and must pass unchecked")
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
