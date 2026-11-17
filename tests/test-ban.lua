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
			},
			header = header,
			HTTP_TOO_MANY_REQUESTS = 429,
			req = {
				clear_header = function(h)
					cleared = cleared or h == "X-Forwarded-For"
				end,
				get_uri_args = function()
					return {}, opts.truncated == "args" and "truncated" or nil
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

if failed > 0 then
	os.exit(1)
end
print("PASS")
