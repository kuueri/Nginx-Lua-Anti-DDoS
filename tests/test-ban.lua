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
	local ctx, exited, cleared = {}, nil, false
	local function env(phase, status)
		_G.ngx = {
			shared = { waf_strikes = dict },
			var = {
				remote_addr = ip,
				realip_remote_addr = opts.realip or ip,
				upstream_status = opts.upstream,
			},
			req = {
				clear_header = function(h)
					cleared = cleared or h == "X-Forwarded-For"
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
	return status, cleared
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

if failed > 0 then
	os.exit(1)
end
print("PASS")
