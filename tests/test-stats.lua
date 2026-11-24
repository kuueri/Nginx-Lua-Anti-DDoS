local script = arg[0]:gsub("[^/]*$", "") .. "../config/waf-stats.lua"

local function dict(t)
	return {
		get_keys = function(_, n)
			assert(n > 0, "get_keys(0) locks the whole dict")
			local r = {}
			for k in pairs(t) do
				r[#r + 1] = k
			end
			return r
		end,
		get = function(_, k)
			return t[k]
		end,
		ttl = function()
			return 42
		end,
	}
end

local said
ngx = {
	time = function()
		return 1
	end,
	say = function(s)
		said = s
	end,
	shared = {
		antiddos = dict({
			total_traffic = 7,
			blocked_total_traffic = 3,
			blocked_ip = 1,
			["r1.2.3.4"] = 5,
			['r"x\\\n'] = 1,
			["pr1.2.3.4"] = 2,
			["9.9.9.9"] = "x",
			["2001:db8::1"] = "x",
			["cachedpage"] = "x",
		}),
		waf_strikes = dict({ ["hit:6.6.6.6"] = 2 }),
		waf_bans = dict({ ["ban:5.5.5.5"] = true, ["bans:5.5.5.5"] = 2 }),
	},
}

dofile(script)
for _, want in ipairs({
	'"total_traffic_allowed":7',
	'"total_traffic_blocked":3',
	'"requests_blocked":1',
	'"requests_per_ip":{"1.2.3.4":5,"\\u0022x\\u005c\\u000a":1}',
	'"js_puzzle_per_ip":{"1.2.3.4":2}',
	'"blocked_ips_ttl":{"2001:db8::1":42,"9.9.9.9":42}',
	'"waf_bans":1',
	'"keys_listed":9',
}) do
	assert(said:find(want, 1, true), "missing " .. want .. " in " .. said)
end

print("PASS")
