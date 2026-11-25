local script = arg[0]:gsub("[^/]*$", "") .. "../config/waf-stats.lua"

local function make_dict(t)
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
		add = function(_, k, v)
			if t[k] ~= nil then
				return false, "exists"
			end
			t[k] = v
			return true
		end,
		set = function(_, k, v)
			t[k] = v
			return true
		end,
		ttl = function()
			return 42
		end,
	}
end

local said
ngx = {
	get_phase = function()
		return "content"
	end,
	time = function()
		return 1
	end,
	say = function(s)
		said = s
	end,
	shared = {
		antiddos = make_dict({
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
		waf_strikes = make_dict({ ["hit:6.6.6.6"] = 2 }),
		waf_bans = make_dict({ ["ban:5.5.5.5"] = true, ["bans:5.5.5.5"] = 2 }),
		waf_stats = make_dict({
			attacks = 12,
			bans = 3,
			banned_requests = 40,
			["cat:sqli"] = 7,
			["cat:xss"] = 5,
		}),
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
	'"waf_attacks_total":12',
	'"waf_bans_total":3',
	'"waf_banned_requests_total":40',
	'"waf_attacks_by_type":{"cmdi":0,"lfi":0,"other":0,"protocol":0,"rce":0,"scanner":0,"sqli":7,"ssrf":0,"xss":5,"xxe":0}',
	'"keys_listed":9',
}) do
	assert(said:find(want, 1, true), "missing " .. want .. " in " .. said)
end

local state_file = os.tmpname()
os.remove(state_file)
localized_global = { WAF_stats_file = state_file }

local timer_cb, timer_delay
local function run_init_worker(worker_id, stats_store)
	timer_cb, timer_delay = nil, nil
	ngx = {
		get_phase = function()
			return "init_worker"
		end,
		worker = {
			id = function()
				return worker_id
			end,
		},
		timer = {
			every = function(delay, cb)
				timer_delay, timer_cb = delay, cb
				return true
			end,
		},
		shared = {
			waf_stats = make_dict(stats_store),
		},
		ERR = 4,
		log = function() end,
	}
	dofile(script)
end

run_init_worker(1, {})
assert(timer_cb == nil, "non-zero worker must not register flush timer")

local live = {}
run_init_worker(0, live)
assert(timer_delay == 30 and type(timer_cb) == "function", "worker 0 must register 30s flush timer")
timer_cb(false)
local f = io.open(state_file, "rb")
assert(f == nil, "flush with zero changes must not write an empty file")

live.attacks = 15
live.bans = 4
live.banned_requests = 99
live["cat:sqli"] = 10
live["cat:rce"] = 5
timer_cb(false)
f = assert(io.open(state_file, "rb"), "flush must write state file after changes")
local first_written = f:read("*a")
f:close()
assert(first_written:find("attacks=15\n", 1, true), "missing attacks=15 in state file")
assert(first_written:find("bans=4\n", 1, true), "missing bans=4 in state file")
assert(first_written:find("cat:sqli=10\n", 1, true), "missing cat:sqli=10 in state file")
assert(first_written:find("cat:rce=5\n", 1, true), "missing cat:rce=5 in state file")

live.attacks = 18
timer_cb(true)
f = assert(io.open(state_file, "rb"))
local shutdown_written = f:read("*a")
f:close()
assert(
	shutdown_written:find("attacks=18\n", 1, true),
	"graceful shutdown flush (premature=true) must persist latest value"
)

local reloaded = { attacks = 25, bans = 4 }
run_init_worker(0, reloaded)
assert(reloaded.attacks == 25, "reload must keep higher live shared dict counter via add()")
assert(reloaded.banned_requests == 99, "reload must fill missing keys from state file")

local restarted = {}
run_init_worker(0, restarted)
assert(
	restarted.attacks == 18 and restarted.bans == 4 and restarted.banned_requests == 99,
	"restart must restore totals from state file"
)
assert(
	restarted["cat:sqli"] == 10 and restarted["cat:rce"] == 5,
	"restart must restore attack categories from state file"
)

os.remove(state_file)
os.remove(state_file .. ".tmp")
print("PASS")
