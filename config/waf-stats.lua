local MAX_KEYS = 10000
local FLUSH_INTERVAL = 30
local CATEGORIES = { "cmdi", "lfi", "other", "protocol", "rce", "scanner", "sqli", "ssrf", "xss", "xxe" }
local STATE_KEYS = {
	"attacks",
	"bans",
	"banned_requests",
	"cat:cmdi",
	"cat:lfi",
	"cat:other",
	"cat:protocol",
	"cat:rce",
	"cat:scanner",
	"cat:sqli",
	"cat:ssrf",
	"cat:xss",
	"cat:xxe",
}
local VALID_KEYS = {}
for _, k in ipairs(STATE_KEYS) do
	VALID_KEYS[k] = true
end

local function state_path()
	return (localized_global and localized_global.WAF_stats_file) or "/var/lib/nginx/waf/stats.txt"
end

local function serialize(stats)
	local lines = {}
	for i, k in ipairs(STATE_KEYS) do
		lines[i] = k .. "=" .. tostring(stats:get(k) or 0)
	end
	return table.concat(lines, "\n") .. "\n"
end

if ngx.get_phase and ngx.get_phase() == "init_worker" then
	if not ngx.worker or ngx.worker.id() ~= 0 then
		return
	end
	local stats = ngx.shared.waf_stats
	if not stats then
		return
	end
	local path = state_path()
	local file_data
	local f = io.open(path, "rb")
	if f then
		file_data = f:read("*a")
		f:close()
		for k, v in file_data:gmatch("([a-z:_]+)=(%d+)") do
			if VALID_KEYS[k] then
				stats:add(k, tonumber(v))
			end
		end
	end
	local empty_lines = {}
	for i, k in ipairs(STATE_KEYS) do
		empty_lines[i] = k .. "=0"
	end
	local last_written = file_data or (table.concat(empty_lines, "\n") .. "\n")
	local logged_err = false
	local function flush(premature)
		local data = serialize(stats)
		if data == last_written then
			return
		end
		local tmp = path .. ".tmp"
		local out, err = io.open(tmp, "wb")
		if not out then
			if not logged_err then
				ngx.log(ngx.ERR, "[WAF stats] failed to open ", tmp, ": ", err)
				logged_err = true
			end
			return
		end
		local ok, werr = out:write(data)
		local closed, cerr = out:close()
		if not ok or not closed then
			os.remove(tmp)
			if not logged_err then
				ngx.log(ngx.ERR, "[WAF stats] failed to write ", tmp, ": ", werr or cerr)
				logged_err = true
			end
			return
		end
		local renamed, rerr = os.rename(tmp, path)
		if not renamed then
			os.remove(tmp)
			if not logged_err then
				ngx.log(ngx.ERR, "[WAF stats] failed to persist ", path, ": ", rerr)
				logged_err = true
			end
			return
		end
		last_written = data
		logged_err = false
	end
	local ok, err = ngx.timer.every(FLUSH_INTERVAL, flush)
	if not ok then
		ngx.log(ngx.ERR, "[WAF stats] failed to start flush timer: ", err)
	end
	return
end

local function encode(v)
	if type(v) == "table" then
		local parts = {}
		for k, x in pairs(v) do
			parts[#parts + 1] = encode(tostring(k)) .. ":" .. encode(x)
		end
		table.sort(parts)
		return "{" .. table.concat(parts, ",") .. "}"
	elseif type(v) == "string" then
		return '"' .. v:gsub('[%c"\\]', function(c)
			return string.format("\\u%04x", c:byte())
		end) .. '"'
	end
	return tostring(v)
end

local dict = ngx.shared.antiddos
local keys = dict:get_keys(MAX_KEYS)
local stats = ngx.shared.waf_stats
local by_type = {}
for _, cat in ipairs(CATEGORIES) do
	by_type[cat] = stats and (stats:get("cat:" .. cat) or 0) or 0
end
local out = {
	current_timestamp = ngx.time(),
	keys_listed = #keys,
	total_traffic_allowed = 0,
	total_traffic_blocked = 0,
	requests_blocked = 0,
	requests_per_ip = {},
	js_puzzle_per_ip = {},
	blocked_ips_ttl = {},
	waf_bans = 0,
	waf_attacks_total = stats and (stats:get("attacks") or 0) or 0,
	waf_bans_total = stats and (stats:get("bans") or 0) or 0,
	waf_banned_requests_total = stats and (stats:get("banned_requests") or 0) or 0,
	waf_attacks_by_type = by_type,
}
for _, k in ipairs(keys) do
	if k == "total_traffic" then
		out.total_traffic_allowed = dict:get(k)
	elseif k == "blocked_total_traffic" then
		out.total_traffic_blocked = dict:get(k)
	elseif k == "blocked_ip" then
		out.requests_blocked = dict:get(k)
	elseif k:find("^pr") then
		out.js_puzzle_per_ip[k:sub(3)] = dict:get(k)
	elseif k:find("^r") then
		out.requests_per_ip[k:sub(2)] = dict:get(k)
	elseif k:find("^%d") or k:find(":", 1, true) then
		out.blocked_ips_ttl[k] = dict:ttl(k)
	end
end
for _, k in ipairs(ngx.shared.waf_bans:get_keys(MAX_KEYS)) do
	if k:find("^ban:") then
		out.waf_bans = out.waf_bans + 1
	end
end
ngx.say(encode(out))
