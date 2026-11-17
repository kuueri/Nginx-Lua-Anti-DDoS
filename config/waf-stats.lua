local MAX_KEYS = 10000

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
for _, k in ipairs(ngx.shared.waf_strikes:get_keys(MAX_KEYS)) do
	if k:find("^ban:") then
		out.waf_bans = out.waf_bans + 1
	end
end
ngx.say(encode(out))
