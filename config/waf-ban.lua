local LIMIT = 5
local WINDOW = 600
local BAN = 3600
local AI_LIMIT = 10
local AI_WINDOW = 60
local BODY_LIMIT = 131072
local BODY_FIELDS = 1000
local AI_AGENTS = {
	"gptbot",
	"chatgpt-user",
	"oai-searchbot",
	"claudebot",
	"claude-user",
	"claude-searchbot",
	"claude-web",
	"anthropic-ai",
	"perplexitybot",
	"perplexity-user",
	"deepseek",
	"ai2bot",
	"ccbot",
	"bytespider",
	"meta-externalagent",
	"amazonbot",
	"cohere-ai",
	"mistralai-user",
	"duckassistbot",
	"youbot",
}
local CRAWLERS = { "bot", "crawl", "spider", "slurp", "turnitin", "facebookexternalhit" }

local strikes = ngx.shared.waf_strikes
local ip = ngx.var.remote_addr
local ua = (ngx.var.http_user_agent or ""):lower()

local function find(list)
	for _, name in ipairs(list) do
		if ua:find(name, 1, true) then
			return name
		end
	end
end

local function json_text(s)
	s = s:gsub("\\u00(%x%x)", function(h)
		return string.char(tonumber(h, 16))
	end)
	return (s:gsub("\\([nrt])", { n = "\n", r = "\r", t = "\t" }):gsub("\\(.)", "%1"))
end

local function multipart_fields(body, ctype)
	local at = ctype:find("boundary", 1, true) or ctype:lower():find("boundary", 1, true)
	local value = at and ctype:sub(at):match("=(.*)")
	local boundary = value and (value:match('^"([^"]*)"') or value:match("^[^,;]*"))
	if not boundary or boundary == "" then
		return nil
	end
	local fields, parts = {}, 0
	local delim = "\n--" .. boundary
	body = "\n" .. body
	local _, stop = body:find(delim, 1, true)
	while stop and body:sub(stop + 1, stop + 2) ~= "--" do
		parts = parts + 1
		local next_at, next_stop = body:find(delim, stop + 1, true)
		local rest = body:sub(stop + 1, (next_at or #body + 1) - 1):match("^[^\n]*\n(.*)$") or ""
		local head, content = ("\n" .. rest):match("^(.-)\n\r?\n(.*)$")
		local cd = (head or ""):lower():match("\ncontent%-disposition:([^\n]*)") or ""
		if not cd:find(";[ \t]*filename=") then
			local name = cd:match(';[ \t]*name="([^"]*)"') or cd:match(";[ \t]*name=([^;\r]*)") or ""
			fields[#fields + 1] = { name, content or rest }
		end
		stop = next_stop
	end
	return parts > 0 and fields or nil
end

local function rule_hit(fields)
	for i, rule in ipairs(localized_global.WAF_query_string_Request_table) do
		local key = "^(?i)" .. rule[1]:gsub("[%^%$]", "") .. "$"
		local val = "^(?i)" .. rule[2] .. "$"
		for _, field in ipairs(fields) do
			if ngx.re.find(field[1], key, "jos") then
				local from, _, err = ngx.re.find(field[2], val, "jo")
				if from or err then
					local name = field[1]:sub(1, 64):gsub("%c", "?")
					return name .. ", WAF_query_string_Request_table rule " .. i .. (err and ", " .. err or "")
				end
			end
		end
	end
end

local function log_hit(what, block, reason)
	ngx.log(
		ngx.STDERR,
		"[WAF] ",
		block and "Blocked" or "Would block (log only)",
		" Request ",
		what,
		" prohibited: ",
		ngx.var.request_uri,
		" (",
		reason,
		")"
	)
end

local function cookie_fields()
	local fields = {}
	for pair in (ngx.var.http_cookie or ""):gmatch("[^;]+") do
		local name, value = pair:match("^%s*([^=]*)=?(.*)$")
		if value ~= "" then
			fields[#fields + 1] = { name, ngx.unescape_uri(value) }
		end
	end
	return fields
end

local function body_hit(uri)
	local ctype = ngx.var.content_type or ""
	local lower = ctype:lower()
	local kind = lower:find("^%s*application/x%-www%-form%-urlencoded") and "form"
		or lower:find("^%s*multipart/form%-data") and "multipart"
		or lower:find("json", 1, true) and "json"
	if not kind then
		return
	end
	for _, skip in ipairs(localized_global.WAF_body_skip) do
		if uri:find(skip) then
			return
		end
	end
	local length = tonumber(ngx.var.content_length)
	if not length or length <= BODY_LIMIT then
		ngx.req.read_body()
		local body = ngx.req.get_body_data()
		local file = not body and ngx.req.get_body_file()
		if file then
			local f = assert(io.open(file, "rb"))
			body = f:read(BODY_LIMIT + 1)
			f:close()
		end
		if not body then
			return
		end
		length = #body
		if length <= BODY_LIMIT then
			local fields
			if kind == "form" then
				fields = {}
				for name, values in pairs(ngx.decode_args(body, BODY_FIELDS + 1)) do
					for _, v in ipairs(type(values) == "table" and values or { values }) do
						fields[#fields + 1] = { name, tostring(v) }
					end
				end
			elseif kind == "multipart" then
				fields = multipart_fields(body, ctype) or { { "", body } }
			else
				fields = { { "", json_text(body) } }
			end
			if #fields > BODY_FIELDS then
				return 413, "over " .. BODY_FIELDS .. " fields"
			end
			for k = 1, #fields do
				fields[#fields + 1] = { fields[k][1], fields[k][1] }
			end
			local reason = rule_hit(fields)
			if reason then
				return ngx.HTTP_FORBIDDEN, "field " .. reason
			end
			return
		end
	end
	if kind ~= "multipart" then
		return 413, "over " .. BODY_LIMIT .. " bytes"
	end
end

if ngx.get_phase() == "rewrite" then
	if ngx.var.realip_remote_addr ~= ip then
		ngx.req.clear_header("X-Forwarded-For")
	end
	if strikes:get("ban:" .. ip) then
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	local args, args_err = ngx.req.get_uri_args()
	local _, headers_err = ngx.req.get_headers()
	if args_err == "truncated" or headers_err == "truncated" then
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	ngx.ctx.waf_ban_checked = true
	local uri = ngx.var.uri
	local url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri
	for i, rule in ipairs(localized_global.WAF_URI_Request_table) do
		if
			ngx.re.find(url, "^(?i)" .. rule[1]:gsub("[%^%$]", "") .. "$", "jo")
			and ngx.re.find(uri, "(?i)" .. rule[2], "jo")
		then
			ngx.log(
				ngx.STDERR,
				"[WAF] Blocked Request URI prohibited after decoding: ",
				ngx.var.request_uri,
				" (WAF_URI_Request_table rule ",
				i,
				")"
			)
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
	end
	local agent = find(AI_AGENTS)
	if agent and (strikes:incr("ai:" .. agent, 1, 0, AI_WINDOW) or 0) > AI_LIMIT then
		ngx.header["Retry-After"] = AI_WINDOW
		return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
	end
	if ngx.req.is_internal() then
		return
	end
	local names = {}
	for name in pairs(args) do
		names[#names + 1] = { name, name }
	end
	local reason = rule_hit(names)
	if reason then
		log_hit("argument name", true, reason)
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	reason = rule_hit(cookie_fields())
	if reason then
		log_hit("cookie", localized_global.WAF_cookie_block, reason)
		if localized_global.WAF_cookie_block then
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
	end
	local status
	status, reason = body_hit(uri)
	if status then
		log_hit("body", localized_global.WAF_body_block, reason)
		if localized_global.WAF_body_block then
			return ngx.exit(status)
		end
	end
	return
end

if not ngx.ctx.waf_ban_checked or ngx.status ~= ngx.HTTP_FORBIDDEN or ngx.var.upstream_status then
	return
end
if
	ip:find("^127%.")
	or ip:find("^10%.")
	or ip:find("^192%.168%.")
	or ip:find("^172%.1[6-9]%.")
	or ip:find("^172%.2%d%.")
	or ip:find("^172%.3[01]%.")
	or ip == "::1"
	or ip:find("^f[cd]")
	or find(AI_AGENTS)
	or find(CRAWLERS)
then
	return
end
local hits = strikes:incr("hit:" .. ip, 1, 0, WINDOW)
if hits and hits >= LIMIT then
	strikes:set("ban:" .. ip, true, BAN)
	strikes:delete("hit:" .. ip)
	ngx.log(ngx.WARN, "[WAF ban] ", ip, " banned for ", BAN, " s after ", hits, " blocked requests")
end
