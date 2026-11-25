local LIMIT = 5
local WINDOW = 600
local BAN = 3600
local CRAWLER_LIMIT = 50
local CRAWLER_WINDOW = 600
local AI_LIMIT = 10
local AI_WINDOW = 60
local BODY_LIMIT = 131072
local BODY_FIELDS = 1000
local COOKIE_FIELDS = 200
local MULTIPART_PARTS = 1000
local MULTIPART_FILES = 100
local CTYPE_LIMIT = 1024
local BAN_HISTORY_TTL = 2592000

local phase = ngx.get_phase()
local cache = package.loaded["waf_ban_cache"]
if not cache then
	cache = {}
	package.loaded["waf_ban_cache"] = cache
end

if phase == "access" then
	if ngx.exit ~= cache.wrapped_exit then
		local orig_exit = ngx.exit
		cache.wrapped_exit = function(code)
			if code == ngx.HTTP_FORBIDDEN and ngx.ctx.waf_in_upstream then
				ngx.ctx.waf_in_upstream = nil
				ngx.ctx.waf_recorded = true
				if cache.lib then
					cache.lib.record_hit(nil)
				end
			end
			return orig_exit(code)
		end
		ngx.exit = cache.wrapped_exit
	end
	cache.upstream = cache.upstream or assert(loadfile("/etc/nginx/lua/waf.lua"))
	if ngx.ctx.waf_ban_checked then
		ngx.ctx.waf_in_upstream = true
	end
	cache.upstream()
	ngx.ctx.waf_in_upstream = nil
	ngx.ctx.waf_access_passed = true
	return
end

if phase == "log" then
	if
		not ngx.ctx.waf_ban_checked
		or ngx.ctx.waf_access_passed
		or ngx.ctx.waf_recorded
		or ngx.status ~= ngx.HTTP_FORBIDDEN
		or ngx.var.upstream_status
	then
		return
	end
end

local ip = ngx.var.remote_addr
local bans = ngx.shared.waf_bans
local stats = ngx.shared.waf_stats
if phase == "rewrite" and bans:get("ban:" .. ip) then
	if stats then
		stats:incr("banned_requests", 1, 0)
	end
	return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local lib = cache.lib
if not lib then
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
	local JSON_ESCAPES = { b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
	local XML_RULE =
		[[(?is)(?:<!(?:doctype|entity)\s|<(?:[\w.-]+:)?include\b[^<>]*\bhref\s*=|http://www\.w3\.org/1999/XSL/Transform|<(?:java|object|void|new)\b[^<>]*\bclass\s*=|<\?(?:php|=)|<script(?![a-z0-9_-])|\$\{jndi|^(?:(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+\})*+(?:[^$]++|\$(?!\{))*+\$\{[^}:]*+:[^}]*+\}|[$#]\{\s*\(*\s*t\s*\(|(?:getclass\s*\(\s*\)\s*\.\s*forname|\.class\.forname|\.inspect)\s*\(|new\s+java\.lang\.(?:processbuilder|runtime)|<#assign\b|freemarker\.template\.utility\.)]]

	local function is_private(addr)
		return addr:find("^127%.")
			or addr:find("^10%.")
			or addr:find("^192%.168%.")
			or addr:find("^172%.1[6-9]%.")
			or addr:find("^172%.2%d%.")
			or addr:find("^172%.3[01]%.")
			or addr == "::1"
			or addr:find("^f[cd]")
	end

	local function compiled(name, prefix, suffix)
		local rules = localized_global[name]
		if cache[name] ~= rules then
			local out = {}
			for i, rule in ipairs(rules) do
				local key = rule[1]:gsub("[%^%$]", "")
				out[i] = {
					key == ".*" or key == "(?s).*",
					"^(?i)" .. key .. "$",
					prefix .. rule[2] .. suffix,
					rule[3] or "other",
				}
			end
			cache[name], cache[name .. " compiled"] = rules, out
		end
		return cache[name .. " compiled"]
	end

	local function compiled_headers()
		local rules = localized_global.WAF_Header_Request_table
		if not rules then
			return {}
		end
		if cache.headers ~= rules then
			local out = {}
			for i, rule in ipairs(rules) do
				local clean = rule[1]:gsub("[%^%$]", "")
				out[i] = { rule[1], clean, rule[2], rule[3] or "other" }
			end
			cache.headers, cache.headers_compiled = rules, out
		end
		return cache.headers_compiled
	end

	local function find(list, ua)
		for _, name in ipairs(list) do
			if ua:find(name, 1, true) then
				return name
			end
		end
	end

	local function json_text(s)
		return (
			s:gsub("\\(.)(%x?%x?%x?%x?)", function(c, h)
				if c == "u" and #h == 4 and h:sub(1, 2) == "00" then
					return string.char(tonumber(h, 16))
				end
				return (JSON_ESCAPES[c] or c) .. h
			end)
		)
	end

	local function json_fields(body)
		local fields, pos = {}, 1
		local function skip()
			pos = body:find("[^ \t\r\n]", pos) or #body + 1
		end
		local function str()
			local at = pos + 1
			while true do
				local q = body:find('["\\]', at)
				if not q then
					return
				end
				if body:byte(q) == 34 then
					local s = json_text(body:sub(pos + 1, q - 1))
					pos = q + 1
					return s
				end
				at = q + 2
			end
		end
		local value
		local function members(key, depth, close)
			pos = pos + 1
			skip()
			if body:sub(pos, pos) == close then
				pos = pos + 1
				return true
			end
			local d
			repeat
				local k = key
				if close == "}" then
					skip()
					k = body:sub(pos, pos) == '"' and str()
					skip()
					if not k or body:sub(pos, pos) ~= ":" then
						return
					end
					pos = pos + 1
					fields[#fields + 1] = { k, k }
					if #fields > BODY_FIELDS then
						return
					end
				end
				if not value(k, depth + 1) then
					return
				end
				skip()
				d = body:sub(pos, pos)
				pos = pos + 1
			until d ~= ","
			return d == close
		end
		function value(key, depth)
			skip()
			local c = body:sub(pos, pos)
			if depth > 100 then
				return
			elseif c == "{" then
				return members(key, depth, "}")
			elseif c == "[" then
				return members(key, depth, "]")
			end
			local s = c == '"' and str() or body:match("^[%w.+-]+", pos)
			if not s then
				return
			elseif c ~= '"' then
				pos = pos + #s
			end
			fields[#fields + 1] = { key, s }
			return #fields <= BODY_FIELDS
		end
		if value("", 0) then
			skip()
			return pos > #body and fields or nil
		end
	end

	local function trim(s)
		return s and s:match("^[ \t]*(.-)[ \t]*$")
	end

	local function extract_boundary(ctype)
		if #ctype > CTYPE_LIMIT then
			return nil, "content-type too long"
		end
		local at = ctype:find("boundary", 1, true) or ctype:lower():find("boundary", 1, true)
		local value = at and ctype:sub(at):match("=(.*)")
		local php = value and (value:sub(1, 1) == '"' and value:match('^"([^"]*)"') or value:match("^[^,;]*"))
		local rfc, count, pos = nil, 0, (ctype:find(";", 1, true) or #ctype) + 1
		while pos <= #ctype do
			local name, stop = ctype:match("^%s*([^=;]*)()", pos)
			local param
			pos = stop
			if ctype:sub(pos, pos) == "=" then
				local q = ctype:match('^%s*()"', pos + 1)
				if q then
					local e = q + 1
					while e <= #ctype and ctype:sub(e, e) ~= '"' do
						e = e + (ctype:sub(e, e) == "\\" and 2 or 1)
					end
					param = ctype:sub(q + 1, e - 1):gsub("\\(.)", "%1")
					pos = e + 1
				else
					param = ctype:match("^[^;]*", pos + 1)
					pos = pos + 1 + #param
				end
			end
			pos = (ctype:find(";", pos, true) or #ctype) + 1
			if trim(name):lower() == "boundary" then
				count = count + 1
				rfc = param
			end
		end
		if count > 1 then
			return nil, "multiple boundaries"
		end
		php, rfc = trim(php), trim(rfc)
		if not php or php == "" or php ~= rfc then
			return nil, "ambiguous boundary"
		end
		if #php > 70 or not php:find("^[A-Za-z0-9'()+_,%-./:=? ]+$") then
			return nil, "invalid boundary"
		end
		return php
	end

	local function part_disposition(head)
		if head:find("\0", 1, true) then
			return nil, "null byte in multipart header"
		end
		if head:find("\n[ \t]") then
			return nil, "folded multipart header"
		end
		local lower = head:lower()
		local _, n = lower:gsub("\ncontent%-disposition:", "")
		if n > 1 then
			return nil, "duplicate content-disposition"
		end
		local cd_start, cd_end = lower:find("\ncontent%-disposition:[^\n]*")
		local cd = cd_start and head:sub(cd_start + 21, cd_end):gsub("\r$", "") or ""
		local name, name_n, file_n, file_star_n = "", 0, 0, 0
		local filenames = {}
		local pos = (cd:find(";", 1, true) or #cd) + 1
		while pos <= #cd do
			local pname, stop = cd:match("^%s*([^=;]*)()", pos)
			local pval = ""
			pos = stop
			if cd:sub(pos, pos) == "=" then
				local q, quote = cd:match("^%s*()([\"'])", pos + 1)
				if q then
					local e = q + 1
					while e <= #cd and cd:sub(e, e) ~= quote do
						e = e + (cd:sub(e, e) == "\\" and 2 or 1)
					end
					if e > #cd then
						return nil, "unterminated quote in content-disposition"
					end
					pval = cd:sub(q + 1, e - 1):gsub("\\(.)", "%1")
					pos = e + 1
				else
					local raw = cd:match("^[^;]*", pos + 1) or ""
					pval = trim(raw) or ""
					pos = pos + 1 + #raw
				end
			end
			pos = (cd:find(";", pos, true) or #cd) + 1
			pname = trim(pname):lower()
			if pname == "name" then
				name_n = name_n + 1
				if name_n > 1 then
					return nil, "duplicate name parameter"
				end
				name = pval
			elseif pname == "filename" then
				file_n = file_n + 1
				if file_n > 1 then
					return nil, "duplicate filename parameter"
				end
				filenames[#filenames + 1] = pval
			elseif pname == "filename*" then
				file_star_n = file_star_n + 1
				if file_star_n > 1 then
					return nil, "duplicate filename* parameter"
				end
				local ext = pval:match("^[^']*'[^']*'(.*)$") or pval
				filenames[#filenames + 1] = ngx.unescape_uri(ext)
			end
		end
		return (file_n > 0 or file_star_n > 0), name, filenames
	end

	local function multipart_fields(read, boundary)
		local delim = "\n--" .. boundary
		local buf, pos, eof = "", 1, false
		local fields, parts, files, field_count, text = {}, 0, 0, 0, 0
		local function more()
			local chunk = not eof and read()
			if not chunk then
				eof = true
				return false
			end
			buf = pos > #buf and chunk or buf:sub(pos) .. chunk
			pos = 1
			return true
		end
		local function upto(keep)
			local out, size = {}, 0
			while true do
				local a, b = buf:find(delim, pos, true)
				local stop = a and a - 1 or eof and #buf or math.max(pos - 1, #buf - #delim)
				if keep then
					size = size + stop - pos + 1
					if text + size > BODY_LIMIT then
						return nil, nil, true
					end
					out[#out + 1] = buf:sub(pos, stop)
				end
				pos = a and b + 1 or stop + 1
				if a or eof then
					text = text + size
					return a ~= nil, table.concat(out)
				end
				more()
			end
		end
		while #buf < #delim and more() do
		end
		local found
		if buf:sub(1, #delim - 1) == delim:sub(2) then
			found, pos = true, #delim
		else
			found = upto(false)
		end
		while found do
			while #buf - pos < 1 and more() do
			end
			if buf:sub(pos, pos + 1) == "--" then
				break
			end
			parts = parts + 1
			if parts > MULTIPART_PARTS then
				return nil, 413, "over " .. MULTIPART_PARTS .. " multipart parts"
			end
			local le, hs, he
			repeat
				le = buf:find("\n", pos, true)
				hs, he = nil, nil
				if le then
					hs, he = buf:find("\n\r?\n", le)
				end
			until hs or #buf - pos > 65536 or not more()
			if not hs or hs - pos > 65536 or (buf:find(delim, pos, true) or hs) < hs then
				return nil, 413, "multipart part without a header end"
			end
			local is_file, name, filenames = part_disposition(buf:sub(le, hs - 1))
			if is_file == nil then
				return nil, ngx.HTTP_FORBIDDEN, name
			end
			if is_file then
				files = files + 1
				if files > MULTIPART_FILES then
					return nil, 413, "over " .. MULTIPART_FILES .. " multipart files"
				end
			end
			pos = he + 1
			local content, over
			found, content, over = upto(not is_file)
			if over then
				return nil, 413, "over " .. BODY_LIMIT .. " bytes of multipart fields"
			end
			if is_file then
				if name ~= "" then
					fields[#fields + 1] = { "", name }
				end
				for _, fn in ipairs(filenames) do
					if fn ~= "" then
						fields[#fields + 1] = { "", fn }
					end
				end
			else
				field_count = field_count + 1
				if field_count > BODY_FIELDS then
					return nil, 413, "over " .. BODY_FIELDS .. " fields"
				end
				fields[#fields + 1] = { name, content }
			end
		end
		return fields, parts
	end

	local function rule_hit(fields)
		for i, rule in ipairs(compiled("WAF_query_string_Request_table", "^(?i)", "$")) do
			for _, field in ipairs(fields) do
				if rule[1] or ngx.re.find(field[1], rule[2], "jos") then
					local from, _, err = ngx.re.find(field[2], rule[3], "jo")
					if from or err then
						local name = field[1]:sub(1, 64):gsub("%c", "?")
						return name .. ", WAF_query_string_Request_table rule " .. i .. (err and ", " .. err or ""),
							rule[4]
					end
				end
			end
		end
	end

	local function classify_upstream()
		local raw_uri = ngx.var.request_uri or ""
		local q_pos = raw_uri:find("?", 1, true)
		local raw_path = q_pos and raw_uri:sub(1, q_pos - 1) or raw_uri
		if raw_path ~= "" and raw_path ~= "/" then
			local url = (ngx.var.scheme or "http") .. "://" .. (ngx.var.host or "") .. raw_uri
			for _, rule in ipairs(compiled("WAF_URI_Request_table", "(?i)", "")) do
				if (rule[1] or ngx.re.find(url, rule[2], "jo")) and ngx.re.find(raw_path, rule[3], "jo") then
					return rule[4]
				end
			end
		end
		local args = ngx.req.get_uri_args()
		if args and next(args) ~= nil then
			local fields = {}
			for name, values in pairs(args) do
				if type(values) == "table" then
					for _, v in ipairs(values) do
						fields[#fields + 1] = { name, tostring(v) }
					end
				else
					fields[#fields + 1] = { name, tostring(values) }
				end
			end
			local _, cat = rule_hit(fields)
			if cat then
				return cat
			end
		end
		local headers = ngx.req.get_headers()
		if headers and next(headers) ~= nil then
			for name, values in pairs(headers) do
				local k = tostring(name):lower()
				local list = type(values) == "table" and values or { values }
				for _, rule in ipairs(compiled_headers()) do
					if k == rule[2] or k == rule[1] or ngx.re.find(k, rule[1], "jo") then
						for _, v in ipairs(list) do
							if ngx.re.find(tostring(v), rule[3], "jo") then
								return rule[4]
							end
						end
					end
				end
			end
		end
		return "other"
	end

	local function record_hit(cat)
		local addr = ngx.var.remote_addr
		local ban_dict = ngx.shared.waf_bans
		if is_private(addr) or ban_dict:get("ban:" .. addr) then
			return
		end
		local stat_dict = ngx.shared.waf_stats
		if stat_dict then
			local kind = cat or classify_upstream()
			stat_dict:incr("attacks", 1, 0)
			stat_dict:incr("cat:" .. kind, 1, 0)
		end
		local ua = (ngx.var.http_user_agent or ""):lower()
		local crawler = find(AI_AGENTS, ua) or find(CRAWLERS, ua)
		local strike_dict = ngx.shared.waf_strikes
		local key = (crawler and "crawl:" or "hit:") .. addr
		local hits = strike_dict:incr(key, 1, 0, crawler and CRAWLER_WINDOW or WINDOW)
		if hits and hits >= (crawler and CRAWLER_LIMIT or LIMIT) then
			local ok, err = ban_dict:add("ban:" .. addr, true, BAN)
			if ok then
				if stat_dict then
					stat_dict:incr("bans", 1, 0)
				end
				local n = ban_dict:incr("bans:" .. addr, 1, 0, BAN_HISTORY_TTL) or 1
				local ban = BAN * 2 ^ (math.min(n, 10) - 1)
				if ban > BAN then
					local set_ok, set_err = ban_dict:set("ban:" .. addr, true, ban)
					if not set_ok then
						ngx.log(ngx.ERR, "[WAF ban] failed to extend ban for ", addr, ": ", set_err)
					end
				end
				ban_dict:set("bans:" .. addr, n, ban + BAN_HISTORY_TTL)
				strike_dict:delete("hit:" .. addr)
				strike_dict:delete("crawl:" .. addr)
				ngx.log(
					ngx.WARN,
					"[WAF ban] ",
					addr,
					" banned for ",
					ban,
					" s (ban ",
					n,
					") after ",
					hits,
					" blocked requests"
				)
			elseif err ~= "exists" then
				ngx.log(ngx.ERR, "[WAF ban] failed to ban ", addr, ": ", err)
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

	local function skipped(name)
		for _, skip in ipairs(localized_global.WAF_cookie_skip or {}) do
			if name:find(skip) then
				return true
			end
		end
	end

	local function cookie_fields()
		local fields, count = {}, 0
		for pair in (ngx.var.http_cookie or ""):gmatch("[^;]+") do
			count = count + 1
			if count > COOKIE_FIELDS then
				return nil, "over " .. COOKIE_FIELDS .. " cookies", "protocol"
			end
			local name, _, value = pair:match("^([^=]*)(=?)(.*)$")
			name = name:match("^%s*(.-)%s*$")
			if name ~= "" then
				local dname = ngx.unescape_uri(name)
				if dname:find("\0", 1, true) then
					return nil, "null byte", "protocol"
				end
				if not skipped(name) or (value ~= "" and not value:find("^[A-Za-z0-9+/=_%.%-~]+$")) then
					fields[#fields + 1] = { dname, dname }
					if value ~= "" then
						local dval = ngx.unescape_uri(value)
						if dval:find("\0", 1, true) then
							return nil, "null byte", "protocol"
						end
						fields[#fields + 1] = { dname, dval }
					end
				end
			elseif value ~= "" then
				local dval = ngx.unescape_uri(value)
				if dval:find("\0", 1, true) then
					return nil, "null byte", "protocol"
				end
				fields[#fields + 1] = { "", dval }
			end
		end
		return fields
	end

	local function body_hit(uri, headers)
		local raw_ct = headers and (headers["content-type"] or headers["Content-Type"])
		if type(raw_ct) == "table" then
			return ngx.HTTP_FORBIDDEN, "duplicate content-type", "protocol"
		end
		local ctype = ngx.var.content_type or ""
		local lower = ctype:lower()
		local subtype = lower:match("^%s*[^/;%s]+/([^;%s]*)") or ""
		local kind = lower:find("^%s*application/x%-www%-form%-urlencoded") and "form"
			or lower:find("^%s*multipart/form%-data") and "multipart"
			or lower:find("json", 1, true) and "json"
			or (subtype == "xml" or subtype:sub(-4) == "+xml") and "xml"
			or (ctype == "" or lower:find("^%s*text/plain")) and "text"
		if not kind then
			return
		end
		for _, skip in ipairs(localized_global.WAF_body_skip) do
			if uri:find(skip) then
				return
			end
		end
		local over = kind ~= "text" and 413 or nil
		local length = tonumber(ngx.var.content_length)
		if kind ~= "multipart" and length and length > BODY_LIMIT then
			return over, "over " .. BODY_LIMIT .. " bytes"
		end
		ngx.req.read_body()
		local body = ngx.req.get_body_data()
		local path = not body and ngx.req.get_body_file()
		local f = path and assert(io.open(path, "rb"))
		if f then
			body = f:read(BODY_LIMIT + 1)
		end
		if not body then
			if f then
				f:close()
			end
			return
		end
		local fields
		if kind == "multipart" then
			local boundary, err = extract_boundary(ctype)
			local first, parts = body, nil
			if boundary then
				fields, parts, err = multipart_fields(function()
					local chunk = first or f and f:read(1048576)
					first = nil
					return chunk
				end, boundary)
			end
			if f then
				f:close()
			end
			if not boundary then
				return ngx.HTTP_FORBIDDEN, err, "protocol"
			elseif not fields then
				return parts, err, parts == ngx.HTTP_FORBIDDEN and "protocol" or nil
			elseif parts == 0 then
				if #body > BODY_LIMIT then
					return 413, "no multipart part in over " .. BODY_LIMIT .. " bytes"
				end
				fields = { { "", body } }
			end
		else
			if f then
				f:close()
			end
			if #body > BODY_LIMIT then
				return over, "over " .. BODY_LIMIT .. " bytes"
			end
			if kind == "text" then
				local c = body:match("^%s*([{%[<])")
				kind = c == "<" and "xml" or c and "json"
				if not kind then
					return
				end
			end
			if kind == "xml" then
				if body:find("\0", 1, true) then
					return ngx.HTTP_FORBIDDEN, "null byte", "protocol"
				end
				local hit, _, err = ngx.re.find(body, XML_RULE, "jo")
				if hit or err then
					return ngx.HTTP_FORBIDDEN, "XML rule" .. (err and ", " .. err or ""), "xxe"
				end
				return
			elseif kind == "form" then
				fields = {}
				for name, values in pairs(ngx.decode_args(body, BODY_FIELDS + 1)) do
					for _, v in ipairs(type(values) == "table" and values or { values }) do
						fields[#fields + 1] = { name, tostring(v) }
					end
				end
			else
				fields = json_fields(body) or { { "", json_text(body) } }
			end
		end
		if kind ~= "multipart" and #fields > BODY_FIELDS then
			return 413, "over " .. BODY_FIELDS .. " fields"
		end
		for k = 1, #fields do
			if fields[k][1]:find("\0", 1, true) or fields[k][2]:find("\0", 1, true) then
				return ngx.HTTP_FORBIDDEN, "null byte", "protocol"
			end
		end
		for k = 1, #fields do
			if fields[k][1] ~= "" then
				fields[#fields + 1] = { fields[k][1], fields[k][1] }
			end
		end
		local reason, cat = rule_hit(fields)
		if reason then
			return ngx.HTTP_FORBIDDEN, "field " .. reason, cat
		end
	end

	lib = {
		ai_agents = AI_AGENTS,
		is_private = is_private,
		compiled = compiled,
		find = find,
		rule_hit = rule_hit,
		record_hit = record_hit,
		log_hit = log_hit,
		cookie_fields = cookie_fields,
		body_hit = body_hit,
	}
	cache.lib = lib
end

local strikes = ngx.shared.waf_strikes

if phase == "rewrite" then
	local realip = ngx.var.realip_remote_addr
	if realip and realip ~= ip then
		ngx.req.clear_header("X-Forwarded-For")
		ngx.req.clear_header("CF-Connecting-IP")
	elseif lib.is_private(ip) then
		ngx.req.clear_header("CF-Connecting-IP")
	end
	local args, args_err = ngx.req.get_uri_args()
	local headers, headers_err = ngx.req.get_headers()
	if args_err == "truncated" or headers_err == "truncated" then
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	ngx.ctx.waf_ban_checked = true
	local uri = ngx.var.uri
	if uri:find("\0", 1, true) then
		lib.log_hit("URI", true, "null byte")
		ngx.ctx.waf_recorded = true
		lib.record_hit("protocol")
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	local url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri
	for i, rule in ipairs(lib.compiled("WAF_URI_Request_table", "(?i)", "")) do
		local hit, _, err = rule[1]
		if not hit then
			hit, _, err = ngx.re.find(url, rule[2], "jo")
		end
		if hit or err then
			hit, _, err = ngx.re.find(uri, rule[3], "jo")
		end
		if hit or err then
			ngx.log(
				ngx.STDERR,
				"[WAF] Blocked Request URI prohibited after decoding: ",
				ngx.var.request_uri,
				" (WAF_URI_Request_table rule ",
				i,
				err and ", " .. err or "",
				")"
			)
			ngx.ctx.waf_recorded = true
			lib.record_hit(rule[4])
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
	end
	if ngx.req.is_internal() then
		return
	end
	local ua = (ngx.var.http_user_agent or ""):lower()
	local agent = lib.find(lib.ai_agents, ua)
	if agent and (strikes:incr("ai:" .. agent, 1, 0, AI_WINDOW) or 0) > AI_LIMIT then
		ngx.header["Retry-After"] = AI_WINDOW
		return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
	end
	local names = {}
	for name, values in pairs(args) do
		if name:find("\0", 1, true) then
			lib.log_hit("argument name", true, "null byte")
			ngx.ctx.waf_recorded = true
			lib.record_hit("protocol")
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
		if type(values) == "table" then
			for _, v in ipairs(values) do
				if type(v) == "string" and v:find("\0", 1, true) then
					lib.log_hit("argument value", true, "null byte")
					ngx.ctx.waf_recorded = true
					lib.record_hit("protocol")
					return ngx.exit(ngx.HTTP_FORBIDDEN)
				end
			end
		elseif type(values) == "string" and values:find("\0", 1, true) then
			lib.log_hit("argument value", true, "null byte")
			ngx.ctx.waf_recorded = true
			lib.record_hit("protocol")
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
		names[#names + 1] = { name, name }
	end
	local reason, cat = lib.rule_hit(names)
	if reason then
		lib.log_hit("argument name", true, reason)
		ngx.ctx.waf_recorded = true
		lib.record_hit(cat)
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	local cfields, creason, ccat = lib.cookie_fields()
	if not cfields then
		reason, cat = creason, ccat
	else
		reason, cat = lib.rule_hit(cfields)
	end
	if reason then
		lib.log_hit("cookie", localized_global.WAF_cookie_block, reason)
		if localized_global.WAF_cookie_block then
			ngx.ctx.waf_recorded = true
			lib.record_hit(cat)
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
	end
	local status
	status, reason, cat = lib.body_hit(uri, headers)
	if status then
		lib.log_hit("body", localized_global.WAF_body_block, reason)
		if localized_global.WAF_body_block then
			if status == ngx.HTTP_FORBIDDEN then
				ngx.ctx.waf_recorded = true
				lib.record_hit(cat)
			end
			return ngx.exit(status)
		end
	end
	return
end

lib.record_hit(nil)
