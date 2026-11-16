local LIMIT = 5
local WINDOW = 600
local BAN = 3600

local strikes = ngx.shared.waf_strikes
local ip = ngx.var.remote_addr

if ngx.get_phase() == "rewrite" then
	if ngx.var.realip_remote_addr ~= ip then
		ngx.req.clear_header("X-Forwarded-For")
	end
	if strikes:get("ban:" .. ip) then
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	ngx.ctx.waf_ban_checked = true
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
then
	return
end
local hits = strikes:incr("hit:" .. ip, 1, 0, WINDOW)
if hits and hits >= LIMIT then
	strikes:set("ban:" .. ip, true, BAN)
	strikes:delete("hit:" .. ip)
	ngx.log(ngx.WARN, "[WAF ban] ", ip, " banned for ", BAN, " s after ", hits, " blocked requests")
end
