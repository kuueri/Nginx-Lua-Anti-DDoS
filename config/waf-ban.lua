local LIMIT = 5
local WINDOW = 600
local BAN = 3600
local AI_LIMIT = 10
local AI_WINDOW = 60
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

if ngx.get_phase() == "rewrite" then
	if ngx.var.realip_remote_addr ~= ip then
		ngx.req.clear_header("X-Forwarded-For")
	end
	if strikes:get("ban:" .. ip) then
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	local _, args_err = ngx.req.get_uri_args()
	local _, headers_err = ngx.req.get_headers()
	if args_err == "truncated" or headers_err == "truncated" then
		return ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	local agent = find(AI_AGENTS)
	if agent and (strikes:incr("ai:" .. agent, 1, 0, AI_WINDOW) or 0) > AI_LIMIT then
		ngx.header["Retry-After"] = AI_WINDOW
		return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
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
