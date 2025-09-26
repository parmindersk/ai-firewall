local cjson = require "cjson.safe"

-- Config
local ai_endpoints = {
  ["/api/v1/llm/query"] = true,
  ["/api/v1/llm/chat"]  = true,
}

local MAX_REQUEST_BYTES  = 64 * 1024
local MAX_RESPONSE_BYTES = 512 * 1024(per-request, chunk-summed)

-- allowlist
local ALLOW_URLS = {
  ["example.com"] = true,
}

local prompt_injection_phrases = {
  "ignore previous instructions",
  "disregard previous instructions",
  "forget all prior instructions",
  "act as system",
  "you are now",
  "bypass safety",
  "jailbreak",
  "override system prompt",
  "role: system",
  "do anything now",
}

local tool_misuse_phrases = {
  "download and run",
  "execute shell",
  "rm -rf /",
  "cat /etc/passwd",
  "exfiltrate",
  "send data to",
  "curl http",
  "powershell -enc",
  "base64 -d",
}

local sensitive_response_patterns = {
  { name = "OpenAI_Key",     rx = [[\bsk-[A-Za-z0-9_-]{10,}\b]] },
  { name = "AWS_Access_Key", rx = [[\bAKIA[0-9A-Z]{16}\b]] },
  { name = "AWS_Secret_Key",
    rx = [[(?i)\baws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*(?:["'][^"']+["']|[0-9A-Za-z/+]{40})]] },
  { name = "JWT",            rx = [[\beyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9._-]+?\.[A-Za-z0-9._-]+\b]] },
  {name = "US_SSN",         rx = [[\b\d{3}-\d{2}-\d{4}\b]]},
  {name = "Credit_Card",    rx = [[\b(?:\d[ -]*?){13,16}\b]]},
  {name = "Email",          rx = [[[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}]]},
  {name = "Phone",          rx = [[\b(?:\+?1\s*(?:[.-]\s*)?)?(?:\(?\d{3}\)?|\d{3})(?:\s*[.-]\s*|\s*)\d{3}(?:\s*[.-]\s*|\s*)\d{4}\b]]},
  {name = "IP_Address",     rx = [[(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)]]},
  {name = "MAC_Address",    rx = [[\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b]]},
  {name = "Medical_Record_Number", rx = [[\bMRN[: ]?\d{6,10}\b]]},
  {name = "ICD10_Code",            rx = [[\b[A-TV-Z][0-9][0-9AB](\.[0-9A-TV-Z]{1,4})?\b]]},
  {name = "IBAN",                  rx = [[\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b]]},
  {name = "US_Routing_Number",     rx = [[\b\d{9}\b]]},
  {name = "API_Key",        rx = [[(?i)\b(?:api[_-]?key|key|token|password)\s*[:=]\s*["']?[A-Za-z0-9._\-]{12,}["']?]]},
}

local function fw_mark(flag)
  ngx.ctx.ai_fw_flags = ngx.ctx.ai_fw_flags or {}
  ngx.ctx.ai_fw_flags[#ngx.ctx.ai_fw_flags + 1] = flag
end

local function read_body()
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  if data then return data, #data end

  local file = ngx.req.get_body_file()
  if file then
    local f = io.open(file, "rb")
    if f then
      local d = f:read("*a")
      f:close()
      d = d or ""
      return d, #d
    end
  end
  return "", 0
end

local function tolower(s) return string.lower(s or "") end

local function contains_any(haystack_lc, list)
  for _, phrase in ipairs(list) do
    if haystack_lc:find(phrase, 1, true) then return phrase end
  end
  return nil
end

local function urls_in_text(s)
  local urls = {}
  for url in s:gmatch("https?://[%w%._%-%/%?%&=%+#%%]+") do
    urls[#urls+1] = url
  end
  return urls
end

local function host_from_url(u)
  return u:match("^https?://([^/%?%:]+)")
end

local function handle_request()
  if ngx.req.get_method() ~= "POST" then return end
  if not ai_endpoints[ngx.var.uri] then return end

  local body, blen = read_body()

  if blen > MAX_REQUEST_BYTES then
    fw_mark("blocked:request_too_large")
    return ngx.exit(413)
  end

  local parsed = cjson.decode(body) or {}
  local prompt_blob = ""

  if type(parsed) == "table" then
    if type(parsed.prompt) == "string" then
      prompt_blob = prompt_blob .. "\n" .. parsed.prompt
    end
    if type(parsed.input) == "string" then
      prompt_blob = prompt_blob .. "\n" .. parsed.input
    end
    if type(parsed.messages) == "table" then
      for _, m in ipairs(parsed.messages) do
        if type(m) == "table" and type(m.content) == "string" then
          prompt_blob = prompt_blob .. "\n" .. m.content
        end
      end
    end
  end
  if prompt_blob == "" then prompt_blob = body end

  local p_lc = tolower(prompt_blob)

  local inj = contains_any(p_lc, prompt_injection_phrases)
  if inj then
    ngx.log(ngx.WARN, "AI-Firewall: prompt-injection detected: ", inj)
    fw_mark("blocked:prompt_injection")
    ngx.status = 400
    ngx.say("Request blocked by AI Firewall: prompt injection detected.")
    return ngx.exit(400)
  end

  local misuse = contains_any(p_lc, tool_misuse_phrases)
  if misuse then
    ngx.log(ngx.WARN, "AI-Firewall: tool/agency misuse hint: ", misuse)
    fw_mark("blocked:excessive_agency")
    ngx.status = 400
    ngx.say("Request blocked by AI Firewall: unsupported tool/agency request.")
    return ngx.exit(400)
  end

  local url_list = urls_in_text(prompt_blob)
  if #url_list > 0 then
    for _, u in ipairs(url_list) do
      local host = host_from_url(u)
      if host and not ALLOW_URLS[host] then
        ngx.log(ngx.WARN, "AI-Firewall: disallowed external URL in prompt: ", u)
        fw_mark("blocked:disallowed_url")
        ngx.status = 400
        ngx.say("Request blocked by AI Firewall: external URL not allowed.")
        return ngx.exit(400)
      end
    end
  end
end

local function handle_header()
  if not ai_endpoints[ngx.var.uri or ""] then return end

  ngx.header["Content-Length"] = nil
  ngx.header["ETag"] = nil

  if ngx.ctx.ai_fw_flags and #ngx.ctx.ai_fw_flags > 0 then
    ngx.header["X-AI-Firewall"] = table.concat(ngx.ctx.ai_fw_flags, ",")
  end
end

local STREAM_TAIL_BYTES = 512

local function handle_response_chunk()
  local uri = ngx.var.uri or ""
  if not ai_endpoints[uri] then return end

  local chunk = ngx.arg[1]
  local eof   = ngx.arg[2]

  if (not chunk or chunk == "") and eof then
    if ngx.ctx._tail and #ngx.ctx._tail > 0 then
      ngx.arg[1] = (ngx.arg[1] or "") .. ngx.ctx._tail
    else
      ngx.arg[1] = ngx.arg[1] or ""
    end
    ngx.ctx._tail = nil
    ngx.ctx.res_bytes = nil
    return
  end

  if not chunk or chunk == "" then
    return
  end

  ngx.ctx.res_bytes = (ngx.ctx.res_bytes or 0) + #chunk
  if ngx.ctx.res_bytes > MAX_RESPONSE_BYTES then
    ngx.log(ngx.WARN, "AI-Firewall: response too large, truncating")
    ngx.arg[1] = ""
    ngx.arg[2] = true
    fw_mark("truncated:response_too_large")
    return
  end

  local tail = ngx.ctx._tail or ""
  local work = tail .. chunk

  local redacted = work
  for _, pat in ipairs(sensitive_response_patterns) do
    local ok, res, n = pcall(function()
      return ngx.re.gsub(redacted, pat.rx, "[REDACTED:" .. pat.name .. "]", "ijo")
    end)
    if ok and res and n and n > 0 then
      redacted = res
      fw_mark("redacted:" .. pat.name)
    end
  end

  local new_tail_len = math.min(STREAM_TAIL_BYTES, #redacted)
  local new_tail     = redacted:sub(#redacted - new_tail_len + 1)

  local out_len = #redacted - new_tail_len
  ngx.arg[1] = out_len > 0 and redacted:sub(1, out_len) or ""

  ngx.ctx._tail = new_tail

  if eof then
    ngx.arg[1] = (ngx.arg[1] or "") .. (ngx.ctx._tail or "")
    ngx.ctx._tail = nil
    ngx.ctx.res_bytes = nil
  end
end

local phase = ngx.get_phase()
if phase == "access" then
  handle_request()
elseif phase == "header_filter" then
  handle_header()
elseif phase == "body_filter" then
  handle_response_chunk()
end
