use crate::app::Shared;

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const MODEL: &str = "claude-opus-4-5";
const MAX_TOOL_ROUNDS: usize = 10;

#[derive(Clone, Copy, PartialEq)]
pub enum AssistantMode {
    General,
    Pentest,
    Exploit,
}

pub async fn chat(
    api_key: String,
    mode: AssistantMode,
    state: Shared,
    history: Vec<serde_json::Value>,
    tx: std::sync::mpsc::SyncSender<Result<String, String>>,
) {
    let client = reqwest::Client::new();
    let system = match mode {
        AssistantMode::General => general_prompt(&state),
        AssistantMode::Pentest => pentest_prompt(&state),
        AssistantMode::Exploit => exploit_prompt(&state),
    };
    let tools = tools_json();
    let mut messages = history;

    for _ in 0..MAX_TOOL_ROUNDS {
        let body = serde_json::json!({
            "model": MODEL,
            "max_tokens": 4096,
            "system": system,
            "tools": tools,
            "messages": messages,
        });

        let resp = match client
            .post(API_URL)
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(format!("Network error: {e}")));
                return;
            }
        };

        let resp_json: serde_json::Value = match resp.json().await {
            Ok(j) => j,
            Err(e) => {
                let _ = tx.send(Err(format!("Parse error: {e}")));
                return;
            }
        };

        if let Some(err) = resp_json.get("error") {
            let msg = err["message"].as_str().unwrap_or("unknown API error");
            let _ = tx.send(Err(format!("API error: {msg}")));
            return;
        }

        let stop_reason = resp_json["stop_reason"].as_str().unwrap_or("");
        let content = resp_json["content"].as_array().cloned().unwrap_or_default();

        messages.push(serde_json::json!({
            "role": "assistant",
            "content": content,
        }));

        if stop_reason == "tool_use" {
            let mut results = Vec::new();
            for block in &content {
                if block["type"] == "tool_use" {
                    let tool_id = block["id"].as_str().unwrap_or("").to_string();
                    let tool_name = block["name"].as_str().unwrap_or("").to_string();
                    let result = execute_tool(&tool_name, &block["input"], &state);
                    results.push(serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": result,
                    }));
                }
            }
            messages.push(serde_json::json!({
                "role": "user",
                "content": results,
            }));
        } else {
            let text = content
                .iter()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let _ = tx.send(Ok(text));
            return;
        }
    }

    let _ = tx.send(Err("Reached tool call limit without a final answer.".into()));
}

fn execute_tool(name: &str, input: &serde_json::Value, state: &Shared) -> String {
    match name {
        "list_requests" => {
            let filter = input["method"].as_str().unwrap_or("").trim().to_ascii_uppercase();
            let s = state.lock().unwrap();
            let items: Vec<serde_json::Value> = s
                .requests
                .iter()
                .filter(|r| filter.is_empty() || r.method.to_ascii_uppercase() == filter)
                .map(|r| {
                    serde_json::json!({
                        "id": r.id, "method": r.method, "url": r.url,
                        "host": r.host, "port": r.port, "tls": r.tls,
                        "status": format!("{:?}", r.status),
                    })
                })
                .collect();
            serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
        }
        "get_requests" => {
            let filter = input["method"].as_str().unwrap_or("").trim().to_ascii_uppercase();
            let s = state.lock().unwrap();
            let items: Vec<serde_json::Value> = s
                .requests
                .iter()
                .filter(|r| filter.is_empty() || r.method.to_ascii_uppercase() == filter)
                .map(|r| {
                    serde_json::json!({
                        "id": r.id, "method": r.method, "url": r.url,
                        "host": r.host, "port": r.port, "tls": r.tls,
                        "status": format!("{:?}", r.status),
                        "raw": String::from_utf8_lossy(r.edited.as_deref().unwrap_or(&r.raw)),
                        "response": r.response.as_deref()
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                            .unwrap_or_default(),
                    })
                })
                .collect();
            serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
        }
        "forward_request" => {
            let id = input["id"].as_u64().unwrap_or(0) as usize;
            let raw = input["raw"].as_str().unwrap_or("").to_string();
            let mut s = state.lock().unwrap();
            let bytes = if raw.trim().is_empty() { None } else { Some(raw.into_bytes()) };
            match s.requests.iter().position(|r| r.id == id) {
                Some(idx) => {
                    let bytes = bytes.unwrap_or_else(|| {
                        let r = &s.requests[idx];
                        r.edited.clone().unwrap_or_else(|| r.raw.clone())
                    });
                    s.forward_at(idx, bytes);
                    format!("ok: request {id} forwarded")
                }
                None => format!("error: no request with id {id}"),
            }
        }
        "drop_request" => {
            let id = input["id"].as_u64().unwrap_or(0) as usize;
            let mut s = state.lock().unwrap();
            match s.requests.iter().position(|r| r.id == id) {
                Some(idx) => {
                    s.drop_at(idx);
                    format!("ok: request {id} dropped")
                }
                None => format!("error: no request with id {id}"),
            }
        }
        _ => format!("error: unknown tool {name}"),
    }
}

fn general_prompt(state: &Shared) -> String {
    let s = state.lock().unwrap();
    let proxy_port = s.settings.proxy_port;
    let pending = s.pending_count();
    let total = s.requests.len();
    format!(
        "You are a security assistant embedded in rustman, a MITM proxy tool (similar to Burp Suite). \
You can read intercepted HTTP requests and help the user with web security testing.\n\n\
Current proxy state: {pending} pending, {total} total, port {proxy_port}.\n\n\
When testing for OWASP Top 10 vulnerabilities:\n\
1. Call get_requests() to see the raw request\n\
2. Show the modified payload to the user before sending it\n\
3. Ask for confirmation before calling forward_request with a modified payload\n\
4. Explain what vulnerability you are testing and how the payload works"
    )
}

fn pentest_prompt(state: &Shared) -> String {
    let s = state.lock().unwrap();
    let proxy_port = s.settings.proxy_port;
    let pending = s.pending_count();
    let total = s.requests.len();
    format!(
        "You are a Senior Web Pentester embedded in rustman (a MITM proxy, similar to Burp Suite). \
Proxy state: {pending} pending, {total} total, port {proxy_port}.\n\n\
## Role\n\
Assist with authorized security testing: HTTP traffic analysis, OWASP Top 10, API testing, \
authentication flaws, authorization bypass, session management, and vulnerability validation.\n\n\
## When analyzing requests from Rustman\n\
1. Use get_requests() to read raw HTTP data first.\n\
2. Systematically review: method, URL, parameters, cookies, tokens, headers, body, responses, status codes.\n\
3. Identify: injection points, auth weaknesses, misconfigs, data exposure, access control flaws.\n\n\
## Response format\n\
Always structure replies as a pentest report:\n\
**Summary** — what is observed.\n\
**Technical Observations** — relevant findings.\n\
**Vulnerability Hypotheses** — possible weaknesses with confidence level (High/Medium/Low).\n\
**Validation** — how to confirm in an authorized environment.\n\
**Impact** — potential consequences.\n\
**Remediation** — concrete fixes referencing OWASP / CWE.\n\
**Priority** — Critical / High / Medium / Low / Info.\n\n\
## Rules\n\
- Never conclude without evidence. Distinguish facts from hypotheses.\n\
- Always show modified payloads to the user and ask for confirmation before calling forward_request.\n\
- Reference OWASP Top 10, CWE, CVSS where applicable."
    )
}

fn exploit_prompt(state: &Shared) -> String {
    let s = state.lock().unwrap();
    let proxy_port = s.settings.proxy_port;
    let total = s.requests.len();
    format!(
        "You are an expert offensive security researcher embedded in rustman (a MITM proxy). \
Proxy state: {total} intercepted requests, port {proxy_port}.\n\n\
## Role\n\
Help develop working proof-of-concept exploits for web vulnerabilities found in intercepted traffic. \
Focus on: SQLi, XSS, SSRF, SSTI, CMDi, Path Traversal, Open Redirect, RCE, auth bypass, IDOR.\n\n\
## Workflow\n\
1. Use get_requests() or list_requests() to examine the target request.\n\
2. Identify the injection point(s) and vulnerability class.\n\
3. Provide a working PoC — prefer multiple formats:\n\
   - Modified raw HTTP request (copy-paste ready)\n\
   - curl one-liner\n\
   - Python requests snippet\n\
4. Explain why the payload works and what to look for in the response.\n\
5. If the app has defenses (WAF, filters), suggest bypass techniques.\n\n\
## Response format\n\
**Vulnerability**: type + confidence\n\
**Injection point**: exact parameter / header / field\n\
**PoC** (raw HTTP / curl / Python)\n\
**Expected response**: what indicates success\n\
**Bypasses** (if applicable)\n\n\
## Rules\n\
- Be direct and technical — skip warnings and disclaimers.\n\
- Show complete, runnable payloads, not redacted examples.\n\
- Always call get_requests() first when the user references a specific request."
    )
}

fn tools_json() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "list_requests",
            "description": "List intercepted HTTP requests (id, method, url, status). Pass empty string to get all.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "method": { "type": "string", "description": "HTTP method filter (GET, POST, …). Empty = all." }
                },
                "required": ["method"]
            }
        },
        {
            "name": "get_requests",
            "description": "Get intercepted requests with full raw bytes and server response.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "method": { "type": "string", "description": "HTTP method filter. Empty = all." }
                },
                "required": ["method"]
            }
        },
        {
            "name": "forward_request",
            "description": "Forward an intercepted request. Supply a modified `raw` to inject a security payload. ALWAYS show the payload to the user and get confirmation before calling this tool.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "id":  { "type": "integer", "description": "Request ID from list_requests." },
                    "raw": { "type": "string",  "description": "Modified raw HTTP bytes. Empty = forward as-is." }
                },
                "required": ["id", "raw"]
            }
        },
        {
            "name": "drop_request",
            "description": "Drop (block) an intercepted request — it never reaches the server.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "id": { "type": "integer", "description": "Request ID to drop." }
                },
                "required": ["id"]
            }
        }
    ])
}
