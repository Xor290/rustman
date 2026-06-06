use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        GetPromptRequestParams, GetPromptResult, ListPromptsResult, PaginatedRequestParams,
        Prompt, PromptMessage, PromptMessageRole, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    },
};

use crate::app::{ChatMessage, Shared};

// ── HTTP server launcher ──────────────────────────────────────────────────────

pub async fn serve(state: Shared, port: u16) {
    let state_clone = state.clone();
    let service: StreamableHttpService<RustmanMcp, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(RustmanMcp::new(state_clone.clone())),
            Default::default(),
            StreamableHttpServerConfig::default(),
        );

    let router = axum::Router::new().nest_service("/mcp", service);
    let addr = format!("127.0.0.1:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[mcp] failed to bind {addr}: {e}");
            return;
        }
    };
    eprintln!("[mcp] listening on http://{addr}/mcp");
    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("[mcp] server error: {e}");
    }
}

// ── Parameter types ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ParamsListRequests {
    #[schemars(description = "HTTP method filter (GET, POST, …). Empty string = return all.")]
    method: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ParamsGetRequests {
    #[schemars(description = "HTTP method filter. Empty string = return all.")]
    method: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ParamsForwardRequest {
    #[schemars(description = "ID of the intercepted request to forward (from list_requests).")]
    id: usize,
    #[schemars(description = "Modified raw HTTP payload. Empty = forward as-is.")]
    raw: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ParamsDropRequest {
    #[schemars(description = "ID of the intercepted request to drop/block.")]
    id: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ParamsReply {
    #[schemars(description = "Message to display in the rustman Claude chat panel.")]
    message: String,
}

// ── Server struct ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RustmanMcp {
    state: Shared,
    tool_router: ToolRouter<Self>,
}

impl RustmanMcp {
    pub fn new(state: Shared) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }
}

// ── Tool definitions ──────────────────────────────────────────────────────────

#[tool_router]
impl RustmanMcp {
    #[tool(description = "List intercepted HTTP requests. Pass an empty method string to get all.")]
    fn list_requests(
        &self,
        Parameters(ParamsListRequests { method }): Parameters<ParamsListRequests>,
    ) -> String {
        let state = self.state.lock().unwrap();
        let filter = method.trim().to_ascii_uppercase();
        let items: Vec<serde_json::Value> = state
            .requests
            .iter()
            .filter(|r| filter.is_empty() || r.method.to_ascii_uppercase() == filter)
            .map(|r| serde_json::json!({
                "id": r.id, "method": r.method, "url": r.url,
                "host": r.host, "port": r.port, "tls": r.tls,
                "status": format!("{:?}", r.status),
            }))
            .collect();
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
    }

    #[tool(description = "Get intercepted requests with full raw bytes and server response.")]
    fn get_requests(
        &self,
        Parameters(ParamsGetRequests { method }): Parameters<ParamsGetRequests>,
    ) -> String {
        let state = self.state.lock().unwrap();
        let filter = method.trim().to_ascii_uppercase();
        let items: Vec<serde_json::Value> = state
            .requests
            .iter()
            .filter(|r| filter.is_empty() || r.method.to_ascii_uppercase() == filter)
            .map(|r| serde_json::json!({
                "id": r.id, "method": r.method, "url": r.url,
                "host": r.host, "port": r.port, "tls": r.tls,
                "status": format!("{:?}", r.status),
                "raw": String::from_utf8_lossy(r.edited.as_deref().unwrap_or(&r.raw)),
                "response": r.response.as_deref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default(),
            }))
            .collect();
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
    }

    #[tool(description = "\
Forward an intercepted request to the server. Supply a modified `raw` payload to inject \
OWASP Top 10 payloads (SQLi, XSS, SSRF, IDOR, path traversal, command injection…). \
ALWAYS show the payload to the user and get confirmation before calling this tool.")]
    fn forward_request(
        &self,
        Parameters(ParamsForwardRequest { id, raw }): Parameters<ParamsForwardRequest>,
    ) -> String {
        let mut state = self.state.lock().unwrap();
        let bytes = if raw.trim().is_empty() { None } else { Some(raw.into_bytes()) };
        let Some(idx) = state.requests.iter().position(|r| r.id == id) else {
            return format!("error: no request with id {id}");
        };
        let bytes = bytes.unwrap_or_else(|| {
            let r = &state.requests[idx];
            r.edited.clone().unwrap_or_else(|| r.raw.clone())
        });
        state.forward_at(idx, bytes);
        format!("ok: request {id} forwarded")
    }

    #[tool(description = "\
Drop (block) an intercepted request — it will never reach the server. \
Always confirm with the user before calling this.")]
    fn drop_request(
        &self,
        Parameters(ParamsDropRequest { id }): Parameters<ParamsDropRequest>,
    ) -> String {
        let mut state = self.state.lock().unwrap();
        let Some(idx) = state.requests.iter().position(|r| r.id == id) else {
            return format!("error: no request with id {id}");
        };
        state.drop_at(idx);
        format!("ok: request {id} dropped")
    }

    #[tool(description = "\
Poll for a message typed by the user in the rustman Claude tab. \
Returns the message if pending, empty string if none. Consumed after reading.")]
    fn get_user_prompt(&self) -> String {
        self.state.lock().unwrap().pending_prompt.take().unwrap_or_default()
    }

    #[tool(description = "\
Send a reply to the rustman Claude chat panel (analysis results, findings, confirmations…).")]
    fn reply_to_user(
        &self,
        Parameters(ParamsReply { message }): Parameters<ParamsReply>,
    ) -> String {
        self.state.lock().unwrap().chat_messages.push(ChatMessage {
            from_user: false,
            text: message,
        });
        "ok".into()
    }
}

// ── ServerHandler (tools + prompts) ──────────────────────────────────────────

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RustmanMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .build(),
        )
        .with_instructions(
            "rustman MITM proxy assistant — inspect HTTP traffic, run OWASP tests, \
             manage intercepted requests. Use the pentest-analyst prompt for structured \
             security analysis.",
        )
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, rmcp::Error> {
        Ok(ListPromptsResult {
            prompts: vec![
                Prompt::new(
                    "pentest-analyst",
                    Some("Senior Web Pentester — structured pentest report format (Summary / Observations / Hypotheses / Validation / Impact / Remediation / Priority)"),
                    None,
                ),
                Prompt::new(
                    "general-assistant",
                    Some("General security assistant for rustman"),
                    None,
                ),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, rmcp::Error> {
        let text = match request.name.as_str() {
            "pentest-analyst" => PENTEST_PROMPT,
            "general-assistant" => GENERAL_PROMPT,
            other => {
                return Err(rmcp::Error::invalid_params(
                    format!("unknown prompt: {other}"),
                    None,
                ))
            }
        };
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            PromptMessageRole::User,
            text,
        )]))
    }
}

// ── Prompt texts ──────────────────────────────────────────────────────────────

const GENERAL_PROMPT: &str = "\
You are a security assistant embedded in rustman, a MITM proxy (similar to Burp Suite). \
Use the available tools to read intercepted HTTP traffic and help with web security testing. \
Always show modified payloads to the user and ask for confirmation before forwarding them.";

const PENTEST_PROMPT: &str = "\
You are a Senior Web Pentester embedded in rustman (a MITM proxy, similar to Burp Suite).

## Role
Assist with authorized security testing: HTTP traffic analysis, OWASP Top 10, API testing, \
authentication flaws, authorization bypass, session management, and vulnerability validation.

## When analyzing requests
1. Call get_requests() to read raw HTTP data first.
2. Review: method, URL, parameters, cookies, tokens, headers, body, responses, status codes.
3. Identify: injection points, auth weaknesses, misconfigs, data exposure, access control flaws.

## Response format — always use this structure
**Summary** — what is observed.
**Technical Observations** — relevant findings with evidence.
**Vulnerability Hypotheses** — possible weaknesses with confidence level (High / Medium / Low).
**Validation** — how to confirm in an authorized environment.
**Impact** — potential consequences (data leak, account takeover, RCE…).
**Remediation** — concrete fixes referencing OWASP / CWE.
**Priority** — Critical / High / Medium / Low / Info.

## Rules
- Never conclude without evidence. Distinguish facts from hypotheses.
- Always show modified payloads to the user and ask for confirmation before calling forward_request.
- Reference OWASP Top 10, CWE, CVSS where applicable.
- Use get_requests() before any analysis — never guess request content.";
