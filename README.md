# rustman

A MITM proxy and web security testing tool written in Rust — similar to Burp Suite, with an integrated Claude AI assistant for OWASP-guided penetration testing.

---

## Features

| Module | Description |
|---|---|
| **Proxy** | Intercept, inspect, edit and forward/drop HTTP(S) requests in real time |
| **Repeater** | Replay and modify captured requests manually |
| **Crawler** | Recursive BFS link follower for a target domain |
| **Claude** | In-app AI assistant (Anthropic API) with Pentest mode |
| **MCP Server** | Expose proxy tools to Claude Code via Model Context Protocol |
| **Settings** | Intercept toggle, ignore list, API key, light/dark theme |

---

## Architecture

```mermaid
graph TB
    subgraph rustman["rustman process"]
        direction TB
        GUI["GUI Thread\negui / eframe"]
        PROXY["Proxy Thread\nTokio runtime #1\n127.0.0.1:8080"]
        BGRT["Background Runtime\nTokio runtime #2"]

        subgraph BGRT
            REPEATER["Repeater tasks"]
            CRAWLER["Crawler tasks"]
            MCP["MCP HTTP Server\n127.0.0.1:8099/mcp"]
            CLAUDE_API["Anthropic API calls"]
        end

        STATE["AppState\nArc&lt;Mutex&lt;AppState&gt;&gt;"]

        GUI <-->|"lock / read-write"| STATE
        PROXY <-->|"lock / push requests"| STATE
        BGRT <-->|"lock / read-write"| STATE
    end

    BROWSER["Browser\n(FoxyProxy → 127.0.0.1:8080)"]
    TARGET["Target Server"]
    CLAUDE_CODE["Claude Code IDE"]
    ANTHROPIC["Anthropic API\napi.anthropic.com"]

    BROWSER -->|"HTTP CONNECT / plain HTTP"| PROXY
    PROXY -->|"forward / drop"| TARGET
    TARGET -->|"response"| PROXY

    CLAUDE_CODE -->|"MCP / HTTP POST"| MCP
    GUI -->|"HTTP POST + API key"| ANTHROPIC
    ANTHROPIC -->|"JSON response"| GUI
```

---

## MITM Proxy Flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant P as Proxy (8080)
    participant CA as CA (rcgen)
    participant S as Target Server

    B->>P: CONNECT example.com:443
    P-->>B: 200 Connection Established

    Note over P,CA: Dynamic certificate generation
    CA->>P: cert for example.com (signed by rustman CA)

    B->>P: TLS ClientHello
    P-->>B: TLS ServerHello (fake cert)
    Note over B,P: TLS tunnel B ↔ P

    P->>S: TLS connect (real)
    Note over P,S: TLS tunnel P ↔ S

    B->>P: GET /api/data HTTP/1.1
    P->>P: Intercept & store in AppState
    Note over P: status = Pending

    alt User forwards
        P->>S: GET /api/data HTTP/1.1
        S-->>P: HTTP 200 { ... }
        P-->>B: HTTP 200 { ... }
        Note over P: status = Forwarded
    else User drops
        Note over P: status = Dropped
        P-->>B: Connection closed
    end
```

---

## Request Interception & Focus System

```mermaid
flowchart TD
    REQ["Incoming request"] --> EXT{"Extension\nrequest?"}
    EXT -->|"moz-extension://\nchrome-extension://"| DROP_SILENT["Silent forward\n(not stored)"]
    EXT -->|"No"| NAV{"Top-level\nnavigation?\n(no Referer)"}
    NAV -->|"Yes"| SET_FOCUS["Set focused_host\n= base domain"]
    SET_FOCUS --> INTERCEPT
    NAV -->|"No"| INTERCEPT{"Intercept\nenabled?"}
    INTERCEPT -->|"No"| DROP_SILENT
    INTERCEPT -->|"Yes"| IGNORED{"Host in\nignore list?"}
    IGNORED -->|"Yes"| DROP_SILENT
    IGNORED -->|"No"| FOCUSED{"Host matches\nfocused_host?"}
    FOCUSED -->|"No"| DROP_SILENT
    FOCUSED -->|"Yes"| STORE["Store in AppState\nstatus = Pending"]
    STORE --> WAIT["Wait for user action\n(Forward / Drop / Edit)"]
```

---

## Repeater Flow

```mermaid
sequenceDiagram
    participant GUI as GUI (Repeater tab)
    participant RT as bg_rt (Tokio)
    participant SRV as Target Server

    GUI->>GUI: Ctrl+R or → Repeater button
    Note over GUI: Creates RepeaterSession\n(host, port, tls, raw request)

    GUI->>RT: spawn repeater_send(host, port, tls, bytes)
    Note over RT: rewrite() adds Connection: close
    RT->>SRV: TCP / TLS connect
    RT->>SRV: Send raw HTTP request
    SRV-->>RT: HTTP response
    RT-->>RT: drain() until EOF
    RT->>GUI: tx.send(response bytes)

    GUI->>GUI: poll_repeater() → display response
```

---

## Crawler Flow

```mermaid
flowchart TD
    START["User enters URL\n+ max depth"] --> PARSE["parse_url()\nextract host, port, tls"]
    PARSE --> QUEUE["BFS Queue\n[(url, depth=0)]"]
    QUEUE --> POP["Pop (url, depth)"]
    POP --> STOP{"stop flag?"}
    STOP -->|"true"| DONE["CrawlMsg::Finished"]
    STOP -->|"false"| REQ["Build GET request\nUser-Agent: rustman-crawler"]
    REQ --> SEND["repeater_send()\nreuse TLS stack"]
    SEND --> RESP["HTTP Response"]
    RESP --> MSG1["CrawlMsg::Done\n(status, response)"]
    MSG1 --> CRAWL{"status=200\nand depth < max?"}
    CRAWL -->|"No"| POP
    CRAWL -->|"Yes"| EXTRACT["extract_links()\nhref= scanning"]
    EXTRACT --> FILTER["Filter:\n- same domain only\n- skip .png .js .css…\n- deduplicate (HashSet)"]
    FILTER --> ENQUEUE["Enqueue new URLs\nCrawlMsg::new_links count"]
    ENQUEUE --> POP
```

---

## Claude AI — Direct API Flow (Claude tab)

```mermaid
sequenceDiagram
    participant U as User (Claude tab)
    participant GUI as GUI
    participant RT as bg_rt
    participant ANT as Anthropic API
    participant ST as AppState

    U->>GUI: Type message + Send
    GUI->>ST: push ChatMessage{from_user: true}
    GUI->>RT: spawn claude_client::chat(api_key, mode, history)

    loop Tool use rounds (max 10)
        RT->>ANT: POST /v1/messages\n(messages, tools, system_prompt)
        ANT-->>RT: {stop_reason: "tool_use", content: [...]}

        RT->>ST: execute_tool(name, input)
        Note over RT,ST: list_requests / get_requests\nforward_request / drop_request

        RT->>ANT: POST /v1/messages\n(+ tool_result)
    end

    ANT-->>RT: {stop_reason: "end_turn", content: [{type:"text"}]}
    RT->>GUI: tx.send(Ok(text))
    GUI->>ST: push ChatMessage{from_user: false, text}
    GUI->>U: Display reply in chat bubble
```

---

## MCP Server — Claude Code Integration

```mermaid
sequenceDiagram
    participant CC as Claude Code (IDE)
    participant MCP as MCP Server\n(8099/mcp)
    participant ST as AppState

    CC->>MCP: POST /mcp\ninitialize
    MCP-->>CC: capabilities {tools, prompts}

    CC->>MCP: prompts/list
    MCP-->>CC: ["pentest-analyst", "general-assistant"]

    CC->>MCP: prompts/get "pentest-analyst"
    MCP-->>CC: PromptMessage (system prompt text)
    Note over CC: Claude Code injects\npentest system prompt

    CC->>MCP: tools/call list_requests {method: "POST"}
    MCP->>ST: lock → filter requests
    MCP-->>CC: [{id:3, method:"POST", url:"/login"...}]

    CC->>MCP: tools/call get_requests {method: "POST"}
    MCP->>ST: lock → raw + response
    MCP-->>CC: [{raw:"POST /login...", response:"HTTP 200..."}]

    Note over CC: Claude generates SQLi payload
    CC->>CC: Show payload to user, ask confirmation

    CC->>MCP: tools/call forward_request {id:3, raw:"POST /login... ' OR 1=1--"}
    MCP->>ST: forward_at(idx, modified_bytes)
    MCP-->>CC: "ok: request 3 forwarded"
```

---

## OWASP Testing Workflow

```mermaid
flowchart LR
    subgraph intercept["1 · Intercept"]
        B["Browser\n→ target site"] --> P["Proxy captures\nPOST /login"]
    end

    subgraph analyse["2 · Analyse"]
        P --> LR["list_requests('POST')"]
        LR --> GR["get_requests('POST')\nread raw bytes"]
    end

    subgraph generate["3 · Generate payloads"]
        GR --> A["Claude\nidentifies injection point\n(username= parameter)"]
        A --> PL["Generates OWASP payloads:\n' OR 1=1--\n' UNION SELECT...\n<script>alert(1)</script>\n../../../etc/passwd"]
    end

    subgraph confirm["4 · Confirm"]
        PL --> USR{"User\nconfirms?"}
        USR -->|"Yes"| FWD["forward_request(id, raw)"]
        USR -->|"No"| DROP["drop_request(id)\nor skip"]
    end

    subgraph report["5 · Report"]
        FWD --> RESP["Read response\nin Proxy / Repeater"]
        RESP --> RPT["Claude generates\npentest report:\nSummary / Hypotheses\nImpact / Remediation\nPriority: Critical"]
    end
```

---

## Setup

### 1. Install the CA certificate

On first launch, rustman generates a CA certificate and attempts to auto-install it into Firefox.

```
[rustman] CA cert: /home/<user>/.local/share/rustman/ca.pem
[rustman] proxy listening on 127.0.0.1:8080
[mcp] listening on http://127.0.0.1:8099/mcp
```

If auto-install fails:
```bash
sudo apt install libnss3-tools
# then restart rustman
```

For Chrome / system trust store, import `ca.pem` manually.

### 2. Configure your browser

Set your browser's HTTP/HTTPS proxy to `127.0.0.1:8080` (e.g. via FoxyProxy).

### 3. Configure Claude (optional)

Go to **Settings → CLAUDE API** and enter your Anthropic API key (`sk-ant-…`).

### 4. Connect Claude Code (optional)

Add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "rustman": {
      "type": "http",
      "url": "http://127.0.0.1:8099/mcp"
    }
  }
}
```

Then in Claude Code:
```
/mcp get prompt pentest-analyst
```

---

## Build

```bash
# Debug
cargo build

# Release
cargo build --release

# Windows executable (from Linux)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+R` | Send selected request to Repeater |

---

## Tabs

### Proxy
Displays all intercepted requests for the focused host. Select a request to view and edit the raw bytes. Forward or drop individually, or use **Forward All** to release everything.

### Repeater
Manually replay requests with custom edits. Multiple sessions, each with its own request editor and response viewer.

### Crawler
Recursive BFS crawler for a target URL. Follows internal links only, skips static assets. Click any entry to inspect its request/response. Send directly to Repeater with **→ Repeater**.

### Claude
In-app AI assistant. Switch between **General** and **Pentest** modes. In Pentest mode every response follows the structured report format (Summary / Observations / Hypotheses / Validation / Impact / Remediation / Priority).

### Settings
| Setting | Description |
|---|---|
| Light mode | Toggle dark/light theme |
| Intercept | Enable or disable request interception |
| Ignore list | Hosts silently forwarded (substring match) |
| Proxy port | Read-only — set at startup |
| Max requests | Prune oldest completed requests when exceeded |
| Claude API key | Anthropic key for the Claude tab |

---

## Project structure

```
src/
├── main.rs          — entry point, proxy + MCP spawn
├── app.rs           — shared state (AppState, Request, Settings, ChatMessage)
├── proxy.rs         — MITM proxy, TLS interception, request routing
├── ca.rs            — dynamic certificate authority (rcgen)
├── gui.rs           — egui/eframe UI (all tabs)
├── repeater.rs      — (logic in proxy.rs repeater_send)
├── crawler.rs       — BFS web crawler
├── mcp.rs           — MCP HTTP server (tools + prompts)
└── claude_client.rs — Anthropic API client with tool-use loop
```
