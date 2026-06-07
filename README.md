# rustman

**Rustman** is an open-source MITM proxy and web security testing tool built in Rust. It intercepts and inspects HTTP/HTTPS traffic, replays requests via a built-in Repeater, and crawls websites to automatically inject OWASP Top 10 payloads across URL parameters, headers, and request bodies. It features a native GUI, a Claude AI assistant for pentest analysis, and an MCP server for Claude Code integration.

---

## Features

| Module | Description |
|---|---|
| **Proxy** | Intercept, inspect, edit and forward/drop HTTP(S) requests in real time |
| **Repeater** | Replay and modify captured requests manually |
| **Crawler** | Recursive BFS crawler with automatic OWASP payload injection |
| **Attacks** | 240+ payloads per category injected into URL params, headers and body |
| **Claude** | In-app AI assistant (Anthropic API) with Pentest mode |
| **MCP Server** | Expose proxy tools to Claude Code via Model Context Protocol |
| **Settings** | Configurable bind address/port, intercept toggle, ignore list, theme |

---

## Architecture

```mermaid
graph TB
    subgraph rustman["rustman process"]
        direction TB
        GUI["GUI Thread\negui / eframe"]
        PROXY["Proxy Thread\nTokio runtime #1\n127.0.0.1:8080"]
        BGRT["Background Runtime\nTokio runtime #2"]
        PROXY_MGR["Proxy Manager Thread\nhandles port/addr restarts"]

        subgraph BGRT
            REPEATER["Repeater tasks"]
            CRAWLER["Crawler tasks"]
            MCP["MCP HTTP Server\n127.0.0.1:8099/mcp"]
            CLAUDE_API["Anthropic API calls"]
            ATK_GEN["Attack generation\nstd::thread (off UI)"]
        end

        STATE["AppState\nArc&lt;Mutex&lt;AppState&gt;&gt;"]

        GUI <-->|"lock / read-write"| STATE
        PROXY <-->|"lock / push requests"| STATE
        BGRT <-->|"lock / read-write"| STATE
        PROXY_MGR <-->|"restart channel"| STATE
    end

    BROWSER["Browser\n(proxy → configured addr:port)"]
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
    participant P as Proxy
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

## Crawler & Attack Flow

```mermaid
flowchart TD
    START["User enters URL + depth"] --> QUEUE["BFS Queue"]
    QUEUE --> POP["Pop (url, depth)"]
    POP --> STOP{"stop flag?"}
    STOP -->|"true"| DONE["Finished"]
    STOP -->|"false"| FETCH["GET request\nrepeater_send()"]
    FETCH --> MSG["CrawlMsg::Done\n(status, response)"]
    MSG --> CRAWL{"200 & depth < max?"}
    CRAWL -->|"No"| POP
    CRAWL -->|"Yes"| EXTRACT["extract_links()\nsame-domain only"]
    EXTRACT --> ENQUEUE["Enqueue new URLs"]
    ENQUEUE --> POP

    MSG --> SELECT["User selects entry"]
    SELECT --> ATK_GEN["std::thread\nattack_request(url, raw)"]
    ATK_GEN --> URL_PARAMS["Inject into\nURL parameters"]
    ATK_GEN --> HEADERS["Inject into\n9 injectable headers"]
    ATK_GEN --> BODY["Inject into\nform body params"]
    URL_PARAMS & HEADERS & BODY --> VARIANTS["~2400 AttackVariants\n8 categories × 240 payloads"]
    VARIANTS --> CLICK["User clicks variant"]
    CLICK --> SEND["repeater_send() in bg"]
    SEND --> RESP["Show request + response"]
```

---

## OWASP Payload Categories

| Category | Payloads | Injection targets |
|---|---|---|
| **SQLi** | 30 | URL params, body, headers |
| **XSS** | 30 | URL params, body, headers |
| **CMDi** | 36 | URL params, body, headers |
| **Path Traversal** | 30 | URL params, body, headers |
| **SSRF** | 32 | URL params, body, headers |
| **SSTI** | 30 | URL params, body, headers |
| **Open Redirect** | 30 | URL params, body, headers |
| **RCE** | 30 | URL params, body, headers |

Payloads are embedded at compile time from `payload/*.json`. Headers tested: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `X-Custom-IP-Authorization`, `X-Original-URL`, `Accept-Language`, `Origin`.

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
    RT->>SRV: TCP / TLS connect
    RT->>SRV: Send raw HTTP request
    SRV-->>RT: HTTP response
    RT->>GUI: tx.send(response bytes)
    GUI->>GUI: poll_repeater() → display response
```

---

## Claude AI — Direct API Flow

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
        RT->>ANT: POST /v1/messages (+ tool_result)
    end

    ANT-->>RT: {stop_reason: "end_turn"}
    RT->>GUI: tx.send(Ok(text))
    GUI->>ST: push ChatMessage{from_user: false}
```

---

## MCP Server — Claude Code Integration

```mermaid
sequenceDiagram
    participant CC as Claude Code (IDE)
    participant MCP as MCP Server (8099/mcp)
    participant ST as AppState

    CC->>MCP: initialize
    MCP-->>CC: capabilities {tools, prompts}

    CC->>MCP: prompts/get "pentest-analyst"
    MCP-->>CC: Senior pentester system prompt

    CC->>MCP: tools/call list_requests {method: "POST"}
    MCP->>ST: lock → filter requests
    MCP-->>CC: [{id, method, url, status}]

    CC->>MCP: tools/call forward_request {id, raw}
    MCP->>ST: forward_at(idx, modified_bytes)
    MCP-->>CC: "ok: request forwarded"
```

**Available MCP tools:** `list_requests`, `get_requests`, `forward_request`, `drop_request`, `get_user_prompt`, `reply_to_user`

**Available MCP prompts:** `pentest-analyst`, `general-assistant`

---

## Setup

### 1. Install the CA certificate

On first launch rustman generates a CA certificate and attempts to auto-install it into Firefox.

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

Set your browser HTTP/HTTPS proxy to the address shown in the top bar (default `127.0.0.1:8080`). The address and port can be changed at runtime in **Settings → Proxy**.

### 3. Configure Claude (optional)

Go to **Settings → Claude API** and enter your Anthropic API key (`sk-ant-…`).

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

---

## Build

```bash
# Debug
cargo build

# Release
cargo build --release

# Windows executable (from Linux, requires MinGW)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

> On Windows builds, `build.rs` automatically converts `logo.png` to a multi-size `.ico` and embeds it as the `.exe` resource icon.

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
Recursive BFS crawler. Click any entry to see its request/response. When a page finishes loading, attack variants are generated in a background thread — click any variant to fire the request and see the real server response side by side.

### Claude
In-app AI assistant. Switch between **General** and **Pentest** modes. In Pentest mode every response follows the structured report format: Summary / Observations / Hypotheses / Validation / Impact / Remediation / Priority.

### Settings

| Setting | Description |
|---|---|
| Light mode | Toggle dark/light theme |
| Intercept | Enable or disable request interception |
| Ignore list | Hosts silently forwarded (case-insensitive substring) |
| Proxy address | Bind IP — use `0.0.0.0` to expose on all interfaces |
| Proxy port | 1024–65535 — applied instantly without restart |
| Max requests | Prune oldest completed requests when the limit is reached |
| Claude API key | Anthropic key for the Claude tab |

---

## Project structure

```
rustman/
├── build.rs             — Windows .exe icon embedding (winres + ico)
├── logo.png             — Application logo (embedded at compile time)
├── payload/
│   ├── sqli.json
│   ├── xss.json
│   ├── cmdi.json
│   ├── path_traversal.json
│   ├── ssrf.json
│   ├── ssti.json
│   ├── open_redirect.json
│   └── rce.json
└── src/
    ├── main.rs          — Entry point, proxy manager thread, MCP spawn
    ├── app.rs           — Shared state (AppState, Request, Settings)
    ├── proxy.rs         — MITM proxy, TLS interception, stoppable accept loop
    ├── ca.rs            — Dynamic certificate authority (rcgen)
    ├── gui.rs           — egui/eframe UI (all tabs, adaptive repaint)
    ├── crawler.rs       — BFS crawler, OWASP attack generation
    ├── mcp.rs           — MCP HTTP server (tools + prompts)
    └── claude_client.rs — Anthropic API client with tool-use loop
```
