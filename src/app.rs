use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Pending,
    Forwarding,
    Forwarded,
    Dropped,
}

pub enum Action {
    Forward(Vec<u8>),
    Drop,
}

pub struct Request {
    pub id: usize,
    pub method: String,
    pub url: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub raw: Vec<u8>,
    pub edited: Option<Vec<u8>>,
    pub status: Status,
    pub response: Option<Vec<u8>>,
    pub tx: Option<oneshot::Sender<Action>>,
}

impl Request {
    pub fn display_text(&self) -> String {
        String::from_utf8_lossy(self.edited.as_deref().unwrap_or(&self.raw)).into_owned()
    }
    pub fn response_text(&self) -> String {
        self.response.as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }
}

// ── Settings ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Settings {
    /// When false every request is auto-forwarded and nothing appears in the list.
    pub intercept_enabled: bool,
    /// Hosts/patterns (lowercase substring match) that are always forwarded silently.
    pub ignore_hosts: Vec<String>,
    /// Maximum number of requests kept in the list; oldest completed ones are pruned.
    pub max_requests: usize,
    /// Informational — updated when the proxy successfully binds.
    pub proxy_addr: String,
    pub proxy_port: u16,
    /// Anthropic API key for the in-app Claude chat.
    pub api_key: String,
    /// Use light theme instead of dark.
    pub light_mode: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            intercept_enabled: true,
            ignore_hosts: Vec::new(),
            max_requests: 500,
            proxy_addr: "127.0.0.1".to_string(),
            proxy_port: 8080,
            api_key: String::new(),
            light_mode: false,
        }
    }
}

// ── AppState ──────────────────────────────────────────────────────────────────

pub struct AppState {
    pub requests: Vec<Request>,
    pub next_id: usize,
    /// Monotonic counter incremented on every structural change to `requests`.
    /// The GUI caches this to skip sync_selection when nothing changed.
    pub version: u64,
    /// Host currently in focus (set when a top-level navigation is detected).
    /// None = no navigation seen yet → auto-forward everything.
    pub focused_host: Option<String>,
    pub settings: Settings,
    /// Unread prompt waiting for Claude Code to pick up.
    pub pending_prompt: Option<String>,
    /// Full chat history displayed in the Claude tab.
    pub chat_messages: Vec<ChatMessage>,
    /// Send (addr, port) here to restart the proxy listener.
    pub proxy_restart_tx: Option<std::sync::mpsc::SyncSender<(String, u16)>>,
    /// Set while a proxy restart is in progress.
    pub proxy_restarting: bool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            next_id: 0,
            version: 0,
            focused_host: None,
            settings: Settings::default(),
            pending_prompt: None,
            chat_messages: Vec::new(),
            proxy_restart_tx: None,
            proxy_restarting: false,
        }
    }

    pub fn push(&mut self, mut req: Request) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        req.id = id;
        self.requests.push(req);
        self.version += 1;
        // Prune oldest completed request when over the limit
        let max = self.settings.max_requests;
        if self.requests.len() > max {
            if let Some(i) = self.requests.iter().position(
                |r| !matches!(r.status, Status::Pending | Status::Forwarding)
            ) {
                self.requests.remove(i);
            }
        }
        id
    }

    pub fn update_status(&mut self, id: usize, status: Status, response: Option<Vec<u8>>) {
        if let Some(r) = self.requests.iter_mut().find(|r| r.id == id) {
            r.status = status;
            if response.is_some() { r.response = response; }
            self.version += 1;
        }
    }

    pub fn forward_at(&mut self, idx: usize, bytes: Vec<u8>) {
        if let Some(req) = self.requests.get_mut(idx) {
            if req.status == Status::Pending {
                if let Some(tx) = req.tx.take() {
                    let _ = tx.send(Action::Forward(bytes));
                    req.status = Status::Forwarding;
                }
            }
        }
    }

    pub fn drop_at(&mut self, idx: usize) {
        if let Some(req) = self.requests.get_mut(idx) {
            if req.status == Status::Pending {
                if let Some(tx) = req.tx.take() {
                    let _ = tx.send(Action::Drop);
                    req.status = Status::Dropped;
                }
            }
        }
    }

    pub fn forward_all_pending(&mut self) {
        for req in self.requests.iter_mut() {
            if req.status == Status::Pending {
                let bytes = req.edited.clone().unwrap_or_else(|| req.raw.clone());
                if let Some(tx) = req.tx.take() {
                    let _ = tx.send(Action::Forward(bytes));
                    req.status = Status::Forwarding;
                }
            }
        }
    }

    pub fn clear_done(&mut self) {
        self.requests.retain(|r| matches!(r.status, Status::Pending | Status::Forwarding));
    }

    pub fn set_edited(&mut self, id: usize, bytes: Vec<u8>) {
        if let Some(r) = self.requests.iter_mut().find(|r| r.id == id) {
            r.edited = Some(bytes);
        }
    }

    pub fn pending_count(&self) -> usize {
        self.requests.iter().filter(|r| r.status == Status::Pending).count()
    }

    /// Return true if `host` belongs to the currently focused site.
    /// Matches on base domain so api.example.com matches example.com.
    pub fn is_focused(&self, host: &str) -> bool {
        match &self.focused_host {
            None => false,
            Some(f) => base_domain(host) == base_domain(f),
        }
    }

    /// Return true if `host` matches any entry in the ignore list.
    pub fn is_ignored(&self, host: &str) -> bool {
        let low = host.to_ascii_lowercase();
        self.settings.ignore_hosts.iter().any(|pat| low.contains(pat.as_str()))
    }
}

pub type Shared = Arc<Mutex<AppState>>;

// ── Chat ──────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ChatMessage {
    pub from_user: bool,
    pub text: String,
}

/// Extract the registrable domain (e.g. "api.example.com" → "example.com").
/// Simple heuristic — good enough for common cases.
pub fn base_domain(host: &str) -> &str {
    let host = host.split(':').next().unwrap_or(host); // strip port
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 | 1 | 2 => host,
        _ => {
            let dots: Vec<usize> = host.match_indices('.').map(|(i, _)| i).collect();
            &host[dots[dots.len() - 2] + 1..]
        }
    }
}
