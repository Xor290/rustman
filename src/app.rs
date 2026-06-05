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

pub struct AppState {
    pub requests: Vec<Request>,
    pub next_id: usize,
    /// Host currently in focus (set when a top-level navigation is detected).
    /// None = no navigation seen yet → auto-forward everything.
    pub focused_host: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self { requests: Vec::new(), next_id: 0, focused_host: None }
    }

    pub fn push(&mut self, mut req: Request) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        req.id = id;
        self.requests.push(req);
        id
    }

    pub fn update_status(&mut self, id: usize, status: Status, response: Option<Vec<u8>>) {
        if let Some(r) = self.requests.iter_mut().find(|r| r.id == id) {
            r.status = status;
            if response.is_some() { r.response = response; }
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
}

pub type Shared = Arc<Mutex<AppState>>;

/// Extract the registrable domain (e.g. "api.example.com" → "example.com").
/// Simple heuristic — good enough for common cases.
pub fn base_domain(host: &str) -> &str {
    let host = host.split(':').next().unwrap_or(host); // strip port
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 | 1 | 2 => host,
        _ => {
            // Keep last two labels; host starts at the third-from-last dot.
            let dots: Vec<usize> = host.match_indices('.').map(|(i, _)| i).collect();
            &host[dots[dots.len() - 2] + 1..]
        }
    }
}
