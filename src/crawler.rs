use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── Public types ──────────────────────────────────────────────────────────────

pub enum CrawlMsg {
    Visiting {
        url: String,
        depth: usize,
        request: Vec<u8>,
    },
    Done {
        url: String,
        status: u16,
        new_links: usize,
        response: Vec<u8>,
    },
    Failed {
        url: String,
        reason: String,
    },
    Finished,
    Attack {
        variant: Vec<AttackVariant>,
    },
}

#[derive(Debug, Clone)]
pub enum EntryStatus {
    Fetching,
    Done(u16, usize), // (status_code, new_links_enqueued)
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct CrawlerEntry {
    pub url: String,
    pub depth: usize,
    pub status: EntryStatus,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

/// Parsed URL components — exposed so the GUI can build a Repeater session.
pub struct UrlParts {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub path: String,
}

pub fn parse_url(url: &str) -> Option<UrlParts> {
    parse_url_parts(url).map(|(host, port, tls, path)| UrlParts {
        host,
        port,
        tls,
        path,
    })
}

// ── Crawler task ──────────────────────────────────────────────────────────────

pub async fn run(
    start_url: String,
    max_depth: usize,
    stop: Arc<AtomicBool>,
    tx: std::sync::mpsc::SyncSender<CrawlMsg>,
) {
    let base = match parse_url_parts(&start_url) {
        Some(b) => b,
        None => {
            let _ = tx.send(CrawlMsg::Failed {
                url: start_url,
                reason: "Invalid URL — start with http:// or https://".into(),
            });
            let _ = tx.send(CrawlMsg::Finished);
            return;
        }
    };

    let (base_host, base_port, base_tls) = (base.0.clone(), base.1, base.2);
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    visited.insert(canonical(&start_url));
    queue.push_back((start_url, 0));

    while let Some((url, depth)) = queue.pop_front() {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let (host, port, tls, path) = match parse_url_parts(&url) {
            Some(p) => p,
            None => {
                let _ = tx.send(CrawlMsg::Failed {
                    url,
                    reason: "Unparseable URL".into(),
                });
                continue;
            }
        };

        let request_bytes = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rustman-crawler/1.0\r\nAccept: text/html,*/*;q=0.9\r\nAccept-Language: en\r\nConnection: close\r\n\r\n"
        ).into_bytes();

        let _ = tx.send(CrawlMsg::Visiting {
            url: url.clone(),
            depth,
            request: request_bytes.clone(),
        });

        let resp = crate::proxy::repeater_send(&host, port, tls, request_bytes).await;
        let (status, body) = split_response(&resp);

        let new_links = if depth < max_depth && status == 200 {
            let links = extract_links(&body, &base_host, base_tls, base_port, &path);
            let mut count = 0;
            for link in links {
                let variants = attack(&link);
                let key = canonical(&link);
                if !visited.contains(&key) {
                    visited.insert(key);
                    queue.push_back((link, depth + 1));
                    count += 1;
                }
                let _ = tx.send(CrawlMsg::Attack {
                    variant: (variants),
                });
            }
            count
        } else {
            0
        };

        let _ = tx.send(CrawlMsg::Done {
            url,
            status,
            new_links,
            response: resp,
        });
    }

    let _ = tx.send(CrawlMsg::Finished);
}

// ── URL helpers ───────────────────────────────────────────────────────────────

fn parse_url_parts(url: &str) -> Option<(String, u16, bool, String)> {
    let (tls, rest) = if url.starts_with("https://") {
        (true, &url[8..])
    } else if url.starts_with("http://") {
        (false, &url[7..])
    } else {
        return None;
    };

    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path = if slash < rest.len() {
        rest[slash..].to_string()
    } else {
        "/".to_string()
    };

    let (host, port) = match authority.rfind(':') {
        Some(c) => match authority[c + 1..].parse::<u16>() {
            Ok(p) => (authority[..c].to_string(), p),
            Err(_) => (authority.to_string(), if tls { 443 } else { 80 }),
        },
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };

    if host.is_empty() {
        return None;
    }
    Some((host, port, tls, path))
}

fn canonical(url: &str) -> String {
    url.split('#')
        .next()
        .unwrap_or(url)
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn split_response(resp: &[u8]) -> (u16, String) {
    let status = std::str::from_utf8(resp)
        .unwrap_or("")
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| String::from_utf8_lossy(&resp[p + 4..]).into_owned())
        .unwrap_or_default();
    (status, body)
}

fn is_crawlable(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_ascii_lowercase();
    const SKIP: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".pdf", ".zip", ".tar",
        ".gz", ".mp4", ".mp3", ".ogg", ".wav", ".woff", ".woff2", ".ttf", ".eot", ".css", ".js",
        ".json", ".xml", ".txt", ".csv", ".map",
    ];
    !SKIP.iter().any(|e| path.ends_with(e))
}

// ── HTML link extraction ──────────────────────────────────────────────────────

fn extract_links(
    html: &str,
    base_host: &str,
    base_tls: bool,
    base_port: u16,
    current_path: &str,
) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut pos = 0;
    let mut links = Vec::new();

    while pos < lower.len() {
        let Some(rel) = lower[pos..].find("href=") else {
            break;
        };
        pos += rel + 5;
        if pos >= lower.len() {
            break;
        }

        let (q, start) = match lower.as_bytes()[pos] {
            b'"' => ('"', pos + 1),
            b'\'' => ('\'', pos + 1),
            _ => {
                pos += 1;
                continue;
            }
        };

        let Some(end_rel) = lower[start..].find(q) else {
            break;
        };
        let href = &html[start..start + end_rel]; // original case
        pos = start + end_rel + 1;

        if let Some(url) = resolve(href, base_host, base_tls, base_port, current_path) {
            if is_crawlable(&url) {
                links.push(url);
            }
        }
    }

    links
}

fn resolve(
    href: &str,
    base_host: &str,
    base_tls: bool,
    base_port: u16,
    current_path: &str,
) -> Option<String> {
    let href = href.trim();
    if href.is_empty()
        || href.starts_with('#')
        || href.starts_with("mailto:")
        || href.starts_with("javascript:")
        || href.starts_with("data:")
        || href.starts_with("tel:")
    {
        return None;
    }

    let proto = if base_tls { "https" } else { "http" };
    let port_sfx = match (base_tls, base_port) {
        (true, 443) | (false, 80) => String::new(),
        _ => format!(":{base_port}"),
    };

    if href.starts_with("http://") || href.starts_with("https://") {
        let is_https = href.starts_with("https://");
        let after = &href[if is_https { 8 } else { 7 }..];
        let authority = after.split('/').next().unwrap_or("");
        let host = authority.split(':').next().unwrap_or(authority);
        if host.eq_ignore_ascii_case(base_host) {
            Some(href.to_string())
        } else {
            None
        }
    } else if href.starts_with("//") {
        let host = href[2..]
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        if host.eq_ignore_ascii_case(base_host) {
            Some(format!("{proto}:{href}"))
        } else {
            None
        }
    } else if href.starts_with('/') {
        Some(format!("{proto}://{base_host}{port_sfx}{href}"))
    } else {
        let dir = current_path
            .rfind('/')
            .map(|i| &current_path[..=i])
            .unwrap_or("/");
        Some(format!("{proto}://{base_host}{port_sfx}{dir}{href}"))
    }
}

#[derive(Debug, Clone)]
pub struct AttackVariant {
    pub url:      String,
    pub param:    String,
    pub category: String,
    pub payload:  String,
}

// ── Payload files embedded at compile time ────────────────────────────────────

static PAYLOADS: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();

fn get_payloads() -> &'static Vec<(String, String)> {
    PAYLOADS.get_or_init(|| {
        let mut all = Vec::new();
        macro_rules! load {
            ($cat:expr, $src:expr) => {
                match serde_json::from_str::<Vec<String>>($src) {
                    Ok(list) => {
                        for p in list {
                            all.push(($cat.to_string(), p));
                        }
                    }
                    Err(e) => eprintln!("[attack] failed to parse {} payloads: {e}", $cat),
                }
            };
        }
        load!("SQLi",          include_str!("../payload/sqli.json"));
        load!("XSS",           include_str!("../payload/xss.json"));
        load!("CMDi",          include_str!("../payload/cmdi.json"));
        load!("PathTraversal", include_str!("../payload/path_traversal.json"));
        load!("SSRF",          include_str!("../payload/ssrf.json"));
        load!("SSTI",          include_str!("../payload/ssti.json"));
        load!("OpenRedirect",  include_str!("../payload/open_redirect.json"));
        load!("RCE",           include_str!("../payload/rce.json"));
        all
    })
}

// ── Attack variant generator ──────────────────────────────────────────────────

pub fn attack(link: &str) -> Vec<AttackVariant> {
    let (base, query) = match link.split_once('?') {
        Some((b, q)) => (b, q),
        None => return vec![],
    };

    let pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            if k.is_empty() { None } else { Some((k, v)) }
        })
        .collect();

    if pairs.is_empty() {
        return vec![];
    }

    let payloads = get_payloads();
    let mut out = Vec::new();

    for (target_key, _) in &pairs {
        for (category, payload) in payloads {
            let new_query: String = pairs
                .iter()
                .map(|(k, v)| {
                    if k == target_key {
                        format!("{}={}", k, url_encode(payload))
                    } else {
                        format!("{}={}", k, v)
                    }
                })
                .collect::<Vec<_>>()
                .join("&");

            out.push(AttackVariant {
                url:      format!("{}?{}", base, new_query),
                param:    target_key.to_string(),
                category: category.clone(),
                payload:  payload.clone(),
            });
        }
    }

    out
}

/// Percent-encode characters that would break a query string.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
