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
    let mut visited: HashSet<String>         = HashSet::new();
    let mut visited_js: HashSet<String>      = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    // JS files queued for API route extraction: (url, depth-of-parent-page)
    let mut js_queue: VecDeque<(String, usize)> = VecDeque::new();

    visited.insert(canonical(&start_url));
    queue.push_back((start_url, 0));

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // ── Drain pending JS files before processing the next HTML page ──────
        while let Some((js_url, parent_depth)) = js_queue.pop_front() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if parent_depth >= max_depth {
                continue;
            }
            let Some((jh, jp, jt, jpath)) = parse_url_parts(&js_url) else { continue };
            let js_req = format!(
                "GET {jpath} HTTP/1.1\r\nHost: {jh}\r\nUser-Agent: rustman-crawler/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            ).into_bytes();
            let js_resp = crate::proxy::repeater_send(&jh, jp, jt, js_req).await;
            let (js_st, js_body) = split_response(&js_resp);
            if js_st == 200 {
                enqueue_js_routes(
                    &js_body,
                    &base_host,
                    base_tls,
                    base_port,
                    parent_depth,
                    max_depth,
                    &mut visited,
                    &mut queue,
                );
            }
        }

        let Some((url, depth)) = queue.pop_front() else { break };

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
            // HTML links
            let links = extract_links(&body, &base_host, base_tls, base_port, &path);
            let mut count = 0;
            for link in links {
                let key = canonical(&link);
                if !visited.contains(&key) {
                    visited.insert(key);
                    queue.push_back((link, depth + 1));
                    count += 1;
                }
            }

            // External JS files (<script src="...">)
            let scripts = extract_script_srcs(&body, &base_host, base_tls, base_port, &path);
            for js_url in scripts {
                let key = canonical(&js_url);
                if !visited_js.contains(&key) {
                    visited_js.insert(key);
                    js_queue.push_back((js_url, depth));
                }
            }

            // Inline JS (<script> without src)
            let inline = extract_inline_js(&body);
            if !inline.is_empty() {
                enqueue_js_routes(
                    &inline,
                    &base_host,
                    base_tls,
                    base_port,
                    depth,
                    max_depth,
                    &mut visited,
                    &mut queue,
                );
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

// ── SPA / JS route extraction ─────────────────────────────────────────────────

/// Returns `true` if the JS URL looks like a third-party library or vendor bundle
/// that belongs to a framework/plugin rather than the site's own application code.
fn is_vendor_js(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_ascii_lowercase();

    // Paths that indicate dependency directories
    const VENDOR_PATHS: &[&str] = &[
        "/node_modules/",
        "/bower_components/",
        "/vendor/",
        "/vendors/",
        "/assets/libs/",
        "/assets/vendor/",
        "/assets/plugins/",
        "/static/libs/",
        "/static/vendor/",
        "/lib/",
        "/libs/",
        "/plugins/",
        "/cdn/",
    ];
    if VENDOR_PATHS.iter().any(|p| path.contains(p)) {
        return true;
    }

    // Extract just the filename
    let filename = path.split('/').next_back().unwrap_or(&path);
    // Strip query and hash
    let filename = filename.split('?').next().unwrap_or(filename);
    let filename = filename.split('#').next().unwrap_or(filename);
    // Strip .min.js, .bundle.js, etc.
    let stem = filename
        .strip_suffix(".js").unwrap_or(filename)
        .strip_suffix(".min").unwrap_or(filename.strip_suffix(".js").unwrap_or(filename))
        .to_ascii_lowercase();

    // Known library / framework names in filename
    const KNOWN_LIBS: &[&str] = &[
        "jquery", "jquery-ui", "jquery-migrate",
        "lodash", "underscore", "ramda",
        "backbone", "ember", "knockout", "prototype", "mootools",
        "bootstrap", "foundation", "materialize", "bulma",
        "moment", "dayjs", "date-fns", "luxon",
        "d3", "chart", "echarts", "highcharts", "apexcharts", "recharts",
        "leaflet", "mapbox", "openlayers",
        "three", "babylon", "pixi", "phaser",
        "gsap", "anime", "tween",
        "popper", "tippy", "sweetalert", "toastr", "notyf",
        "alpinejs", "htmx", "stimulus",
        "swiper", "slick", "glide", "splide",
        "fontawesome", "feather",
        "crypto-js", "forge",
        "socket.io", "sockjs",
        "pdfmake", "jspdf", "xlsx",
    ];
    if KNOWN_LIBS.iter().any(|lib| stem.starts_with(lib) || stem.contains(&format!("-{lib}")) || stem.contains(&format!(".{lib}"))) {
        return true;
    }

    // Webpack vendor chunk patterns
    const VENDOR_STEMS: &[&str] = &[
        "vendor", "vendors", "chunk-vendors", "vendors~",
        "polyfill", "polyfills", "runtime", "runtime~",
        "commons", "common~", "framework",
    ];
    if VENDOR_STEMS.iter().any(|p| stem.starts_with(p) || stem == *p) {
        return true;
    }

    false
}

/// Extract `<script src="...">` URLs from an HTML page.
fn extract_script_srcs(
    html: &str,
    base_host: &str,
    base_tls: bool,
    base_port: u16,
    current_path: &str,
) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut pos = 0;
    let mut srcs = Vec::new();

    loop {
        let Some(off) = lower[pos..].find("<script") else { break };
        let tag_start = pos + off + 7;
        let Some(gt_off) = lower[tag_start..].find('>') else { break };
        let tag_lc = &lower[tag_start..tag_start + gt_off];
        let tag_orig = &html[tag_start..tag_start + gt_off];
        pos = tag_start + gt_off + 1;

        let Some(src_off) = tag_lc.find("src=") else { continue };
        let after = src_off + 4;
        if after >= tag_orig.len() { continue; }
        let (q, str_start) = match tag_orig.as_bytes()[after] {
            b'"' => (b'"', after + 1),
            b'\'' => (b'\'', after + 1),
            _ => continue,
        };
        let Some(str_end) = tag_orig[str_start..].find(q as char) else { continue };
        let src = &tag_orig[str_start..str_start + str_end];

        // Only JS files, and only the site's own application code
        let src_lc = src.to_ascii_lowercase();
        if !src_lc.ends_with(".js") && !src_lc.contains(".js?") && !src_lc.contains(".js#") {
            continue;
        }
        if let Some(url) = resolve(src, base_host, base_tls, base_port, current_path) {
            if !is_vendor_js(&url) {
                srcs.push(url);
            }
        }
    }
    srcs
}

/// Concatenate the content of inline `<script>` blocks (no src attribute).
fn extract_inline_js(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut pos = 0;
    let mut out = String::new();

    loop {
        let Some(off) = lower[pos..].find("<script") else { break };
        let tag_start = pos + off + 7;
        let Some(gt_off) = lower[tag_start..].find('>') else { break };
        let tag_lc = &lower[tag_start..tag_start + gt_off];
        pos = tag_start + gt_off + 1;

        if tag_lc.contains("src=") { continue; } // external — handled separately

        let Some(close_off) = lower[pos..].find("</script>") else { break };
        out.push_str(&html[pos..pos + close_off]);
        out.push('\n');
        pos += close_off + 9;
    }
    out
}

/// Scan JS source for API route strings and add new ones to the crawl queue.
fn enqueue_js_routes(
    js: &str,
    base_host: &str,
    base_tls: bool,
    base_port: u16,
    parent_depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    queue: &mut VecDeque<(String, usize)>,
) {
    if parent_depth >= max_depth { return; }
    let routes = extract_api_routes_from_js(js);
    let proto   = if base_tls { "https" } else { "http" };
    let port_sfx = match (base_tls, base_port) {
        (true, 443) | (false, 80) => String::new(),
        _ => format!(":{base_port}"),
    };
    for route in routes {
        let full_url = if route.starts_with("http://") || route.starts_with("https://") {
            if let Some((rh, _, _, _)) = parse_url_parts(&route) {
                // Accept: same domain as crawler target, OR any IP/localhost (any port).
                // Reject: a different named domain — it belongs to another site.
                if !rh.eq_ignore_ascii_case(base_host) && !is_ip_host(&rh) {
                    continue;
                }
            }
            route
        } else {
            format!("{proto}://{base_host}{port_sfx}{route}")
        };
        let key = canonical(&full_url);
        if !visited.contains(&key) && is_crawlable(&full_url) {
            visited.insert(key);
            queue.push_back((full_url, parent_depth + 1));
        }
    }
}

/// Extract API-looking path strings from JavaScript / TypeScript source.
pub fn extract_api_routes_from_js(js: &str) -> Vec<String> {
    let mut routes = Vec::new();

    // Patterns that are immediately followed by a string argument containing the URL.
    const CALL_PATTERNS: &[&str] = &[
        "fetch(",
        "axios.get(",
        "axios.post(",
        "axios.put(",
        "axios.delete(",
        "axios.patch(",
        "axios.request(",
        "$.get(",
        "$.post(",
        "$.put(",
        "$.delete(",
        "$http.get(",
        "$http.post(",
        "$http.put(",
        "$http.delete(",
        "this.http.get(",
        "this.http.post(",
        "this.http.put(",
        "this.http.delete(",
        "http.get(",
        "http.post(",
        "http.put(",
        "http.delete(",
        "request.get(",
        "request.post(",
        "superagent.get(",
        "superagent.post(",
        "got.get(",
        "got.post(",
        "ky.get(",
        "ky.post(",
    ];

    // Key-value patterns where the value is the URL.
    const KV_PATTERNS: &[&str] = &[
        "url:",
        "url :",
        "baseURL:",
        "baseUrl:",
        "endpoint:",
        "apiUrl:",
        "apiURL:",
        "path:",
        "path :",
        "route:",
        "href:",
        "action:",
    ];

    // String literal prefixes that indicate an API path even without surrounding context.
    const PATH_PREFIXES: &[&str] = &[
        "/api/",
        "/v1/",
        "/v2/",
        "/v3/",
        "/v4/",
        "/v5/",
        "/graphql",
        "/gql",
        "/rest/",
        "/oauth",
        "/oauth2",
        "/auth/",
        "/login",
        "/logout",
        "/register",
        "/signup",
        "/user/",
        "/users/",
        "/admin/",
        "/search",
        "/account",
        "/profile",
        "/settings",
        "/config",
        "/data/",
        "/rpc",
        "/ws",
        "/socket",
        "/stream",
    ];

    // Scan call patterns
    for pat in CALL_PATTERNS {
        let mut pos = 0;
        while let Some(i) = js[pos..].find(pat) {
            let after = pos + i + pat.len();
            if let Some((s, _)) = next_string_literal(js, after) {
                if looks_like_api_path(&s) {
                    routes.push(s);
                }
            }
            pos += i + 1;
        }
    }

    // Scan key-value patterns
    for pat in KV_PATTERNS {
        let mut pos = 0;
        while let Some(i) = js[pos..].find(pat) {
            let after = pos + i + pat.len();
            if let Some((s, _)) = next_string_literal(js, after) {
                if looks_like_api_path(&s) {
                    routes.push(s);
                }
            }
            pos += i + 1;
        }
    }

    // Scan direct string literals matching known API prefixes
    for prefix in PATH_PREFIXES {
        for &q in &[b'"', b'\'', b'`'] {
            let search: Vec<u8> = std::iter::once(q).chain(prefix.bytes()).collect();
            let mut pos = 0;
            while let Some(i) = find_bytes(js.as_bytes(), &search, pos) {
                let str_start = i + 1; // after opening quote
                if let Some((s, _)) = extract_until_closing_quote(js, str_start, q) {
                    if looks_like_api_path(&s) {
                        routes.push(s);
                    }
                }
                pos = i + 1;
            }
        }
    }

    routes.sort();
    routes.dedup();
    routes
}

/// Find the next string literal (starting with `"`, `'`, or `` ` ``) at or after `start`,
/// skipping leading whitespace.  Returns the unescaped content and the index after the
/// closing quote.
fn next_string_literal(s: &str, start: usize) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let mut i = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b'(' | b'[') {
        i += 1;
    }
    if i >= bytes.len() { return None; }
    match bytes[i] {
        q @ (b'"' | b'\'' | b'`') => extract_until_closing_quote(s, i + 1, q),
        _ => None,
    }
}

/// Extract a string literal from `start` until the matching closing `quote` byte,
/// handling backslash escapes.  Returns `(content, end_index_after_closing_quote)`.
fn extract_until_closing_quote(s: &str, start: usize, quote: u8) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let mut result = String::new();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escape sequence
            continue;
        }
        if bytes[i] == quote {
            return Some((result, i + 1));
        }
        // Stop on newline for single/double-quoted strings (template literals allow them)
        if quote != b'`' && (bytes[i] == b'\n' || bytes[i] == b'\r') {
            return None;
        }
        if bytes[i].is_ascii() {
            result.push(bytes[i] as char);
        }
        i += 1;
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start + needle.len() > haystack.len() { return None; }
    haystack[start..].windows(needle.len()).position(|w| w == needle).map(|p| p + start)
}

/// Returns `true` if `host` (already stripped of port by `parse_url_parts`) is an
/// IP address or localhost — meaning we accept it regardless of the crawler domain.
fn is_ip_host(host: &str) -> bool {
    // localhost (any case)
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // IPv4: exactly 4 dot-separated decimal octets
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|s| s.parse::<u8>().is_ok()) {
        return true;
    }
    // IPv6 (bare like ::1, or bracketed like [::1]): contains a colon
    if host.contains(':') {
        return true;
    }
    false
}

fn looks_like_api_path(s: &str) -> bool {
    if s.is_empty() || s.len() > 512 { return false; }
    // Must start with / or http
    if !s.starts_with('/') && !s.starts_with("http://") && !s.starts_with("https://") {
        return false;
    }
    // Reject template expressions
    if s.contains("${") { return false; }
    // Reject static asset extensions
    let lower = s.split('?').next().unwrap_or(s).to_ascii_lowercase();
    const SKIP: &[&str] = &[
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".json",
    ];
    if SKIP.iter().any(|e| lower.ends_with(e)) { return false; }
    // Must be more than just "/"
    if s == "/" { return false; }
    true
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

/// Where in the HTTP request the payload was injected.
#[derive(Debug, Clone, PartialEq)]
pub enum AttackTarget {
    UrlParam(String),
    Header(String),
    BodyParam(String),
}

impl std::fmt::Display for AttackTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackTarget::UrlParam(p)  => write!(f, "URL ?{p}"),
            AttackTarget::Header(h)    => write!(f, "Header {h}"),
            AttackTarget::BodyParam(p) => write!(f, "Body {p}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttackVariant {
    pub url:         String,
    pub raw_request: Vec<u8>,
    pub target:      AttackTarget,
    pub category:    String,
    pub payload:     String,
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

// ── Attack variant generators ─────────────────────────────────────────────────

/// Generate all attack variants for a fetched request (URL params + headers + body).
pub fn attack_request(url: &str, raw: &[u8]) -> Vec<AttackVariant> {
    let mut out = Vec::new();
    out.extend(attack_url_params(url, raw));
    out.extend(attack_headers(url, raw));
    out.extend(attack_body_params(url, raw));
    out
}

/// Backward-compat alias used in the crawler loop (URL params only, no raw needed).
pub fn attack(link: &str) -> Vec<AttackVariant> {
    attack_url_params(link, &[])
}

/// Inject payloads into every URL query parameter.
/// If the URL has no query string, a synthetic `id=` parameter is added.
fn attack_url_params(url: &str, raw: &[u8]) -> Vec<AttackVariant> {
    let (base, query_opt) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None         => (url, None),
    };

    let owned;
    let pairs: Vec<(&str, &str)> = match query_opt {
        Some(q) => {
            let p = parse_kv(q);
            if p.is_empty() { return vec![]; }
            p
        }
        None => {
            // No query string: synthesize a common injectable param.
            owned = vec![("id", "1")];
            owned.iter().map(|(k, v)| (*k, *v)).collect()
        }
    };

    let payloads = get_payloads();
    let mut out  = Vec::new();

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

            let new_url = format!("{}?{}", base, new_query);
            let new_raw = replace_url_in_request(raw, url, &new_url);
            out.push(AttackVariant {
                url:         new_url,
                raw_request: new_raw,
                target:      AttackTarget::UrlParam(target_key.to_string()),
                category:    category.clone(),
                payload:     payload.clone(),
            });
        }
    }
    out
}

/// Inject payloads into injectable request headers.
fn attack_headers(url: &str, raw: &[u8]) -> Vec<AttackVariant> {
    const INJECTABLE_HEADERS: &[&str] = &[
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "X-Custom-IP-Authorization",
        "X-Original-URL",
        "Accept-Language",
        "Origin",
    ];

    let src = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let payloads = get_payloads();
    let mut out  = Vec::new();

    for header_name in INJECTABLE_HEADERS {
        let header_lc = header_name.to_ascii_lowercase();
        let present = src.lines().any(|l| {
            l.to_ascii_lowercase().starts_with(&format!("{}:", header_lc))
        });

        for (category, payload) in payloads {
            // Replace if present, append before blank line if absent.
            let new_raw = if present {
                replace_header_value(src, &header_lc, payload)
            } else {
                append_header(src, header_name, payload)
            };
            out.push(AttackVariant {
                url:         url.to_string(),
                raw_request: new_raw,
                target:      AttackTarget::Header(header_name.to_string()),
                category:    category.clone(),
                payload:     payload.clone(),
            });
        }
    }
    out
}

/// Inject payloads into form-urlencoded body parameters.
fn attack_body_params(url: &str, raw: &[u8]) -> Vec<AttackVariant> {
    let src = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    // Only process form-encoded bodies.
    let is_form = src.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("content-type:")
            && l.to_ascii_lowercase().contains("application/x-www-form-urlencoded")
    });
    if !is_form { return vec![]; }

    // Body is after the blank line.
    let body = match src.split_once("\r\n\r\n") {
        Some((_, b)) => b,
        None => match src.split_once("\n\n") {
            Some((_, b)) => b,
            None => return vec![],
        },
    };

    let pairs: Vec<(&str, &str)> = parse_kv(body.trim());
    if pairs.is_empty() { return vec![]; }

    let payloads = get_payloads();
    let mut out  = Vec::new();

    for (target_key, _) in &pairs {
        for (category, payload) in payloads {
            let new_body: String = pairs
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

            let new_raw = replace_body(src, &new_body);
            out.push(AttackVariant {
                url:         url.to_string(),
                raw_request: new_raw,
                target:      AttackTarget::BodyParam(target_key.to_string()),
                category:    category.clone(),
                payload:     payload.clone(),
            });
        }
    }
    out
}

// ── Request surgery helpers ───────────────────────────────────────────────────

fn parse_kv<'a>(s: &'a str) -> Vec<(&'a str, &'a str)> {
    s.split('&')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            if k.is_empty() { None } else { Some((k, v)) }
        })
        .collect()
}

/// Swap the URL in the request-line (first line) of a raw HTTP request.
fn replace_url_in_request(raw: &[u8], _old_url: &str, new_url: &str) -> Vec<u8> {
    if raw.is_empty() {
        // No existing raw — build a minimal GET request.
        return format!("GET {new_url} HTTP/1.1\r\nConnection: close\r\n\r\n").into_bytes();
    }
    let src = String::from_utf8_lossy(raw);
    // Extract just the path+query from the new URL.
    let path = new_url
        .splitn(3, '/')
        .skip(2)
        .next()
        .map(|s| format!("/{s}"))
        .unwrap_or_else(|| "/".to_string());

    // Replace only the path portion in the request-line.
    if let Some(first_end) = src.find("\r\n").or_else(|| src.find('\n')) {
        let first_line = &src[..first_end];
        let mut parts = first_line.splitn(3, ' ');
        let method  = parts.next().unwrap_or("GET");
        let _old_path = parts.next().unwrap_or("/");
        let version = parts.next().unwrap_or("HTTP/1.1");
        let new_first = format!("{method} {path} {version}");
        let rest = &src[first_end..];
        return format!("{new_first}{rest}").into_bytes();
    }
    raw.to_vec()
}

/// Append a new header before the blank line that separates headers from body.
fn append_header(src: &str, header_name: &str, payload: &str) -> Vec<u8> {
    let sep = if src.contains("\r\n\r\n") { "\r\n\r\n" } else { "\n\n" };
    match src.split_once(sep) {
        Some((headers, body)) => {
            format!("{}\r\n{}: {}{}{}", headers, header_name, payload, sep, body).into_bytes()
        }
        None => {
            format!("{}\r\n{}: {}\r\n\r\n", src, header_name, payload).into_bytes()
        }
    }
}

/// Replace the value of a header in a raw HTTP request string.
fn replace_header_value(src: &str, header_lc: &str, payload: &str) -> Vec<u8> {
    let prefix = format!("{}:", header_lc);
    src.lines()
        .map(|line| {
            if line.to_ascii_lowercase().starts_with(&prefix) {
                let name = &line[..line.find(':').unwrap_or(line.len())];
                format!("{}: {}", name, payload)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        .into_bytes()
}

/// Replace the body of a raw HTTP request with `new_body`.
fn replace_body(src: &str, new_body: &str) -> Vec<u8> {
    let sep = if src.contains("\r\n\r\n") { "\r\n\r\n" } else { "\n\n" };
    let headers = src.split_once(sep).map(|(h, _)| h).unwrap_or(src);
    // Fix Content-Length.
    let new_len = new_body.len();
    let headers = headers
        .lines()
        .map(|l| {
            if l.to_ascii_lowercase().starts_with("content-length:") {
                format!("Content-Length: {new_len}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    format!("{headers}{sep}{new_body}").into_bytes()
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
