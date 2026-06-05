use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::app::{Action, Request, Shared, Status};
use crate::ca::Ca;

// ── rustls client config (skip server cert verification — we are the MITM) ───

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self, _end: &rustls::pki_types::CertificateDer<'_>,
        _chain: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8], _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, msg: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
    -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(msg, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, msg: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
    -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(msg, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

static CLIENT_CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
fn client_cfg() -> Arc<rustls::ClientConfig> {
    CLIENT_CFG.get_or_init(|| {
        Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerify))
                .with_no_client_auth(),
        )
    }).clone()
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(state: Shared, ca: Arc<Ca>, port: u16, ready: std::sync::mpsc::SyncSender<Result<u16, String>>) {
    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => { ready.send(Ok(port)).ok(); l }
        Err(e) => { ready.send(Err(e.to_string())).ok(); return; }
    };
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let s = state.clone();
                let c = ca.clone();
                tokio::spawn(async move { dispatch(stream, s, c).await });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

async fn dispatch(mut stream: TcpStream, state: Shared, ca: Arc<Ca>) {
    let mut buf = vec![0u8; 16384];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let raw = buf[..n].to_vec();

    match first_line(&raw) {
        Some((ref m, ref target)) if m == "CONNECT" => {
            eprintln!("[proxy] CONNECT {target}");
            do_mitm(stream, target, state, ca).await;
        }
        Some((ref m, ref path)) => {
            eprintln!("[proxy] HTTP {m} {path}");
            intercept_http(stream, state, raw).await;
        }
        None => {
            eprintln!("[proxy] unreadable request ({} bytes)", raw.len());
        }
    }
}

// ── HTTPS MITM ────────────────────────────────────────────────────────────────

async fn do_mitm(mut client: TcpStream, target: &str, state: Shared, ca: Arc<Ca>) {
    let (host, port) = split_host_port(target, 443);

    // Tell browser we accept the tunnel
    if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return;
    }

    // TLS handshake with browser — we present a cert signed by our CA
    let acceptor = TlsAcceptor::from(ca.server_config_for(&host));
    let browser_tls = match acceptor.accept(client).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[mitm] browser TLS handshake failed for {host}: {e}");
            eprintln!("       → The CA cert is not installed in the browser.");
            eprintln!("       → Import ~/.rustman/ca.crt in Firefox: Settings → Privacy → Certificates → Import");
            return;
        }
    };

    let (mut br, mut bw) = tokio::io::split(browser_tls);
    let mut buf = Vec::new();

    loop {
        // Read one complete HTTP request from browser (over TLS)
        let raw = match read_request(&mut br, buf).await {
            Some(r) if !r.is_empty() => r,
            _ => break,
        };

        let keep_alive = is_keep_alive(&raw);
        let method    = parse_method(&raw).unwrap_or_default();
        let url_path  = path_only(&parse_path(&raw).unwrap_or_else(|| "/".into()));

        let intercept = update_focus_and_check(&state, &raw, &host);

        if !intercept {
            let resp = forward_tls(&host, port, rewrite(raw)).await;
            if bw.write_all(&resp).await.is_err() { break; }
            if !keep_alive { break; }
            buf = Vec::new();
            continue;
        }

        eprintln!("[proxy] intercepting HTTPS {method} {host}:{port}{url_path}");
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut s = state.lock().unwrap();
            s.push(Request {
                id: 0, method, url: url_path,
                host: host.clone(), port, tls: true,
                raw, edited: None,
                status: Status::Pending, response: None, tx: Some(tx),
            })
        };

        match rx.await {
            Ok(Action::Forward(data)) => {
                let resp = forward_tls(&host, port, rewrite(data)).await;
                let _ = bw.write_all(&resp).await;
                state.lock().unwrap().update_status(id, Status::Forwarded, Some(resp));
            }
            Ok(Action::Drop) | Err(_) => {
                let _ = bw.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
                state.lock().unwrap().update_status(id, Status::Dropped, None);
                break;
            }
        }

        if !keep_alive { break; }
        buf = Vec::new();
    }
}

/// Open a fresh TLS connection to `host:port`, send `request`, drain response.
async fn forward_tls(host: &str, port: u16, request: Vec<u8>) -> Vec<u8> {
    let err_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec();

    let tcp = match TcpStream::connect(format!("{host}:{port}")).await {
        Ok(s) => s, Err(_) => return err_resp,
    };
    let sni = match rustls::pki_types::ServerName::try_from(host).map(|n| n.to_owned()) {
        Ok(s) => s, Err(_) => return err_resp,
    };
    let mut tls = match TlsConnector::from(client_cfg()).connect(sni, tcp).await {
        Ok(s) => s, Err(_) => return err_resp,
    };
    if tls.write_all(&request).await.is_err() { return err_resp; }
    drain(&mut tls).await
}

// ── Plain HTTP intercept ──────────────────────────────────────────────────────

async fn intercept_http(mut client: TcpStream, state: Shared, first_chunk: Vec<u8>) {
    let mut buf = first_chunk;
    loop {
        let raw = match read_request(&mut client, buf).await {
            Some(b) if !b.is_empty() => b,
            _ => return,
        };

        let keep_alive = is_keep_alive(&raw);
        let method    = parse_method(&raw).unwrap_or_default();
        let raw_path  = parse_path(&raw).unwrap_or_else(|| "/".into());
        let (host, port) = extract_host(&raw, &raw_path);
        let url_path  = path_only(&raw_path);

        let intercept = update_focus_and_check(&state, &raw, &host);

        if !intercept {
            match TcpStream::connect(format!("{host}:{port}")).await {
                Ok(mut s) => {
                    let _ = s.write_all(&rewrite(raw)).await;
                    let resp = drain(&mut s).await;
                    let _ = client.write_all(&resp).await;
                }
                Err(_) => { let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await; return; }
            }
            if !keep_alive { return; }
            buf = Vec::new();
            continue;
        }

        eprintln!("[proxy] intercepting HTTP {method} {host}:{port}{url_path}");
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut s = state.lock().unwrap();
            s.push(Request {
                id: 0, method, url: url_path,
                host: host.clone(), port, tls: false,
                raw, edited: None,
                status: Status::Pending, response: None, tx: Some(tx),
            })
        };

        match rx.await {
            Ok(Action::Forward(data)) => {
                let out = rewrite(data);
                match TcpStream::connect(format!("{host}:{port}")).await {
                    Ok(mut s) => {
                        if s.write_all(&out).await.is_ok() {
                            let resp = drain(&mut s).await;
                            let _ = client.write_all(&resp).await;
                            state.lock().unwrap().update_status(id, Status::Forwarded, Some(resp));
                        }
                    }
                    Err(_) => {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        state.lock().unwrap().update_status(id, Status::Dropped, None);
                        return;
                    }
                }
            }
            Ok(Action::Drop) | Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
                state.lock().unwrap().update_status(id, Status::Dropped, None);
                if !keep_alive { return; }
                buf = Vec::new();
                continue;
            }
        }

        if !keep_alive { return; }
        buf = Vec::new();
    }
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

async fn read_request<R: AsyncRead + Unpin>(r: &mut R, mut buf: Vec<u8>) -> Option<Vec<u8>> {
    let mut tmp = [0u8; 4096];
    let hdr_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = r.read(&mut tmp).await.ok().filter(|&n| n > 0)?;
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 256 * 1024 { return None; }
    };
    if let Some(cl) = content_length(&buf[..hdr_end]) {
        let need = cl.saturating_sub(buf.len() - hdr_end);
        if need > 0 {
            let start = buf.len();
            buf.resize(start + need, 0);
            r.read_exact(&mut buf[start..]).await.ok()?;
        }
    }
    Some(buf)
}

async fn drain<R: AsyncRead + Unpin>(r: &mut R) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match r.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    buf
}

// ── Focus / tab tracking ──────────────────────────────────────────────────────

/// Returns true if this request should be intercepted.
/// Side-effect: if the request is a top-level navigation, updates focused_host.
fn update_focus_and_check(state: &Shared, raw: &[u8], host: &str) -> bool {
    let nav = is_navigation(raw);
    let mut s = state.lock().unwrap();
    if nav {
        eprintln!("[focus] navigation → {host}");
        s.focused_host = Some(host.to_string());
    }
    s.is_focused(host)
}

/// True when the request is a top-level page navigation.
/// Detection uses Sec-Fetch-Mode (modern browsers) with a fallback
/// to "GET with no Referer" for older/non-standard clients.
fn is_navigation(raw: &[u8]) -> bool {
    let text = std::str::from_utf8(raw).unwrap_or("");
    let mut has_sec_fetch = false;

    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("sec-fetch-mode:") {
            has_sec_fetch = true;
            return lower.contains("navigate");
        }
    }

    // Fallback: GET with no Referer header (likely a fresh navigation)
    if !has_sec_fetch {
        let is_get = text.lines().next()
            .map(|l| l.starts_with("GET ")).unwrap_or(false);
        let has_referer = text.lines()
            .any(|l| l.to_ascii_lowercase().starts_with("referer:"));
        return is_get && !has_referer;
    }

    false
}

// ── Request rewriting ─────────────────────────────────────────────────────────

fn rewrite(raw: Vec<u8>) -> Vec<u8> {
    // Normalise bare \n → \r\n (egui TextEdit strips \r)
    let raw = {
        let mut out = Vec::with_capacity(raw.len() + 64);
        let mut prev = 0u8;
        for b in raw { if b == b'\n' && prev != b'\r' { out.push(b'\r'); } out.push(b); prev = b; }
        out
    };

    let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(raw.len());
    let body = raw[hdr_end..].to_vec();

    let hdr_text = match std::str::from_utf8(&raw[..hdr_end]) { Ok(s) => s, Err(_) => return raw };
    let mut segs: Vec<&str> = hdr_text.split("\r\n").collect();
    while segs.last() == Some(&"") { segs.pop(); }
    if segs.is_empty() { return raw; }

    let req_line = {
        let p: Vec<&str> = segs[0].splitn(3, ' ').collect();
        if p.len() == 3 { format!("{} {} {}", p[0], path_only(p[1]), p[2]) } else { segs[0].into() }
    };

    let mut out = vec![req_line];
    let mut has_conn = false;
    for &line in &segs[1..] {
        if line.is_empty() { continue; }
        let low = line.to_ascii_lowercase();
        if low.starts_with("connection:")        { out.push("Connection: close".into()); has_conn = true; }
        else if low.starts_with("proxy-connection:") { /* strip */ }
        else                                     { out.push(line.into()); }
    }
    if !has_conn { out.push("Connection: close".into()); }

    let mut result = out.join("\r\n").into_bytes();
    result.extend_from_slice(b"\r\n\r\n");
    result.extend_from_slice(&body);
    result
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

fn first_line(raw: &[u8]) -> Option<(String, String)> {
    let end = raw.windows(2).position(|w| w == b"\r\n")
        .or_else(|| raw.iter().position(|&b| b == b'\n'))?;
    let line = std::str::from_utf8(&raw[..end]).ok()?;
    let mut it = line.splitn(3, ' ');
    Some((it.next()?.to_string(), it.next()?.to_string()))
}

fn parse_method(r: &[u8]) -> Option<String> { Some(first_line(r)?.0) }
fn parse_path(r: &[u8])   -> Option<String> { Some(first_line(r)?.1) }

fn content_length(hdr: &[u8]) -> Option<usize> {
    std::str::from_utf8(hdr).ok()?.lines().find_map(|l| {
        let l = l.trim();
        if l.to_ascii_lowercase().starts_with("content-length:") { l[15..].trim().parse().ok() } else { None }
    })
}

fn is_keep_alive(raw: &[u8]) -> bool {
    let text = std::str::from_utf8(raw).unwrap_or("");
    let http11 = text.contains("HTTP/1.1");
    let conn = text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("connection:"))
        .map(|l| l.to_ascii_lowercase()).unwrap_or_default();
    if conn.contains("close") { return false; }
    http11 || conn.contains("keep-alive")
}

fn split_host_port(s: &str, default: u16) -> (String, u16) {
    if let Some(c) = s.rfind(':') {
        if let Ok(p) = s[c + 1..].parse::<u16>() { return (s[..c].to_string(), p); }
    }
    (s.to_string(), default)
}

fn path_only(url: &str) -> String {
    if let Some(p) = url.find("://") {
        let after = &url[p + 3..];
        return after.find('/').map(|i| after[i..].to_string()).unwrap_or_else(|| "/".into());
    }
    if url.is_empty() { "/".into() } else { url.to_string() }
}

fn extract_host(raw: &[u8], url: &str) -> (String, u16) {
    if url.starts_with("http://") || url.starts_with("https://") {
        let after = &url[url.find("://").unwrap() + 3..];
        let auth  = after.split('/').next().unwrap_or(after);
        let def   = if url.starts_with("https") { 443 } else { 80 };
        return split_host_port(auth, def);
    }
    let text = std::str::from_utf8(raw).unwrap_or("");
    for line in text.lines() {
        if line.to_ascii_lowercase().starts_with("host:") {
            return split_host_port(line[5..].trim(), 80);
        }
    }
    ("localhost".to_string(), 80)
}
