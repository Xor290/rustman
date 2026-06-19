use printpdf::*;
use std::io::BufWriter;

// ── Public types ──────────────────────────────────────────────────────────────

/// Confirmed finding — kept for the UI badge / VULN indicator.
#[derive(Clone)]
pub struct Finding {
    pub url:      String,
    pub category: String,
    pub target:   String,
    pub payload:  String,
    pub evidence: String,
}

/// Full record of every single attack attempt, used for PDF generation.
#[derive(Clone)]
pub struct AttackRecord {
    pub url:         String,
    pub category:    String,
    pub target:      String,
    pub payload:     String,
    pub status_code: u16,
    /// `Some(evidence)` when the payload was confirmed as reflected / triggered.
    pub evidence:    Option<String>,
    /// Full raw HTTP request sent (populated for all records).
    pub raw_request: String,
}

// ── Finding quality filter ────────────────────────────────────────────────────

/// Returns `true` when the HTTP response code makes the finding a false positive.
///
/// - **404** for any category: the endpoint does not exist — any apparent match
///   in the body is just an error page, not a real reflection or trigger.
/// - **302** for XSS/SQLi/CMDi/RCE/PathTraversal: almost always a login redirect
///   or post-submit bounce.  OpenRedirect and SSRF are excluded because their
///   detection is redirect-based by design.
pub fn is_false_positive(category: &str, status_code: u16) -> bool {
    if status_code == 404 {
        return true;
    }
    status_code == 302
        && matches!(category, "XSS" | "SQLi" | "CMDi" | "RCE" | "PathTraversal")
}

// ── Context helpers ───────────────────────────────────────────────────────────

/// `true` if `pos` in `s` is inside an HTML comment `<!-- … -->`.
fn inside_comment(s: &str, pos: usize) -> bool {
    let before = &s[..pos];
    if let Some(cs) = before.rfind("<!--") {
        !s[cs + 4..pos].contains("-->")
    } else {
        false
    }
}

/// `true` if `needle` appears at least once in HTML *text content*
/// (between a closing `>` and an opening `<`) and outside any HTML comment.
/// This rejects matches that live inside tag attributes, class names, CSS, etc.
fn in_text_content(body: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(rel) = body[start..].find(needle) {
        let pos = start + rel;
        let before = &body[..pos];
        let in_text = match (before.rfind('>'), before.rfind('<')) {
            (Some(g), Some(l)) => g > l, // last `>` is more recent than last `<`
            (Some(_), None)    => true,
            _                  => false,
        };
        if in_text && !inside_comment(body, pos) {
            return true;
        }
        start = pos + 1;
    }
    false
}

/// `true` if `needle` appears as a whole token — not directly adjacent to an
/// alphanumeric char or `_`/`-` on either side.
/// Prevents `49` matching inside `col-49`, `149`, `id_49px`, etc.
fn whole_word(body: &str, needle: &str) -> bool {
    let bytes = body.as_bytes();
    let nlen  = needle.len();
    let mut start = 0;
    while let Some(rel) = body[start..].find(needle) {
        let pos = start + rel;
        let left_ok = pos == 0 || {
            let b = bytes[pos - 1];
            !b.is_ascii_alphanumeric() && b != b'_' && b != b'-'
        };
        let right_ok = pos + nlen >= bytes.len() || {
            let b = bytes[pos + nlen];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        if left_ok && right_ok {
            return true;
        }
        start = pos + 1;
    }
    false
}

// ── Payload reflection detection ──────────────────────────────────────────────

/// Extract the actual redirect target domain from an OpenRedirect payload
/// (already lowercased).  Handles protocol prefixes, `//`, `\\/`, user@host
/// tricks, and common percent-encoded slashes.
fn redirect_target_domain(payload_lc: &str) -> Option<String> {
    // Decode common %-encoded slashes so path normalisation works.
    let decoded = payload_lc
        .replace("%2f%2f", "//")
        .replace("%2f", "/");
    let s = decoded.as_str()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("//")
        .trim_start_matches("/\\")
        .trim_start_matches("\\/")
        .trim_start_matches('/');
    // Handle user@host tricks (`https://trusted.com@evil.com`):
    // the actual host is the last `@`-segment.
    let host_part = s.rsplit('@').next().unwrap_or(s);
    let domain = host_part
        .split(&['/', '?', '#', ' ', '\t', '\r', '\n'][..])
        .next()?;
    // Must look like a real hostname (contains a dot) or be localhost/IP.
    if domain.len() > 3 && (domain.contains('.') || domain == "localhost") {
        Some(domain.to_string())
    } else {
        None
    }
}

pub fn check_reflected(category: &str, payload: &str, response: &[u8]) -> Option<String> {
    let resp = String::from_utf8_lossy(response);

    let (headers, body) = if let Some(p) = resp.find("\r\n\r\n") {
        (&resp[..p], &resp[p + 4..])
    } else if let Some(p) = resp.find("\n\n") {
        (&resp[..p], &resp[p + 2..])
    } else {
        (resp.as_ref(), resp.as_ref())
    };

    let body_lc    = body.to_ascii_lowercase();
    let payload_lc = payload.to_ascii_lowercase();

    match category {
        // ── XSS ──────────────────────────────────────────────────────────────
        // The payload must appear literally (unescaped) and NOT only inside
        // HTML comments where it cannot execute.
        "XSS" => {
            let mut start = 0;
            while let Some(rel) = body_lc[start..].find(&payload_lc) {
                let abs = start + rel;
                if !inside_comment(&body_lc, abs) {
                    return Some(snippet(body, payload));
                }
                start = abs + 1;
            }
            None
        }

        // ── SQLi ─────────────────────────────────────────────────────────────
        // Specific DB error strings are reliable on their own.
        // Generic markers ("syntax error") require text-content placement to
        // exclude JS-comment false positives like `// syntax error in ...`.
        "SQLi" => {
            const SPECIFIC: &[&str] = &[
                "you have an error in your sql syntax",
                "warning: mysql",
                "ora-01",
                "pg_query()",
                "sqlite3.operationalerror",
                "unclosed quotation mark",
                "quoted string not properly terminated",
                "supplied argument is not a valid mysql",
                "sql command not properly ended",
                "mysql_fetch_array",
                "mysql_num_rows",
                "odbc microsoft",
                "microsoft ole db provider for sql server",
            ];
            for m in SPECIFIC {
                if body_lc.contains(m) {
                    return Some(snippet_lc(body, m));
                }
            }
            // "syntax error" / "invalid query" are generic — only trust them in
            // visible text content, not inside JS/CSS/HTML comments.
            for m in &["syntax error", "invalid query"] {
                if in_text_content(&body_lc, m) {
                    return Some(snippet_lc(body, m));
                }
            }
            None
        }

        // ── CMDi ─────────────────────────────────────────────────────────────
        // Command output lands in visible text. Require text-content placement
        // for markers that could appear in documentation or source comments.
        "CMDi" => {
            // Very specific markers: trust anywhere in body.
            const SPECIFIC: &[&str] = &[
                "root:x:0:0",
                "uid=0(root)",
                "daemon:x:",
                "www-data:x:",
                "nobody:x:",
            ];
            for m in SPECIFIC {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }
            // Ambiguous markers: require visible text content.
            for m in &["/bin/bash", "/bin/sh", "/etc/passwd"] {
                if in_text_content(body, m) {
                    return Some(snippet(body, m));
                }
            }
            None
        }

        // ── PathTraversal ─────────────────────────────────────────────────────
        // /etc/passwd content or win.ini sections must appear as visible text.
        "PathTraversal" => {
            const SPECIFIC: &[&str] = &[
                "root:x:0:0",
                "[boot loader]",
                "for 16-bit app support",
                "[fonts]",
            ];
            for m in SPECIFIC {
                if in_text_content(body, m) || in_text_content(&body_lc, &m.to_ascii_lowercase()) {
                    return Some(snippet_lc(body, &m.to_ascii_lowercase()));
                }
            }
            // "extension=" appears in php.ini — only meaningful in text context.
            if in_text_content(&body_lc, "extension=") {
                return Some(snippet_lc(body, "extension="));
            }
            // Windows path markers
            for m in &["windows\\system32", "\\windows\\win.ini"] {
                if body_lc.contains(m) {
                    return Some(snippet_lc(body, m));
                }
            }
            None
        }

        // ── SSTI ─────────────────────────────────────────────────────────────
        // Math-based probes (7*7 → 49): require the template expression was
        // actually consumed (not echoed verbatim) AND the result appears as a
        // standalone number in HTML text content (not in a CSS class, attribute
        // value, or any other non-output location).
        "SSTI" => {
            if payload.contains("7*7") {
                // If the raw expression appears verbatim in the body, the engine
                // did NOT evaluate it — it's just reflected input, not SSTI.
                if body.contains(payload) {
                    return None;
                }
                // "49" must be a whole word AND in HTML text content.
                if whole_word(body, "49") && in_text_content(body, "49") {
                    return Some(snippet(body, "49"));
                }
                return None;
            }
            // Template engine diagnostic markers.
            const MARKERS: &[&str] = &["jinja2", "twig", "freemarker", "velocity"];
            for m in MARKERS {
                if body_lc.contains(m) {
                    return Some(snippet_lc(body, m));
                }
            }
            None
        }

        // ── OpenRedirect ──────────────────────────────────────────────────────
        // Checking only "is there a redirect + Location?" produces massive false
        // positives (login redirects, CSRF bounces, etc.).  We require the
        // Location header to actually reflect the domain we injected, proving
        // the server used our payload as the redirect target.
        "OpenRedirect" => {
            let first_line = resp.lines().next().unwrap_or("");
            let is_redirect = ["301", "302", "303", "307", "308"]
                .iter()
                .any(|c| first_line.contains(c));
            if !is_redirect { return None; }

            if let Some(loc_line) = headers
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("location:"))
            {
                let colon = loc_line.find(':').unwrap_or(0);
                let location = loc_line[colon + 1..].trim();
                let loc_lc   = location.to_ascii_lowercase();
                let pay_lc   = payload.to_ascii_lowercase();

                // Extract the target domain from the injected payload so we can
                // verify the server actually used our URL, not its own internal one.
                let confirmed = if let Some(target) = redirect_target_domain(&pay_lc) {
                    loc_lc.contains(&target)
                } else {
                    // javascript:/data: payloads — check literal presence.
                    loc_lc.contains(&pay_lc)
                };

                if confirmed {
                    return Some(format!("Location: {location}"));
                }
            }
            None
        }

        // ── SSRF ─────────────────────────────────────────────────────────────
        // Internal addresses must appear in visible text (not in a JS config
        // comment or a help-page example). Highly specific strings bypass this.
        "SSRF" => {
            // Highly specific: AWS metadata endpoint — trust anywhere.
            if body_lc.contains("169.254.169.254") {
                return Some(snippet_lc(body, "169.254.169.254"));
            }
            if body_lc.contains("aws_secret") || body_lc.contains("metadata.google") {
                for m in &["aws_secret", "metadata.google"] {
                    if body_lc.contains(m) { return Some(snippet_lc(body, m)); }
                }
            }
            // Generic internal addresses: require visible text content so that
            // help pages mentioning "127.0.0.1" don't trigger false positives.
            for m in &["127.0.0.1", "localhost", "::1"] {
                if in_text_content(&body_lc, m) {
                    return Some(snippet_lc(body, m));
                }
            }
            None
        }

        // ── RCE ──────────────────────────────────────────────────────────────
        // Command output should appear in text content. Short markers like
        // "uid=" require whole-word matching to avoid matching CSS properties
        // or HTML attributes that happen to contain those substrings.
        "RCE" => {
            // Very specific: require whole word to avoid "build_uid=123" etc.
            for m in &["uid=", "gid="] {
                if whole_word(&body_lc, m) && in_text_content(&body_lc, m) {
                    return Some(snippet_lc(body, m));
                }
            }
            // Specific system strings — text content required.
            for m in &["root:x:0:0", "cmd.exe", "system32", "/bin/sh"] {
                if in_text_content(&body_lc, m) {
                    return Some(snippet_lc(body, m));
                }
            }
            // TTL patterns from ping output: whole word (avoids "ttl=640").
            for m in &["ttl=64", "ttl=128"] {
                if whole_word(&body_lc, m) {
                    return Some(snippet_lc(body, m));
                }
            }
            None
        }

        _ => {
            if body.contains(payload) {
                Some(snippet(body, payload))
            } else {
                None
            }
        }
    }
}

fn snippet(haystack: &str, needle: &str) -> String {
    let pos   = haystack.find(needle).unwrap_or(0);
    let start = pos.saturating_sub(35);
    let end   = (pos + needle.len() + 35).min(haystack.len());
    let s: String = haystack[start..end]
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect();
    format!("…{s}…")
}

fn snippet_lc(haystack: &str, needle_lc: &str) -> String {
    snippet(haystack, needle_lc)
}

// ── PDF generation ────────────────────────────────────────────────────────────

pub fn generate_pdf(
    target_url:    &str,
    crawled_count: usize,
    records:       &[AttackRecord],
) -> Result<Vec<u8>, String> {
    // Skip 404s and no-response entries from the log (still counted in cover stats).
    let display_records: Vec<&AttackRecord> = records
        .iter()
        .filter(|r| r.status_code != 404 && r.status_code != 0)
        .collect();
    let findings_count = display_records.iter().filter(|r| r.evidence.is_some()).count();

    let (doc, p0, l0) = PdfDocument::new(
        "Rustman Security Report",
        Mm(210.0),
        Mm(297.0),
        "main",
    );

    let font      = doc.add_builtin_font(BuiltinFont::Helvetica)
                       .map_err(|e| e.to_string())?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)
                       .map_err(|e| e.to_string())?;

    // ── Cover page ────────────────────────────────────────────────────────────
    {
        let layer = doc.get_page(p0).get_layer(l0);

        layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 0.63, 0.24, None)));
        layer.use_text("RUSTMAN — Security Scan Report", 20.0_f32, Mm(20.0), Mm(270.0), &font_bold);
        layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (y, mo, d, h, mi) = unix_to_date(now);
        let date_str = format!("{y}-{mo:02}-{d:02}  {h:02}:{mi:02} UTC");

        layer.use_text(format!("Generated       : {date_str}"),          10.0_f32, Mm(20.0), Mm(258.0), &font);
        layer.use_text(format!("Target          : {target_url}"),         10.0_f32, Mm(20.0), Mm(251.0), &font);
        layer.use_text(format!("URLs crawled    : {crawled_count}"),       10.0_f32, Mm(20.0), Mm(244.0), &font);
        layer.use_text(format!("Attacks sent    : {}", records.len()),    10.0_f32, Mm(20.0), Mm(237.0), &font);

        let finding_color = if findings_count > 0 {
            Color::Rgb(Rgb::new(0.9, 0.3, 0.2, None))
        } else {
            Color::Rgb(Rgb::new(0.3, 0.7, 0.3, None))
        };
        layer.set_fill_color(finding_color);
        layer.use_text(
            format!("Confirmed findings : {findings_count}"),
            10.0_f32, Mm(20.0), Mm(230.0), &font_bold,
        );
        layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        // Separator
        let line = Line {
            points: vec![
                (Point::new(Mm(20.0), Mm(224.0)), false),
                (Point::new(Mm(190.0), Mm(224.0)), false),
            ],
            is_closed: false,
        };
        layer.set_outline_color(Color::Rgb(Rgb::new(0.6, 0.6, 0.6, None)));
        layer.add_line(line);
        layer.set_outline_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        if display_records.is_empty() {
            layer.set_fill_color(Color::Rgb(Rgb::new(0.3, 0.7, 0.3, None)));
            layer.use_text("No attacks recorded.", 12.0_f32, Mm(20.0), Mm(212.0), &font_bold);
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            return save_doc(doc).map_err(|e| e.to_string());
        }
    }

    // ── Attack log pages ──────────────────────────────────────────────────────
    let mut cur_page  = p0;
    let mut cur_layer = l0;
    let mut y: f32    = 218.0;

    macro_rules! new_page {
        () => {{
            let (np, nl) = doc.add_page(Mm(210.0), Mm(297.0), "main");
            cur_page  = np;
            cur_layer = nl;
            y = 277.0;
        }};
    }

    macro_rules! layer {
        () => { doc.get_page(cur_page).get_layer(cur_layer) };
    }

    // Section header
    layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    layer!().use_text("ATTACK LOG", 13.0_f32, Mm(20.0), Mm(y), &font_bold);
    y -= 10.0;

    let mut last_cat = String::new();

    for (n, r) in display_records.into_iter().enumerate() {
        // Estimate height: category header + url + payload + http + evidence(opt) + sep
        let has_ev   = r.evidence.is_some();
        let cat_h    = if r.category != last_cat { 8.0_f32 } else { 0.0_f32 };
        // For confirmed findings: evidence + "Request:" label + up to 8 request lines.
        let ev_h     = if has_ev { 5.0 + 4.5 + 8.0 * 4.0 } else { 0.0_f32 };
        let need     = cat_h + 5.5 + 5.0 + 5.0 + ev_h + 5.0;

        if y < need + 18.0 {
            new_page!();
            last_cat.clear();
        }

        // Category header when it changes
        if r.category != last_cat {
            last_cat = r.category.clone();
            let color = category_color(&r.category);
            layer!().set_fill_color(color);
            layer!().use_text(
                format!("[{}]", r.category),
                11.0_f32, Mm(20.0), Mm(y), &font_bold,
            );
            layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            y -= 7.0;
        }

        // Finding number — red if vuln, grey otherwise
        let num_color = if has_ev {
            Color::Rgb(Rgb::new(0.9, 0.2, 0.2, None))
        } else {
            Color::Rgb(Rgb::new(0.5, 0.5, 0.5, None))
        };
        layer!().set_fill_color(num_color);
        layer!().use_text(
            format!("#{}", n + 1),
            8.0_f32, Mm(22.0), Mm(y), &font_bold,
        );
        layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        y -= 5.5;

        // URL
        let url_s = trunc(&r.url, 88);
        layer!().use_text(
            format!("URL     : {url_s}"),
            8.0_f32, Mm(24.0), Mm(y), &font,
        );
        y -= 4.8;

        // Payload
        let pl = trunc(&r.payload, 80);
        layer!().use_text(
            format!("Payload : {pl}"),
            8.0_f32, Mm(24.0), Mm(y), &font,
        );
        y -= 4.8;

        // HTTP status code — colored
        let (http_r, http_g, http_b) = http_color(r.status_code, has_ev);
        layer!().set_fill_color(Color::Rgb(Rgb::new(http_r, http_g, http_b, None)));
        let status_label = format!(
            "HTTP    : {}  {}",
            r.status_code,
            status_reason(r.status_code)
        );
        layer!().use_text(status_label, 8.0_f32, Mm(24.0), Mm(y), &font_bold);
        layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        y -= 4.8;

        // Evidence + full request (only for confirmed findings)
        if let Some(ref ev) = r.evidence {
            let ev_clean: String = ev.chars().filter(|c| c.is_ascii() && !c.is_control()).collect();
            let ev_s = trunc(&ev_clean, 85);
            layer!().set_fill_color(Color::Rgb(Rgb::new(0.9, 0.2, 0.2, None)));
            layer!().use_text(
                format!("Evidence: {ev_s}"),
                7.5_f32, Mm(24.0), Mm(y), &font_bold,
            );
            layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            y -= 4.8;
            // Show the full HTTP request sent for this finding.
            layer!().set_fill_color(Color::Rgb(Rgb::new(0.4, 0.5, 0.75, None)));
            layer!().use_text("Request :", 7.5_f32, Mm(24.0), Mm(y), &font_bold);
            layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            y -= 4.5;
            for line in r.raw_request.lines().take(8) {
                let clean: String = line.chars().filter(|c| c.is_ascii() && !c.is_control()).collect();
                if clean.is_empty() { break; }
                if y < 14.0 { new_page!(); }
                layer!().set_fill_color(Color::Rgb(Rgb::new(0.5, 0.6, 0.8, None)));
                layer!().use_text(
                    format!("  {}", trunc(&clean, 82)),
                    6.5_f32, Mm(24.0), Mm(y), &font,
                );
                layer!().set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
                y -= 4.0;
            }
        }

        // Thin separator
        let sep_color = if has_ev {
            Color::Rgb(Rgb::new(0.7, 0.3, 0.3, None))
        } else {
            Color::Rgb(Rgb::new(0.88, 0.88, 0.88, None))
        };
        let line = Line {
            points: vec![
                (Point::new(Mm(22.0), Mm(y + 1.0)), false),
                (Point::new(Mm(188.0), Mm(y + 1.0)), false),
            ],
            is_closed: false,
        };
        layer!().set_outline_color(sep_color);
        layer!().add_line(line);
        layer!().set_outline_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        y -= 3.5;
    }

    save_doc(doc).map_err(|e| e.to_string())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn http_color(code: u16, is_finding: bool) -> (f32, f32, f32) {
    if is_finding {
        return (0.9, 0.2, 0.2); // bright red for confirmed vulns
    }
    match code {
        200..=299 => (0.2, 0.7, 0.3), // green — target responded normally
        300..=399 => (0.2, 0.6, 0.9), // blue — redirect
        400..=499 => (0.9, 0.65, 0.1), // orange — client error
        500..=599 => (0.8, 0.3, 0.1), // red-orange — server error (interesting)
        _ => (0.5, 0.5, 0.5),
    }
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn trunc(s: &str, max: usize) -> String {
    let s: String = s.chars().filter(|c| c.is_ascii() && !c.is_control()).collect();
    if s.len() <= max {
        s
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn category_color(cat: &str) -> Color {
    match cat {
        "XSS"           => Color::Rgb(Rgb::new(0.9,  0.75, 0.0,  None)),
        "SQLi"          => Color::Rgb(Rgb::new(1.0,  0.3,  0.1,  None)),
        "CMDi"          => Color::Rgb(Rgb::new(0.85, 0.1,  0.1,  None)),
        "RCE"           => Color::Rgb(Rgb::new(0.85, 0.1,  0.1,  None)),
        "PathTraversal" => Color::Rgb(Rgb::new(0.2,  0.65, 1.0,  None)),
        "SSRF"          => Color::Rgb(Rgb::new(0.1,  0.8,  0.55, None)),
        "SSTI"          => Color::Rgb(Rgb::new(0.75, 0.2,  1.0,  None)),
        "OpenRedirect"  => Color::Rgb(Rgb::new(1.0,  0.5,  0.7,  None)),
        _               => Color::Rgb(Rgb::new(0.5,  0.5,  0.5,  None)),
    }
}

fn save_doc(doc: PdfDocumentReference) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    doc.save(&mut BufWriter::new(&mut bytes))
       .map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn unix_to_date(ts: u64) -> (u64, u64, u64, u64, u64) {
    let min  = (ts / 60) % 60;
    let hour = (ts / 3600) % 24;
    let days = ts / 86400;

    let (year, day_of_year) = days_to_year(days);
    let (month, day) = day_of_year_to_month_day(day_of_year, is_leap(year));
    (year, month, day, hour, min)
}

fn days_to_year(mut days: u64) -> (u64, u64) {
    let mut year = 1970u64;
    loop {
        let ydays = if is_leap(year) { 366 } else { 365 };
        if days < ydays { break; }
        days -= ydays;
        year += 1;
    }
    (year, days)
}

fn day_of_year_to_month_day(mut d: u64, leap: bool) -> (u64, u64) {
    let months = if leap {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for (i, &mlen) in months.iter().enumerate() {
        if d < mlen { return (i as u64 + 1, d + 1); }
        d -= mlen;
    }
    (12, 31)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
