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

/// Returns `true` when the HTTP status code alone makes a finding a false positive,
/// regardless of the response body.
///
/// Only two blanket rules apply here:
/// - **404 / 0** — endpoint does not exist or no response received.
/// - **302** for content-injection categories — almost always a login redirect;
///   OpenRedirect and SSRF are excluded because their detection IS redirect-based.
///
/// The former rule "200 → FP for CMDi/RCE/…" has been removed: a 200 OK response
/// that also contains `uid=0(root)` or `/etc/passwd` content IS a real finding.
/// Precision now comes from the specificity of the body markers in `check_reflected`.
pub fn is_false_positive(category: &str, status_code: u16) -> bool {
    if status_code == 404 || status_code == 0 {
        return true;
    }
    status_code == 302
        && matches!(category, "XSS" | "SQLi" | "CMDi" | "RCE" | "PathTraversal" | "SSTI")
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

/// `true` if `pos` is inside a `<script>` or `<style>` block.
/// Content inside those tags is JS/CSS source, not visible HTML text, so
/// markers like `/bin/bash` or `127.0.0.1` that appear there must not be
/// treated as evidence of a vulnerability.
fn inside_script_or_style(s: &str, pos: usize) -> bool {
    let before_lc = s[..pos].to_ascii_lowercase();
    let script_pos = before_lc.rfind("<script");
    let style_pos  = before_lc.rfind("<style");
    let (tag_name, open_pos) = match (script_pos, style_pos) {
        (Some(a), Some(b)) => if a > b { ("script", a) } else { ("style", b) },
        (Some(a), None)    => ("script", a),
        (None, Some(b))    => ("style",  b),
        (None, None)       => return false,
    };
    let close = format!("</{tag_name}");
    !before_lc[open_pos..].contains(&close)
}

/// `true` if `needle` appears at least once in HTML *text content*
/// (between a closing `>` and an opening `<`), outside any HTML comment,
/// and outside any `<script>` / `<style>` block.
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
        if in_text && !inside_comment(body, pos) && !inside_script_or_style(body, pos) {
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

/// Returns `true` when `needle` (lowercase) already appears in the body of
/// `baseline` — meaning it was there before our payload was injected.
fn baseline_has(baseline: Option<&[u8]>, needle: &str) -> bool {
    let Some(b) = baseline else { return false };
    let text = String::from_utf8_lossy(b);
    let body_start = text.find("\r\n\r\n").map(|p| p + 4)
        .or_else(|| text.find("\n\n").map(|p| p + 2))
        .unwrap_or(0);
    text[body_start..].to_ascii_lowercase().contains(needle)
}

// ── Extra detection helpers ───────────────────────────────────────────────────

/// Extract a snippet from `body` (original case) using the byte position
/// found by searching `body_lc` (lowercase body) for `needle_lc`.
/// This avoids case mismatches when the body was lowercased for matching.
fn evidence_at(body: &str, body_lc: &str, needle_lc: &str) -> String {
    let pos   = body_lc.find(needle_lc).unwrap_or(0);
    let start = pos.saturating_sub(40);
    let end   = (pos + needle_lc.len() + 40).min(body.len());
    let s: String = body[start..end]
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect();
    format!("…{s}…")
}

/// Returns `true` when `body_lc` (lowercased) contains the output of the Unix
/// `id` command, i.e. a pattern `uid=DIGITS(` (e.g. `uid=0(root)` or
/// `uid=33(www-data)`).  The parenthesis after the digit run makes this
/// extremely specific — it cannot match CSS properties or HTML attributes.
fn has_id_cmd_output(body_lc: &str) -> bool {
    let mut pos = 0;
    while let Some(rel) = body_lc[pos..].find("uid=") {
        let abs   = pos + rel;
        let after = &body_lc[abs + 4..];
        let digs  = after.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digs > 0 && after.as_bytes().get(digs) == Some(&b'(') {
            return true;
        }
        pos = abs + 1;
    }
    false
}

/// `baseline` is the raw HTTP response for the same endpoint *without* injection.
/// Any detection string that also appears in the baseline is a pre-existing
/// condition, not caused by the payload, and is silently filtered out.
pub fn check_reflected(category: &str, payload: &str, response: &[u8], baseline: Option<&[u8]>) -> Option<String> {
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

    // If the response shows SQL error markers the payload was reflected inside a SQL
    // query — only the SQLi detector should fire; all other categories would be false
    // positives (e.g. java.lang.Runtime in the echoed SQL ≠ RCE).
    const SQL_ERR: &[&str] = &[
        "sql logic error", "erreur: sql", "erreur db:", "sql error:",
        "you have an error in your sql syntax", "sqlite3.operationalerror",
        "postgresql error", "psql error", "sequelizedatabaseerror",
        "no such table", "no such column", "syntax error in sql",
        "requête: select", "requête: update", "requête: insert", "requête: delete",
        "sql command not properly ended", "unclosed quotation mark",
        "invalid sql statement", "ora-00", "microsoft ole db provider for sql server",
    ];
    let body_has_sql_error = SQL_ERR.iter().any(|m| body_lc.contains(m));

    match category {
        // ── XSS ──────────────────────────────────────────────────────────────
        // XSS is not meaningful for JSON APIs: the client must render the response
        // as HTML for the reflection to be exploitable. Never confirm on JSON/plain.
        "XSS" => {
            if baseline_has(baseline, &payload_lc) { return None; }

            let is_json_or_text = headers.lines().any(|l| {
                let lc = l.to_ascii_lowercase();
                lc.starts_with("content-type:")
                    && (lc.contains("application/json") || lc.contains("text/plain"))
            });
            // API response: skip — reflection in JSON ≠ exploitable XSS.
            if is_json_or_text { return None; }

            // HTML response: payload must appear in a renderable position.
            let can_break_out = payload_lc.contains("</script") || payload_lc.contains("</style");
            let mut start = 0;
            while let Some(rel) = body_lc[start..].find(&payload_lc) {
                let abs = start + rel;
                if !inside_comment(&body_lc, abs) {
                    if inside_script_or_style(&body_lc, abs) {
                        if can_break_out {
                            return Some(snippet(body, payload));
                        }
                    } else {
                        return Some(snippet(body, payload));
                    }
                }
                start = abs + 1;
            }
            None
        }

        // ── SQLi ─────────────────────────────────────────────────────────────
        // Match database-specific error strings that appear only when our quote /
        // comment / UNION injection is actually parsed by a SQL engine.
        // Covers MySQL, MariaDB, PostgreSQL, SQLite, MSSQL, Oracle, and ORMs.
        "SQLi" => {
            const DB_ERRORS: &[&str] = &[
                // MySQL / MariaDB
                "you have an error in your sql syntax",
                "warning: mysql",
                "mysql_fetch_array",
                "mysql_num_rows",
                "mysql_fetch_assoc",
                "mysql_fetch_object",
                "mysql_result",
                "supplied argument is not a valid mysql",
                "com.mysql.jdbc",
                // PostgreSQL
                "pg_query()",
                "pg_exec()",
                "postgresql error",
                "psql error",
                "error: syntax error at or near",
                "invalid input syntax for",
                "unterminated quoted string at or near",
                "operator does not exist",
                // SQLite
                "sqlite3.operationalerror",
                "sqlite_error",
                "[sqlite3]",
                "sqlite error",
                "sqlite3::query",
                "sql logic error",
                "no such table",
                "no such column",
                "unrecognized token",
                "near \".\": syntax error",
                // French / custom app error prefixes (app echoes the SQL error)
                "erreur: sql",
                "erreur db:",
                "erreur db :",
                "sql error:",
                // Query disclosure: app leaks the raw SQL in the error message
                "requête: select",
                "requête: insert",
                "requête: update",
                "requête: delete",
                // Microsoft SQL Server / MSSQL
                "unclosed quotation mark",
                "quoted string not properly terminated",
                "microsoft ole db provider for sql server",
                "odbc microsoft",
                "odbc sql server driver",
                "[sql server]",
                "sql server error",
                "microsoft sql native client error",
                "conversion failed when converting",
                // Oracle
                "ora-01",
                "ora-00933",
                "ora-00907",
                "ora-00942",
                "ora-01756",
                "sql command not properly ended",
                // Java / Hibernate / Sequelize
                "java.sql.sqlexception",
                "java.sql.sqlsyntaxerrorexception",
                "hibernate.exception",
                "sequelizedatabaseerror",
                "sequelize database error",
                // Error-based extraction (XPath trick)
                "xpath syntax error",
                // Generic
                "db error",
                "sql syntax",
                "syntax error in sql",
                "invalid sql statement",
                "error in your sql",
                "sql error",
                "database error",
            ];
            for m in DB_ERRORS {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }
            None
        }

        // ── CMDi ─────────────────────────────────────────────────────────────
        // Detect actual command output: `id`, `whoami`, `cat /etc/passwd`,
        // `ls -la`, `uname -a`, `ping`, `echo`.
        "CMDi" => {
            if body_has_sql_error { return None; }

            // Build URL-encoded form of payload to catch reflections like
            // "open ; echo%20vulnerable: no such file or directory".
            let payload_urlenc = payload_lc.replace(' ', "%20").replace(';', "%3b");

            // If the payload itself (plain or URL-encoded) appears in the response
            // alongside a filesystem / network / parse error, it was used as *input*,
            // not executed as a shell command.
            let payload_in_body = body_lc.contains(&payload_lc)
                || body_lc.contains(&payload_urlenc)
                || body_lc.contains(&payload_lc.replace(' ', "+"));
            let is_input_error =
                body_lc.contains("no such file or directory")
                || body_lc.contains("unsupported protocol")
                || body_lc.contains("invalid url")
                || body_lc.contains("erreur fetch")
                || body_lc.contains("impossible de lire")
                || body_lc.contains("open ")   // Go os.Open error prefix
                || body_lc.contains("failed to open");
            if payload_in_body && is_input_error { return None; }

            // ── /etc/passwd content (from `cat /etc/passwd` payloads) ──
            for m in &["root:x:0:0", "root:!:0:0", "daemon:x:1:1",
                       "daemon:x:", "www-data:x:", "nobody:x:",
                       "bin:x:1:1", "sys:x:2:2"] {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }

            // ── `id` command output: uid=N(name) ──
            if has_id_cmd_output(&body_lc) && !baseline_has(baseline, "uid=") {
                return Some(evidence_at(body, &body_lc, "uid="));
            }

            // ── `ls -la` output: Unix permission strings ──
            for m in &["drwxr-xr-x", "drwx------", "drwxrwxrwx",
                       "-rw-r--r--", "-rwxr-xr-x", "-rwsr-xr-x"] {
                if body.contains(m) && !baseline_has(baseline, m) {
                    return Some(snippet(body, m));
                }
            }

            // ── `uname -a` output ──
            for m in &["#1 smp", "#2 smp", "x86_64 gnu/linux", "aarch64 gnu/linux",
                       "x86_64 x86_64 x86_64"] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── `ping -c 1 127.0.0.1` output ──
            for m in &["bytes from 127.0.0.1", "icmp_seq=1 ttl=", "packets transmitted"] {
                if body_lc.contains(m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── `echo vulnerable` payload ──
            // Only confirm if "vulnerable" appears WITHOUT the command string around it:
            // if "echo vulnerable" (or its encoded form) is present the payload was
            // reflected, not executed.
            if payload_lc.contains("echo vulnerable") && body_lc.contains("vulnerable")
                && !baseline_has(baseline, "vulnerable")
                && !body_lc.contains("echo vulnerable")
                && !body_lc.contains("echo%20vulnerable")
                && !body_lc.contains("%20echo%20vulnerable")
            {
                return Some(evidence_at(body, &body_lc, "vulnerable"));
            }

            // ── curl / wget exfil confirmed ──
            for m in &["/bin/bash", "/bin/sh", "/etc/passwd"] {
                if in_text_content(body, m) {
                    return Some(snippet(body, m));
                }
            }

            None
        }

        // ── PathTraversal ─────────────────────────────────────────────────────
        // Detect file contents that can only appear when the server opened the
        // requested file: /etc/passwd, /etc/shadow, /etc/hosts, /proc/version,
        // Windows ini files, PHP ini, and web server logs.
        "PathTraversal" => {
            if body_has_sql_error { return None; }
            // ── /etc/passwd ──
            for m in &["root:x:0:0", "root:!:0:0", "daemon:x:1:1",
                       "daemon:x:", "nobody:x:", "www-data:x:", "bin:x:1:1"] {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }

            // ── /etc/shadow (hashed password lines) ──
            // Patterns: `root:$6$`, `root:$1$`, `root:*:`, `root:!:`
            for m in &["root:$6$", "root:$1$", "root:$2", "root:$5$"] {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }

            // ── /proc/version ──
            // "Linux version 5.4.0 (gcc …)"
            if body_lc.contains("linux version ") && body_lc.contains("(gcc") {
                return Some(evidence_at(body, &body_lc, "linux version "));
            }

            // ── /proc/self/environ ──
            // Environment variable dump contains HOME= or PATH= as null-separated entries
            for m in &["home=/", "path=/usr", "shell=/bin", "user=root", "logname="] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── /etc/hosts ──
            // Only flag when both IP and "localhost" appear together and it looks
            // like a hosts file (entries at start of line).
            if body_lc.contains("127.0.0.1") && body_lc.contains("localhost")
                && body_lc.contains("::1")
                && !baseline_has(baseline, "127.0.0.1")
            {
                return Some(evidence_at(body, &body_lc, "127.0.0.1"));
            }

            // ── Apache / Nginx access log ──
            // Log lines: `"GET /path HTTP/1.1"` — the quoted method+space is unique.
            for m in &["\"get /", "\"post /", "\"head /", "\"put /"] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Windows ini files ──
            for m in &["[boot loader]", "for 16-bit app support", "[fonts]",
                       "[extensions]", "[autorun]"] {
                let m_lc = m.to_ascii_lowercase();
                if body_lc.contains(&m_lc) && !baseline_has(baseline, &m_lc) {
                    return Some(evidence_at(body, &body_lc, &m_lc));
                }
            }
            for m in &["windows\\system32", "\\windows\\win.ini",
                       "c:\\windows\\", "c:\\boot.ini"] {
                if body_lc.contains(m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── PHP ini (php://filter) ──
            if in_text_content(&body_lc, "extension=") && !baseline_has(baseline, "extension=") {
                return Some(evidence_at(body, &body_lc, "extension="));
            }

            None
        }

        // ── SSTI ─────────────────────────────────────────────────────────────
        // Server-Side Template Injection is confirmed via:
        // 1. Arithmetic evaluation of injected math probes.
        // 2. Object/class dumps from Python introspection payloads.
        // 3. Command output from RCE chains inside templates.
        // 4. Template engine name in error messages.
        "SSTI" => {
            if body_has_sql_error { return None; }
            // ── 7777*7777 = 60493729 (all engines except Jinja2 string-repeat) ──
            if payload.contains("7777*7777") {
                if body.contains(payload) { return None; } // raw echo → not evaluated
                if body_lc.contains("60493729") {
                    return Some(evidence_at(body, &body_lc, "60493729"));
                }
                return None;
            }

            // ── {{7*'7'}} → Jinja2 returns "7777777", Twig returns "49" ──
            if payload_lc.contains("7*'7'") {
                if body.contains("7777777") {
                    return Some(snippet(body, "7777777"));
                }
                // Twig / PHP string multiply → 49
                if body.contains("49") && !body.contains(payload)
                    && !baseline_has(baseline, "49")
                    && whole_word(body, "49")
                {
                    return Some(snippet(body, "49"));
                }
            }

            // ── Combined probe: {{7*'7'}}abc{{7777*7777}} ──
            if payload_lc.contains("7*'7'") && payload_lc.contains("7777*7777") {
                for m in &["60493729", "7777777"] {
                    if body.contains(m) {
                        return Some(snippet(body, m));
                    }
                }
            }

            // ── ${7777*7777} style (Freemarker, Spring EL, Groovy) ──
            if payload_lc.starts_with("${") || payload_lc.starts_with("#{") || payload_lc.starts_with("*{") {
                if body_lc.contains("60493729") {
                    return Some(evidence_at(body, &body_lc, "60493729"));
                }
            }

            // ── ERB / Slim: <%= 7777*7777 %> ──
            if payload_lc.contains("<%=") {
                if body_lc.contains("60493729") {
                    return Some(evidence_at(body, &body_lc, "60493729"));
                }
            }

            // ── `id` command output via RCE chains inside templates ──
            // Payloads: {{config...os.popen('id').read()}} etc.
            if payload_lc.contains("popen") || payload_lc.contains(".exec(")
               || payload_lc.contains("shell=true")
            {
                if has_id_cmd_output(&body_lc) && !baseline_has(baseline, "uid=") {
                    return Some(evidence_at(body, &body_lc, "uid="));
                }
            }

            // ── /etc/passwd content via file-read chains ──
            for m in &["root:x:0:0", "daemon:x:"] {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }

            // ── Python introspection: {{''.__class__.__mro__}} etc. ──
            if payload_lc.contains("__class__") || payload_lc.contains("__subclasses__")
               || payload_lc.contains("__mro__")
            {
                if body_lc.contains("<class '") && !baseline_has(baseline, "<class '") {
                    return Some(evidence_at(body, &body_lc, "<class '"));
                }
            }

            // ── Flask/Jinja2 config object: {{config}} ──
            if payload_lc.trim() == "{{config}}" {
                if (body_lc.contains("'debug':") || body_lc.contains("\"debug\":"))
                    && !baseline_has(baseline, "debug")
                {
                    return Some(evidence_at(body, &body_lc,
                        if body_lc.contains("'debug':") { "'debug':" } else { "\"debug\":" }));
                }
            }

            // ── Template engine names in error messages ──
            for m in &["jinja2", "jinja", "twig", "freemarker", "velocity",
                       "pebble", "thymeleaf", "smarty", "mako template",
                       "ruby template", "handlebars", "mustache",
                       "template rendering error"] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            None
        }

        // ── OpenRedirect ──────────────────────────────────────────────────────
        // Two detection paths:
        // 1. Classic HTTP redirect (3xx + Location header with injected domain).
        // 2. Server-side fetch proxy: server fetches the injected URL and returns
        //    the response body + headers as JSON (200 OK but body contains the
        //    external site's response — open redirect via server proxy).
        "OpenRedirect" => {
            let pay_lc = payload.to_ascii_lowercase();

            // ── Path 1: classic HTTP redirect ─────────────────────────────────
            let first_line = resp.lines().next().unwrap_or("");
            let is_redirect = ["301", "302", "303", "307", "308"]
                .iter().any(|c| first_line.contains(c));
            if is_redirect {
                if let Some(loc_line) = headers
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("location:"))
                {
                    let colon    = loc_line.find(':').unwrap_or(0);
                    let location = loc_line[colon + 1..].trim();
                    let loc_lc   = location.to_ascii_lowercase();

                    let confirmed = if let Some(target) = redirect_target_domain(&pay_lc) {
                        loc_lc.contains(&target)
                    } else {
                        loc_lc.contains(&pay_lc)
                    };
                    if confirmed {
                        return Some(format!("Location: {location}"));
                    }
                }
            }

            // ── Path 2: server-side fetch proxy ──────────────────────────────
            // The server fetches the injected URL and returns the result as JSON
            // containing the external site's headers and body.
            // Signature: response body has "headers": {...} AND "status": N AND
            // "body": "..." all at the top level of the JSON, meaning the server
            // proxied our URL.
            if pay_lc.starts_with("http://") || pay_lc.starts_with("https://") {
                let has_headers = body_lc.contains("\"headers\":")
                    || body_lc.contains("'headers':");
                let has_status  = body_lc.contains("\"status\":")
                    || body_lc.contains("'status':");
                let has_body    = body_lc.contains("\"body\":")
                    || body_lc.contains("'body':");
                if has_headers && (has_status || has_body)
                    && !baseline_has(baseline, "\"headers\":")
                {
                    return Some(format!(
                        "Serveur proxy : contenu de {} renvoyé dans la réponse (headers/body/status visibles)",
                        payload
                    ));
                }
                // Unicode-escaped HTML echoed inside JSON body
                if body_lc.contains("\\u003c") && !baseline_has(baseline, "\\u003c") {
                    return Some(format!(
                        "Serveur proxy : HTML de {} encodé en unicode dans la réponse",
                        payload
                    ));
                }
            }

            None
        }

        // ── SSRF ─────────────────────────────────────────────────────────────
        // Detecting SSRF requires the server to echo back the fetched content.
        // We check for:
        // 1. Cloud metadata fields (AWS/GCP/Azure/Alibaba)
        // 2. Internal service banners (Redis, Elasticsearch, MongoDB, SSH)
        // 3. File content when the payload is file:///etc/passwd
        "SSRF" => {
            if body_has_sql_error { return None; }

            // ── Cloud provider metadata ──
            const CLOUD: &[&str] = &[
                // AWS
                "aws_secret_access_key",
                "aws_access_key_id",
                "x-aws-ec2-metadata-token",
                "ami-id",
                "instance-id",
                "security-credentials",
                "iam/security-credentials",
                // GCP
                "metadata.google.internal",
                "computemetadata/v1",
                "google-compute-engine",
                // Azure
                "metadata.azure.com",
                "azure_client_id",
                // Alibaba Cloud
                "100.100.100.200",
                // Generic metadata echoed in response
                "169.254.169.254",
            ];
            // Cloud marker must appear in the response but NOT come from the payload
            // itself (reflection). Real SSRF returns fetched *content*, not the URL.
            for m in CLOUD {
                if body_lc.contains(m) && !payload_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Redis banner (raw TCP via HTTP tunnel) ──
            for m in &["+pong\r\n", "-wrongtype", "-err wrong"] {
                if (body_lc.starts_with(m) || body_lc.contains(m)) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Elasticsearch ──
            if body_lc.contains("you know, for search") && !baseline_has(baseline, "you know, for search") {
                return Some(evidence_at(body, &body_lc, "you know, for search"));
            }

            // ── MongoDB ──
            if body_lc.contains("it looks like you are trying to access mongodb")
                && !baseline_has(baseline, "mongodb")
            {
                return Some(evidence_at(body, &body_lc, "mongodb"));
            }

            // ── SSH banner ──
            if body.starts_with("SSH-2.0") || body.starts_with("SSH-1.") {
                return Some(snippet(body, "SSH-"));
            }
            if body_lc.contains("openssh") && !baseline_has(baseline, "openssh") {
                return Some(evidence_at(body, &body_lc, "openssh"));
            }

            // ── MySQL banner (connection refused with auth error) ──
            if body_lc.contains("is not allowed to connect to this mysql server")
                && !baseline_has(baseline, "mysql server")
            {
                return Some(evidence_at(body, &body_lc, "mysql server"));
            }

            // ── file:///etc/passwd SSRF ──
            if payload_lc.contains("file:///etc/passwd") || payload_lc.contains("file:///etc") {
                for m in &["root:x:0:0", "daemon:x:", "nobody:x:"] {
                    if body.contains(m) {
                        return Some(snippet(body, m));
                    }
                }
            }

            // ── Internal service error: server attempted the connection (SSRF confirmed) ──
            // These strings cannot come from the payload URL, so no reflection check needed.
            for m in &[
                "connection refused",
                "connection reset by peer",
                "no route to host",
                "failed to connect",
                "could not connect to server",
                "cannot connect to",
                "network is unreachable",
            ] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Server proxied the URL and returned its content ──
            // Require evidence that actual HTTP response headers/body were forwarded,
            // not just that the URL string appears in a JSON field.
            if payload_lc.starts_with("http://") || payload_lc.starts_with("https://") {
                // Proxied JSON: contains both "headers" and "status" from the fetched response
                let has_headers_key = body_lc.contains("\"headers\":")
                    || body_lc.contains("'headers':");
                let has_status_key  = body_lc.contains("\"status\":")
                    || body_lc.contains("'status':");
                if has_headers_key && has_status_key && !baseline_has(baseline, "\"headers\":") {
                    return Some(evidence_at(body, &body_lc, "headers"));
                }

                // Server returned raw HTML fetched from the URL
                if body_lc.contains("\\u003c") && !baseline_has(baseline, "\\u003c") {
                    return Some(evidence_at(body, &body_lc, "\\u003c"));
                }
                for m in &["<html", "<!doctype html", "<body"] {
                    if body_lc.contains(m) && !baseline_has(baseline, m) {
                        return Some(evidence_at(body, &body_lc, m));
                    }
                }
            }

            None
        }

        // ── RCE ──────────────────────────────────────────────────────────────
        // Remote Code Execution is confirmed by actual command output in the
        // response: `id`, `/etc/passwd` content, shell error messages, etc.
        "RCE" => {
            if body_has_sql_error { return None; }

            let payload_urlenc = payload_lc.replace(' ', "%20").replace(';', "%3b");

            // If the payload appears in the response alongside an input/parse error,
            // it was used as data, not executed.
            let payload_in_body = body_lc.contains(&payload_lc)
                || body_lc.contains(&payload_urlenc)
                || body_lc.contains(&payload_lc.replace(' ', "+"));
            let is_input_error =
                body_lc.contains("no such file or directory")
                || body_lc.contains("unsupported protocol")
                || body_lc.contains("invalid url")
                || body_lc.contains("erreur fetch")
                || body_lc.contains("impossible de lire")
                || body_lc.contains("failed to open")
                || body_lc.contains("parse error")
                || body_lc.contains("cannot execute");
            if payload_in_body && is_input_error { return None; }

            // ── `id` command output ──
            if has_id_cmd_output(&body_lc) && !baseline_has(baseline, "uid=") {
                return Some(evidence_at(body, &body_lc, "uid="));
            }

            // ── /etc/passwd content ──
            for m in &["root:x:0:0", "daemon:x:", "www-data:x:"] {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }

            // ── Windows-specific RCE output ──
            for m in &["nt authority\\system", "nt authority\\network service",
                       "windows\\system32\\", "microsoft windows [version"] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Java/Spring EL: only confirm if the marker is NOT in the payload
            // (java.lang.Runtime in the payload + reflected ≠ executed).
            for m in &["java.lang.processbuilder", "java.lang.runtime",
                       "java.io.ioexception"] {
                if body_lc.contains(m) && !payload_lc.contains(m)
                    && !baseline_has(baseline, m)
                {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Shell error messages (command reached the shell but failed) ──
            // These can only come from actual shell execution, not from reflection.
            for m in &["sh: 1:", "bash: command not found", "/bin/sh: 1:",
                       "execve(", "permission denied"] {
                if body_lc.contains(m) && !payload_lc.contains(m)
                    && !baseline_has(baseline, m)
                {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── ping output: TTL confirmation ──
            for m in &["ttl=64 ", "ttl=128 "] {
                if whole_word(&body_lc, m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
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
