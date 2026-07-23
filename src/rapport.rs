pub fn is_false_positive(category: &str, status_code: u16) -> bool {
    if status_code == 404 || status_code == 0 {
        return true;
    }
    status_code == 302
        && matches!(
            category,
            "XSS" | "SQLi" | "NoSQLi" | "CMDi" | "RCE" | "PathTraversal" | "SSTI"
        )
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

fn inside_script_or_style(s: &str, pos: usize) -> bool {
    let before_lc = s[..pos].to_ascii_lowercase();
    let script_pos = before_lc.rfind("<script");
    let style_pos = before_lc.rfind("<style");
    let (tag_name, open_pos) = match (script_pos, style_pos) {
        (Some(a), Some(b)) => {
            if a > b {
                ("script", a)
            } else {
                ("style", b)
            }
        }
        (Some(a), None) => ("script", a),
        (None, Some(b)) => ("style", b),
        (None, None) => return false,
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
            (Some(_), None) => true,
            _ => false,
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
    let nlen = needle.len();
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
    let decoded = payload_lc.replace("%2f%2f", "//").replace("%2f", "/");
    let s = decoded
        .as_str()
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
    let body_start = text
        .find("\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| text.find("\n\n").map(|p| p + 2))
        .unwrap_or(0);
    text[body_start..].to_ascii_lowercase().contains(needle)
}

// ── Extra detection helpers ───────────────────────────────────────────────────

/// Extract a snippet from `body` (original case) using the byte position
/// found by searching `body_lc` (lowercase body) for `needle_lc`.
/// This avoids case mismatches when the body was lowercased for matching.
fn evidence_at(body: &str, body_lc: &str, needle_lc: &str) -> String {
    let pos = body_lc.find(needle_lc).unwrap_or(0);
    let start = pos.saturating_sub(40);
    let end = (pos + needle_lc.len() + 40).min(body.len());
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
        let abs = pos + rel;
        let after = &body_lc[abs + 4..];
        let digs = after.bytes().take_while(|b| b.is_ascii_digit()).count();
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
pub fn check_reflected(
    category: &str,
    payload: &str,
    response: &[u8],
    baseline: Option<&[u8]>,
) -> Option<String> {
    let resp = String::from_utf8_lossy(response);

    let (headers, body) = if let Some(p) = resp.find("\r\n\r\n") {
        (&resp[..p], &resp[p + 4..])
    } else if let Some(p) = resp.find("\n\n") {
        (&resp[..p], &resp[p + 2..])
    } else {
        (resp.as_ref(), resp.as_ref())
    };

    let body_lc = body.to_ascii_lowercase();
    let payload_lc = payload.to_ascii_lowercase();

    // If the response shows SQL error markers the payload was reflected inside a SQL
    // query — only the SQLi detector should fire; all other categories would be false
    // positives (e.g. java.lang.Runtime in the echoed SQL ≠ RCE).
    const SQL_ERR: &[&str] = &[
        "sql logic error",
        "erreur: sql",
        "erreur db:",
        "sql error:",
        "you have an error in your sql syntax",
        "sqlite3.operationalerror",
        "postgresql error",
        "psql error",
        "sequelizedatabaseerror",
        "no such table",
        "no such column",
        "syntax error in sql",
        "requête: select",
        "requête: update",
        "requête: insert",
        "requête: delete",
        "sql command not properly ended",
        "unclosed quotation mark",
        "invalid sql statement",
        "ora-00",
        "microsoft ole db provider for sql server",
    ];
    let body_has_sql_error = SQL_ERR.iter().any(|m| body_lc.contains(m));

    match category {
        // ── XSS ──────────────────────────────────────────────────────────────
        // XSS is not meaningful for JSON APIs: the client must render the response
        // as HTML for the reflection to be exploitable. Never confirm on JSON/plain.
        "XSS" => {
            if baseline_has(baseline, &payload_lc) {
                return None;
            }

            let is_json_or_text = headers.lines().any(|l| {
                let lc = l.to_ascii_lowercase();
                lc.starts_with("content-type:")
                    && (lc.contains("application/json") || lc.contains("text/plain"))
            });
            // API response: skip — reflection in JSON ≠ exploitable XSS.
            if is_json_or_text {
                return None;
            }

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

        // ── NoSQLi ───────────────────────────────────────────────────────────
        // Injection NoSQL (MongoDB / Mongoose / CouchDB). Confirmée uniquement
        // par des messages d'erreur spécifiques au driver, qui n'apparaissent
        // que lorsque l'opérateur / la syntaxe injecté est réellement interprété
        // par la base. Ces chaînes sont très spécifiques et ne peuvent pas
        // provenir d'un simple reflet du payload.
        "NoSQLi" => {
            // Une erreur SQL classique signifie que l'entrée atteint un moteur
            // SQL et non NoSQL → ce serait un faux positif pour cette catégorie.
            if body_has_sql_error {
                return None;
            }
            const NOSQL_ERRORS: &[&str] = &[
                // MongoDB / driver Node
                "mongoservererror",
                "mongonetworkerror",
                "mongoparseerror",
                "mongoerror",
                "mongo error",
                "e11000 duplicate key",
                "unknown top level operator",
                "unknown operator:",
                "can't canonicalize query",
                "bsonerror",
                "bson error",
                "$where is not allowed",
                "$where must be",
                // Mongoose (ODM)
                "cast to objectid failed",
                "cast to number failed",
                "casterror",
                "strictmodeerror",
                "objectparametererror",
                // CouchDB / autres
                "query_parse_error",
                "no_usable_index",
                "unexpected end of json input while parsing",
            ];
            for m in NOSQL_ERRORS {
                // Garde de réflexion + baseline : le marqueur ne doit pas provenir
                // du payload renvoyé tel quel, ni préexister dans la réponse.
                if body_lc.contains(m) && !payload_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }
            None
        }

        // ── CMDi ─────────────────────────────────────────────────────────────
        // Detect actual command output: `id`, `whoami`, `cat /etc/passwd`,
        // `ls -la`, `uname -a`, `ping`, `echo`.
        "CMDi" => {
            if body_has_sql_error {
                return None;
            }

            // Build URL-encoded form of payload to catch reflections like
            // "open ; echo%20vulnerable: no such file or directory".
            let payload_urlenc = payload_lc.replace(' ', "%20").replace(';', "%3b");

            // If the payload itself (plain or URL-encoded) appears in the response
            // alongside a filesystem / network / parse error, it was used as *input*,
            // not executed as a shell command.
            let payload_in_body = body_lc.contains(&payload_lc)
                || body_lc.contains(&payload_urlenc)
                || body_lc.contains(&payload_lc.replace(' ', "+"));
            let is_input_error = body_lc.contains("no such file or directory")
                || body_lc.contains("unsupported protocol")
                || body_lc.contains("invalid url")
                || body_lc.contains("erreur fetch")
                || body_lc.contains("impossible de lire")
                || body_lc.contains("open ")   // Go os.Open error prefix
                || body_lc.contains("failed to open");
            if payload_in_body && is_input_error {
                return None;
            }

            // ── /etc/passwd content (from `cat /etc/passwd` payloads) ──
            for m in &[
                "root:x:0:0",
                "root:!:0:0",
                "daemon:x:1:1",
                "daemon:x:",
                "www-data:x:",
                "nobody:x:",
                "bin:x:1:1",
                "sys:x:2:2",
            ] {
                if body.contains(m) {
                    return Some(snippet(body, m));
                }
            }

            // ── `id` command output: uid=N(name) ──
            if has_id_cmd_output(&body_lc) && !baseline_has(baseline, "uid=") {
                return Some(evidence_at(body, &body_lc, "uid="));
            }

            // ── `ls -la` output: Unix permission strings ──
            for m in &[
                "drwxr-xr-x",
                "drwx------",
                "drwxrwxrwx",
                "-rw-r--r--",
                "-rwxr-xr-x",
                "-rwsr-xr-x",
            ] {
                if body.contains(m) && !baseline_has(baseline, m) {
                    return Some(snippet(body, m));
                }
            }

            // ── `uname -a` output ──
            for m in &[
                "#1 smp",
                "#2 smp",
                "x86_64 gnu/linux",
                "aarch64 gnu/linux",
                "x86_64 x86_64 x86_64",
            ] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── `ping -c 1 127.0.0.1` output ──
            for m in &[
                "bytes from 127.0.0.1",
                "icmp_seq=1 ttl=",
                "packets transmitted",
            ] {
                if body_lc.contains(m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── `echo vulnerable` payload ──
            // Only confirm if "vulnerable" appears WITHOUT the command string around it:
            // if "echo vulnerable" (or its encoded form) is present the payload was
            // reflected, not executed.
            if payload_lc.contains("echo vulnerable")
                && body_lc.contains("vulnerable")
                && !baseline_has(baseline, "vulnerable")
                && !body_lc.contains("echo vulnerable")
                && !body_lc.contains("echo%20vulnerable")
                && !body_lc.contains("%20echo%20vulnerable")
            {
                return Some(evidence_at(body, &body_lc, "vulnerable"));
            }

            // ── curl / wget exfil confirmed ──
            // Garde de réflexion : ne pas confirmer si le marqueur provient du
            // payload lui-même renvoyé tel quel (ex: `; cat /etc/passwd` réfléchi
            // dans une page HTML n'est PAS une exécution de commande).
            for m in &["/bin/bash", "/bin/sh", "/etc/passwd"] {
                if in_text_content(body, m) && !payload_lc.contains(m) {
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
            if body_has_sql_error {
                return None;
            }
            // ── /etc/passwd ──
            for m in &[
                "root:x:0:0",
                "root:!:0:0",
                "daemon:x:1:1",
                "daemon:x:",
                "nobody:x:",
                "www-data:x:",
                "bin:x:1:1",
            ] {
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
            if body_lc.contains("127.0.0.1")
                && body_lc.contains("localhost")
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
            for m in &[
                "[boot loader]",
                "for 16-bit app support",
                "[fonts]",
                "[extensions]",
                "[autorun]",
            ] {
                let m_lc = m.to_ascii_lowercase();
                if body_lc.contains(&m_lc) && !baseline_has(baseline, &m_lc) {
                    return Some(evidence_at(body, &body_lc, &m_lc));
                }
            }
            for m in &[
                "windows\\system32",
                "\\windows\\win.ini",
                "c:\\windows\\",
                "c:\\boot.ini",
            ] {
                // Garde de réflexion + baseline : un payload de traversée qui
                // contient déjà `windows\system32` ne doit pas se confirmer par
                // simple réflexion, ni si le marqueur préexiste dans la réponse.
                if body_lc.contains(m) && !payload_lc.contains(m) && !baseline_has(baseline, m) {
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
            if body_has_sql_error {
                return None;
            }
            // ── 7777*7777 = 60481729 (all engines except Jinja2 string-repeat) ──
            if payload.contains("7777*7777") {
                if body.contains(payload) {
                    return None;
                } // raw echo → not evaluated
                if body_lc.contains("60481729") {
                    return Some(evidence_at(body, &body_lc, "60481729"));
                }
                return None;
            }

            // ── {{7*'7'}} → Jinja2 renvoie "7777777" (spécifique, fiable) ──
            // NB : on NE teste PAS le "49" de Twig/PHP : le nombre 49 est bien
            // trop courant (valeurs CSS, coordonnées, IDs…) et provoque des faux
            // positifs sur toute grande page HTML. La sonde arithmétique
            // `7777*7777=60481729` (8 chiffres) couvre la détection sans ce risque.
            if payload_lc.contains("7*'7'") && body.contains("7777777") {
                return Some(snippet(body, "7777777"));
            }

            // ── Combined probe: {{7*'7'}}abc{{7777*7777}} ──
            if payload_lc.contains("7*'7'") && payload_lc.contains("7777*7777") {
                for m in &["60481729", "7777777"] {
                    if body.contains(m) {
                        return Some(snippet(body, m));
                    }
                }
            }

            // ── ${7777*7777} style (Freemarker, Spring EL, Groovy) ──
            if payload_lc.starts_with("${")
                || payload_lc.starts_with("#{")
                || payload_lc.starts_with("*{")
            {
                if body_lc.contains("60481729") {
                    return Some(evidence_at(body, &body_lc, "60481729"));
                }
            }

            // ── ERB / Slim: <%= 7777*7777 %> ──
            if payload_lc.contains("<%=") {
                if body_lc.contains("60481729") {
                    return Some(evidence_at(body, &body_lc, "60481729"));
                }
            }

            // ── `id` command output via RCE chains inside templates ──
            // Payloads: {{config...os.popen('id').read()}} etc.
            if payload_lc.contains("popen")
                || payload_lc.contains(".exec(")
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
            if payload_lc.contains("__class__")
                || payload_lc.contains("__subclasses__")
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
                    return Some(evidence_at(
                        body,
                        &body_lc,
                        if body_lc.contains("'debug':") {
                            "'debug':"
                        } else {
                            "\"debug\":"
                        },
                    ));
                }
            }

            // ── Template engine names in error messages ──
            for m in &[
                "jinja2",
                "jinja",
                "twig",
                "freemarker",
                "velocity",
                "pebble",
                "thymeleaf",
                "smarty",
                "mako template",
                "ruby template",
                "handlebars",
                "mustache",
                "template rendering error",
            ] {
                // Garde de réflexion : le nom du moteur ne doit pas provenir du
                // payload renvoyé tel quel (ex: un payload Freemarker réfléchi
                // dans une réponse JSON contient « freemarker » sans exécution).
                if body_lc.contains(m) && !payload_lc.contains(m) && !baseline_has(baseline, m) {
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
                .iter()
                .any(|c| first_line.contains(c));
            if is_redirect {
                if let Some(loc_line) = headers
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("location:"))
                {
                    let colon = loc_line.find(':').unwrap_or(0);
                    let location = loc_line[colon + 1..].trim();
                    let loc_lc = location.to_ascii_lowercase();

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
                let has_headers =
                    body_lc.contains("\"headers\":") || body_lc.contains("'headers':");
                let has_status = body_lc.contains("\"status\":") || body_lc.contains("'status':");
                let has_body = body_lc.contains("\"body\":") || body_lc.contains("'body':");
                if has_headers
                    && (has_status || has_body)
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
            if body_has_sql_error {
                return None;
            }

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
            if body_lc.contains("you know, for search")
                && !baseline_has(baseline, "you know, for search")
            {
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
                let has_headers_key =
                    body_lc.contains("\"headers\":") || body_lc.contains("'headers':");
                let has_status_key =
                    body_lc.contains("\"status\":") || body_lc.contains("'status':");
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
            if body_has_sql_error {
                return None;
            }

            let payload_urlenc = payload_lc.replace(' ', "%20").replace(';', "%3b");

            // If the payload appears in the response alongside an input/parse error,
            // it was used as data, not executed.
            let payload_in_body = body_lc.contains(&payload_lc)
                || body_lc.contains(&payload_urlenc)
                || body_lc.contains(&payload_lc.replace(' ', "+"));
            let is_input_error = body_lc.contains("no such file or directory")
                || body_lc.contains("unsupported protocol")
                || body_lc.contains("invalid url")
                || body_lc.contains("erreur fetch")
                || body_lc.contains("impossible de lire")
                || body_lc.contains("failed to open")
                || body_lc.contains("parse error")
                || body_lc.contains("cannot execute");
            if payload_in_body && is_input_error {
                return None;
            }

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
            for m in &[
                "nt authority\\system",
                "nt authority\\network service",
                "windows\\system32\\",
                "microsoft windows [version",
            ] {
                if body_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Java/Spring EL: only confirm if the marker is NOT in the payload
            // (java.lang.Runtime in the payload + reflected ≠ executed).
            for m in &[
                "java.lang.processbuilder",
                "java.lang.runtime",
                "java.io.ioexception",
            ] {
                if body_lc.contains(m) && !payload_lc.contains(m) && !baseline_has(baseline, m) {
                    return Some(evidence_at(body, &body_lc, m));
                }
            }

            // ── Shell error messages (command reached the shell but failed) ──
            // These can only come from actual shell execution, not from reflection.
            for m in &[
                "sh: 1:",
                "bash: command not found",
                "/bin/sh: 1:",
                "execve(",
                "permission denied",
            ] {
                if body_lc.contains(m) && !payload_lc.contains(m) && !baseline_has(baseline, m) {
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
    let pos = haystack.find(needle).unwrap_or(0);
    let start = pos.saturating_sub(35);
    let end = (pos + needle.len() + 35).min(haystack.len());
    let s: String = haystack[start..end]
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect();
    format!("…{s}…")
}
