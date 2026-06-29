use crate::openapi::{ApiEndpoint, ParamLoc, ScanResult};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

// ── CLI argument parsing ───────────────────────────────────────────────────────

pub enum OutputFormat {
    Markdown,
    Json,
}

pub struct CliArgs {
    pub openapi_file: String,
    pub target: Option<String>,
    pub payload_dir: String,
    pub output: Option<String>,
    pub format: OutputFormat,
    pub fail_on_vuln: bool,
    pub concurrency: usize,
    pub bearer: Option<String>,
    pub cookie: Option<String>,
    pub api_key_header: Option<String>,
    pub api_key_value: Option<String>,
}

/// Returns `Some(CliArgs)` when the binary is invoked with `--scan`, `None` to
/// fall through to GUI mode.
pub fn parse_args() -> Option<CliArgs> {
    let args: Vec<String> = std::env::args().collect();

    // Trigger CLI mode with --scan or --openapi <file>
    let scan_mode = args.iter().any(|a| a == "--scan" || a == "--openapi");
    if !scan_mode {
        return None;
    }

    let get = |flag: &str| -> Option<String> {
        args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
    };
    let has = |flag: &str| args.iter().any(|a| a == flag);

    let openapi_file = get("--openapi").unwrap_or_else(|| {
        eprintln!("error: --openapi <file> is required");
        std::process::exit(2);
    });

    let output = get("--output");

    // --format overrides; otherwise infer from output file extension.
    let format = match get("--format").as_deref() {
        Some("json") => OutputFormat::Json,
        Some("markdown") => OutputFormat::Markdown,
        _ => match output
            .as_deref()
            .and_then(|p| std::path::Path::new(p).extension())
            .and_then(|e| e.to_str())
        {
            Some("json") => OutputFormat::Json,
            _ => OutputFormat::Markdown,
        },
    };

    let payload_dir = get("--payload-dir").unwrap_or_else(|| {
        // Same resolution logic as the GUI: cwd/payload, then exe-dir/payload.
        let from_cwd = std::env::current_dir().ok().map(|d| d.join("payload"));
        let from_exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("payload")));
        from_cwd
            .iter()
            .chain(from_exe.iter())
            .find(|p| p.exists())
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_else(|| "payload".to_string())
    });

    let concurrency = get("--concurrency")
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    Some(CliArgs {
        openapi_file,
        target: get("--target"),
        payload_dir,
        output,
        format,
        fail_on_vuln: has("--fail-on-vuln"),
        concurrency,
        bearer: get("--bearer"),
        cookie: get("--cookie"),
        api_key_header: get("--api-key-header"),
        api_key_value: get("--api-key-value"),
    })
}

pub fn print_usage() {
    eprintln!("Usage: rustman --scan --openapi <spec.(json|yaml)> --target <url> [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --openapi <file>          OpenAPI / Swagger spec (JSON or YAML)  [required]");
    eprintln!("  --target <url>            Target base URL (overrides spec servers[0])");
    eprintln!(
        "  --payload-dir <dir>       Directory containing payload JSON files  [default: ./payload]"
    );
    eprintln!("  --format <markdown|json>  Output format  [default: markdown]");
    eprintln!("  --output <file>           Write report to file instead of stdout");
    eprintln!("  --fail-on-vuln            Exit 1 when vulnerabilities are confirmed");
    eprintln!("  --concurrency <n>         Parallel endpoint scans  [default: 8]");
    eprintln!("  --bearer <token>          Bearer token for Authorization header");
    eprintln!("  --cookie <value>          Cookie header value");
    eprintln!("  --api-key-header <name>   Custom API key header name");
    eprintln!("  --api-key-value <value>   Custom API key header value");
    eprintln!();
    eprintln!("Exit codes:");
    eprintln!("  0  Clean scan (no vulnerabilities)");
    eprintln!("  1  Vulnerabilities found (only with --fail-on-vuln)");
    eprintln!("  2  Usage / configuration error");
    eprintln!("  3  Scan error (connection refused, invalid spec, …)");
}

// ── Headless scan ─────────────────────────────────────────────────────────────

pub async fn run(args: CliArgs) -> i32 {
    // ── Parse spec ─────────────────────────────────────────────────────────────
    let spec_text = match std::fs::read_to_string(&args.openapi_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", args.openapi_file);
            return 3;
        }
    };

    let parsed = match crate::openapi::parse(&spec_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 3;
        }
    };

    // Resolve target: CLI flag > spec servers[0] > error
    let target = args.target.or(parsed.server_url).unwrap_or_else(|| {
        eprintln!("error: no --target provided and spec has no servers[0]");
        std::process::exit(2);
    });

    let creds = {
        let mut c = parsed.credentials.unwrap_or_default();
        if let Some(b) = args.bearer {
            c.bearer = Some(b);
        }
        if let Some(k) = args.cookie {
            c.cookie = Some(k);
        }
        if let Some(h) = args.api_key_header {
            c.api_key_header = Some(h);
        }
        if let Some(v) = args.api_key_value {
            c.api_key_value = Some(v);
        }
        c
    };

    let endpoints = parsed.endpoints;

    // ── Load payloads ──────────────────────────────────────────────────────────
    let payloads = crate::openapi::load_payloads(&args.payload_dir);
    if payloads.is_empty() {
        eprintln!(
            "error: no payload JSON files found in '{}'",
            args.payload_dir
        );
        return 3;
    }

    let total_payloads: usize = payloads.iter().map(|(_, p)| p.len()).sum();
    let total_requests: usize = endpoints
        .iter()
        .map(|ep| {
            let n = ep.body_fields.len() + ep.query_params.len() + ep.path_params.len();
            let n = if n == 0 { 1 } else { n };
            n * total_payloads
        })
        .sum();

    eprintln!("[rustman] target        : {target}");
    eprintln!("[rustman] spec          : {}", args.openapi_file);
    eprintln!("[rustman] endpoints     : {}", endpoints.len());
    eprintln!("[rustman] payload cats  : {}", payloads.len());
    eprintln!("[rustman] max requests  : {total_requests}");
    eprintln!("[rustman] concurrency   : {}", args.concurrency);
    eprintln!("[rustman] scanning…");

    // ── Resolve host/port/tls from target URL ──────────────────────────────────
    let Some(parts) = crate::crawler::parse_url(&target) else {
        eprintln!("error: cannot parse target URL '{target}'");
        return 3;
    };

    let payloads = Arc::new(payloads);
    let stop = Arc::new(AtomicBool::new(false));
    let sem = Arc::new(tokio::sync::Semaphore::new(args.concurrency));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ScanResult>(4096);

    // Spawn one task per endpoint (same pattern as the GUI scan).
    let mut handles = Vec::new();
    for (ep_idx, ep) in endpoints.iter().cloned().enumerate() {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let permit = sem.clone().acquire_owned().await.unwrap();
        let tx2 = tx.clone();
        let creds2 = creds.clone();
        let host2 = parts.host.clone();
        let stop2 = stop.clone();
        let payloads2 = payloads.clone();
        let port = parts.port;
        let tls = parts.tls;

        handles.push(tokio::spawn(async move {
            let _permit = permit;

            let mut params: Vec<(String, ParamLoc)> = ep.body_fields.iter()
                .map(|f| (f.clone(), ParamLoc::Body))
                .chain(ep.query_params.iter().map(|q| (q.clone(), ParamLoc::Query)))
                .chain(ep.path_params.iter().map(|p| (p.clone(), ParamLoc::Path)))
                .collect();
            if params.is_empty() {
                let fallback = if matches!(ep.method.to_uppercase().as_str(), "POST"|"PUT"|"PATCH") {
                    ("data".to_string(), ParamLoc::Body)
                } else {
                    ("id".to_string(), ParamLoc::Query)
                };
                params.push(fallback);
            }

            let total_ep_payloads: usize = params.len()
                * payloads2.as_ref().iter().map(|(_, p)| p.len()).sum::<usize>();
            let mut processed = 0usize;

            'ep_loop: for (param, loc) in &params {
                for (cat, plist) in payloads2.as_ref() {
                    if stop2.load(Ordering::Relaxed) { break 'ep_loop; }

                    let display_cat = crate::openapi::payload_cat_name(cat).to_string();

                    for payload in plist {
                        if stop2.load(Ordering::Relaxed) { break 'ep_loop; }
                        processed += 1;

                        let raw = ep.build_request_fuzzed(
                            &host2, port, tls,
                            creds2.cookie.as_deref().unwrap_or(""),
                            creds2.bearer.as_deref().unwrap_or(""),
                            creds2.api_key_header.as_deref().unwrap_or(""),
                            creds2.api_key_value.as_deref().unwrap_or(""),
                            param, loc, payload,
                        );
                        let raw_request = raw.clone();
                        let resp_bytes = crate::proxy::repeater_send(&host2, port, tls, raw).await;
                        let status: u16 = std::str::from_utf8(&resp_bytes)
                            .unwrap_or("")
                            .lines().next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);

                        let evidence = {
                            let ev = crate::rapport::check_reflected(
                                &display_cat, payload, &resp_bytes, None);
                            if crate::rapport::is_false_positive(&display_cat, status) {
                                None
                            } else {
                                ev
                            }
                        };

                        let vuln_confirmed = evidence.is_some();
                        let _ = tx2.send(ScanResult {
                            ep_idx,
                            param:    param.clone(),
                            loc:      loc.clone(),
                            category: display_cat.clone(),
                            payload:  payload.clone(),
                            status,
                            response:    resp_bytes,
                            evidence,
                            raw_request,
                        }).await;

                        if vuln_confirmed {
                            let remaining = total_ep_payloads - processed;
                            if remaining > 0 {
                                eprintln!("[rustman] [{ep_idx}] vuln confirmed — skipping {remaining} remaining payloads");
                            }
                            break 'ep_loop;
                        }
                    }
                }
            }
        }));
    }

    drop(tx); // close sender so receiver drains when all tasks finish

    // Collect results while tasks run.
    let mut results: Vec<ScanResult> = Vec::new();
    while let Some(r) = rx.recv().await {
        if r.evidence.is_some() {
            let ep = &endpoints[r.ep_idx];
            eprintln!(
                "[rustman] VULN {} {} param={} cat={}",
                ep.method, ep.path, r.param, r.category
            );
        }
        results.push(r);
    }

    for h in handles {
        let _ = h.await;
    }

    let vuln_count = results.iter().filter(|r| r.evidence.is_some()).count();
    eprintln!(
        "[rustman] scan complete — {} requests, {} vulnerabilities",
        results.len(),
        vuln_count
    );

    // ── Generate report ────────────────────────────────────────────────────────
    let report = match args.format {
        OutputFormat::Markdown => build_markdown(&target, &endpoints, &results),
        OutputFormat::Json => build_json(&target, &endpoints, &results),
    };

    match args.output {
        Some(ref path) => {
            if let Err(e) = std::fs::write(path, &report) {
                eprintln!("error: cannot write report to {path}: {e}");
                return 3;
            }
            eprintln!("[rustman] report written to {path}");
        }
        None => print!("{report}"),
    }

    if args.fail_on_vuln && vuln_count > 0 {
        1
    } else {
        0
    }
}

// ── Report builders ───────────────────────────────────────────────────────────

fn build_json(target: &str, endpoints: &[ApiEndpoint], results: &[ScanResult]) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let vulns: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| r.evidence.is_some())
        .map(|r| {
            let ep = &endpoints[r.ep_idx];
            serde_json::json!({
                "endpoint": format!("{} {}", ep.method, ep.path),
                "parameter": r.param,
                "location": match r.loc {
                    ParamLoc::Body  => "body",
                    ParamLoc::Query => "query",
                    ParamLoc::Path  => "path",
                },
                "category": r.category,
                "severity": category_severity(&r.category),
                "payload": r.payload,
                "http_status": r.status,
                "evidence": r.evidence,
                "remediation": category_remediation(&r.category),
            })
        })
        .collect();

    let report = serde_json::json!({
        "tool": "rustman",
        "scan_date_unix": ts,
        "target": target,
        "endpoints_scanned": endpoints.len(),
        "requests_sent": results.len(),
        "vulnerability_count": vulns.len(),
        "vulnerabilities": vulns,
    });

    serde_json::to_string_pretty(&report).unwrap_or_default()
}

fn category_remediation(cat: &str) -> &'static str {
    match cat {
        "CMDi" => "\
Ne jamais passer des entrées utilisateur directement à un interpréteur de commandes shell.\n\
- Utiliser des API natives du langage plutôt que `system()`, `exec()`, `popen()`.\n\
- Si une commande est inévitable, utiliser une liste d'arguments (pas une chaîne) et valider chaque argument contre une allowlist stricte.\n\
- Exécuter le processus avec les privilèges minimaux nécessaires (principe de moindre privilège).",

        "RCE" => "\
L'exécution de code arbitraire côté serveur représente une compromission totale.\n\
- Désérialiser uniquement des données fiables avec des types stricts et sans polymorphisme.\n\
- Mettre à jour immédiatement les dépendances vulnérables.\n\
- Appliquer une sandbox (seccomp, AppArmor) pour limiter les appels système disponibles.\n\
- Auditer les routes qui évaluent dynamiquement du code (`eval`, `exec`, réflexion Java).",

        "SQLi" => "\
Toujours utiliser des requêtes préparées (prepared statements) avec des paramètres liés.\n\
- Ne jamais construire des requêtes SQL par concaténation de chaînes.\n\
- Appliquer le principe de moindre privilège sur le compte de base de données.\n\
- Activer le mode strict de l'ORM si applicable.\n\
- Ne jamais exposer les messages d'erreur SQL à l'utilisateur final.",

        "PathTraversal" => "\
Valider et normaliser tout chemin de fichier avant utilisation.\n\
- Appeler `Path::canonicalize()` / `realpath()` puis vérifier que le chemin résultant commence par le répertoire autorisé.\n\
- Utiliser une allowlist d'extensions de fichiers acceptées.\n\
- Ne jamais construire un chemin à partir d'une entrée brute (`../`).\n\
- Isoler les fichiers sensibles hors de la racine web.",

        "XSS" => "\
Échapper toutes les données insérées dans du HTML, JavaScript, CSS ou des attributs.\n\
- Utiliser un moteur de template qui échappe par défaut (e.g. Jinja2 autoescape, React JSX).\n\
- Définir un Content-Security-Policy (CSP) restrictif (`default-src 'self'`).\n\
- Pour les APIs JSON, forcer `Content-Type: application/json` afin que les navigateurs n'interprètent pas la réponse comme HTML.\n\
- Valider et assainir les entrées utilisateur côté serveur.",

        "SSRF" => "\
Ne jamais effectuer de requêtes HTTP vers des URL fournies par l'utilisateur sans validation stricte.\n\
- Maintenir une allowlist d'hôtes et de ports autorisés.\n\
- Bloquer les plages d'adresses privées (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16) au niveau réseau et applicatif.\n\
- Résoudre le DNS après validation et vérifier que l'IP résolue est dans l'allowlist.\n\
- Désactiver les redirections HTTP automatiques ou les limiter à des domaines autorisés.",

        "SSTI" => "\
Ne jamais rendre des templates construits à partir d'entrées utilisateur.\n\
- Utiliser uniquement des templates statiques avec des variables injectées via le contexte.\n\
- Si du contenu dynamique est indispensable, utiliser un moteur sandbox sans accès aux objets système (`SandboxedEnvironment` en Jinja2).\n\
- Valider et rejeter toute entrée contenant des caractères de délimitation de template (`{{`, `{%`, `${`, `<%`).",

        "OpenRedirect" => "\
Ne jamais rediriger vers une URL fournie directement par l'utilisateur.\n\
- Utiliser des identifiants opaques (token, index) mappés côté serveur vers les URLs autorisées.\n\
- Si une URL est nécessaire, valider qu'elle appartient à la liste d'hôtes autorisés.\n\
- Ajouter un avertissement intermédiaire lorsqu'une redirection externe est inévitable.",

        "XXE" => "\
Désactiver le traitement des entités externes XML dans tous les parseurs utilisés.\n\
- En Java : `factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`.\n\
- En Python (lxml) : `resolve_entities=False`.\n\
- Préférer des formats de données sans DTD (JSON) lorsque XML n'est pas imposé.\n\
- Ne jamais accepter de DOCTYPE dans les documents XML fournis par l'utilisateur.",

        _ => "Valider et assainir toutes les entrées utilisateur. Appliquer le principe de moindre privilège.",
    }
}

fn build_markdown(target: &str, endpoints: &[ApiEndpoint], results: &[ScanResult]) -> String {
    use std::fmt::Write;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = unix_to_hms(ts);

    let vulns: Vec<&ScanResult> = results.iter().filter(|r| r.evidence.is_some()).collect();
    let vuln_count = vulns.len();

    let mut by_cat: std::collections::BTreeMap<&str, Vec<&ScanResult>> =
        std::collections::BTreeMap::new();
    for r in &vulns {
        by_cat.entry(r.category.as_str()).or_default().push(r);
    }

    let mut md = String::new();

    let _ = writeln!(md, "# Security Report — Rustman OpenAPI Scanner");
    let _ = writeln!(md);
    let _ = writeln!(md, "| Field | Value |");
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| **Target** | `{target}` |");
    let _ = writeln!(
        md,
        "| **Date** | {y}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC |"
    );
    let _ = writeln!(md, "| **Endpoints scanned** | {} |", endpoints.len());
    let _ = writeln!(md, "| **Requests sent** | {} |", results.len());
    let _ = writeln!(md, "| **Confirmed vulnerabilities** | **{vuln_count}** |");
    let _ = writeln!(md);

    let _ = writeln!(md, "## Vulnerability Summary");
    let _ = writeln!(md);
    if by_cat.is_empty() {
        let _ = writeln!(md, "> No confirmed vulnerabilities.");
    } else {
        let _ = writeln!(md, "| Category | Count | Severity |");
        let _ = writeln!(md, "|---|---|---|");
        for (cat, rs) in &by_cat {
            let _ = writeln!(
                md,
                "| **{cat}** | {} | {} |",
                rs.len(),
                category_severity(cat)
            );
        }
    }
    let _ = writeln!(md);

    if !by_cat.is_empty() {
        let _ = writeln!(md, "## Findings");
        let _ = writeln!(md);

        let mut idx = 1usize;
        for (cat, rs) in &by_cat {
            for r in rs {
                let ep = &endpoints[r.ep_idx];
                let loc_s = match r.loc {
                    ParamLoc::Body => "body",
                    ParamLoc::Query => "query param",
                    ParamLoc::Path => "path param",
                };
                let ev = r.evidence.as_deref().unwrap_or("—");
                let _ = writeln!(
                    md,
                    "### Finding #{idx} — {cat} ({})",
                    category_severity(cat)
                );
                let _ = writeln!(md);
                let _ = writeln!(md, "| Field | Value |");
                let _ = writeln!(md, "|---|---|");
                let _ = writeln!(md, "| **Endpoint** | `{} {}` |", ep.method, ep.path);
                let _ = writeln!(md, "| **Parameter** | `{}` ({loc_s}) |", r.param);
                let _ = writeln!(md, "| **Payload** | `{}` |", r.payload.replace('|', "\\|"));
                let _ = writeln!(md, "| **HTTP Status** | {} |", r.status);
                let _ = writeln!(md, "| **Evidence** | `{}` |", ev.replace('|', "\\|"));
                let _ = writeln!(md);
                if !r.raw_request.is_empty() {
                    let _ = writeln!(md, "#### Requête HTTP");
                    let _ = writeln!(md);
                    let _ = writeln!(md, "```http");
                    let _ = writeln!(md, "{}", String::from_utf8_lossy(&r.raw_request).trim_end());
                    let _ = writeln!(md, "```");
                    let _ = writeln!(md);
                }
                let _ = writeln!(md, "#### Remédiation");
                let _ = writeln!(md);
                let _ = writeln!(md, "{}", category_remediation(cat));
                let _ = writeln!(md);
                let _ = writeln!(md, "---");
                let _ = writeln!(md);
                idx += 1;
            }
        }
    }

    let _ = writeln!(md, "## Endpoints Scanned");
    let _ = writeln!(md);
    let _ = writeln!(md, "| Method | Path | Parameters | Vulnerabilities |");
    let _ = writeln!(md, "|---|---|---|---|");
    for (i, ep) in endpoints.iter().enumerate() {
        let params: Vec<String> = ep
            .body_fields
            .iter()
            .map(|f| format!("`{f}` (body)"))
            .chain(ep.query_params.iter().map(|q| format!("`{q}` (query)")))
            .chain(ep.path_params.iter().map(|p| format!("`{p}` (path)")))
            .collect();
        let params_s = if params.is_empty() {
            "—".into()
        } else {
            params.join(", ")
        };
        let ep_vulns: Vec<String> = results
            .iter()
            .filter(|r| r.ep_idx == i && r.evidence.is_some())
            .map(|r| format!("{} ({})", r.category, r.param))
            .collect();
        let vuln_s = if ep_vulns.is_empty() {
            "—".into()
        } else {
            ep_vulns.join(", ")
        };
        let _ = writeln!(
            md,
            "| **{}** | `{}` | {} | {} |",
            ep.method, ep.path, params_s, vuln_s
        );
    }

    let _ = writeln!(md);
    let _ = writeln!(md, "---");
    let _ = writeln!(md, "*Generated by **Rustman** — OpenAPI security scanner*");

    md
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn category_severity(cat: &str) -> &'static str {
    match cat {
        "CMDi" | "RCE" => "Critical",
        "SQLi" | "PathTraversal" => "High",
        "SSRF" | "SSTI" | "XXE" => "High",
        "XSS" => "Medium",
        "OpenRedirect" => "Low",
        _ => "Unknown",
    }
}

fn unix_to_hms(ts: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = ts % 60;
    let mi = (ts / 60) % 60;
    let h = (ts / 3600) % 24;
    let mut days = ts / 86400;
    let mut y = 1970u64;
    loop {
        let dy = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays: &[u64] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u64;
    for &md in mdays {
        if days < md {
            break;
        }
        days -= md;
        mo += 1;
    }
    (y, mo, days + 1, h, mi, s)
}
