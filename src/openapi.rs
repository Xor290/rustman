use serde_json::Value;

// ── Types publics ─────────────────────────────────────────────────────────────

/// Emplacement du paramètre à fuzzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamLoc {
    Body,
    Query,
    Path,
}

/// Résultat d'un test de payload sur un paramètre.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ep_idx: usize,
    pub param: String,
    pub loc: ParamLoc,
    pub category: String,
    pub payload: String,
    pub status: u16,
    pub response: Vec<u8>,
    pub evidence: Option<String>,
    pub raw_request: Vec<u8>,
}

/// Messages envoyés par le background scan task vers le GUI.
pub enum ScanMsg {
    Result(ScanResult),
    TripleDone,
    Skipped(usize),
    Finished,
}

/// Convertit le nom de fichier payload (ex: "sqli") vers le nom de catégorie rapport.
pub fn payload_cat_name(stem: &str) -> &'static str {
    match stem {
        "sqli" => "SQLi",
        "nosql" => "NoSQLi",
        "xss" => "XSS",
        "cmdi" => "CMDi",
        "rce" => "RCE",
        "path_traversal" => "PathTraversal",
        "ssrf" => "SSRF",
        "ssti" => "SSTI",
        "open_redirect" => "OpenRedirect",
        "xxe" => "XXE",
        _ => "Other",
    }
}

/// Charge tous les fichiers JSON de payloads d'un répertoire.
/// Retourne Vec<(nom_catégorie, payloads)>.
pub fn load_payloads(dir: &str) -> Vec<(String, Vec<String>)> {
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return result;
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    for path in paths {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(arr) = serde_json::from_str::<Vec<String>>(&text) else {
            continue;
        };
        if !arr.is_empty() {
            result.push((stem.to_string(), arr));
        }
    }
    result
}

/// Credentials extraites du champ `x-credentials` du spec OpenAPI.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub bearer: Option<String>,
    pub cookie: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_key_header: Option<String>,
    pub api_key_value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub method: String,
    pub path: String,
    pub query_params: Vec<String>,
    pub body_fields: Vec<String>,
    pub path_params: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Remediation {
    pub vuln_type: String,
    pub remediation_text: String,
    pub cvss: u8,
    pub categorie_owasp: String,
}

pub struct PayloadCategories {
    pub sqli: String,
    pub xxe: String,
    pub xss: String,
}

impl ApiEndpoint {
    pub fn build_request_fuzzed(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        cookie_hdr: &str,
        bearer: &str,
        api_key_header: &str,
        api_key_value: &str,
        fuzz_param: &str,
        fuzz_loc: &ParamLoc,
        payload: &str,
    ) -> Vec<u8> {
        let method = self.method.to_uppercase();

        // Replace path params: fuzzed one gets URL-encoded payload, others get "1"
        let clean = {
            let mut result = String::new();
            let mut remaining = self.path.as_str();
            while let Some(start) = remaining.find('{') {
                result.push_str(&remaining[..start]);
                remaining = &remaining[start + 1..];
                if let Some(end) = remaining.find('}') {
                    let param_name = &remaining[..end];
                    remaining = &remaining[end + 1..];
                    if *fuzz_loc == ParamLoc::Path && param_name == fuzz_param {
                        result.push_str(&urlencoded(payload));
                    } else {
                        result.push('1');
                    }
                }
            }
            result.push_str(remaining);
            result
        };

        // Query string : injecte les params du spec + tout param hors-spec fuzzé.
        let query = {
            let mut parts: Vec<String> = self
                .query_params
                .iter()
                .map(|p| {
                    let val = if *fuzz_loc == ParamLoc::Query && p == fuzz_param {
                        urlencoded(payload)
                    } else {
                        "test".to_string()
                    };
                    format!("{p}={val}")
                })
                .collect();
            // Param hors-spec (fallback no-param endpoint) : on l'ajoute quand même.
            if *fuzz_loc == ParamLoc::Query && !self.query_params.iter().any(|q| q == fuzz_param) {
                parts.push(format!("{}={}", fuzz_param, urlencoded(payload)));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("?{}", parts.join("&"))
            }
        };

        let full_path = format!("{clean}{query}");
        let port_sfx = match (tls, port) {
            (true, 443) | (false, 80) => String::new(),
            _ => format!(":{port}"),
        };
        let host_hdr = format!("{host}{port_sfx}");

        let cookie_line = if cookie_hdr.is_empty() {
            String::new()
        } else {
            format!("Cookie: {cookie_hdr}\r\n")
        };
        let auth_line = if bearer.is_empty() {
            String::new()
        } else {
            format!("Authorization: Bearer {bearer}\r\n")
        };
        let api_key_line = if !api_key_header.is_empty() && !api_key_value.is_empty() {
            format!("{api_key_header}: {api_key_value}\r\n")
        } else {
            String::new()
        };

        if matches!(method.as_str(), "GET" | "DELETE" | "HEAD" | "OPTIONS") {
            format!(
                "{method} {full_path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: rustman-scanner/1.0\r\nAccept: application/json\r\n{cookie_line}{auth_line}{api_key_line}Connection: close\r\n\r\n"
            ).into_bytes()
        } else {
            let body = if !self.body_fields.is_empty() {
                let fields: Vec<String> = self
                    .body_fields
                    .iter()
                    .map(|f| {
                        let val = if *fuzz_loc == ParamLoc::Body && f == fuzz_param {
                            serde_json::to_string(payload)
                                .unwrap_or_else(|_| format!("\"{}\"", payload))
                        } else {
                            "\"test\"".to_string()
                        };
                        format!("\"{}\":{}", f, val)
                    })
                    .collect();
                format!("{{{}}}", fields.join(","))
            } else {
                // Pas de body field connu : on essaie quand même avec le champ fuzzé.
                if *fuzz_loc == ParamLoc::Body {
                    let val = serde_json::to_string(payload)
                        .unwrap_or_else(|_| format!("\"{}\"", payload));
                    format!("{{\"{}\":{}}}", fuzz_param, val)
                } else {
                    "{}".to_string()
                }
            };
            let body_len = body.len();
            format!(
                "{method} {full_path} HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nAccept: application/json\r\n{cookie_line}{auth_line}{api_key_line}Connection: close\r\n\r\n{body}"
            ).into_bytes()
        }
    }
}

/// Nom de paramètre sentinelle pour construire une requête « propre » (baseline).
/// Il ne correspond à aucun paramètre réel : `build_request_fuzzed` n'injecte donc
/// aucun payload et tous les champs reçoivent leur valeur bénigne par défaut.
const BASELINE_SENTINEL: &str = "__rustman_baseline__";

/// Valeur bénigne de contrôle réinjectée lors de la passe de confirmation.
/// Purement alphanumérique : ne contient ni métacaractère HTML/SQL/shell, ni URL,
/// donc ne peut légitimement déclencher aucun détecteur côté serveur.
const CONTROL_VALUE: &str = "rustmanctl7391";

impl ApiEndpoint {
    /// Construit une requête baseline : aucune injection, tous les paramètres
    /// reçoivent leur valeur bénigne. Sert de référence pour distinguer un
    /// marqueur causé par le payload d'un marqueur déjà présent dans la réponse
    /// normale de l'endpoint (cf. `check_reflected` / `baseline_has`).
    pub fn build_request_baseline(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        cookie_hdr: &str,
        bearer: &str,
        api_key_header: &str,
        api_key_value: &str,
    ) -> Vec<u8> {
        self.build_request_fuzzed(
            host,
            port,
            tls,
            cookie_hdr,
            bearer,
            api_key_header,
            api_key_value,
            BASELINE_SENTINEL,
            &ParamLoc::Path,
            "",
        )
    }
}

/// Passe de confirmation anti-faux-positif appliquée à toute détection avant de
/// la valider. Renvoie `true` uniquement si la vulnérabilité est confirmée.
///
/// 1. **Rejeu du même payload** — l'evidence doit réapparaître. Élimine les
///    réponses transitoires / non-déterministes (rate-limit, WAF, contenu
///    dynamique, aléa serveur).
/// 2. **Contrôle bénin** — on rejoue le *même paramètre* avec une valeur bénigne
///    (`CONTROL_VALUE`) ; l'evidence doit être **absente**. Élimine les marqueurs
///    indépendants de l'injection (l'endpoint renvoie le marqueur quel que soit
///    l'input). Non appliqué à XSS : le détecteur XSS considère toute réflexion
///    comme exploitable, donc un contrôle réfléchi le déclencherait à tort et
///    invaliderait un vrai XSS. Idem pour OpenRedirect (le payload est réfléchi
///    dans l'en-tête `Location`). Pour ces deux catégories, l'étape 1 suffit ;
///    leurs détecteurs exigent déjà que le payload lui-même apparaisse dans la
///    réponse, ce qui écarte les redirections/réflexions fixes non contrôlées.
#[allow(clippy::too_many_arguments)]
pub async fn confirm_detection(
    ep: &ApiEndpoint,
    host: &str,
    port: u16,
    tls: bool,
    creds: &Credentials,
    param: &str,
    loc: &ParamLoc,
    payload: &str,
    category: &str,
    baseline: Option<&[u8]>,
) -> bool {
    let cookie = creds.cookie.as_deref().unwrap_or("");
    let bearer = creds.bearer.as_deref().unwrap_or("");
    let akh = creds.api_key_header.as_deref().unwrap_or("");
    let akv = creds.api_key_value.as_deref().unwrap_or("");

    // 1. Rejeu du même payload : l'evidence doit réapparaître.
    let raw = ep.build_request_fuzzed(
        host, port, tls, cookie, bearer, akh, akv, param, loc, payload,
    );
    let resp = crate::proxy::repeater_send(host, port, tls, raw).await;
    if crate::rapport::check_reflected(category, payload, &resp, baseline).is_none() {
        return false; // réponse transitoire → non confirmé
    }

    // 2. Contrôle bénin : l'evidence doit être absente (hors catégories
    //    réflexives XSS / OpenRedirect).
    if category != "XSS" && category != "OpenRedirect" {
        let raw_ctl = ep.build_request_fuzzed(
            host, port, tls, cookie, bearer, akh, akv, param, loc, CONTROL_VALUE,
        );
        let resp_ctl = crate::proxy::repeater_send(host, port, tls, raw_ctl).await;
        if crate::rapport::check_reflected(category, CONTROL_VALUE, &resp_ctl, baseline).is_some() {
            return false; // marqueur indépendant de l'injection → faux positif
        }
    }

    true
}

/// Événement émis pendant le scan d'un endpoint.
pub enum ScanEvent {
    /// Résultat d'un test de payload (vuln confirmée si `evidence.is_some()`).
    Result(ScanResult),
    /// `n` payloads restants ont été sautés après une confirmation (early-stop).
    Skipped(usize),
}

/// Scanne un endpoint de bout en bout : baseline, fuzzing de chaque paramètre ×
/// payload, détection puis passe de confirmation anti-faux-positif. Chaque
/// résultat est transmis via `emit`.
///
/// C'est la logique partagée par toutes les sources d'endpoints (scanner OpenAPI
/// CLI + GUI, et scanner issu du crawler) : le durcissement anti-FP (baseline +
/// [`confirm_detection`] + gardes de réflexion dans `check_reflected`) s'applique
/// donc à l'identique quelle que soit la provenance de l'endpoint.
#[allow(clippy::too_many_arguments)]
pub async fn scan_one_endpoint<F>(
    ep: &ApiEndpoint,
    ep_idx: usize,
    host: &str,
    port: u16,
    tls: bool,
    creds: &Credentials,
    payloads: &[(String, Vec<String>)],
    stop: &std::sync::atomic::AtomicBool,
    mut emit: F,
) where
    F: FnMut(ScanEvent),
{
    use std::sync::atomic::Ordering;

    let cookie = creds.cookie.as_deref().unwrap_or("");
    let bearer = creds.bearer.as_deref().unwrap_or("");
    let akh = creds.api_key_header.as_deref().unwrap_or("");
    let akv = creds.api_key_value.as_deref().unwrap_or("");

    let mut params: Vec<(String, ParamLoc)> = ep
        .body_fields
        .iter()
        .map(|f| (f.clone(), ParamLoc::Body))
        .chain(ep.query_params.iter().map(|q| (q.clone(), ParamLoc::Query)))
        .chain(ep.path_params.iter().map(|p| (p.clone(), ParamLoc::Path)))
        .collect();
    // Endpoint sans paramètre détecté : on injecte via un paramètre générique
    // pour ne jamais laisser un endpoint non testé.
    if params.is_empty() {
        let fallback = if matches!(ep.method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH") {
            ("data".to_string(), ParamLoc::Body)
        } else {
            ("id".to_string(), ParamLoc::Query)
        };
        params.push(fallback);
    }

    let total_ep_payloads: usize =
        params.len() * payloads.iter().map(|(_, p)| p.len()).sum::<usize>();
    let mut processed = 0usize;

    // Baseline : une requête « propre » par endpoint. Référence pour filtrer
    // tout marqueur déjà présent dans la réponse normale.
    let baseline: Vec<u8> = {
        let raw = ep.build_request_baseline(host, port, tls, cookie, bearer, akh, akv);
        crate::proxy::repeater_send(host, port, tls, raw).await
    };

    'ep_loop: for (param, loc) in &params {
        for (cat, plist) in payloads {
            if stop.load(Ordering::Relaxed) {
                break 'ep_loop;
            }
            let display_cat = payload_cat_name(cat).to_string();

            for payload in plist {
                if stop.load(Ordering::Relaxed) {
                    break 'ep_loop;
                }
                processed += 1;

                let raw = ep.build_request_fuzzed(
                    host, port, tls, cookie, bearer, akh, akv, param, loc, payload,
                );
                let raw_request = raw.clone();
                let resp_bytes = crate::proxy::repeater_send(host, port, tls, raw).await;
                let status: u16 = std::str::from_utf8(&resp_bytes)
                    .unwrap_or("")
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);

                let evidence = {
                    let ev = crate::rapport::check_reflected(
                        &display_cat,
                        payload,
                        &resp_bytes,
                        Some(&baseline),
                    );
                    if crate::rapport::is_false_positive(&display_cat, status) {
                        None
                    } else {
                        ev
                    }
                };

                // Passe de confirmation : rejeu + contrôle bénin (~0 faux positif).
                let evidence = if evidence.is_some()
                    && confirm_detection(
                        ep,
                        host,
                        port,
                        tls,
                        creds,
                        param,
                        loc,
                        payload,
                        &display_cat,
                        Some(&baseline),
                    )
                    .await
                {
                    evidence
                } else {
                    None
                };

                let vuln_confirmed = evidence.is_some();
                emit(ScanEvent::Result(ScanResult {
                    ep_idx,
                    param: param.clone(),
                    loc: loc.clone(),
                    category: display_cat.clone(),
                    payload: payload.clone(),
                    status,
                    response: resp_bytes,
                    evidence,
                    raw_request,
                }));

                if vuln_confirmed {
                    let remaining = total_ep_payloads - processed;
                    if remaining > 0 {
                        emit(ScanEvent::Skipped(remaining));
                    }
                    break 'ep_loop;
                }
            }
        }
    }
}

fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
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

// ── Point d'entrée public ─────────────────────────────────────────────────────

/// Résultat du parsing d'un spec OpenAPI.
pub struct ParseResult {
    pub endpoints: Vec<ApiEndpoint>,
    pub credentials: Option<Credentials>,
    /// Première URL de la liste `servers` (base URL de l'API).
    pub server_url: Option<String>,
}

/// Parse un spec OpenAPI 3.x ou Swagger 2.x en JSON **ou YAML**.
pub fn parse(text: &str) -> Result<ParseResult, String> {
    let v = parse_to_json_value(text.trim())?;
    let credentials = extract_credentials(&v);
    let server_url = extract_server_url(&v);
    let endpoints = if v.get("openapi").is_some() {
        parse_openapi3(&v)?
    } else if v.get("swagger").is_some() {
        parse_swagger2(&v)?
    } else {
        return Err("Document non reconnu : aucun champ 'openapi' ou 'swagger' trouvé".into());
    };
    Ok(ParseResult {
        endpoints,
        credentials,
        server_url,
    })
}

// ── Parsing JSON / YAML ───────────────────────────────────────────────────────

fn parse_to_json_value(text: &str) -> Result<Value, String> {
    // Heuristique : si le texte commence par { ou [, c'est du JSON
    let first = text.chars().find(|c| !c.is_whitespace());
    if matches!(first, Some('{') | Some('[')) {
        return serde_json::from_str(text).map_err(|e| format!("JSON invalide : {e}"));
    }
    // Sinon on essaie YAML (OpenAPI YAML commence généralement par "openapi:")
    serde_yaml::from_str::<Value>(text).map_err(|e| format!("YAML invalide : {e}"))
}

// ── Extraction des credentials ────────────────────────────────────────────────

fn extract_server_url(v: &Value) -> Option<String> {
    v.get("servers")?
        .as_array()?
        .first()?
        .get("url")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn extract_credentials(v: &Value) -> Option<Credentials> {
    let xc = v.get("x-credentials")?;

    let get = |k: &str| -> Option<String> {
        xc.get(k)?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let c = Credentials {
        bearer: get("bearer"),
        cookie: get("cookie"),
        username: get("username"),
        password: get("password"),
        api_key_header: get("api_key_header"),
        api_key_value: get("api_key_value"),
    };

    // Retourne None si aucun champ n'est renseigné
    if c.bearer.is_none()
        && c.cookie.is_none()
        && c.username.is_none()
        && c.password.is_none()
        && c.api_key_header.is_none()
        && c.api_key_value.is_none()
    {
        return None;
    }
    Some(c)
}

// ── Parsers OpenAPI 3.x / Swagger 2.x ────────────────────────────────────────

fn parse_openapi3(v: &Value) -> Result<Vec<ApiEndpoint>, String> {
    let paths = v.get("paths").ok_or("Champ 'paths' introuvable")?;
    let paths_obj = paths.as_object().ok_or("'paths' n'est pas un objet")?;
    let mut endpoints = Vec::new();

    for (path, path_val) in paths_obj {
        let Some(path_obj) = path_val.as_object() else {
            continue;
        };

        // Parameters defined at the path level (shared by all operations)
        let path_level: Vec<&Value> = path_obj
            .get("parameters")
            .and_then(|p| p.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();

        for (method, op) in path_obj {
            if !is_http_method(method) {
                continue;
            }

            // Operation-level parameters override path-level ones with same name+in
            let op_level: Vec<&Value> = op
                .get("parameters")
                .and_then(|p| p.as_array())
                .map(|a| a.iter().collect())
                .unwrap_or_default();

            let mut merged: Vec<&Value> = Vec::new();
            // Start with path-level, skip any overridden by op-level
            for p in &path_level {
                let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let loc = p.get("in").and_then(|i| i.as_str()).unwrap_or("");
                let overridden = op_level.iter().any(|q| {
                    q.get("name").and_then(|n| n.as_str()).unwrap_or("") == name
                        && q.get("in").and_then(|i| i.as_str()).unwrap_or("") == loc
                });
                if !overridden {
                    merged.push(p);
                }
            }
            merged.extend_from_slice(&op_level);

            let mut query_params = Vec::new();
            let mut path_params = Vec::new();

            for param in &merged {
                let loc = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                match loc {
                    "query" => query_params.push(name.to_string()),
                    "path" => path_params.push(name.to_string()),
                    _ => {}
                }
            }

            // Body fields from requestBody (JSON or form-encoded)
            let mut body_fields = Vec::new();
            if let Some(body) = op.get("requestBody") {
                let content = body.get("content");
                let schema = content
                    .and_then(|c| c.get("application/json"))
                    .and_then(|j| j.get("schema"))
                    .or_else(|| {
                        content
                            .and_then(|c| c.get("application/x-www-form-urlencoded"))
                            .and_then(|j| j.get("schema"))
                    });
                if let Some(s) = schema {
                    body_fields = extract_schema_fields(v, s);
                }
            }

            endpoints.push(ApiEndpoint {
                method: method.to_uppercase(),
                path: path.clone(),
                query_params,
                body_fields,
                path_params,
            });
        }
    }

    if endpoints.is_empty() {
        return Err("Aucun endpoint trouvé dans le spec".into());
    }
    Ok(endpoints)
}

fn parse_swagger2(v: &Value) -> Result<Vec<ApiEndpoint>, String> {
    let base_path = v.get("basePath").and_then(|b| b.as_str()).unwrap_or("/");
    let paths = v.get("paths").ok_or("Champ 'paths' introuvable")?;
    let paths_obj = paths.as_object().ok_or("'paths' n'est pas un objet")?;
    let mut endpoints = Vec::new();

    for (path, methods_val) in paths_obj {
        let Some(methods) = methods_val.as_object() else {
            continue;
        };
        for (method, op) in methods {
            if !is_http_method(method) {
                continue;
            }
            let mut query_params = Vec::new();
            let mut body_fields = Vec::new();

            if let Some(arr) = op.get("parameters").and_then(|p| p.as_array()) {
                for param in arr {
                    let loc = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    match loc {
                        "query" if !name.is_empty() => query_params.push(name.to_string()),
                        "body" => {
                            if let Some(schema) = param.get("schema") {
                                body_fields = extract_schema_fields(v, schema);
                            }
                        }
                        "formData" if !name.is_empty() => body_fields.push(name.to_string()),
                        _ => {}
                    }
                }
            }

            let full_path = if base_path == "/" {
                path.clone()
            } else {
                format!("{}{}", base_path.trim_end_matches('/'), path)
            };

            endpoints.push(ApiEndpoint {
                method: method.to_uppercase(),
                path: full_path,
                query_params,
                body_fields,
                path_params: Vec::new(),
            });
        }
    }

    if endpoints.is_empty() {
        return Err("Aucun endpoint trouvé dans le spec".into());
    }
    Ok(endpoints)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolves a JSON Pointer like "#/components/schemas/User" within `doc`.
fn resolve_ref<'a>(doc: &'a Value, r: &str) -> Option<&'a Value> {
    let path = r.strip_prefix("#/")?;
    let mut cur = doc;
    for part in path.split('/') {
        let key = part.replace("~1", "/").replace("~0", "~");
        cur = cur.get(key.as_str())?;
    }
    Some(cur)
}

/// Extracts fuzzable field names from an OpenAPI schema node.
/// Handles $ref, allOf/oneOf/anyOf, direct properties, and additionalProperties.
fn extract_schema_fields(doc: &Value, schema: &Value) -> Vec<String> {
    // Resolve $ref
    if let Some(r) = schema.get("$ref").and_then(|r| r.as_str()) {
        return resolve_ref(doc, r)
            .map(|resolved| extract_schema_fields(doc, resolved))
            .unwrap_or_default();
    }

    // allOf / oneOf / anyOf — union of all sub-schema fields
    for key in &["allOf", "oneOf", "anyOf"] {
        if let Some(arr) = schema.get(key).and_then(|a| a.as_array()) {
            let mut fields: Vec<String> = arr
                .iter()
                .flat_map(|sub| extract_schema_fields(doc, sub))
                .collect();
            fields.sort_unstable();
            fields.dedup();
            return fields;
        }
    }

    // Direct properties
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        return props.keys().cloned().collect();
    }

    // additionalProperties: true — use example keys if present
    if schema.get("additionalProperties").and_then(|a| a.as_bool()) == Some(true) {
        if let Some(ex) = schema.get("example").and_then(|e| e.as_object()) {
            let keys: Vec<String> = ex.keys().cloned().collect();
            if !keys.is_empty() {
                return keys;
            }
        }
        return vec!["value".to_string()];
    }

    Vec::new()
}

fn is_http_method(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La requête baseline ne doit contenir aucune valeur d'injection : les
    /// paramètres de chemin valent `1`, les query params `test`, aucun paramètre
    /// parasite (`?=…`) et surtout jamais la sentinelle ni un payload.
    #[test]
    fn baseline_request_is_clean() {
        let ep = ApiEndpoint {
            method: "GET".into(),
            path: "/users/{id}".into(),
            query_params: vec!["q".into()],
            body_fields: vec![],
            path_params: vec!["id".into()],
        };
        let raw = ep.build_request_baseline("example.com", 443, true, "", "", "", "");
        let s = String::from_utf8(raw).unwrap();
        let request_line = s.lines().next().unwrap();
        assert!(request_line.starts_with("GET /users/1?q=test "), "got: {request_line}");
        assert!(!s.contains(BASELINE_SENTINEL), "sentinel leaked into request");
        // Pas de paramètre à nom vide injecté par le fallback query.
        assert!(!request_line.contains("?=") && !request_line.contains("&="));
    }

    /// Baseline pour un POST : le body contient les champs avec des valeurs
    /// bénignes, jamais un payload.
    #[test]
    fn baseline_post_body_is_benign() {
        let ep = ApiEndpoint {
            method: "POST".into(),
            path: "/login".into(),
            query_params: vec![],
            body_fields: vec!["username".into(), "password".into()],
            path_params: vec![],
        };
        let raw = ep.build_request_baseline("example.com", 443, true, "", "", "", "");
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains(r#""username":"test""#), "got: {s}");
        assert!(s.contains(r#""password":"test""#), "got: {s}");
        assert!(!s.contains(BASELINE_SENTINEL));
    }
}
