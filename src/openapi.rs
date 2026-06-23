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
    pub ep_idx:      usize,
    pub param:       String,
    pub loc:         ParamLoc,
    pub category:    String,   // nom rapport : "SQLi", "XSS", etc.
    pub payload:     String,
    pub status:      u16,
    pub response:    Vec<u8>,
    pub evidence:    Option<String>, // Some(_) = vulnérabilité confirmée
    pub raw_request: Vec<u8>,        // peuplé uniquement si evidence.is_some()
}

/// Messages envoyés par le background scan task vers le GUI.
pub enum ScanMsg {
    Result(ScanResult),
    /// Un triple (endpoint, param, catégorie) est terminé (hit ou payloads épuisés).
    TripleDone,
    /// N payloads ignorés car l'endpoint a déjà une vulnérabilité confirmée.
    Skipped(usize),
    Finished,
}

/// Convertit le nom de fichier payload (ex: "sqli") vers le nom de catégorie rapport.
pub fn payload_cat_name(stem: &str) -> &'static str {
    match stem {
        "sqli"           => "SQLi",
        "xss"            => "XSS",
        "cmdi"           => "CMDi",
        "rce"            => "RCE",
        "path_traversal" => "PathTraversal",
        "ssrf"           => "SSRF",
        "ssti"           => "SSTI",
        "open_redirect"  => "OpenRedirect",
        _                => "Other",
    }
}

/// Charge tous les fichiers JSON de payloads d'un répertoire.
/// Retourne Vec<(nom_catégorie, payloads)>.
pub fn load_payloads(dir: &str) -> Vec<(String, Vec<String>)> {
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return result };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    for path in paths {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(arr)  = serde_json::from_str::<Vec<String>>(&text) else { continue };
        if !arr.is_empty() {
            result.push((stem.to_string(), arr));
        }
    }
    result
}

/// Credentials extraites du champ `x-credentials` du spec OpenAPI.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// Valeur brute du Bearer token (sans le préfixe "Bearer ").
    pub bearer: Option<String>,
    /// Cookie header complet, ex : "session=abc123; csrf=xyz".
    pub cookie: Option<String>,
    /// Nom d'utilisateur pour le crawler auth.
    pub username: Option<String>,
    /// Mot de passe pour le crawler auth.
    pub password: Option<String>,
    /// Nom du header custom (ex : "X-Admin-Key").
    pub api_key_header: Option<String>,
    /// Valeur du header custom.
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

impl ApiEndpoint {
    /// Construit la requête HTTP brute prête à être envoyée sur le réseau.
    pub fn build_request(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        cookie_hdr: &str,
        bearer: &str,
        api_key_header: &str,
        api_key_value: &str,
    ) -> Vec<u8> {
        let method = self.method.to_uppercase();

        // Résolution des paramètres de chemin {id} → "1"
        let mut clean = self.path.clone();
        loop {
            if let (Some(a), Some(b)) = (clean.find('{'), clean.find('}')) {
                if b > a {
                    clean = format!("{}1{}", &clean[..a], &clean[b + 1..]);
                    continue;
                }
            }
            break;
        }

        let query = if !self.query_params.is_empty() {
            let qs = self.query_params.iter()
                .map(|p| format!("{p}=test"))
                .collect::<Vec<_>>()
                .join("&");
            format!("?{qs}")
        } else {
            String::new()
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
            )
            .into_bytes()
        } else {
            let body = if !self.body_fields.is_empty() {
                let fields: Vec<String> = self.body_fields.iter()
                    .map(|f| format!("\"{}\":\"test\"", f))
                    .collect();
                format!("{{{}}}", fields.join(","))
            } else {
                "{}".to_string()
            };
            let body_len = body.len();
            format!(
                "{method} {full_path} HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nAccept: application/json\r\n{cookie_line}{auth_line}{api_key_line}Connection: close\r\n\r\n{body}"
            )
            .into_bytes()
        }
    }

    /// Comme `build_request` mais injecte `payload` dans le paramètre `fuzz_param`
    /// (body field ou query param). Les autres params restent à "test".
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
            let mut parts: Vec<String> = self.query_params.iter()
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
            if *fuzz_loc == ParamLoc::Query
                && !self.query_params.iter().any(|q| q == fuzz_param)
            {
                parts.push(format!("{}={}", fuzz_param, urlencoded(payload)));
            }
            if parts.is_empty() { String::new() } else { format!("?{}", parts.join("&")) }
        };

        let full_path = format!("{clean}{query}");
        let port_sfx = match (tls, port) {
            (true, 443) | (false, 80) => String::new(),
            _ => format!(":{port}"),
        };
        let host_hdr = format!("{host}{port_sfx}");

        let cookie_line = if cookie_hdr.is_empty() { String::new() }
            else { format!("Cookie: {cookie_hdr}\r\n") };
        let auth_line = if bearer.is_empty() { String::new() }
            else { format!("Authorization: Bearer {bearer}\r\n") };
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
                let fields: Vec<String> = self.body_fields.iter()
                    .map(|f| {
                        let val = if *fuzz_loc == ParamLoc::Body && f == fuzz_param {
                            serde_json::to_string(payload).unwrap_or_else(|_| format!("\"{}\"", payload))
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

fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ── Point d'entrée public ─────────────────────────────────────────────────────

/// Résultat du parsing d'un spec OpenAPI.
pub struct ParseResult {
    pub endpoints:  Vec<ApiEndpoint>,
    pub credentials: Option<Credentials>,
    /// Première URL de la liste `servers` (base URL de l'API).
    pub server_url: Option<String>,
}

/// Parse un spec OpenAPI 3.x ou Swagger 2.x en JSON **ou YAML**.
pub fn parse(text: &str) -> Result<ParseResult, String> {
    let v = parse_to_json_value(text.trim())?;
    let credentials = extract_credentials(&v);
    let server_url  = extract_server_url(&v);
    let endpoints = if v.get("openapi").is_some() {
        parse_openapi3(&v)?
    } else if v.get("swagger").is_some() {
        parse_swagger2(&v)?
    } else {
        return Err("Document non reconnu : aucun champ 'openapi' ou 'swagger' trouvé".into());
    };
    Ok(ParseResult { endpoints, credentials, server_url })
}

// ── Parsing JSON / YAML ───────────────────────────────────────────────────────

fn parse_to_json_value(text: &str) -> Result<Value, String> {
    // Heuristique : si le texte commence par { ou [, c'est du JSON
    let first = text.chars().find(|c| !c.is_whitespace());
    if matches!(first, Some('{') | Some('[')) {
        return serde_json::from_str(text)
            .map_err(|e| format!("JSON invalide : {e}"));
    }
    // Sinon on essaie YAML (OpenAPI YAML commence généralement par "openapi:")
    serde_yaml::from_str::<Value>(text)
        .map_err(|e| format!("YAML invalide : {e}"))
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
        xc.get(k)?.as_str().filter(|s| !s.is_empty()).map(str::to_string)
    };

    let c = Credentials {
        bearer:         get("bearer"),
        cookie:         get("cookie"),
        username:       get("username"),
        password:       get("password"),
        api_key_header: get("api_key_header"),
        api_key_value:  get("api_key_value"),
    };

    // Retourne None si aucun champ n'est renseigné
    if c.bearer.is_none() && c.cookie.is_none() && c.username.is_none()
        && c.password.is_none() && c.api_key_header.is_none() && c.api_key_value.is_none()
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
        let Some(path_obj) = path_val.as_object() else { continue };

        // Parameters defined at the path level (shared by all operations)
        let path_level: Vec<&Value> = path_obj
            .get("parameters")
            .and_then(|p| p.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();

        for (method, op) in path_obj {
            if !is_http_method(method) { continue; }

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
                let loc  = p.get("in").and_then(|i| i.as_str()).unwrap_or("");
                let overridden = op_level.iter().any(|q| {
                    q.get("name").and_then(|n| n.as_str()).unwrap_or("") == name
                    && q.get("in").and_then(|i| i.as_str()).unwrap_or("") == loc
                });
                if !overridden { merged.push(p); }
            }
            merged.extend_from_slice(&op_level);

            let mut query_params = Vec::new();
            let mut path_params  = Vec::new();

            for param in &merged {
                let loc  = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if name.is_empty() { continue; }
                match loc {
                    "query" => query_params.push(name.to_string()),
                    "path"  => path_params.push(name.to_string()),
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
                    .or_else(|| content
                        .and_then(|c| c.get("application/x-www-form-urlencoded"))
                        .and_then(|j| j.get("schema")));
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
        let Some(methods) = methods_val.as_object() else { continue };
        for (method, op) in methods {
            if !is_http_method(method) { continue; }
            let mut query_params = Vec::new();
            let mut body_fields  = Vec::new();

            if let Some(arr) = op.get("parameters").and_then(|p| p.as_array()) {
                for param in arr {
                    let loc  = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
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
            let mut fields: Vec<String> = arr.iter()
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
            if !keys.is_empty() { return keys; }
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
