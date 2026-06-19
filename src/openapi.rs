use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub method: String,
    pub path: String,
    pub query_params: Vec<String>,
    pub body_fields: Vec<String>,
}

impl ApiEndpoint {
    pub fn build_request(&self, host: &str, port: u16, tls: bool, cookie_hdr: &str, bearer: &str) -> Vec<u8> {
        let method = self.method.to_uppercase();
        // Replace path params {id} → "test"
        let mut clean = self.path.clone();
        loop {
            if let (Some(a), Some(b)) = (clean.find('{'), clean.find('}')) {
                if b > a {
                    clean = format!("{}test{}", &clean[..a], &clean[b + 1..]);
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
        if matches!(method.as_str(), "GET" | "DELETE" | "HEAD" | "OPTIONS") {
            format!(
                "{method} {full_path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: rustman-scanner/1.0\r\nAccept: application/json\r\n{cookie_line}{auth_line}Connection: close\r\n\r\n"
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
                "{method} {full_path} HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nAccept: application/json\r\n{cookie_line}{auth_line}Connection: close\r\n\r\n{body}"
            )
            .into_bytes()
        }
    }
}

/// Parse an OpenAPI 3.x or Swagger 2.x JSON spec.
pub fn parse(json_text: &str) -> Result<Vec<ApiEndpoint>, String> {
    let v: Value = serde_json::from_str(json_text).map_err(|e| e.to_string())?;
    if v.get("openapi").is_some() {
        parse_openapi3(&v)
    } else if v.get("swagger").is_some() {
        parse_swagger2(&v)
    } else {
        Err("Not a valid OpenAPI 3.x or Swagger 2.x document".into())
    }
}

fn parse_openapi3(v: &Value) -> Result<Vec<ApiEndpoint>, String> {
    let paths = v.get("paths").ok_or("No 'paths' field found")?;
    let paths_obj = paths.as_object().ok_or("'paths' is not an object")?;
    let mut endpoints = Vec::new();

    for (path, methods_val) in paths_obj {
        let Some(methods) = methods_val.as_object() else { continue };
        for (method, op) in methods {
            if !is_http_method(method) { continue; }
            let mut query_params = Vec::new();
            let mut body_fields = Vec::new();

            if let Some(arr) = op.get("parameters").and_then(|p| p.as_array()) {
                for param in arr {
                    let loc = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if loc == "query" && !name.is_empty() {
                        query_params.push(name.to_string());
                    }
                }
            }

            if let Some(body) = op.get("requestBody") {
                let schema = body
                    .get("content")
                    .and_then(|c| c.get("application/json"))
                    .and_then(|j| j.get("schema"));
                if let Some(s) = schema {
                    body_fields = extract_schema_fields(s);
                }
            }

            endpoints.push(ApiEndpoint {
                method: method.to_uppercase(),
                path: path.clone(),
                query_params,
                body_fields,
            });
        }
    }

    if endpoints.is_empty() {
        return Err("No API endpoints found in the spec".into());
    }
    Ok(endpoints)
}

fn parse_swagger2(v: &Value) -> Result<Vec<ApiEndpoint>, String> {
    let base_path = v.get("basePath").and_then(|b| b.as_str()).unwrap_or("/");
    let paths = v.get("paths").ok_or("No 'paths' field found")?;
    let paths_obj = paths.as_object().ok_or("'paths' is not an object")?;
    let mut endpoints = Vec::new();

    for (path, methods_val) in paths_obj {
        let Some(methods) = methods_val.as_object() else { continue };
        for (method, op) in methods {
            if !is_http_method(method) { continue; }
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
                                body_fields = extract_schema_fields(schema);
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
            });
        }
    }

    if endpoints.is_empty() {
        return Err("No API endpoints found in the spec".into());
    }
    Ok(endpoints)
}

fn extract_schema_fields(schema: &Value) -> Vec<String> {
    schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default()
}

fn is_http_method(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options"
    )
}
