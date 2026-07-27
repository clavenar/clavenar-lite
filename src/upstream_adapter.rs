//! Explicit upstream wire adapters.
//!
//! `raw-json` preserves the developer-laptop compatibility path.
//! Internet-hosted deployments must select `mcp-jsonrpc-v1`, which bounds both
//! directions and verifies that the upstream speaks the same JSON-RPC exchange
//! rather than accepting an unrelated HTTP JSON API.

use std::{fmt, str::FromStr};

use axum::body::Bytes;
use reqwest::{Client, StatusCode, header};

pub const REQUEST_BODY_BYTES: usize = 1_048_576;
pub const RESPONSE_BODY_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpstreamAdapter {
    #[default]
    RawJson,
    McpJsonRpcV1,
}

impl FromStr for UpstreamAdapter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "raw-json" => Ok(Self::RawJson),
            "mcp-jsonrpc-v1" => Ok(Self::McpJsonRpcV1),
            other => Err(format!(
                "unknown upstream adapter {other:?}; expected raw-json or mcp-jsonrpc-v1"
            )),
        }
    }
}

impl fmt::Display for UpstreamAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RawJson => "raw-json",
            Self::McpJsonRpcV1 => "mcp-jsonrpc-v1",
        })
    }
}

#[derive(Debug)]
pub struct ForwardedResponse {
    pub status: StatusCode,
    pub content_type: Option<String>,
    pub body: Bytes,
}

impl UpstreamAdapter {
    pub fn validate_request(self, body: &[u8]) -> Result<Option<serde_json::Value>, String> {
        if body.len() > REQUEST_BODY_BYTES {
            return Err(format!(
                "upstream request body exceeds {REQUEST_BODY_BYTES} bytes"
            ));
        }
        if self == Self::RawJson {
            return Ok(None);
        }
        let request: serde_json::Value = serde_json::from_slice(body)
            .map_err(|error| format!("MCP adapter request is not JSON: {error}"))?;
        if request.get("jsonrpc") != Some(&serde_json::Value::String("2.0".to_string())) {
            return Err("MCP adapter request requires jsonrpc=\"2.0\"".to_string());
        }
        let method = request
            .get("method")
            .and_then(serde_json::Value::as_str)
            .filter(|method| !method.is_empty())
            .ok_or_else(|| "MCP adapter request requires a method".to_string())?;
        let request_id = request.get("id").cloned();
        if !method.starts_with("notifications/")
            && request_id.as_ref().is_none_or(serde_json::Value::is_null)
        {
            return Err("MCP adapter request requires a non-null id".to_string());
        }
        Ok(request_id)
    }

    pub async fn forward(
        self,
        client: &Client,
        upstream_url: &str,
        upstream_api_key: Option<&str>,
        body: Bytes,
    ) -> Result<ForwardedResponse, String> {
        let request_id = self.validate_request(&body)?;
        let mut request = client
            .post(upstream_url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(api_key) = upstream_api_key {
            request = request.bearer_auth(api_key);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| format!("upstream request failed: {error}"))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("upstream response read failed: {error}"))?
        {
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_BODY_BYTES {
                return Err(format!(
                    "upstream response body exceeds {RESPONSE_BODY_BYTES} bytes"
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = Bytes::from(bytes);
        if self == Self::McpJsonRpcV1 {
            validate_mcp_response(status, content_type.as_deref(), &body, request_id.as_ref())?;
        }
        Ok(ForwardedResponse {
            status,
            content_type,
            body,
        })
    }
}

fn validate_mcp_response(
    status: StatusCode,
    content_type: Option<&str>,
    body: &[u8],
    request_id: Option<&serde_json::Value>,
) -> Result<(), String> {
    if request_id.is_none() && status == StatusCode::NO_CONTENT && body.is_empty() {
        return Ok(());
    }
    if !content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err("MCP adapter response requires application/json".to_string());
    }
    let response: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("MCP adapter response is not JSON: {error}"))?;
    if response.get("jsonrpc") != Some(&serde_json::Value::String("2.0".to_string())) {
        return Err("MCP adapter response requires jsonrpc=\"2.0\"".to_string());
    }
    if response.get("id") != request_id {
        return Err("MCP adapter response id does not match the request".to_string());
    }
    let result = response.get("result").is_some();
    let error = response.get("error").is_some();
    if result == error {
        return Err("MCP adapter response requires exactly one of result or error".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    async fn spawn_upstream(
        response: serde_json::Value,
        content_type: &'static str,
    ) -> (String, Arc<AtomicUsize>) {
        let effects = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&effects);
        let app = Router::new().route(
            "/mcp",
            post(move || {
                let counted = Arc::clone(&counted);
                let response = response.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    (
                        [(header::CONTENT_TYPE.as_str(), content_type)],
                        serde_json::to_vec(&response).unwrap(),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/mcp"), effects)
    }

    fn request() -> Bytes {
        Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"ping","arguments":{}}}"#,
        )
    }

    #[tokio::test]
    async fn compatible_adapter_accepts_an_exact_exchange() {
        let (url, effects) = spawn_upstream(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "request-1",
                "result": {"ok": true}
            }),
            "application/json; charset=utf-8",
        )
        .await;
        let response = UpstreamAdapter::McpJsonRpcV1
            .forward(&Client::new(), &url, None, request())
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn incompatible_response_identity_and_content_type_fail_closed() {
        let (url, _) = spawn_upstream(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "substituted",
                "result": {"ok": true}
            }),
            "application/json",
        )
        .await;
        assert!(
            UpstreamAdapter::McpJsonRpcV1
                .forward(&Client::new(), &url, None, request())
                .await
                .unwrap_err()
                .contains("id does not match")
        );

        let (url, _) = spawn_upstream(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "request-1",
                "result": {"ok": true}
            }),
            "text/plain",
        )
        .await;
        assert!(
            UpstreamAdapter::McpJsonRpcV1
                .forward(&Client::new(), &url, None, request())
                .await
                .unwrap_err()
                .contains("application/json")
        );
    }

    #[tokio::test]
    async fn oversized_request_fails_before_an_upstream_effect() {
        let (url, effects) = spawn_upstream(
            serde_json::json!({"jsonrpc":"2.0","id":"request-1","result":{}}),
            "application/json",
        )
        .await;
        let error = UpstreamAdapter::McpJsonRpcV1
            .forward(
                &Client::new(),
                &url,
                None,
                Bytes::from(vec![b'x'; REQUEST_BODY_BYTES + 1]),
            )
            .await
            .unwrap_err();
        assert!(error.contains("request body exceeds"));
        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn request_contract_rejects_missing_version_method_and_id() {
        for body in [
            br#"{"id":1,"method":"tools/call"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1}"#.as_slice(),
            br#"{"jsonrpc":"2.0","method":"tools/call"}"#.as_slice(),
        ] {
            assert!(
                UpstreamAdapter::McpJsonRpcV1
                    .validate_request(body)
                    .is_err()
            );
        }
    }
}
