//! Embedded HTTP proxy (Layer 1, OSS edition).
//!
//! Single axum handler at `POST /mcp` that orchestrates the security
//! pipeline serially:
//!
//! 1. Parse the MCP / JSON-RPC body, extract method + tool name.
//! 2. Run the embedded heuristic Brain.
//! 3. Run the embedded policy engine.
//! 4. If both said allow, forward to the configured upstream and return
//!    the response. Otherwise 403 with the joined reason strings.
//! 5. Append exactly one entry to the embedded ledger (matches the
//!    full edition's "one row per request from the proxy emitter"
//!    invariant — Lite skips the policy-engine NATS row because the
//!    policy decision lives in the same process).
//!
//! This is the security-first orchestration model from the full
//! `warden-proxy` (post-2026-05-02). There's no race, no Yellow-tier
//! HITL roundtrip, and no Vault — Lite is for developer-laptop use
//! where the agent already has its own creds.
//!
//! # Authentication
//!
//! Lite supports an optional bearer-token auth pre-shared via
//! `WARDEN_LITE_TOKEN`. If unset, the proxy accepts every connection
//! (fine for `127.0.0.1` developer use). If set, every request must
//! send `Authorization: Bearer <token>` or it's 401. mTLS is the full
//! edition's job.
//!
//! # Rust idioms in this file
//!
//! * `axum::extract::State<Arc<AppState>>` — same shared-state pattern
//!   the full edition uses. `Arc` so cloning the state into each
//!   request future is cheap.
//! * `body: Bytes` — axum extractor that hands the raw request body as
//!   a contiguous byte buffer. We parse it twice (once to pull
//!   method+tool, once to forward) without re-allocating.
//! * `let upstream_resp = state.http.post(...).body(body.clone())` —
//!   `Bytes` is `Clone`-cheap (it's an Arc'd buffer internally), so the
//!   forward path doesn't need to re-read the body.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::heuristics::{self, HeuristicVerdict};
use crate::ledger::{Ledger, LogRequest};
use crate::policy::{AgentHistory, PolicyDecision, PolicyEngine, PolicyInput};

/// Shared state behind an `Arc`. Cloned per-request via `State<Arc<...>>`.
pub struct AppState {
    pub policy: Arc<PolicyEngine>,
    pub ledger: Arc<Ledger>,
    pub upstream_url: String,
    pub http: reqwest::Client,
    /// Optional bearer token for inbound auth. `None` means accept all
    /// connections; safe for `127.0.0.1` developer use.
    pub bearer_token: Option<String>,
    /// Pre-shared upstream API key, injected into the forwarded request
    /// as `Authorization: Bearer <key>`. Same role as the full
    /// edition's Vault credential injection — minus Vault. `None` means
    /// don't inject (the upstream is responsible for its own auth).
    pub upstream_api_key: Option<String>,
}

/// Wire shape for the `POST /mcp` request body. We accept any JSON
/// object and only require `method`; extra fields ride through to the
/// upstream untouched. Mirrors the full edition's `McpRequest`.
#[derive(Debug, Deserialize, Serialize)]
struct McpRequest {
    /// JSON-RPC method, e.g. `"call_tool"`. Required by the validator.
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    jsonrpc: Option<String>,
}

/// Response we emit on a security-rejected request. JSON shape so
/// agent-side libraries can parse the reason without string-munging.
#[derive(Debug, Serialize)]
struct DenyResponse {
    error: &'static str,
    reasons: Vec<String>,
    review_reasons: Vec<String>,
    intent_category: String,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/mcp", post(handle_mcp))
        .with_state(state)
}

async fn health() -> &'static str {
    "Agent Warden Lite is active."
}

/// Core request handler — security-first orchestration.
///
/// Returns the upstream response on success, a 403 with structured
/// reasons on a security-pipeline veto, or a 401 if the bearer token
/// is configured and the request didn't supply it.
async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Bearer auth (if configured). `Authorization: Bearer <token>` —
    // any other shape is 401.
    if let Some(expected) = &state.bearer_token {
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if supplied != Some(expected.as_str()) {
            return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
        }
    }

    // Parse + validate the request body. We use a permissive shape so
    // the proxy doesn't refuse otherwise-valid MCP variants we don't
    // happen to model — only `method` is required.
    let parsed: McpRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid JSON-RPC body: {}", e))
                .into_response()
        }
    };

    // `tool_type` is `params.name` when this is a tool call; otherwise
    // we tag it with the JSON-RPC method name itself so the policy
    // rules can distinguish tool calls from other RPC verbs.
    let tool_type = parsed
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(parsed.method.as_str())
        .to_string();

    // Agent-id source: bearer token if present, else "anonymous". The
    // full edition trusts the mTLS CN; Lite has no PKI, so we just use
    // the configured token as the rough identity. Good enough for
    // developer-laptop use; reach for the full edition when you need
    // real per-agent identity.
    let agent_id = state
        .bearer_token
        .as_deref()
        .map(|_| "bearer-agent")
        .unwrap_or("anonymous")
        .to_string();

    let body_str = String::from_utf8_lossy(&body);

    // -------- Heuristic Brain --------
    let brain: HeuristicVerdict = heuristics::inspect(&tool_type, &body_str);

    // -------- Policy engine --------
    let policy_input = PolicyInput {
        tool_type: tool_type.clone(),
        agent_history: AgentHistory::default(),
        intent_score: brain.intent_score,
        current_time: None,
        agent_id: Some(agent_id.clone()),
        method: Some(parsed.method.clone()),
        recent_request_count: 0,
        correlation_id: None,
    };
    let policy: PolicyDecision = state.policy.evaluate(policy_input).await;

    let allowed = brain.authorized && policy.allow && policy.review_reasons.is_empty();

    // -------- Ledger emission (always) --------
    // One entry per request, regardless of outcome. The full edition
    // emits two (proxy + policy NATS rows); Lite collapses to one
    // because the proxy and policy are the same process.
    let combined_reasoning = build_reasoning(&brain, &policy);
    let log_intent = if allowed {
        brain.intent_category.clone()
    } else if !policy.review_reasons.is_empty() {
        "ReviewSoftDeny".to_string()
    } else if brain.injection_detected {
        "PromptInjection".to_string()
    } else if !policy.allow {
        "PolicyDeny".to_string()
    } else {
        "BrainDeny".to_string()
    };

    let log_req = LogRequest {
        agent_id: agent_id.clone(),
        method: parsed.method.clone(),
        intent_category: log_intent,
        authorized: allowed,
        reasoning: combined_reasoning.clone(),
        policy_decision: serde_json::to_value(&policy).ok(),
    };
    if let Err(e) = state.ledger.append(log_req).await {
        tracing::warn!("ledger append failed: {}", e);
    }

    if !allowed {
        // Combine policy + brain reasons so the agent-side caller sees
        // the full audit string in one place. `review_reasons` is kept
        // separate in the JSON so callers that key on it (e.g., a
        // future Lite Web UI) don't have to substring-match.
        let mut reasons = policy.reasons.clone();
        if !brain.authorized {
            reasons.push(brain.reasoning.clone());
        }
        let resp = DenyResponse {
            error: "security_violation",
            reasons,
            review_reasons: policy.review_reasons.clone(),
            intent_category: brain.intent_category.clone(),
        };
        return (StatusCode::FORBIDDEN, Json(resp)).into_response();
    }

    // -------- Forward upstream --------
    let mut req_builder = state
        .http
        .post(&state.upstream_url)
        .header("Content-Type", "application/json")
        .body(body.clone());
    if let Some(api_key) = &state.upstream_api_key {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", api_key));
    }

    let upstream = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream unreachable: {}", e),
            )
                .into_response()
        }
    };

    let status = upstream.status();
    let upstream_body = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream body read error: {}", e),
            )
                .into_response()
        }
    };

    // Pass the upstream status + body through. Convert to axum's
    // expected types — `StatusCode::from_u16` wraps the upstream's
    // numeric status; the body rides through as `Bytes`.
    let out_status = StatusCode::from_u16(status.as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (out_status, upstream_body).into_response()
}

/// Concatenate brain + policy reasoning into one audit string.
fn build_reasoning(brain: &HeuristicVerdict, policy: &PolicyDecision) -> String {
    let policy_reasons = if policy.reasons.is_empty() {
        "no policy reasons".to_string()
    } else {
        policy.reasons.join(" | ")
    };
    let review = if policy.review_reasons.is_empty() {
        "".to_string()
    } else {
        format!(" | review: {}", policy.review_reasons.join(", "))
    };
    format!(
        "brain[{}]: {} | policy: {}{}",
        brain.intent_category, brain.reasoning, policy_reasons, review,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use crate::policy::PolicyEngine;
    use std::path::PathBuf;

    fn policies_dir() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("policies");
        p
    }

    #[tokio::test]
    async fn build_reasoning_includes_review() {
        let brain = HeuristicVerdict {
            authorized: true,
            intent_category: "Routine".to_string(),
            intent_score: 0.05,
            reasoning: "ok".to_string(),
            injection_detected: false,
            injection_confidence: 0.0,
            matched_signals: vec![],
        };
        let policy = PolicyDecision {
            allow: false,
            reasons: vec![],
            review_reasons: vec!["Review: Wire transfers require human approval before execution.".into()],
        };
        let s = build_reasoning(&brain, &policy);
        assert!(s.contains("review"));
        assert!(s.contains("Wire transfers"));
    }

    #[tokio::test]
    async fn full_pipeline_constructible() {
        // Smoke test that AppState can be wired up. Doesn't issue a
        // real request — that lives in tests/proxy_integration.rs
        // where we spawn a stub upstream.
        let policy = Arc::new(PolicyEngine::from_dir(&policies_dir(), 60).unwrap());
        let ledger = Arc::new(Ledger::open(":memory:").unwrap());
        let _state = Arc::new(AppState {
            policy,
            ledger,
            upstream_url: "http://127.0.0.1:0/never-called".into(),
            http: reqwest::Client::new(),
            bearer_token: None,
            upstream_api_key: None,
        });
    }
}
