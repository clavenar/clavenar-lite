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
//! HIL roundtrip, and no Vault — Lite is for developer-laptop use
//! where the agent already has its own creds.
//!
//! # Authentication
//!
//! Lite supports an optional bearer-token auth pre-shared via
//! `WARDEN_LITE_TOKEN` or — for multi-agent deployments — an explicit
//! `WARDEN_LITE_AGENTS` registry mapping tokens to agent ids. If
//! neither is configured, the proxy accepts every connection (fine
//! for `127.0.0.1` developer use). If either is configured, every
//! request must send `Authorization: Bearer <token>` or it's 401.
//! mTLS is the full edition's job.
//!
//! ## Multi-agent
//!
//! `WARDEN_LITE_AGENTS=agent-a:tok-a,agent-b:tok-b` registers two
//! distinct agents behind the same proxy. The token that matched
//! determines the `agent_id` recorded on the ledger entry and surfaced
//! to the policy engine — Rego rules can branch on `input.agent_id`
//! to scope tool access per agent. Tokens must be unique across
//! agents; duplicates fail boot.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::heuristics::{self, HeuristicVerdict};
use crate::ledger::{
    DecideError, Ledger, LogRequest, ParkRequest, Pending, PendingFilter, PendingSort,
};
use crate::policy::{AgentHistory, PolicyDecision, PolicyEngine, PolicyInput};

const CORRELATION_HEADER: &str = "X-Warden-Correlation-Id";

/// Stamp the standard warden response headers on a response.
/// `correlation_id` is included unconditionally — even auth-fail and
/// parse-error responses get one, so partners can trace rejected
/// attempts through the access log. `mode` is the current
/// {@link WardenMode}; `would_deny` / `would_pend` only matter in
/// observe (in enforce mode the pipeline already short-circuited with
/// a 403 or 202 before this header would have meaning).
fn warden_headers(
    correlation_id: &str,
    mode: WardenMode,
    would_deny: bool,
    would_pend: bool,
) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        CORRELATION_HEADER,
        correlation_id.parse().expect("uuid is ascii"),
    );
    h.insert(
        "X-Warden-Mode",
        mode.as_str().parse().expect("mode is ascii"),
    );
    if would_deny {
        h.insert(
            "X-Warden-Would-Deny",
            "true".parse().expect("static ascii"),
        );
    }
    if would_pend {
        h.insert(
            "X-Warden-Would-Pend",
            "true".parse().expect("static ascii"),
        );
    }
    h
}

/// Enforcement posture. `Enforce` is the default and returns 403 on a
/// would-deny; `Observe` is the rollout knob — every request forwards
/// upstream regardless of the security pipeline's verdict, and the
/// response carries `X-Warden-Would-Deny: true` for partners who want
/// to count would-have-denies before they flip enforcement on. The
/// ledger entry is unaffected: `authorized=false` still gets written
/// for a would-deny in observe mode, so the audit trail of what the
/// pipeline *would* have done stays accurate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WardenMode {
    Enforce,
    Observe,
}

impl WardenMode {
    fn as_str(self) -> &'static str {
        match self {
            WardenMode::Enforce => "enforce",
            WardenMode::Observe => "observe",
        }
    }
}

/// Maps a bearer token to a per-agent identity. `None` in
/// `AppState.agents` means inbound auth is disabled entirely (every
/// request is treated as `agent_id="anonymous"`); a single-entry
/// registry built from `WARDEN_LITE_TOKEN` keeps the v0.x
/// single-agent default of `agent_id="bearer-agent"`; a multi-entry
/// registry built from `WARDEN_LITE_AGENTS` gives each token its own
/// `agent_id`.
#[derive(Debug, Clone)]
pub struct AgentRegistry {
    by_token: HashMap<String, String>,
}

impl AgentRegistry {
    /// Build a registry from the v0.x single-token form. Used as the
    /// fallback when `WARDEN_LITE_AGENTS` is unset but `WARDEN_LITE_TOKEN`
    /// is set — the lone token maps to `agent_id="bearer-agent"`.
    pub fn single(token: String) -> Self {
        let mut by_token = HashMap::new();
        by_token.insert(token, "bearer-agent".to_string());
        Self { by_token }
    }

    /// Build a multi-agent registry from the `id:token,id:token` form
    /// of `WARDEN_LITE_AGENTS`. Tokens must be unique; agent ids must
    /// be non-empty and may contain `[A-Za-z0-9_-]`. Duplicate tokens
    /// or malformed entries return `Err` so the binary exits at boot.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut by_token: HashMap<String, String> = HashMap::new();
        for raw in spec.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            let (id, token) = entry
                .split_once(':')
                .ok_or_else(|| format!("agent registry entry missing ':' separator: {entry:?}"))?;
            let id = id.trim();
            let token = token.trim();
            if id.is_empty() {
                return Err(format!("agent registry entry has empty id: {entry:?}"));
            }
            if token.is_empty() {
                return Err(format!("agent registry entry {id:?} has empty token"));
            }
            if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(format!(
                    "agent registry id {id:?} must match [A-Za-z0-9_-]"
                ));
            }
            if let Some(existing) = by_token.insert(token.to_string(), id.to_string()) {
                return Err(format!(
                    "agent registry has duplicate token shared by {existing:?} and {id:?}"
                ));
            }
        }
        if by_token.is_empty() {
            return Err("agent registry is empty (no id:token pairs parsed)".to_string());
        }
        Ok(Self { by_token })
    }

    /// Lookup agent_id for a supplied bearer token. `None` means the
    /// token does not match any registered agent and the request
    /// should be rejected with 401.
    pub fn lookup(&self, token: &str) -> Option<&str> {
        // Constant-time compare per-entry — the matching prefix length
        // does not leak via response timing.
        for (registered_token, agent_id) in &self.by_token {
            if constant_time_eq(token.as_bytes(), registered_token.as_bytes()) {
                return Some(agent_id);
            }
        }
        None
    }

    /// Count of registered agents. Used by the boot log.
    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    /// Always non-empty after a successful build (`parse` and
    /// `single` both refuse to construct an empty registry); the
    /// method exists only to satisfy `clippy::len_without_is_empty`.
    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }

    /// Pretty-print the registered agent ids (not the tokens) for
    /// boot logging.
    pub fn agent_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.by_token.values().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }
}

/// Shared state behind an `Arc`. Cloned per-request via `State<Arc<...>>`.
pub struct AppState {
    pub policy: Arc<PolicyEngine>,
    pub ledger: Arc<Ledger>,
    pub upstream_url: String,
    pub http: reqwest::Client,
    /// Optional per-agent identity registry. `None` means inbound auth
    /// is disabled (developer-laptop default). A single-entry registry
    /// preserves the v0.x `bearer-agent` behavior; a multi-entry
    /// registry gives each token a distinct `agent_id`.
    pub agents: Option<AgentRegistry>,
    /// Optional bearer token gating `POST /pending/{id}/decide`. Held
    /// separately from `bearer_token` because the agent identity that
    /// drives `/mcp` is a strictly weaker capability than the operator
    /// identity that approves parked requests — sharing one token would
    /// silently grant agents the ability to approve their own pendings.
    /// `None` means decide is open (developer-laptop default).
    pub decide_token: Option<String>,
    /// Pre-shared upstream API key, injected into the forwarded request
    /// as `Authorization: Bearer <key>`. Same role as the full
    /// edition's Vault credential injection — minus Vault. `None` means
    /// don't inject (the upstream is responsible for its own auth).
    pub upstream_api_key: Option<String>,
    /// Enforcement posture (see {@link WardenMode}).
    pub mode: WardenMode,
    /// Optional Slack-incoming-webhook URL. When set, every yellow-tier
    /// park spawns a fire-and-forget POST with a formatted alert. No
    /// return path — operators decide via `warden-lite pending decide`
    /// or curl.
    pub slack_webhook_url: Option<String>,
    /// Async-HIL callback URL allowlist. Each entry is a literal URL
    /// prefix; an inbound `X-Warden-Callback-URL` header is accepted
    /// only if it starts with one of these prefixes. Empty list (the
    /// default) means callback URLs are rejected entirely — partners
    /// must poll. The allowlist protects against agents using
    /// warden-lite as a reflector to ping arbitrary internal URLs.
    pub callback_allowlist: Vec<String>,
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

/// Response we emit on a yellow-tier park (202 Accepted). The SDK
/// constructs the poll/decide URLs from its endpoint config and the
/// `correlation_id`; we deliberately return relative-only state here
/// to avoid the external-URL ambiguity (Caddy/LB rewrites, custom
/// paths).
#[derive(Debug, Serialize)]
struct PendingResponse {
    status: &'static str,
    correlation_id: String,
    review_reasons: Vec<String>,
}

/// Three-way outcome of running brain + policy on one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// Brain green + policy.allow + no review_reasons → forward.
    Green,
    /// `policy.allow && !review_reasons.is_empty()` — the pipeline
    /// wants a human to look before it forwards. Parked in `pendings`
    /// and returned as 202 in enforce mode.
    Yellow,
    /// Brain red or `!policy.allow` — hard deny (403 in enforce).
    Red,
}

fn classify(brain: &HeuristicVerdict, policy: &PolicyDecision) -> Tier {
    if !brain.authorized || !policy.allow {
        Tier::Red
    } else if !policy.review_reasons.is_empty() {
        Tier::Yellow
    } else {
        Tier::Green
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // `/` kept as an alias so the fly.toml health check (which
        // targets `/`) continues to pass without a config rev.
        // `/health` + `/readyz` match the cross-service convention
        // every other warden-* service exposes — kubelet liveness
        // probes target `/health`, readiness probes `/readyz`.
        .route("/", get(health))
        .route("/health", get(health))
        .route("/readyz", get(readyz))
        .route("/mcp", post(handle_mcp))
        .route("/pending", get(handle_list_pendings))
        .route("/pending/:id", get(handle_get_pending))
        .route("/pending/:id/decide", post(handle_decide_pending))
        .with_state(state)
}

async fn health() -> &'static str {
    "Agent Warden Lite is active."
}

/// Readiness probe — returns 200 once the in-process ledger + policy
/// engine are wired (i.e. always, after boot). Same wire shape as the
/// full-stack services (`{status, checks}`) so a single Helm probe
/// template parses any warden component. Lite has no external
/// dependency to poll (SQLite is in-process; brain + policy live in
/// the same binary), so the checks map is intentionally empty.
async fn readyz() -> (axum::http::StatusCode, axum::Json<ReadinessResponse>) {
    (
        axum::http::StatusCode::OK,
        axum::Json(ReadinessResponse {
            status: "ready",
            checks: std::collections::BTreeMap::new(),
        }),
    )
}

/// Wire shape for `/readyz`. Mirrors the duplicate-on-purpose pattern
/// in warden-brain, warden-policy-engine, warden-ledger, warden-hil,
/// and warden-identity — keeping it inline avoids a shared crate for
/// one tiny struct that almost never changes.
#[derive(serde::Serialize)]
struct ReadinessResponse {
    status: &'static str,
    checks: std::collections::BTreeMap<&'static str, &'static str>,
}

/// Decision payload posted by an operator (or by a Slack bot, or the
/// HIL UI when one exists). `decision` is the only required field;
/// `note` is a free-text reason that surfaces in the audit ledger.
#[derive(Debug, Deserialize)]
struct DecideRequest {
    decision: String,
    #[serde(default)]
    note: Option<String>,
}

/// JSON shape returned by `POST /pending/{id}/decide` and by the
/// poll endpoint (Wed). Mirrors the SQLite `Pending` row except
/// `requested_at` / `decided_at` are RFC 3339 strings so the wire
/// format is language-agnostic.
#[derive(Debug, Serialize)]
struct PendingView {
    correlation_id: String,
    agent_id: String,
    tool_type: String,
    method: String,
    review_reasons: Vec<String>,
    requested_at: String,
    decided_at: Option<String>,
    decision: Option<String>,
    decider_note: Option<String>,
}

impl From<Pending> for PendingView {
    fn from(p: Pending) -> Self {
        PendingView {
            correlation_id: p.correlation_id,
            agent_id: p.agent_id,
            tool_type: p.tool_type,
            method: p.method,
            review_reasons: p.review_reasons,
            requested_at: p.requested_at.to_rfc3339(),
            decided_at: p.decided_at.map(|t| t.to_rfc3339()),
            decision: p.decision,
            decider_note: p.decider_note,
        }
    }
}

/// Query string params for `GET /pending`. `status` defaults to
/// `parked` (operator triage view). `limit` defaults to 50 and is
/// hard-capped server-side at 500 — a misconfigured client asking for
/// 1M rows can't exhaust memory.
#[derive(Debug, Deserialize)]
struct ListPendingParams {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    /// `oldest` (triage queue) or `newest` (history). Default depends
    /// on the status filter — `parked` reads oldest-first (handle the
    /// longest-waiting first), `decided`/`all` read newest-first
    /// (recent decisions are usually more interesting).
    #[serde(default)]
    sort: Option<String>,
}

const LIST_PENDING_DEFAULT_LIMIT: u32 = 50;
const LIST_PENDING_MAX_LIMIT: u32 = 500;

async fn handle_list_pendings(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListPendingParams>,
    headers: HeaderMap,
) -> Response {
    // Listing pendings is an operator capability — same token gate as
    // `decide`. Auth is required if `--decide-token` was set at boot;
    // otherwise the endpoint is open (single-user developer mode).
    let corr = Uuid::new_v4().to_string();
    if let Some(expected) = &state.decide_token {
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let ok = match supplied {
            Some(s) => constant_time_eq(s.as_bytes(), expected.as_bytes()),
            None => false,
        };
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                warden_headers(&corr, state.mode, false, false),
                "missing or invalid decide token",
            )
                .into_response();
        }
    }

    let filter = match params.status.as_deref() {
        None | Some("parked") => PendingFilter::Parked,
        Some("decided") => PendingFilter::Decided,
        Some("all") => PendingFilter::All,
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                warden_headers(&corr, state.mode, false, false),
                format!(
                    "unknown status filter {:?} (want parked|decided|all)",
                    other
                ),
            )
                .into_response();
        }
    };
    let sort = match params.sort.as_deref() {
        None => match filter {
            PendingFilter::Parked => PendingSort::Oldest,
            PendingFilter::Decided | PendingFilter::All => PendingSort::Newest,
        },
        Some("oldest") => PendingSort::Oldest,
        Some("newest") => PendingSort::Newest,
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                warden_headers(&corr, state.mode, false, false),
                format!("unknown sort {:?} (want oldest|newest)", other),
            )
                .into_response();
        }
    };
    let limit = params
        .limit
        .unwrap_or(LIST_PENDING_DEFAULT_LIMIT)
        .min(LIST_PENDING_MAX_LIMIT);

    match state.ledger.list_pendings(filter, limit, sort).await {
        Ok(rows) => {
            let views: Vec<PendingView> = rows.into_iter().map(PendingView::from).collect();
            (
                StatusCode::OK,
                warden_headers(&corr, state.mode, false, false),
                Json(views),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("list_pendings sqlite failure: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                warden_headers(&corr, state.mode, false, false),
                "internal ledger error",
            )
                .into_response()
        }
    }
}

async fn handle_get_pending(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let poll_corr = Uuid::new_v4().to_string();

    // Reuse the agent registry for poll auth. Polling is a strictly
    // read-only capability the SDK needs after parking a tool call,
    // so the same identity that issued the `/mcp` call is the natural
    // caller — any registered agent's bearer can read any correlation
    // id. Lite does not scope polls per-correlation-id; for
    // production per-agent isolation, ship to the full edition.
    if let Some(registry) = &state.agents {
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let ok = supplied.is_some_and(|s| registry.lookup(s).is_some());
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                warden_headers(&poll_corr, state.mode, false, false),
                "missing or invalid bearer token",
            )
                .into_response();
        }
    }

    match state.ledger.get_pending(&id).await {
        Ok(Some(p)) => (
            StatusCode::OK,
            warden_headers(&poll_corr, state.mode, false, false),
            Json(PendingView::from(p)),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            warden_headers(&poll_corr, state.mode, false, false),
            format!("no pending with correlation_id {}", id),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("get_pending sqlite failure: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                warden_headers(&poll_corr, state.mode, false, false),
                "internal ledger error",
            )
                .into_response()
        }
    }
}

async fn handle_decide_pending(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Decide-token auth, structurally mirrors /mcp's check but reads
    // a separate token so operator and agent capabilities don't
    // collapse into one secret. Each response carries a freshly minted
    // correlation id for access-log tracing — we do NOT reuse the
    // pending's `id` here because the access-log line tracks the
    // decide HTTP call, not the original tool call.
    let decide_corr = Uuid::new_v4().to_string();
    if let Some(expected) = &state.decide_token {
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let ok = match supplied {
            Some(s) => constant_time_eq(s.as_bytes(), expected.as_bytes()),
            None => false,
        };
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                warden_headers(&decide_corr, state.mode, false, false),
                "missing or invalid decide token",
            )
                .into_response();
        }
    }

    let req: DecideRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                warden_headers(&decide_corr, state.mode, false, false),
                format!("invalid decision body: {}", e),
            )
                .into_response();
        }
    };

    let decided = match state
        .ledger
        .decide_pending(&id, &req.decision, req.note.as_deref())
        .await
    {
        Ok(p) => p,
        Err(DecideError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                warden_headers(&decide_corr, state.mode, false, false),
                format!("no pending with correlation_id {}", id),
            )
                .into_response();
        }
        Err(DecideError::AlreadyDecided) => {
            return (
                StatusCode::CONFLICT,
                warden_headers(&decide_corr, state.mode, false, false),
                "pending already decided",
            )
                .into_response();
        }
        Err(DecideError::InvalidDecision(d)) => {
            return (
                StatusCode::BAD_REQUEST,
                warden_headers(&decide_corr, state.mode, false, false),
                format!(
                    "invalid decision {:?}: expected \"allow\" or \"deny\"",
                    d
                ),
            )
                .into_response();
        }
        Err(DecideError::Sqlite(e)) => {
            tracing::error!("decide_pending sqlite failure: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                warden_headers(&decide_corr, state.mode, false, false),
                "internal ledger error",
            )
                .into_response();
        }
    };

    // Forensic chain: write a second ledger entry tied to the same
    // correlation_id as the park row. `intent_category` distinguishes
    // the operator-driven decision from the pipeline's original park,
    // and `authorized` reflects the final outcome (true on allow, false
    // on deny). The original agent_id is preserved so `audit <agent>`
    // surfaces both the park and the resolve.
    let (intent, authorized) = if decided.decision.as_deref() == Some("allow") {
        ("PendingApproved", true)
    } else {
        ("PendingDenied", false)
    };
    let reasoning = format_decide_reasoning(&decided);
    let log_req = LogRequest {
        agent_id: decided.agent_id.clone(),
        method: decided.method.clone(),
        intent_category: intent.to_string(),
        authorized,
        reasoning,
        policy_decision: None,
        correlation_id: Some(decided.correlation_id.clone()),
    };
    if let Err(e) = state.ledger.append(log_req).await {
        // The pendings row is already flipped, so the operator's
        // decision is durable; only the audit-trail second row is
        // missing. Log loudly and still return success — losing the
        // audit row on a transient SQLite hiccup is the wrong reason
        // to surface a 500 for a decision the operator already made.
        tracing::error!("decide-ledger append failed (decision still recorded): {}", e);
    }

    // Async-HIL webhook: if the agent registered a callback URL at
    // park time, fire-and-forget POST the decision. Spawn so the
    // operator's HTTP response doesn't wait on a flaky partner
    // endpoint — the pendings row is the durable source of truth and
    // the partner can always fall back to polling.
    if let Some(url) = decided.callback_url.clone() {
        let http = state.http.clone();
        let body_owned = (
            decided.correlation_id.clone(),
            decided.decision.clone().unwrap_or_default(),
            decided.decider_note.clone(),
            decided.decided_at.map(|t| t.to_rfc3339()),
        );
        tokio::spawn(async move {
            let (corr, decision, note, ts) = &body_owned;
            fire_callback(
                http,
                url,
                CallbackBody {
                    correlation_id: corr,
                    decision,
                    decider_note: note.as_deref(),
                    decided_at: ts.clone(),
                },
            )
            .await;
        });
    }

    (
        StatusCode::OK,
        warden_headers(&decide_corr, state.mode, false, false),
        Json(PendingView::from(decided)),
    )
        .into_response()
}

/// Build the audit-string for the decide ledger entry. Includes the
/// original review reasons (so the audit row tells the full story
/// without needing to join back to `pendings`) plus the operator's
/// note when present.
fn format_decide_reasoning(p: &Pending) -> String {
    let reviews = if p.review_reasons.is_empty() {
        "no review reasons".to_string()
    } else {
        p.review_reasons.join(" | ")
    };
    let note = p
        .decider_note
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!(" | note: {}", s))
        .unwrap_or_default();
    format!(
        "decide[{}] review: {}{}",
        p.decision.as_deref().unwrap_or("?"),
        reviews,
        note
    )
}

const CALLBACK_HEADER: &str = "X-Warden-Callback-URL";

/// Validate the inbound `X-Warden-Callback-URL` header against the
/// configured allowlist. Returns:
///
/// - `Ok(None)` if no header was supplied (the partner is on the
///   polling path).
/// - `Ok(Some(url))` if the header is present, syntactically a URL,
///   and matches one of the configured allowlist prefixes.
/// - `Err(reason)` for an empty allowlist + non-empty header, a
///   malformed URL, or a URL outside the allowlist. The reason
///   string is surfaced verbatim in the 400 response body so the
///   partner can fix their config.
fn validate_callback_url(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Option<String>, String> {
    let raw = match headers.get(CALLBACK_HEADER).and_then(|v| v.to_str().ok()) {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };
    if state.callback_allowlist.is_empty() {
        return Err(format!(
            "{} supplied but no allowlist is configured on this warden-lite; \
             set WARDEN_LITE_CALLBACK_ALLOWLIST to enable async-HIL webhooks",
            CALLBACK_HEADER
        ));
    }
    if reqwest::Url::parse(raw).is_err() {
        return Err(format!("{} is not a valid URL: {:?}", CALLBACK_HEADER, raw));
    }
    if !state
        .callback_allowlist
        .iter()
        .any(|prefix| raw.starts_with(prefix.as_str()))
    {
        return Err(format!(
            "{} {:?} is not on the configured allowlist",
            CALLBACK_HEADER, raw
        ));
    }
    Ok(Some(raw.to_string()))
}

/// Wire shape for the async-HIL callback POST body. Mirrors the GET
/// /pending/{id} view but trimmed to the fields a partner needs to
/// flip its in-memory pending registry on receipt.
#[derive(Debug, Serialize)]
struct CallbackBody<'a> {
    correlation_id: &'a str,
    decision: &'a str,
    decider_note: Option<&'a str>,
    decided_at: Option<String>,
}

/// Fire-and-forget POST of a decision to a partner's callback URL.
/// Never blocks the operator's decide response — failures land in
/// the trace log and the partner falls back to polling.
async fn fire_callback(http: reqwest::Client, url: String, body: CallbackBody<'_>) {
    let payload = match serde_json::to_vec(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("callback {}: serialize failed: {}", url, e);
            return;
        }
    };
    let res = http
        .post(&url)
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .body(payload)
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => {
            tracing::info!("callback {}: delivered ({})", url, r.status());
        }
        Ok(r) => {
            tracing::warn!("callback {}: returned non-2xx {}", url, r.status());
        }
        Err(e) => {
            tracing::warn!("callback {}: send failed: {}", url, e);
        }
    }
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
    metrics::counter!("warden_lite_inspect_total").increment(1);

    // Mint the correlation id BEFORE any auth check so every response
    // — including 401s — carries a trace id. Partners filter the
    // ledger by this id from the X-Warden-Correlation-Id header on
    // the throw they catch SDK-side.
    let correlation_id = Uuid::new_v4().to_string();

    // Bearer auth (if configured). `Authorization: Bearer <token>` —
    // any other shape is 401. Compared in constant time so the
    // matching-prefix length does not leak via response timing. In a
    // multi-agent registry, the matched token also yields the
    // `agent_id` we tag the request with.
    let agent_id: String = match &state.agents {
        Some(registry) => {
            let supplied = headers
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "));
            let matched = supplied.and_then(|s| registry.lookup(s));
            match matched {
                Some(id) => id.to_string(),
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        warden_headers(&correlation_id, state.mode, false, false),
                        "missing or invalid bearer token",
                    )
                        .into_response();
                }
            }
        }
        None => "anonymous".to_string(),
    };

    // Optional async-HIL callback URL. If the agent supplied a
    // `X-Warden-Callback-URL` header, validate it against the
    // configured allowlist BEFORE doing any pipeline work. Reject
    // with 400 if the URL isn't on the allowlist — fail-loud so the
    // partner can fix their config.
    let callback_url: Option<String> = match validate_callback_url(&headers, &state) {
        Ok(v) => v,
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                warden_headers(&correlation_id, state.mode, false, false),
                reason,
            )
                .into_response();
        }
    };

    // Parse + validate the request body. We use a permissive shape so
    // the proxy doesn't refuse otherwise-valid MCP variants we don't
    // happen to model — only `method` is required.
    let parsed: McpRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                warden_headers(&correlation_id, state.mode, false, false),
                format!("invalid JSON-RPC body: {}", e),
            )
                .into_response();
        }
    };
    // JSON-RPC 2.0 §4: `method` must be a non-empty string. Without
    // this guard an empty method slides through to Brain / policy as
    // tool_type="" and matches no rule, silently allowing the request.
    if parsed.method.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            warden_headers(&correlation_id, state.mode, false, false),
            "method must be a non-empty string",
        )
            .into_response();
    }

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
        correlation_id: Some(correlation_id.clone()),
    };
    let policy: PolicyDecision = state.policy.evaluate(policy_input).await;

    let tier = classify(&brain, &policy);

    // -------- Ledger emission (always) --------
    // One entry per request at this orchestration step, regardless of
    // outcome. Yellow-tier parks get a second entry when the operator
    // decides (see Tue's decide endpoint). The full edition emits two
    // (proxy + policy NATS rows); Lite collapses to one because the
    // proxy and policy are the same process.
    let combined_reasoning = build_reasoning(&brain, &policy);
    let log_intent = match tier {
        Tier::Green => brain.intent_category.clone(),
        Tier::Yellow => "PendingReview".to_string(),
        Tier::Red if brain.injection_detected => "PromptInjection".to_string(),
        Tier::Red if !policy.allow => "PolicyDeny".to_string(),
        Tier::Red => "BrainDeny".to_string(),
    };
    let log_authorized = matches!(tier, Tier::Green);

    let log_req = LogRequest {
        agent_id: agent_id.clone(),
        method: parsed.method.clone(),
        intent_category: log_intent,
        authorized: log_authorized,
        reasoning: combined_reasoning.clone(),
        policy_decision: serde_json::to_value(&policy).ok(),
        correlation_id: Some(correlation_id.clone()),
    };
    if let Err(e) = state.ledger.append(log_req).await {
        tracing::warn!("ledger append failed: {}", e);
    }

    let would_deny = matches!(tier, Tier::Red);
    let would_pend = matches!(tier, Tier::Yellow);

    // -------- Yellow tier: park + 202 (enforce) or forward + flag (observe) --------
    if would_pend && state.mode == WardenMode::Enforce {
        // Park the request for human review. The operator (Tue's
        // decide endpoint) flips this row; SDK polls (Wed's GET
        // endpoint) to learn the outcome.
        let park = ParkRequest {
            correlation_id: correlation_id.clone(),
            agent_id: agent_id.clone(),
            tool_type: tool_type.clone(),
            method: parsed.method.clone(),
            review_reasons: policy.review_reasons.clone(),
            callback_url: callback_url.clone(),
        };
        let parked = match state.ledger.park_pending(park).await {
            Ok(p) => p,
            Err(e) => {
                // Park failed (most likely a duplicate correlation_id —
                // shouldn't happen with Uuid::new_v4 but be defensive).
                // Surface it as a 500 rather than silently 202'ing
                // without backing state.
                tracing::error!("park_pending failed: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    warden_headers(&correlation_id, state.mode, false, false),
                    "failed to park pending request",
                )
                    .into_response();
            }
        };

        // Fire-and-forget Slack alert if configured. The agent's 202
        // never waits on Slack — a flaky webhook would otherwise
        // bottleneck every parked tool call.
        if let Some(url) = &state.slack_webhook_url {
            let http = state.http.clone();
            let url = url.clone();
            tokio::spawn(async move {
                crate::slack::notify_pending_parked(&http, &url, &parked).await;
            });
        }

        let resp = PendingResponse {
            status: "pending",
            correlation_id: correlation_id.clone(),
            review_reasons: policy.review_reasons.clone(),
        };
        return (
            StatusCode::ACCEPTED,
            warden_headers(&correlation_id, state.mode, false, false),
            Json(resp),
        )
            .into_response();
    }

    if would_deny && state.mode == WardenMode::Enforce {
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
        return (
            StatusCode::FORBIDDEN,
            warden_headers(&correlation_id, state.mode, false, false),
            Json(resp),
        )
            .into_response();
    }
    // Observe mode falls through to the upstream forward even when
    // the pipeline would have denied or parked — the partner still
    // gets a real response, and X-Warden-Would-Deny / X-Warden-Would-Pend
    // below tell them what enforce mode would have done.

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
                warden_headers(&correlation_id, state.mode, would_deny, would_pend),
                format!("upstream unreachable: {}", e),
            )
                .into_response();
        }
    };

    let status = upstream.status();
    let upstream_body = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                warden_headers(&correlation_id, state.mode, would_deny, would_pend),
                format!("upstream body read error: {}", e),
            )
                .into_response();
        }
    };

    // Pass the upstream status + body through. Convert to axum's
    // expected types — `StatusCode::from_u16` wraps the upstream's
    // numeric status; the body rides through as `Bytes`.
    let out_status = StatusCode::from_u16(status.as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        out_status,
        warden_headers(&correlation_id, state.mode, would_deny, would_pend),
        upstream_body,
    )
        .into_response()
}

/// Byte-equality in time proportional to `expected.len()`. Used for
/// the bearer-token check so a partial-prefix match isn't detectable
/// by request latency.
fn constant_time_eq(supplied: &[u8], expected: &[u8]) -> bool {
    if supplied.len() != expected.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..expected.len() {
        diff |= supplied[i] ^ expected[i];
    }
    diff == 0
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

    #[test]
    fn constant_time_eq_matches_only_full_value() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrex"));
        assert!(!constant_time_eq(b"secre", b"secret"));
        assert!(!constant_time_eq(b"secret-extra", b"secret"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn agent_registry_single_round_trips() {
        let r = AgentRegistry::single("tok-x".to_string());
        assert_eq!(r.len(), 1);
        assert_eq!(r.lookup("tok-x"), Some("bearer-agent"));
        assert_eq!(r.lookup("tok-y"), None);
    }

    #[test]
    fn agent_registry_parses_multi() {
        let r = AgentRegistry::parse("agent-a:tok-a, agent-b:tok-b").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r.lookup("tok-a"), Some("agent-a"));
        assert_eq!(r.lookup("tok-b"), Some("agent-b"));
        assert_eq!(r.lookup("tok-c"), None);
    }

    #[test]
    fn agent_registry_rejects_duplicate_tokens() {
        let err = AgentRegistry::parse("agent-a:tok-x,agent-b:tok-x").unwrap_err();
        assert!(err.contains("duplicate token"));
    }

    #[test]
    fn agent_registry_rejects_missing_separator() {
        let err = AgentRegistry::parse("agent-a-no-colon").unwrap_err();
        assert!(err.contains("missing ':'"));
    }

    #[test]
    fn agent_registry_rejects_empty_id_or_token() {
        assert!(AgentRegistry::parse(":tok").is_err());
        assert!(AgentRegistry::parse("agent:").is_err());
    }

    #[test]
    fn agent_registry_rejects_bad_id_chars() {
        let err = AgentRegistry::parse("agent.with.dots:tok").unwrap_err();
        assert!(err.contains("[A-Za-z0-9_-]"));
    }

    #[test]
    fn agent_registry_rejects_empty_spec() {
        assert!(AgentRegistry::parse("").is_err());
        assert!(AgentRegistry::parse("   , ,").is_err());
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
            agents: None,
            decide_token: None,
            upstream_api_key: None,
            mode: WardenMode::Enforce,
            slack_webhook_url: None,
            callback_allowlist: Vec::new(),
        });
    }
}
