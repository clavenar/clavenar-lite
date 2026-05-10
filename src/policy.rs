//! Embedded Rego policy engine (Layer 3, OSS edition).
//!
//! Thin wrapper around `regorus::Engine` that loads every `*.rego` file
//! under a configured policy directory at startup, and evaluates each
//! request against `data.warden.authz.{allow,deny,review}`. Same wire
//! shape as the full edition's `warden_policy_engine::PolicyDecision`,
//! so a custom `governance.rego` written for the full edition runs
//! verbatim under Lite (and vice versa).
//!
//! Lite differs from the full edition in two ways:
//!   1. No NATS publish — Lite is single-process, the ledger lives in
//!      the same binary, so we just call `append_entry` directly.
//!   2. No multi-instance velocity tracker. Lite is for single-laptop
//!      developer use; the in-process counter is plenty. The
//!      `recent_request_count` field on `PolicyInput` still exists so
//!      the same `governance.rego` shape works.

use regorus::{Engine, Value as RegoValue};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Input to a policy evaluation. Field-for-field compatible with the full
/// edition's `warden_policy_engine::PolicyInput` so a `governance.rego`
/// written for the full edition runs unchanged under Lite.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyInput {
    pub tool_type: String,
    pub agent_history: AgentHistory,
    pub intent_score: f32,
    pub current_time: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub recent_request_count: u32,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AgentHistory {
    pub last_tool: Option<String>,
}

/// Output of a policy evaluation. Mirrors the full edition's
/// `PolicyDecision` exactly.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyDecision {
    pub allow: bool,
    pub reasons: Vec<String>,
    /// In the full edition, non-empty `review_reasons` route the request
    /// to warden-hil for human approval. Lite has no HIL, so we treat
    /// any review match as a soft-deny — surfaced in the response but
    /// not auto-approved.
    #[serde(default)]
    pub review_reasons: Vec<String>,
}

/// Per-process velocity counter. Single mutex over a `HashMap<agent_id,
/// VecDeque<Instant>>`; on each call we evict entries older than the
/// configured window and return the remaining count. This is the same
/// `InProcessTracker` the full edition uses by default — Lite simply
/// doesn't expose the NATS-KV alternative.
pub struct VelocityTracker {
    inner: Mutex<std::collections::HashMap<String, std::collections::VecDeque<Instant>>>,
    window: std::time::Duration,
}

impl VelocityTracker {
    pub fn new(window_secs: u64) -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// Record a hit for `agent_id`, evict expired entries, return the
    /// resulting count (including the hit we just inserted).
    pub async fn record_and_count(&self, agent_id: &str) -> u32 {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let entry = map.entry(agent_id.to_string()).or_default();
        // Evict expired entries from the front. `pop_front_if` would be
        // cleaner but isn't stable; this is the same idiom as the full
        // edition's `InProcessTracker`.
        while let Some(&front) = entry.front() {
            if now.duration_since(front) > self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.push_back(now);
        entry.len() as u32
    }
}

pub struct PolicyEngine {
    engine: Mutex<Engine>,
    tracker: Arc<VelocityTracker>,
}

impl PolicyEngine {
    /// Load every `*.rego` file under `policy_dir` into a fresh regorus
    /// engine. Errors out if no policies are found — failing closed at
    /// startup is better than silently allowing every request because
    /// the user pointed at the wrong directory.
    pub fn from_dir(policy_dir: &Path, velocity_window_secs: u64) -> anyhow::Result<Self> {
        let mut engine = Engine::new();
        let entries = std::fs::read_dir(policy_dir)
            .map_err(|e| anyhow::anyhow!("read policy dir {}: {}", policy_dir.display(), e))?;

        let mut loaded = 0usize;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("rego") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("read {}: {}", path.display(), e))?;
            engine
                .add_policy(path.display().to_string(), text)
                .map_err(|e| anyhow::anyhow!("add_policy {}: {}", path.display(), e))?;
            loaded += 1;
        }

        if loaded == 0 {
            anyhow::bail!("no .rego files found in {}", policy_dir.display());
        }
        tracing::info!("loaded {} rego policy file(s) from {}", loaded, policy_dir.display());

        Ok(Self {
            engine: Mutex::new(engine),
            tracker: Arc::new(VelocityTracker::new(velocity_window_secs)),
        })
    }

    /// Evaluate a single decision. Internally records the request in the
    /// velocity tracker (when `agent_id` is set and the caller didn't
    /// pre-populate `recent_request_count`), serializes input to JSON,
    /// then queries `allow` / `deny` / `review`.
    pub async fn evaluate(&self, input: PolicyInput) -> PolicyDecision {
        // Inject live velocity count if the caller didn't preload one.
        // Tests can preload `recent_request_count` to drive the
        // circuit-breaker rule deterministically.
        let mut effective = input;
        if effective.recent_request_count == 0
            && let Some(agent_id) = &effective.agent_id
        {
            effective.recent_request_count =
                self.tracker.record_and_count(agent_id).await;
        }

        let input_json = match serde_json::to_string(&effective) {
            Ok(s) => s,
            Err(e) => {
                return PolicyDecision {
                    allow: false,
                    reasons: vec![format!("Policy input serialize error: {}", e)],
                    review_reasons: Vec::new(),
                }
            }
        };

        let mut guard = self.engine.lock().await;

        let deny_with = |reason: String| PolicyDecision {
            allow: false,
            reasons: vec![reason],
            review_reasons: Vec::new(),
        };
        let eval = |guard: &mut Engine, rule: &str, label: &str| -> Result<RegoValue, String> {
            guard
                .eval_rule(rule.to_string())
                .map_err(|e| format!("Policy engine error (eval {}): {}", label, e))
        };

        if let Err(e) = guard.set_input_json(&input_json) {
            return deny_with(format!("Policy engine error (set_input): {}", e));
        }

        let allow_value = match eval(&mut guard, "data.warden.authz.allow", "allow") {
            Ok(v) => v,
            Err(r) => return deny_with(r),
        };
        let deny_value = match eval(&mut guard, "data.warden.authz.deny", "deny") {
            Ok(v) => v,
            Err(r) => return deny_with(r),
        };
        let review_value = match eval(&mut guard, "data.warden.authz.review", "review") {
            Ok(v) => v,
            Err(r) => return deny_with(r),
        };
        drop(guard);

        let allow = matches!(allow_value, RegoValue::Bool(true));
        let mut reasons = extract_reasons(&deny_value);
        let review_reasons = extract_reasons(&review_value);

        if allow && reasons.is_empty() && review_reasons.is_empty() {
            reasons.push("Deterministic policy check passed.".to_string());
        }

        PolicyDecision {
            allow,
            reasons,
            review_reasons,
        }
    }
}

/// Pull `Vec<String>` out of a regorus `Value::Set` or `Value::Array`,
/// silently skipping any non-string entries. Sorted for stable output —
/// Rego sets are unordered and the audit surface is more useful when
/// reasons appear in a deterministic order across runs.
fn extract_reasons(deny: &RegoValue) -> Vec<String> {
    let mut out: Vec<String> = match deny {
        RegoValue::Set(items) => items
            .iter()
            .filter_map(|v| match v {
                RegoValue::String(s) => Some(s.to_string()),
                _ => None,
            })
            .collect(),
        RegoValue::Array(items) => items
            .iter()
            .filter_map(|v| match v {
                RegoValue::String(s) => Some(s.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn policies_dir() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("policies");
        p
    }

    #[tokio::test]
    async fn routine_request_allowed() {
        let engine = PolicyEngine::from_dir(&policies_dir(), 60).unwrap();
        let dec = engine
            .evaluate(PolicyInput {
                tool_type: "ping".into(),
                agent_history: AgentHistory::default(),
                intent_score: 0.05,
                current_time: Some("2026-05-02T12:00:00Z".into()),
                agent_id: Some("test-agent".into()),
                method: Some("call_tool".into()),
                recent_request_count: 0,
                correlation_id: None,
            })
            .await;
        assert!(dec.allow, "expected allow, got reasons={:?}", dec.reasons);
    }

    #[tokio::test]
    async fn sql_execute_blocked() {
        let engine = PolicyEngine::from_dir(&policies_dir(), 60).unwrap();
        let dec = engine
            .evaluate(PolicyInput {
                tool_type: "sql_execute".into(),
                agent_history: AgentHistory::default(),
                intent_score: 0.05,
                current_time: Some("2026-05-02T12:00:00Z".into()),
                agent_id: Some("test-agent".into()),
                method: Some("call_tool".into()),
                recent_request_count: 0,
                correlation_id: None,
            })
            .await;
        assert!(!dec.allow);
        assert!(dec.reasons.iter().any(|r| r.contains("SQL")));
    }

    #[tokio::test]
    async fn high_intent_score_blocks() {
        let engine = PolicyEngine::from_dir(&policies_dir(), 60).unwrap();
        let dec = engine
            .evaluate(PolicyInput {
                tool_type: "ping".into(),
                agent_history: AgentHistory::default(),
                intent_score: 0.9,
                current_time: Some("2026-05-02T12:00:00Z".into()),
                agent_id: Some("test-agent".into()),
                method: Some("call_tool".into()),
                recent_request_count: 0,
                correlation_id: None,
            })
            .await;
        assert!(!dec.allow);
        assert!(dec.reasons.iter().any(|r| r.contains("Intent score")));
    }

    #[tokio::test]
    async fn wire_transfer_review_tier() {
        let engine = PolicyEngine::from_dir(&policies_dir(), 60).unwrap();
        let dec = engine
            .evaluate(PolicyInput {
                tool_type: "wire_transfer".into(),
                agent_history: AgentHistory::default(),
                intent_score: 0.05,
                current_time: Some("2026-05-02T12:00:00Z".into()),
                agent_id: Some("test-agent".into()),
                method: Some("call_tool".into()),
                recent_request_count: 0,
                correlation_id: None,
            })
            .await;
        // In Lite, review-tier matches mean allow=false (because the
        // governance.rego `allow` block requires `count(review) == 0`).
        assert!(!dec.allow);
        assert!(!dec.review_reasons.is_empty());
        assert!(dec.review_reasons[0].contains("Wire transfer"));
    }

    #[tokio::test]
    async fn velocity_tracker_records_hits() {
        let tracker = VelocityTracker::new(60);
        for _ in 0..5 {
            tracker.record_and_count("burst-agent").await;
        }
        let count = tracker.record_and_count("burst-agent").await;
        assert_eq!(count, 6);
    }

    #[tokio::test]
    async fn velocity_breaker_at_threshold() {
        let engine = PolicyEngine::from_dir(&policies_dir(), 60).unwrap();
        let dec = engine
            .evaluate(PolicyInput {
                tool_type: "ping".into(),
                agent_history: AgentHistory::default(),
                intent_score: 0.05,
                current_time: Some("2026-05-02T12:00:00Z".into()),
                agent_id: Some("hot-agent".into()),
                method: Some("call_tool".into()),
                // Pre-loaded — exercise the rule without firing 100+ requests.
                recent_request_count: 150,
                correlation_id: None,
            })
            .await;
        assert!(!dec.allow);
        assert!(dec
            .reasons
            .iter()
            .any(|r| r.contains("Token velocity") || r.contains("velocity")));
    }
}
