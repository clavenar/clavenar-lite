//! Outbound verdict webhooks — structured JSON POSTs to an operator
//! SIEM / Datadog HTTP sink / generic webhook receiver.
//!
//! Distinct from [`crate::slack`]: Slack notifications are
//! Slack-flavored Markdown alerts targeted at a human approver; this
//! module emits machine-readable JSON, one event per terminal
//! pipeline outcome (and one per operator decide), so partner
//! ingest pipelines can index every verdict without parsing human
//! prose.
//!
//! Fire-and-forget by design: every emission is spawned onto the
//! tokio runtime by the caller, with a hard 5-second per-request
//! timeout. A wedged or slow sink never delays the agent's response
//! or the operator's decide ack. The ledger remains the durable
//! source of truth; the webhook is observability, not a write path.
//!
//! Wire shape is stable v1: SIEM queries grep on these JSON keys, so
//! field renames are a breaking change. New fields can be added; old
//! fields stay until v2.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::time::Duration;

/// Event variant. The discriminator a SIEM rule keys on. Keep these
/// strings stable across releases.
pub const EVENT_ALLOW: &str = "allow";
pub const EVENT_DENY: &str = "deny";
pub const EVENT_PARK: &str = "park";
pub const EVENT_DECIDE_ALLOW: &str = "decide_allow";
pub const EVENT_DECIDE_DENY: &str = "decide_deny";
pub const EVENT_WOULD_DENY: &str = "would_deny";
pub const EVENT_WOULD_PARK: &str = "would_park";

/// Wire shape of an outbound webhook POST. One event per terminal
/// pipeline outcome plus one per operator decide. Borrowed strings
/// avoid cloning in the hot path; the serializer copies once at
/// JSON time. Construct as a struct literal — every field is `pub`
/// because there's no derived invariant beyond "values come from
/// the surrounding request context."
#[derive(Debug, Serialize)]
pub struct WebhookEvent<'a> {
    /// One of the `EVENT_*` constants. SIEM rules key on this field.
    pub event: &'a str,
    pub correlation_id: &'a str,
    pub agent_id: &'a str,
    pub tool_type: &'a str,
    pub method: &'a str,
    /// Brain intent_category for /mcp events; `"OperatorDecide"` for
    /// decide events. Distinguishes pipeline outcomes from
    /// human-driven resolutions in downstream queries without joining
    /// on event_type.
    pub intent_category: &'a str,
    pub reasoning: &'a str,
    pub review_reasons: &'a [String],
    /// Enforcement posture at the time of the verdict — `enforce` or
    /// `observe`. Lets a SIEM correlate `would_deny`/`would_park`
    /// volume with the rollout phase.
    pub mode: &'a str,
    /// RFC 3339 UTC timestamp. Always emitted by the clavenar side,
    /// not the receiver, so a downstream sink isn't responsible for
    /// per-event clock skew.
    pub ts: String,
}

/// Current UTC time as RFC 3339 with millisecond precision and `Z`
/// zone. Single producer keeps the timestamp format consistent
/// across event types.
pub fn now_rfc3339() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// POST one event to the configured sink. Failures land at `warn`
/// level — the caller never sees them. Per-call 5s timeout caps
/// blast radius on a flaky sink.
pub async fn fire_event(http: reqwest::Client, url: String, body: serde_json::Value) {
    let res = http
        .post(&url)
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(5))
        .json(&body)
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => {
            tracing::debug!("webhook {} delivered ({})", url, r.status());
        }
        Ok(r) => {
            tracing::warn!("webhook {} returned non-2xx {}", url, r.status());
        }
        Err(e) => {
            tracing::warn!("webhook {} send failed: {}", url, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_with_all_keys() {
        let reasons = vec!["Review: wire transfers".to_string()];
        let evt = WebhookEvent {
            event: EVENT_PARK,
            correlation_id: "corr-1",
            agent_id: "agent-a",
            tool_type: "wire_transfer",
            method: "call_tool",
            intent_category: "PendingReview",
            reasoning: "brain[ok] policy[review]",
            review_reasons: &reasons,
            mode: "enforce",
            ts: now_rfc3339(),
        };
        let v = serde_json::to_value(&evt).unwrap();
        let obj = v.as_object().unwrap();
        // Stable wire-shape — assert exact key set so a typo in the
        // struct doesn't break SIEM rules silently.
        for k in [
            "event",
            "correlation_id",
            "agent_id",
            "tool_type",
            "method",
            "intent_category",
            "reasoning",
            "review_reasons",
            "mode",
            "ts",
        ] {
            assert!(obj.contains_key(k), "missing key {}", k);
        }
        assert_eq!(obj["event"], "park");
        assert_eq!(obj["correlation_id"], "corr-1");
        assert_eq!(obj["mode"], "enforce");
        assert_eq!(obj["review_reasons"][0], "Review: wire transfers");
    }

    #[test]
    fn ts_is_rfc3339_with_z_suffix() {
        let ts = now_rfc3339();
        // ISO 8601 / RFC 3339 with millisecond precision and Z zone.
        assert!(ts.ends_with('Z'), "expected Z suffix, got {}", ts);
        assert!(ts.contains('T'), "expected T separator, got {}", ts);
        // Parse round-trip — confirms producer + consumer share format.
        let _: DateTime<Utc> = ts.parse().unwrap_or_else(|e| panic!("parse {}: {}", ts, e));
    }

    #[test]
    fn event_constants_are_stable() {
        // These string values are the SIEM query keys partners build
        // dashboards on. Renaming any of them is a breaking change —
        // this test pins the wire contract.
        assert_eq!(EVENT_ALLOW, "allow");
        assert_eq!(EVENT_DENY, "deny");
        assert_eq!(EVENT_PARK, "park");
        assert_eq!(EVENT_DECIDE_ALLOW, "decide_allow");
        assert_eq!(EVENT_DECIDE_DENY, "decide_deny");
        assert_eq!(EVENT_WOULD_DENY, "would_deny");
        assert_eq!(EVENT_WOULD_PARK, "would_park");
    }
}
