//! Optional Slack-incoming-webhook notifications for yellow-tier
//! parks.
//!
//! One-way only: clavenar-lite POSTs a formatted message to the operator's
//! webhook URL each time a tool call lands in the pendings table. There
//! is no return path from Slack — operators decide via the CLI
//! (`clavenar-lite pending decide`) or via curl to `/pending/:id/decide`.
//! A Slack-button approval flow needs the full edition's HIL service.
//!
//! Fire-and-forget by design: the `notify_pending_parked` call returns
//! immediately if no webhook URL is configured, and the actual HTTP
//! POST is spawned onto the tokio runtime by the caller so a slow or
//! failed Slack does not delay the agent's 202 response.

use crate::ledger::Pending;

/// Format the in-Slack message body for a parked tool call. Plain
/// markdown — Slack renders the backticks as inline code and the
/// `•` bullets verbatim. Kept simple so the same string round-trips
/// to a generic webhook (Discord, MS Teams) with passable rendering.
pub fn format_pending_message(p: &Pending) -> String {
    let reasons = if p.review_reasons.is_empty() {
        "(none reported)".to_string()
    } else {
        p.review_reasons
            .iter()
            .map(|r| format!("  • {}", r))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        ":warning: *Clavenar parked a tool call for review*\n\
         \n\
         *Tool:* `{}`\n\
         *Agent:* `{}`\n\
         *Correlation ID:* `{}`\n\
         *Reasons:*\n{}\n\
         \n\
         Approve: `clavenar-lite pending decide {} --allow`\n\
         Deny:    `clavenar-lite pending decide {} --deny --note \"…\"`",
        p.tool_type, p.agent_id, p.correlation_id, reasons, p.correlation_id, p.correlation_id
    )
}

/// POST the formatted message to the configured webhook URL. Errors
/// are logged at `warn` level — the caller never sees them, because
/// failing the park on a flaky Slack would be the wrong tradeoff.
pub async fn notify_pending_parked(http: &reqwest::Client, webhook_url: &str, pending: &Pending) {
    let body = serde_json::json!({ "text": format_pending_message(pending) });
    match http.post(webhook_url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            tracing::warn!(
                "slack webhook returned {}: pending {} not notified",
                resp.status(),
                pending.correlation_id
            );
        }
        Err(e) => {
            tracing::warn!(
                "slack webhook POST failed for pending {}: {}",
                pending.correlation_id,
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_pending() -> Pending {
        Pending {
            correlation_id: "abc-123".to_string(),
            agent_id: "bearer-agent".to_string(),
            tool_type: "wire_transfer".to_string(),
            method: "call_tool".to_string(),
            review_reasons: vec!["Review: Wire transfers require human approval.".to_string()],
            requested_at: Utc::now(),
            decided_at: None,
            decision: None,
            decider_note: None,
            callback_url: None,
        }
    }

    #[test]
    fn message_contains_load_bearing_fields() {
        let p = sample_pending();
        let msg = format_pending_message(&p);
        assert!(msg.contains("wire_transfer"));
        assert!(msg.contains("bearer-agent"));
        assert!(msg.contains("abc-123"));
        assert!(msg.contains("Wire transfers require human approval."));
        // CLI hints must surface — partners shouldn't have to look up
        // the decide command separately.
        assert!(msg.contains("clavenar-lite pending decide abc-123 --allow"));
        assert!(msg.contains("clavenar-lite pending decide abc-123 --deny"));
    }

    #[test]
    fn message_handles_empty_reasons() {
        let mut p = sample_pending();
        p.review_reasons.clear();
        let msg = format_pending_message(&p);
        assert!(msg.contains("(none reported)"));
    }
}
