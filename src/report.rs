//! Observe→enforce graduation report.
//!
//! After running the guard in observe mode, `clavenar-lite graduate
//! report` summarizes from the local hash-chained ledger exactly what
//! enforce mode *would* have blocked or parked, and signs the summary
//! with an offline Ed25519 key so the artifact is tamper-evident.
//!
//! Lite is offline / OSS, so signing does **not** call clavenar-identity:
//! the operator points `--signing-key` at a local PKCS#8 PEM
//! (`openssl genpkey -algorithm ed25519`). The signed report embeds the
//! SPKI public key (`pubkey_pem`) so a reader verifies with no network
//! and no key distribution — `clavenar-lite graduate verify` reads it
//! straight out of the file.
//!
//! ## Canonical form is load-bearing
//!
//! The signature covers [`GraduationReport`] serialized in struct
//! declaration order. Every field is a primitive, `String`, or `Vec` of
//! those — no maps, no `serde_json::Value` — so `serde_json::to_string`
//! is byte-deterministic across builds. `report_canonical_json` carries
//! the exact signed bytes; `verify` re-serializes the structured report
//! and refuses if it doesn't match before checking the signature.

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ledger::GraduationStats;

/// Wire-schema version for the graduation report body. Bumped on any
/// incompatible field change (which would also change the canonical
/// signing form).
pub const REPORT_SCHEMA_VERSION: &str = "1";

/// Key id stamped on a report signed by lite's offline file signer.
/// Distinct from the full edition's `clavenar-identity-file:v1` so a
/// reader never confuses an offline lite key with an issuer key.
pub const REPORT_KEY_ID: &str = "clavenar-lite-file:v1";

/// One `intent_category` → count entry in the report breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentCount {
    pub intent_category: String,
    pub count: u64,
}

/// One `agent_id` → count entry in the report breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentCount {
    pub agent_id: String,
    pub count: u64,
}

/// The signed body. Field order is the canonical signing order — do not
/// reorder without bumping [`REPORT_SCHEMA_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraduationReport {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub ledger_entries_checked: u64,
    pub ledger_chain_valid: bool,
    pub total_requests: u64,
    pub would_deny: u64,
    pub would_pend: u64,
    pub allowed: u64,
    pub by_intent_category: Vec<IntentCount>,
    pub top_agents: Vec<AgentCount>,
    pub recommend_enforce: bool,
    pub recommendation: String,
}

impl GraduationReport {
    /// Build a report from aggregated ledger stats + a chain-validity
    /// flag. `generated_at` is passed in (rather than read from the
    /// clock) so callers control determinism in tests.
    pub fn from_stats(
        stats: &GraduationStats,
        ledger_chain_valid: bool,
        generated_at: DateTime<Utc>,
    ) -> Self {
        let (recommend_enforce, recommendation) = recommendation(stats, ledger_chain_valid);
        GraduationReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            generated_at,
            window_start: stats.window_start,
            window_end: stats.window_end,
            ledger_entries_checked: stats.total,
            ledger_chain_valid,
            total_requests: stats.total,
            would_deny: stats.would_deny,
            would_pend: stats.would_pend,
            allowed: stats.allowed,
            by_intent_category: stats
                .by_intent
                .iter()
                .map(|(intent_category, count)| IntentCount {
                    intent_category: intent_category.clone(),
                    count: *count,
                })
                .collect(),
            top_agents: stats
                .top_agents
                .iter()
                .map(|(agent_id, count)| AgentCount {
                    agent_id: agent_id.clone(),
                    count: *count,
                })
                .collect(),
            recommend_enforce,
            recommendation,
        }
    }
}

/// Signed (or explicitly unsigned) graduation report — the artifact
/// written to disk. `report_canonical_json` is the exact bytes the
/// signature covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGraduationReport {
    pub report: GraduationReport,
    pub report_canonical_json: String,
    /// base64 of the raw 64-byte Ed25519 signature; `None` when the
    /// report was emitted unsigned (no `--signing-key`).
    pub signature: Option<String>,
    pub algorithm: String,
    pub key_id: String,
    /// SPKI PEM of the signing key's public half, embedded so a reader
    /// verifies offline. `None` on an unsigned report.
    pub pubkey_pem: Option<String>,
    pub signed_at: Option<DateTime<Utc>>,
}

/// Canonical signing bytes for a report. Deterministic: the struct holds
/// only primitives / `String` / `Vec`, so `to_string` walks fields in
/// declaration order with no map-ordering ambiguity.
pub fn build_report_canonical_json(report: &GraduationReport) -> Result<String, serde_json::Error> {
    serde_json::to_string(report)
}

/// `(recommend_enforce, prose)`. Enforce is "safe to flip" only when the
/// chain verifies and nothing in the window would be blocked or parked —
/// i.e. flipping to enforce changes no observed outcome.
fn recommendation(stats: &GraduationStats, chain_valid: bool) -> (bool, String) {
    if !chain_valid {
        return (
            false,
            "DO NOT ENFORCE — the observe-mode ledger failed its integrity check; investigate before trusting these counts.".to_string(),
        );
    }
    if stats.total == 0 {
        return (
            false,
            "NO DATA — no traffic observed yet; run representative traffic before graduating.".to_string(),
        );
    }
    if stats.would_deny == 0 && stats.would_pend == 0 {
        (
            true,
            format!(
                "SAFE TO ENFORCE — {} request(s) observed, none would be blocked or parked.",
                stats.total
            ),
        )
    } else {
        (
            false,
            format!(
                "REVIEW FIRST — enforce would block {} and park {} of {} observed request(s).",
                stats.would_deny, stats.would_pend, stats.total
            ),
        )
    }
}

/// Sign a report with a local Ed25519 key. Embeds the SPKI public key so
/// the artifact verifies offline.
pub fn sign_report(
    report: &GraduationReport,
    key: &SigningKey,
    signed_at: DateTime<Utc>,
) -> Result<SignedGraduationReport, ReportError> {
    let canonical = build_report_canonical_json(report)?;
    let sig: Signature = key.sign(canonical.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let pubkey_pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| ReportError::Pem(e.to_string()))?;
    Ok(SignedGraduationReport {
        report: report.clone(),
        report_canonical_json: canonical,
        signature: Some(sig_b64),
        algorithm: "ed25519".to_string(),
        key_id: REPORT_KEY_ID.to_string(),
        pubkey_pem: Some(pubkey_pem),
        signed_at: Some(signed_at),
    })
}

/// Wrap a report unsigned (no signing key configured). Still useful as a
/// summary; just not tamper-evident.
pub fn unsigned_report(report: &GraduationReport) -> Result<SignedGraduationReport, ReportError> {
    let canonical = build_report_canonical_json(report)?;
    Ok(SignedGraduationReport {
        report: report.clone(),
        report_canonical_json: canonical,
        signature: None,
        algorithm: "ed25519".to_string(),
        key_id: REPORT_KEY_ID.to_string(),
        pubkey_pem: None,
        signed_at: None,
    })
}

/// Result of verifying a signed report.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Signature valid against the embedded (or supplied) public key.
    Valid,
    /// Report carries no signature — informative, not a failure.
    Unsigned,
    /// Signature present but verification failed, or the structured
    /// report doesn't match its canonical bytes.
    Forged(String),
    /// Could not even attempt verification (bad PEM, bad base64, …).
    Malformed(String),
}

/// Verify a signed report. `pubkey_pem_override` (SPKI PEM) pins an
/// org-published key instead of trusting the report's embedded one;
/// `None` falls back to the embedded `pubkey_pem`.
pub fn verify_report(
    signed: &SignedGraduationReport,
    pubkey_pem_override: Option<&str>,
) -> VerifyOutcome {
    // The structured report must round-trip to its canonical bytes —
    // catches an editor that changed a count without re-signing.
    match build_report_canonical_json(&signed.report) {
        Ok(c) if c == signed.report_canonical_json => {}
        Ok(_) => {
            return VerifyOutcome::Forged(
                "structured report does not match its canonical JSON".to_string(),
            );
        }
        Err(e) => return VerifyOutcome::Malformed(format!("re-serialize: {e}")),
    }

    let Some(sig_b64) = signed.signature.as_deref() else {
        return VerifyOutcome::Unsigned;
    };
    let pem = match pubkey_pem_override.or(signed.pubkey_pem.as_deref()) {
        Some(p) => p,
        None => {
            return VerifyOutcome::Malformed(
                "signed report has no embedded pubkey_pem and no override supplied".to_string(),
            );
        }
    };
    let vk = match VerifyingKey::from_public_key_pem(pem) {
        Ok(k) => k,
        Err(e) => return VerifyOutcome::Malformed(format!("public key PEM: {e}")),
    };
    let raw = match base64::engine::general_purpose::STANDARD.decode(sig_b64) {
        Ok(b) => b,
        Err(e) => return VerifyOutcome::Malformed(format!("signature base64: {e}")),
    };
    let sig = match Signature::from_slice(&raw) {
        Ok(s) => s,
        Err(e) => return VerifyOutcome::Malformed(format!("signature bytes: {e}")),
    };
    match vk.verify(signed.report_canonical_json.as_bytes(), &sig) {
        Ok(()) => VerifyOutcome::Valid,
        Err(_) => VerifyOutcome::Forged("ed25519 verification failed".to_string()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("pem: {0}")]
    Pem(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(total: u64, would_deny: u64, would_pend: u64) -> GraduationStats {
        GraduationStats {
            total,
            would_deny,
            would_pend,
            allowed: total.saturating_sub(would_deny + would_pend),
            by_intent: vec![("PolicyDeny".to_string(), would_deny)],
            top_agents: vec![("agent-a".to_string(), total)],
            window_start: None,
            window_end: None,
        }
    }

    fn report(total: u64, would_deny: u64, would_pend: u64) -> GraduationReport {
        let ts = DateTime::parse_from_rfc3339("2026-06-07T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        GraduationReport::from_stats(&stats(total, would_deny, would_pend), true, ts)
    }

    fn test_key() -> SigningKey {
        // Deterministic 32-byte seed — fine for a unit test signer.
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn canonical_json_is_field_ordered_and_stable() {
        let r = report(10, 2, 1);
        let a = build_report_canonical_json(&r).unwrap();
        let b = build_report_canonical_json(&r).unwrap();
        assert_eq!(a, b);
        // schema_version is the first field of the canonical form.
        assert!(a.starts_with("{\"schema_version\":\"1\""));
    }

    #[test]
    fn recommends_enforce_only_when_clean() {
        assert!(report(10, 0, 0).recommend_enforce);
        assert!(!report(10, 1, 0).recommend_enforce);
        assert!(!report(10, 0, 1).recommend_enforce);
        assert!(!report(0, 0, 0).recommend_enforce); // no data
    }

    #[test]
    fn chain_invalid_never_recommends_enforce() {
        let ts = DateTime::parse_from_rfc3339("2026-06-07T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let r = GraduationReport::from_stats(&stats(10, 0, 0), false, ts);
        assert!(!r.recommend_enforce);
        assert!(r.recommendation.contains("DO NOT ENFORCE"));
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let r = report(10, 0, 0);
        let ts = r.generated_at;
        let signed = sign_report(&r, &test_key(), ts).unwrap();
        assert_eq!(verify_report(&signed, None), VerifyOutcome::Valid);
    }

    #[test]
    fn tampered_count_is_forged() {
        let r = report(10, 0, 0);
        let mut signed = sign_report(&r, &test_key(), r.generated_at).unwrap();
        // Flip a count in the structured report but leave the signed
        // canonical bytes + signature intact.
        signed.report.would_deny = 99;
        assert!(matches!(verify_report(&signed, None), VerifyOutcome::Forged(_)));
    }

    #[test]
    fn unsigned_report_reports_unsigned() {
        let signed = unsigned_report(&report(10, 0, 0)).unwrap();
        assert_eq!(verify_report(&signed, None), VerifyOutcome::Unsigned);
    }
}
