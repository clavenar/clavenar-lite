//! Cross-edition Rego conformance.
//!
//! Lite's Cargo.toml claims a full-edition `governance.rego` "works
//! verbatim" here because both editions embed the same regorus engine.
//! That claim silently broke once before (Lite on regorus 0.2 could not
//! evaluate `import rego.v1` policies the full edition's 0.9 accepts),
//! so this suite pins it two ways:
//!
//!   1. Lite's bundled policy keeps its documented floor semantics.
//!   2. The full edition's `governance.rego` — read from the sibling
//!      `clavenar-policy-engine` checkout when present — evaluates under
//!      Lite's engine with the exact verdicts the full edition's own
//!      `tests/temporal_test.rs` asserts.
//!
//! The sibling half skips (with a note) on a standalone Lite checkout;
//! it always runs in the multi-repo workspace and in CI jobs that clone
//! the sibling.

use clavenar_lite::policy::{AgentHistory, PolicyEngine, PolicyInput};
use std::path::{Path, PathBuf};

fn input(tool_type: &str, intent_score: f32, recent: u32) -> PolicyInput {
    PolicyInput {
        tool_type: tool_type.into(),
        agent_history: AgentHistory::default(),
        intent_score,
        // A Wednesday, 14:00 UTC — inside business hours in both
        // editions' rulesets, matching the full edition's test pin.
        current_time: Some("2026-04-29T14:00:00Z".into()),
        agent_id: Some("conformance-agent".into()),
        method: Some("call_tool".into()),
        recent_request_count: recent,
        correlation_id: None,
    }
}

fn engine_for(rego: &Path) -> PolicyEngine {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(rego, dir.path().join("governance.rego")).expect("copy rego");
    let engine = PolicyEngine::from_dir(dir.path(), 60).expect("load rego");
    // `from_dir` reads the files eagerly; the tempdir can go.
    drop(dir);
    engine
}

fn lite_rego() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("policies/governance.rego")
}

fn full_edition_rego() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../clavenar-policy-engine/policies/governance.rego");
    p.exists().then_some(p)
}

#[tokio::test]
async fn lite_ruleset_keeps_floor_semantics() {
    let engine = engine_for(&lite_rego());

    let ok = engine.evaluate(input("ping", 0.05, 0)).await;
    assert!(ok.allow, "routine call must pass: {:?}", ok.reasons);

    let sql = engine.evaluate(input("sql_execute", 0.05, 0)).await;
    assert!(!sql.allow);
    assert!(sql.reasons.iter().any(|r| r.contains("SQL")));

    let hot = engine.evaluate(input("ping", 0.9, 0)).await;
    assert!(!hot.allow);

    let burst = engine.evaluate(input("ping", 0.05, 150)).await;
    assert!(!burst.allow);
    assert!(burst.reasons.iter().any(|r| r.contains("velocity")));

    // Lite tier contract: review-only requests keep allow=true; the
    // proxy classifies allow+review as a 202 park (see src/proxy.rs).
    let wire = engine.evaluate(input("wire_transfer", 0.05, 0)).await;
    assert!(wire.allow);
    assert!(!wire.review_reasons.is_empty());
}

#[tokio::test]
async fn full_edition_rego_runs_verbatim() {
    let Some(rego) = full_edition_rego() else {
        eprintln!("skipped: sibling clavenar-policy-engine checkout not found");
        return;
    };
    let engine = engine_for(&rego);

    // Vectors below mirror clavenar-policy-engine/tests/temporal_test.rs
    // one-for-one; a divergence here means the two editions no longer
    // agree on the same policy file.
    let ok = engine.evaluate(input("call_tool", 0.05, 0)).await;
    assert!(ok.allow, "business-hours safe call: {:?}", ok.reasons);

    let sql = engine.evaluate(input("sql_execute", 0.05, 0)).await;
    assert!(!sql.allow);
    assert!(
        sql.reasons
            .iter()
            .any(|r| r.contains("Direct execution of SQL queries is prohibited"))
    );

    let shell = engine.evaluate(input("shell_exec", 0.05, 0)).await;
    assert!(!shell.allow);
    assert!(
        shell
            .reasons
            .iter()
            .any(|r| r.contains("Direct shell access is prohibited"))
    );

    let hot = engine.evaluate(input("call_tool", 0.5, 0)).await;
    assert!(!hot.allow, "full edition denies intent 0.5: {:?}", hot);

    let burst = engine.evaluate(input("call_tool", 0.05, 150)).await;
    assert!(!burst.allow);
    assert!(burst.reasons.iter().any(|r| r.contains("Token velocity")));

    // Full-edition tier contract differs from Lite's bundled file on
    // purpose: review folds into the allow gate, so older clients
    // fail safe. Verbatim means Lite must reproduce that too.
    let wire = engine.evaluate(input("wire_transfer", 0.05, 0)).await;
    assert!(!wire.allow, "full edition wire_transfer: {:?}", wire);
    assert!(
        wire.review_reasons
            .iter()
            .any(|r| r.contains("Wire transfers require human approval"))
    );
    assert!(
        wire.reasons.is_empty(),
        "no deny reasons: {:?}",
        wire.reasons
    );
}
