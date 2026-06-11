//! Clavenar Lite — single-binary OSS edition.
//!
//! Re-exports the four embedded layers so integration tests (and a
//! future clavenar-sdk) can import them as a library:
//!
//! * [`heuristics`] — embedded heuristic Brain (Layer 2).
//! * [`policy`]     — embedded Rego policy engine (Layer 3).
//! * [`ledger`]     — embedded SHA-256 hash-chained SQLite ledger (Layer 4).
//! * [`proxy`]      — embedded HTTP proxy + orchestrator (Layer 1).
//! * [`rate_limit`] — per-agent token-bucket gate at `/mcp` ingress.
//! * [`slack`]      — optional Slack-webhook side-channel for park alerts.
//! * [`webhook`]    — optional outbound JSON webhook for SIEM / Datadog ingest.
//!
//! See `README.md` for what Lite does versus the full Clavenar
//! edition. The short version: Lite is a single binary for developer-
//! laptop use. Full edition is a multi-service control plane for
//! production deployments.

pub mod heuristics;
pub mod ledger;
pub mod policy;
pub mod proxy;
pub mod rate_limit;
pub mod report;
pub mod slack;
pub mod supply_chain;
pub mod webhook;
