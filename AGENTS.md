<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-lite — single-binary OSS edition of the proxy + ledger (drop-in alternative to the multi-service control plane)

All four Clavenar layers collapse into one process and one binary:
embedded heuristic Brain (L2), Rego policy engine (L3), SHA-256
hash-chained SQLite ledger (L4), behind an HTTP proxy/orchestrator (L1).
Developer-laptop scope — no mTLS, Vault, semantic LLM Brain, or
multi-instance velocity (those are the full edition). Apache-2.0, Rust
edition 2024.

## Build, test, lint

```bash
cargo build                                # release: cargo build --release
cargo build --release --locked --target x86_64-unknown-linux-musl   # static release artifact (needs musl-tools; CI asserts truly static via ldd)
cargo test
./scripts/smoke-e2e.sh                     # CI e2e (needs docker): boots the runtime image — all three verdicts + park-poll-decide loop + concurrent audit read
cargo clippy --all-targets -- -D warnings
cargo deny check all                       # supply-chain gate
cargo cyclonedx --format json --describe crate   # SBOM
docker build -t ghcr.io/clavenar/clavenar-lite:latest .
```

Host-build caveat: `target/` may be root-owned from prior docker builds — pass `CARGO_TARGET_DIR=/tmp/clavenar-lite-target`. Release workflow ships multi-arch amd64+arm64 on `v*` tags; tag must match `Cargo.toml` version.

Run: single bin `clavenar-lite` (`clavenar-lite start …`); HTTP server binds `0.0.0.0:8088` (`--port` / `CLAVENAR_LITE_PORT`). Subcommands: `start`, `verify`, `audit <agent_id>`, `backup`, `restore`, `graduate {report,verify}`, `pending {list,get,decide}`. Every flag has a `CLAVENAR_LITE_*` env fallback (see README matrix).

## Layout
- `src/main.rs` — clap CLI, subcommand dispatch, fail-fast startup checks, `TcpListener` bind, `/metrics` wiring.
- `src/lib.rs` — re-exports the modules below for tests / library consumers.
- `src/proxy.rs` — L1: axum `build_router`, `AppState`, `AgentRegistry`, `ClavenarMode`, `/mcp` orchestration, pending handlers.
- `src/heuristics.rs` — L2: pure-Rust regex/substring injection/jailbreak matcher (~14 needles).
- `src/policy.rs` — L3: `regorus` Rego evaluator + in-process velocity tracker.
- `src/ledger.rs` — L4: bundled SQLite, SHA-256 hash chain, `verify`/`audit`/`backup`/`restore`, schema migration on open.
- `src/rate_limit.rs` — per-agent token-bucket gate at `/mcp` ingress (runs before brain/policy).
- `src/report.rs` — observe→enforce graduation report, Ed25519-signed offline.
- `src/slack.rs` / `src/webhook.rs` — optional fire-and-forget side-channels (Slack park alert / SIEM JSON verdict).
- `src/supply_chain.rs` — pins first `tools/list`, diffs later ones → `tool_schema_poisoned` row.
- `policies/governance.rego` — bundled baseline (denylist, intent threshold, business-hours, velocity, wire-transfer review). `tests/proxy_integration.rs`. `scripts/{smoke-e2e,smoke-install}.sh`. `docs/SEQUENCES.md`.
- Routes (port 8088): `GET /`,`/health`,`/readyz`,`/metrics`; `POST /mcp`; `GET /pending`, `GET /pending/{id}`, `POST /pending/{id}/decide`.

## Conventions & invariants
- **Wire + chain are byte-compatible with the full edition.** A Lite-produced chain verifies under the production ledger; full-edition `governance.rego` runs verbatim here. Don't change the hash-chain serialization or the `PolicyInput` shape without matching the full edition.
- Three verdicts: `200` allow / `403` deny (`security_violation`) / `202` park (`pending`). Observe mode passes everything through, still writes `authorized=false` rows, and adds `X-Clavenar-Would-Deny: true`. Every response (incl. 4xx/5xx) carries `X-Clavenar-Correlation-Id` + `X-Clavenar-Mode`.
- Default mode is `enforce` (CLI/env default); README quickstarts set `observe` explicitly — keep that distinction intact.
- `verify` exit codes are CI contracts: `0` valid, `1` runtime error, `2` for any invalid/unverifiable chain — tamper (the message points at the first bad seq) OR a row written under a newer `chain_version` this binary can't verify (message says "Upgrade", not tamper).
- Two independent auth tokens: agent `--token` gates `/mcp` + pending reads; operator `--decide-token` gates decide — so an agent can't approve its own pending. Decide is idempotent: a second decide returns `409`, never a silent overwrite.
- Rate-limit gate emits `429` + a `RateLimitDenied` ledger row + the `clavenar_lite_rate_limit_denied_total` counter; it runs before any brain/policy work.
- `--verbose-verdicts` is a dev knob, OFF by default — it leaks detector logic to the caller; the binary logs a startup warning when on.
- Dependency choices are load-bearing for the one-command static install: `reqwest` rustls-tls (no system openssl), `rusqlite` `bundled` (no system libsqlite). Don't reintroduce native-tls or a system-lib dep.
- `[lints.rust] unreachable_pub = "warn"` — keep the module surface tight; don't widen visibility past what `lib.rs` needs to re-export.

Rust house rules: clippy `-D warnings` is mandatory — fix the code, never `#[allow]` to silence (a documented false positive is the only exception). Types in a `pub` fn signature must be `pub` (no `pub(crate)` leaking through). Tests live at file bottom in `#[cfg(test)] mod tests`. Prefer `writeln!` over `write!(…, "\n")` and let-chains over nested `if let`. Doc comments: no `+ ` line-start continuations (clippy reads them as list items). `deny.toml` is synced verbatim from `clavenar-specs` — edit it there first, then mirror the exact bytes. Bash scripts: `set -euo pipefail`, pass `shellcheck -S warning`, quote everything.

## Pointers
README.md · SECURITY.md · docs/SEQUENCES.md
