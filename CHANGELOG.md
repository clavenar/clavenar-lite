# Changelog

All notable changes to `warden-lite` are documented here. Format based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-11

Trust-onboarding release. Adds the rollout knob (observe mode), the
audit-trail hook (correlation id), and the container surface
(Dockerfile + Fly.io) so partners can deploy a warden-lite in front
of their agent in 60 seconds without standing up a Rust toolchain.

### Added

- **Observe mode** (`--mode observe` / `WARDEN_LITE_MODE=observe`).
  Every request forwards upstream regardless of policy / Brain
  verdict. The ledger still records `authorized=false` for would-have-
  denied requests so the audit trail of what enforce mode *would*
  have done stays accurate. Responses carry `X-Warden-Mode` and (on
  would-have-denies) `X-Warden-Would-Deny: true`.
- **Correlation id** on every `/mcp` response — `X-Warden-Correlation-Id`
  is a UUID v4 minted per request and persisted to a new
  `correlation_id` ledger column. Partners catch `WardenDenied` SDK-side
  and look the call up in the ledger with one query. The column is
  deliberately NOT part of `HashableEntryV1`, so the hash chain stays
  byte-compatible with the full edition's verifier.
- **Multi-stage Dockerfile** producing a 38.5 MB compressed image.
  Runs as nonroot UID 65532, tini as PID 1, bundles the default
  `governance.rego` at `/etc/warden-lite/policies`, all
  `WARDEN_LITE_*` envs honoured.
- **Fly.io deploy template** (`fly.toml`) — shared-cpu-1x, 256 MB,
  auto-stop/start, observe mode by default. One-click "Deploy on
  Fly.io" button on the README.
- README "Run it in 60 seconds" + "Try it with your agent" sections
  pairing warden-lite with the
  [`@vanteguardlabs/warden-ai-sdk`](https://www.npmjs.com/package/@vanteguardlabs/warden-ai-sdk)
  wrap pattern end-to-end.

### Migration notes

- Existing ledger DBs (0.1.0 schema) are upgraded automatically on
  the first 0.2.0 boot via idempotent `ALTER TABLE ADD COLUMN
  correlation_id TEXT`. The migration is read-only on existing rows
  (legacy entries return `None` for the new field) and the hash
  chain re-verifies cleanly.
- Default mode is still `enforce` — upgrading 0.1.0 → 0.2.0 changes
  no enforcement behaviour. Opt into observe per-deploy.

## [0.1.0] - 2026-05-08

Initial public release. Single-binary OSS edition of Agent Warden
with the embedded heuristic Brain, `regorus`-backed Rego policy
engine, SHA-256 hash-chained SQLite ledger, and axum proxy. Wire
format and chain shape are byte-compatible with the full edition.

[0.2.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.2.0
[0.1.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.1.0
