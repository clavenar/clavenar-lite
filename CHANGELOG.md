# Changelog

All notable changes to `warden-lite` are documented here. Format based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Week-6 partner-readiness bundle. Targets a v0.4.0 cut at end-of-week
once Slack webhook + fresh-host smoke test + demo wiring land.

### Added

- **`GET /pending`** — operator list endpoint. Query params:
  `?status=parked|decided|all` (default `parked`), `?limit=N` (default
  50, server hard-cap 500). Returns array of pending views, newest
  requested first. Requires `--decide-token` if configured.
- **`warden-lite pending {list,get,decide}`** CLI subcommands. Talks
  to a running warden-lite over HTTP; same wire contract as the
  endpoints. `pending list` prints a table by default, `--json` for
  scripting. `pending decide` takes `--allow` or `--deny` (mutually
  exclusive) + optional `--note`. Falls back to `WARDEN_LITE_URL`,
  `WARDEN_LITE_DECIDE_TOKEN`, `WARDEN_LITE_TOKEN` envs.

## [0.3.0] - 2026-05-11

Yellow-tier release. Pairs with
[`@vanteguardlabs/warden-ai-sdk`](https://www.npmjs.com/package/@vanteguardlabs/warden-ai-sdk)
v0.2.0+'s async-HIL flow. Adds the wire contract for parking
risky-but-not-banned tool calls for operator approval — a third
verdict between `200 OK` (green) and `403 Forbidden` (red).

### Added

- **`202 Accepted` from `/mcp`** when the Rego policy's `review` rule
  fires alongside `allow := true`. Body is
  `{status, correlation_id, review_reasons}`; the request is parked in
  a new `pendings` SQLite table awaiting a decide call. The hash chain
  keeps the existing entry shape — `pendings` is a separate table,
  deliberately not part of `HashableEntryV1`, so chains produced by
  lite remain byte-compatible with the full edition's verifier.
- **`POST /pending/:id/decide`** — operator capability. Accepts
  `{decision: "allow" | "deny", note?: string}`. Single-decision: a
  second decide call against the same correlation id returns
  `409 Conflict`. A second ledger entry (`PendingApproved` /
  `PendingDenied`) is written tied to the same correlation id, so the
  audit trail captures both the original park and the final outcome.
  Gated by `--decide-token` / `WARDEN_LITE_DECIDE_TOKEN` — distinct
  from the agent bearer token so an agent cannot self-approve.
- **`GET /pending/:id`** — poll endpoint returning the full pending
  view (status, decision, decider_note, RFC 3339 timestamps).
- **Static linux-x86_64 binary** as a GitHub release asset
  (`warden-lite-<version>-x86_64-linux-musl.tar.gz` + matching
  `.sha256`). Built with musl, fully static, no glibc dependency. For
  partners who want the binary on a host without docker.
- README "Container" snippet now pulls
  `ghcr.io/vanteguardlabs/warden-lite:latest` directly instead of
  `git clone + docker build`.

### Migration notes

- Existing 200/403 callers unaffected — yellow tier only fires when
  the policy emits both `allow := true` and a non-empty `review` set.
  The default `governance.rego` ships with a `review` rule for
  `wire_transfer`; older policy bundles without any `review` rules
  retain v0.2.0's binary behavior.
- The Rego `allow` rule previously suppressed itself when `review`
  was non-empty (collapsing yellow into red). It now only checks
  `count(deny) == 0`. If you have a custom policy that relied on the
  old behavior, gate the `review` rule on whatever conditions you
  wanted to deny outright.

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

[0.3.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.3.0
[0.2.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.2.0
[0.1.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.1.0
