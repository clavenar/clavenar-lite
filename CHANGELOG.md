# Changelog

All notable changes to `warden-lite` are documented here. Format based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-05-12

Multi-agent release. One warden-lite binary can now front N
independent agents, each with its own bearer token and ledger
identity — collapsing the v1 ergonomic gap where every partner with
multiple agents had to run a warden-lite per agent.

### Added

- **Multi-agent registry.** `WARDEN_LITE_AGENTS=agent-a:tok-a,agent-b:tok-b`
  (or `--agents`) registers N agents behind one binary. The token
  that matched on inbound auth determines the `agent_id` written to
  the ledger and surfaced to Rego policy as `input.agent_id`, so
  policies can scope tool access per agent. Mutually exclusive with
  the legacy single-token `WARDEN_LITE_TOKEN`; both set picks the
  registry. Tokens must be unique across agents — duplicates fail
  boot loudly.
- **`AgentRegistry`** type exported from `warden_lite::proxy` for
  embedders that want to wire their own state.
- **9 new tests** (7 unit, 2 integration) covering registry parsing,
  per-token agent_id routing on the ledger, and 401 rejection of
  unknown tokens.

### Changed

- `AppState.bearer_token: Option<String>` is now
  `AppState.agents: Option<AgentRegistry>`. The legacy
  `WARDEN_LITE_TOKEN` env path builds a one-entry registry under the
  hood so existing single-agent deployments keep their
  `agent_id="bearer-agent"` ledger identity.

### Migration notes

- If you embed `warden-lite` as a library and construct `AppState`
  directly, rename `bearer_token` → `agents` and wrap the value in
  `AgentRegistry::single(token)` (or `AgentRegistry::parse(spec)?`
  for the multi-agent form). The runtime / CLI surface is otherwise
  unchanged.

## [0.4.1] - 2026-05-12

Partner-day-1 hardening release. Closes the SQLite-concurrency gap
that hung the `warden-lite audit` CLI against a running proxy,
sharpens the operator triage queue, and wires the end-to-end smoke
into CI so future changes can't silently break the day-1 surface.

### Changed

- **SQLite WAL + busy_timeout** on ledger open. Lets the
  `warden-lite audit` CLI read the ledger DB concurrently with a
  running proxy (previously the second opener deadlocked on the
  writer lock and hung indefinitely). `busy_timeout=5000` backstops
  brief contention with a short wait instead of `SQLITE_BUSY`. The
  `:memory:` path silently falls back to a memory-mode journal.

### Added

- **`pending list` sort + color UX.** Triage-queue ergonomics: the
  `parked` filter now defaults to **oldest-first** so the
  longest-waiting request reads at the top; `decided` and `all`
  default to newest-first (history view). Both can be overridden via
  `?sort=oldest|newest` on the server and `--sort` on the CLI. The
  STATUS column emits ANSI color on a TTY (yellow=parked, green=allow,
  red=deny) and stays plain text on pipes or when `NO_COLOR` is set
  (https://no-color.org).
- **`scripts/smoke-e2e.sh`** — partner-day-1 quality gate. Boots
  warden-lite from a freshly-built local image on a dedicated docker
  network with a Python upstream stub, then exercises all three
  verdicts, the yellow-tier park-poll-decide loop, second-decide
  `409`, the decide-token gating (rejecting an agent bearer on the
  operator endpoint), and a concurrent `warden-lite audit` CLI read
  against the same DB file (proves WAL works). 20 checks against
  the live HTTP surface; cleans up on exit. Wired into CI so every
  push proves the gate. Companion to `smoke-install.sh` — this one
  verifies they actually work.

## [0.4.0] - 2026-05-12

Partner-readiness release. Closes the gap between "partner says yes"
and "partner is running warden-lite in front of their agent." Single
binary now covers server + operator ops; yellow-tier parks alert
Slack with a one-click-ready decide command line; the SDK demo
demonstrates the canonical operator flow end-to-end.

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
- **Slack-webhook park alerts** via `--slack-webhook-url` (or
  `WARDEN_LITE_SLACK_WEBHOOK_URL`). Every yellow-tier park spawns a
  fire-and-forget POST with the correlation id, agent, tool, review
  reasons, and the exact `warden-lite pending decide` command line
  for the approver. One-way — operators decide via the CLI or curl
  (no Slack→warden return path; that lives in the full edition's HIL
  service). Failed webhooks log at `warn` and never block the
  agent's 202.

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

[0.4.1]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.4.1
[0.4.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.4.0
[0.3.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.3.0
[0.2.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.2.0
[0.1.0]: https://github.com/vanteguardlabs/warden-lite/releases/tag/v0.1.0
