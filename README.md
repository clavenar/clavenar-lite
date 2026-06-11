# clavenar-lite

[![CI](https://github.com/clavenar/clavenar-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/clavenar/clavenar-lite/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

Single-binary OSS edition of [Clavenar](https://github.com/clavenar).
A drop-in proxy that sits between an AI agent and the LLM/tool API it
calls — inspecting every request, evaluating policy, and writing a
hash-chained forensic ledger — without standing up a multi-service
control plane.

[![Deploy on Fly.io](https://fly.io/static/images/launch/deploy.svg)](https://fly.io/launch/?repo=https://github.com/clavenar/clavenar-lite)

Sequence diagrams for the five primary runtime paths — boot pipeline,
Green-tier `/mcp` fast path, Yellow-tier park with Slack + outbound
webhook, operator decide + async-HIL callback, and `verify`
chain-version dispatch — plus a tier/mode flowchart, live in
[`docs/SEQUENCES.md`](docs/SEQUENCES.md).

## Run it in 60 seconds

Pick whichever surface fits how you ship today. All three boot with
`observe` mode set so the first request through the proxy never 403s
— flip to `enforce` when you trust the verdicts.

**Container** (no Rust toolchain needed):

```bash
docker run -p 8088:8088 \
  -e CLAVENAR_LITE_UPSTREAM_URL=https://api.openai.com/v1/chat/completions \
  -e CLAVENAR_LITE_MODE=observe \
  ghcr.io/clavenar/clavenar-lite:latest
```

The image is multi-arch (`linux/amd64` + `linux/arm64`), published from
the [release workflow](.github/workflows/release.yml) on every `v*`
tag. Pin to `:0.4.0` if you want a fixed version; `:latest` tracks the
newest tagged release.

**Fly.io** (deploy button above, or):

```bash
fly launch --copy-config
fly secrets set CLAVENAR_LITE_UPSTREAM_URL=https://api.openai.com/v1/chat/completions
fly deploy
```

**Static binary** (no Rust toolchain, no docker):

```bash
V=0.4.0
curl -fsSL "https://github.com/clavenar/clavenar-lite/releases/download/v${V}/clavenar-lite-${V}-x86_64-linux-musl.tar.gz" \
  | tar -xz
./clavenar-lite start --mode observe \
  --upstream https://api.openai.com/v1/chat/completions
```

Linux x86_64, fully static (musl) — no glibc dependency, no system
libsqlite. A `.sha256` companion file is published alongside if you
want to verify before extracting.

Hit it once to confirm:

```bash
curl -i http://localhost:8088/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"call_tool",
       "params":{"name":"search","arguments":{"q":"hello"}}}'
```

Every response carries `X-Clavenar-Mode`, `X-Clavenar-Correlation-Id`,
and (in observe, on would-have-denied requests) `X-Clavenar-Would-Deny:
true`. The correlation id round-trips into the audit ledger so you
can look the call up later:

```bash
clavenar-lite audit anonymous
clavenar-lite verify
```

## Try it with your agent

The companion TypeScript SDK,
[`@clavenar/agent-sdk`](https://www.npmjs.com/package/@clavenar/agent-sdk),
wraps your Anthropic / OpenAI client so every `tool_use` is
inspected before your tool-execution loop sees it. Point it at the
local proxy:

```ts
import Anthropic from '@anthropic-ai/sdk';
import { clavenarWrap, ClavenarDenied } from '@clavenar/agent-sdk';

const client = clavenarWrap(new Anthropic(), {
  endpoint: 'http://localhost:8088',   // the clavenar-lite you just booted
  mode: 'enforce',                     // throw on deny; 'observe' to passthrough
});

try {
  const msg = await client.messages.create({
    model: 'claude-opus-4-7', max_tokens: 1024,
    tools: [/* your tool schemas */],
    messages: [{ role: 'user', content: 'delete the alice user' }],
  });
} catch (e) {
  if (e instanceof ClavenarDenied) {
    console.warn('blocked', e.toolName, e.reasons, e.correlationId);
  }
}
```

OpenAI works the same way — pass `new OpenAI()` instead, the SDK
auto-detects the client shape. See the
[SDK README](https://github.com/clavenar/clavenar-typescript-sdk) for
streaming, observe mode, retry, and verdict-callback options.

## What's in the box

| Layer                | What it does                                                              | Lite ships                                                     |
|----------------------|---------------------------------------------------------------------------|----------------------------------------------------------------|
| **Heuristic Brain**  | Scan payload for prompt injection / jailbreak / dangerous-tool signatures | Pure-Rust regex/substring matcher; ~14 needles                 |
| **Policy Engine**    | Evaluate Rego rules over `tool_type`, `intent_score`, time-of-day, velocity | `regorus` (pure-Rust Rego), in-process velocity tracker        |
| **Ledger**           | Append-only forensic store with SHA-256 hash chain                        | SQLite (bundled), `verify` and `audit` CLI subcommands         |
| **Proxy**            | HTTP ingress, security-first orchestration, upstream credential injection | axum + reqwest, optional bearer-token auth                     |

The chain format and policy input shape are byte-compatible with the
full Clavenar edition. A chain produced by `clavenar-lite` verifies
under the production ledger; a `governance.rego` written for the full
edition runs verbatim under Lite.

## Promoting to production

For real traffic, layer these on top of the default deploy:

- **Persistent ledger.** Mount a volume at `/var/lib/clavenar-lite` and
  set `CLAVENAR_LITE_LEDGER=/var/lib/clavenar-lite/ledger.db`. The hash
  chain survives restarts; `clavenar-lite verify` keeps validating.
- **Custom policies.** Bind-mount your own Rego directory at
  `/etc/clavenar-lite/policies` (or any path you prefer with
  `CLAVENAR_LITE_POLICY_DIR`). The bundled `governance.rego` is a
  starting baseline, not a finished policy.
- **Ingress auth.** Set `CLAVENAR_LITE_TOKEN`; partners then send
  `Authorization: Bearer <token>` and unauthenticated requests get
  401. Without it the proxy accepts every connection.
- **Multi-agent.** Set `CLAVENAR_LITE_AGENTS=agent-a:tok-a,agent-b:tok-b`
  to front N agents from one binary. Each token gets its own
  `agent_id` on the ledger and in `input.agent_id` so Rego rules
  can scope tool access per agent. Mutually exclusive with the
  single-agent `CLAVENAR_LITE_TOKEN`; both being set picks the
  registry. Tokens must be unique across agents.
- **Async-HIL webhooks.** Set
  `CLAVENAR_LITE_CALLBACK_ALLOWLIST=https://my-app.example.com/`
  (comma-separated prefixes) to enable agent-supplied callback
  URLs. Agents send `X-Clavenar-Callback-URL: <url>` on `/mcp`; on
  operator decide clavenar POSTs `{correlation_id, decision,
  decider_note, decided_at}` to that URL fire-and-forget. URLs
  outside the allowlist are rejected with 400. Unset (the default)
  rejects callbacks entirely — partners poll
  `GET /pending/{id}`.
- **Outbound verdict webhooks.** Set
  `CLAVENAR_LITE_WEBHOOK_URL=https://siem.example.com/ingest` to
  fire-and-forget a structured JSON event on every terminal
  pipeline outcome (`allow` / `deny` / `park`, plus `would_deny` /
  `would_park` in observe mode) and on every operator decide
  (`decide_allow` / `decide_deny`). Distinct from Slack — the
  payload is machine-readable JSON for SIEM / Datadog HTTP ingest.
  Each POST carries `{event, correlation_id, agent_id, tool_type,
  method, intent_category, reasoning, review_reasons, mode, ts}`
  with a 5s per-request timeout; failures land at `warn` and never
  delay the agent or operator response. The ledger remains the
  durable source of truth.
- **Upstream creds.** `CLAVENAR_LITE_UPSTREAM_API_KEY` injects the key
  into forwarded requests so your agent never sees it. Same shape
  as the full edition's Vault injection, minus Vault.
- **Enforce mode.** Flip `CLAVENAR_LITE_MODE=enforce` once the observe
  data is clean.

## Subcommands

```
clavenar-lite start [--port N] [--upstream URL] [--policies DIR] [--ledger PATH]
                  [--velocity-window SECS] [--token TOKEN] [--agents SPEC]
                  [--decide-token TOKEN] [--upstream-api-key KEY]
                  [--upstream-timeout-secs SECS] [--slack-webhook-url URL]
                  [--callback-allowlist PREFIXES] [--webhook-url URL]
clavenar-lite verify [--ledger PATH]
clavenar-lite audit  [--ledger PATH] <agent_id>
clavenar-lite backup  [--ledger PATH] --output FILE
clavenar-lite restore --input FILE [--ledger PATH] [--force]
clavenar-lite graduate report [--ledger PATH] [--since 24h|RFC3339]
                            [--signing-key key.pem] [--output FILE]
                            [--format json|text]
clavenar-lite graduate verify --report FILE [--pubkey FILE]
clavenar-lite pending list   [--endpoint URL] [--decide-token TOKEN]
                            [--status parked|decided|all] [--limit N]
                            [--sort oldest|newest] [--json]
clavenar-lite pending get    <correlation_id> [--endpoint URL] [--token TOKEN] [--json]
clavenar-lite pending decide <correlation_id> --allow | --deny [--note STRING]
                            [--endpoint URL] [--decide-token TOKEN]
```

The `pending` subcommands talk to a *running* clavenar-lite over HTTP —
the same endpoints your agent posts to. Operators use them to triage
parked tool calls without curl'ing the API directly.

Every flag falls back to a `CLAVENAR_LITE_*` env var:

| Flag                       | Env var                              | Default                   |
|----------------------------|--------------------------------------|---------------------------|
| `--port`                   | `CLAVENAR_LITE_PORT`                   | 8088                      |
| `--upstream`               | `CLAVENAR_LITE_UPSTREAM_URL`           | http://localhost:9000/mcp |
| `--policies`               | `CLAVENAR_LITE_POLICY_DIR`             | ./policies                |
| `--ledger`                 | `CLAVENAR_LITE_LEDGER`                 | ./clavenar-lite.db          |
| `--velocity-window`        | `CLAVENAR_LITE_VELOCITY_WINDOW_SECS`   | 60                        |
| `--token`                  | `CLAVENAR_LITE_TOKEN`                  | (none — open access)      |
| `--agents`                 | `CLAVENAR_LITE_AGENTS`                 | (none — single-agent)     |
| `--callback-allowlist`     | `CLAVENAR_LITE_CALLBACK_ALLOWLIST`     | (none — callbacks off)    |
| `--upstream-api-key`       | `CLAVENAR_LITE_UPSTREAM_API_KEY`       | (none — pass-through)     |
| `--upstream-timeout-secs`  | `CLAVENAR_LITE_UPSTREAM_TIMEOUT_SECS`  | 120                       |
| `--mode`                   | `CLAVENAR_LITE_MODE`                   | `enforce`                 |
| `--decide-token`           | `CLAVENAR_LITE_DECIDE_TOKEN`           | (none — open access)      |
| `--slack-webhook-url`      | `CLAVENAR_LITE_SLACK_WEBHOOK_URL`      | (none — alerts off)       |
| `--webhook-url`            | `CLAVENAR_LITE_WEBHOOK_URL`            | (none — webhook off)      |
| `--rate-limit-qps`         | `CLAVENAR_LITE_RATE_LIMIT_QPS`         | 0 (rate limit off)        |
| `--rate-limit-burst`       | `CLAVENAR_LITE_RATE_LIMIT_BURST`       | `ceil(qps)`               |
| `--signing-key` (graduate) | `CLAVENAR_LITE_SIGNING_KEY_PATH`       | (none — unsigned report)  |

### Per-agent rate limiting

Set `--rate-limit-qps` (or `CLAVENAR_LITE_RATE_LIMIT_QPS`) above zero to
turn on a per-agent token bucket at `/mcp` ingress. The gate runs
*before* the brain/policy pipeline so a runaway agent doesn't burn
local CPU. An over-limit request gets HTTP 429 with a JSON body:

```json
{
  "error": "rate_limited",
  "agent_id": "<agent>",
  "retry_after_secs": 1,
  "correlation_id": "..."
}
```

Each 429 also writes a ledger row with
`intent_category="RateLimitDenied"` so `clavenar-lite audit <agent>`
surfaces the throttle alongside Allow / Deny / Park decisions, and a
`clavenar_lite_rate_limit_denied_total` counter appears on `/metrics`.

The upstream URL is parsed at startup and a typo fails fast with exit
code `1` rather than 502-ing the first request through.

## Rollout: observe before enforce

`--mode observe` flips clavenar-lite into a pass-through observability
layer:

- Every request forwards upstream regardless of policy / Brain verdict.
- The ledger still records `authorized=false` for would-have-denied
  requests, so the audit trail of what enforce mode *would* have done
  stays accurate.
- Every response carries `X-Clavenar-Mode: observe`. Would-have-denied
  responses also carry `X-Clavenar-Would-Deny: true` — count those to
  size the blast radius of flipping enforce on.

Recommended rollout: deploy in observe for a week, watch the
`X-Clavenar-Would-Deny` rate per tool in your dashboards, tune policies
until the rate is on the floor of "things that genuinely should be
denied," then flip `CLAVENAR_LITE_MODE=enforce` and pop the gate.

```bash
clavenar-lite start --mode observe --upstream https://api.openai.com/v1
```

### Graduation report

Before flipping to enforce, turn the observe-mode ledger into a signed,
human-readable summary of exactly what enforce *would* have blocked or
parked. The report is signed with a local Ed25519 key (no online
service) and embeds its public key so anyone verifies it offline.

```bash
# One-time: generate a signing key.
openssl genpkey -algorithm ed25519 -out clavenar-lite.key

# After an observe window:
clavenar-lite graduate report --signing-key clavenar-lite.key --format text
#   …prints would-deny / would-pend counts, top offenders, and a
#   SAFE TO ENFORCE / REVIEW FIRST recommendation.

# Emit + verify the signed JSON artifact (verification is offline):
clavenar-lite graduate report --signing-key clavenar-lite.key --output report.json
clavenar-lite graduate verify --report report.json
```

`graduate report` recommends enforce only when the chain verifies and
nothing in the window would have been blocked or parked. Without
`--signing-key` it still prints a summary, just not a tamper-evident one.
`clavenarctl init --guard --upstream <URL>` scaffolds this whole flow in
one command.

## Backup + restore

```bash
# Snapshot the live ledger to a portable file. Safe to run against a
# running clavenar-lite — uses SQLite's online-backup API.
clavenar-lite backup --output snapshot.db

# Restore from a snapshot. Verifies the snapshot's chain BEFORE
# touching the target; refuses to overwrite an existing ledger
# without --force. Recommended: stop clavenar-lite, restore, restart.
clavenar-lite restore --input snapshot.db --force
```

The snapshot is a self-contained SQLite DB; `clavenar-lite verify
--ledger snapshot.db` is a valid sanity check on its own. Schema
migrations for older ledgers run on the first `Ledger::open`
automatically — no manual SQL surgery needed.

## Wire format

`POST /mcp` with a JSON-RPC body:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "call_tool",
  "params": {
    "name": "search",
    "arguments": { "q": "..." }
  }
}
```

`params.name` is the `tool_type` evaluated by Rego. `method` rides
through into the ledger row. Unknown extra fields pass through to
upstream untouched.

Three outcomes are possible:

- **`200 OK`** — green. Allowed. Upstream's response rides through.
- **`403 Forbidden`** — red. Denied. Body shape:
  ```json
  {
    "error": "security_violation",
    "reasons": ["Violation: Direct execution of SQL queries is prohibited for this agent."],
    "review_reasons": [],
    "intent_category": "DangerousTool"
  }
  ```
- **`202 Accepted`** — yellow. Parked for human review (see the next
  section). Body shape:
  ```json
  {
    "status": "pending",
    "correlation_id": "8f1d...",
    "review_reasons": ["Review: Wire transfers require human approval before execution."]
  }
  ```

Every response — including 401, 400, and 5xx — carries an
`X-Clavenar-Correlation-Id` header so a partner can pivot from a thrown
error in SDK code to the matching row in `clavenar-lite audit`.

Exit codes from the `verify` subcommand are CI-friendly: `0` valid, `2`
chain corruption detected, `1` runtime error (DB unreadable, etc.).

## Human-in-the-loop: park, poll, decide

When policy returns `allow: true` with `review` non-empty (the
`wire_transfer` rule in the default `governance.rego` is the
canonical example), clavenar-lite parks the request:

1. **Park** — `POST /mcp` returns `202` with `{status, correlation_id,
   review_reasons}`. The pendings table records the call; one ledger
   row is written with `intent_category=PendingReview, authorized=false`.
2. **Poll** — `GET /pending/{correlation_id}` returns the current state:
   ```json
   {
     "correlation_id": "8f1d...",
     "agent_id": "bearer-agent",
     "tool_type": "wire_transfer",
     "method": "call_tool",
     "review_reasons": ["Review: Wire transfers require human approval before execution."],
     "requested_at": "2026-05-12T10:14:03Z",
     "decided_at": null,
     "decision": null,
     "decider_note": null
   }
   ```
   The SDK polls this until `decision` flips from `null` to `"allow"`
   or `"deny"`. Auth: reuses the agent `--token` (same identity that
   issued the `/mcp` call).
3. **Decide** — `POST /pending/{correlation_id}/decide` with
   `{decision: "allow" | "deny", note?}`. Operator-driven. Writes a
   second ledger row (`PendingApproved` / `PendingDenied`) and flips
   the pendings row. Idempotent in the failure direction: a second
   decide returns `409`, never silently overwriting. Auth: separate
   `--decide-token` so agent bearers cannot approve their own
   pendings.

```bash
# Park a wire transfer (in another terminal, agent-side):
$ curl -sS -X POST http://localhost:8088/mcp \
    -H 'Authorization: Bearer agent-token' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"call_tool",
         "params":{"name":"wire_transfer","arguments":{"to":"acct-1","amount":100}}}'
# → 202
# {"status":"pending","correlation_id":"8f1d...","review_reasons":[...]}

# Approve it (operator-side) — either curl, or the built-in CLI:
$ clavenar-lite pending list --decide-token op-token
CORRELATION_ID                         AGENT_ID         TOOL_TYPE        REQUESTED_AT         STATUS
8f1d...                                bearer-agent     wire_transfer    2026-05-12T10:14:03Z parked

$ clavenar-lite pending decide 8f1d... --decide-token op-token --allow --note "ok by sec"
ok: pending 8f1d... decided allow
```

The CLI is a thin wrapper over `/pending/*` — partners can use either,
and the wire format is the source of truth. `--endpoint`,
`--decide-token`, and `--token` fall back to `CLAVENAR_LITE_URL`,
`CLAVENAR_LITE_DECIDE_TOKEN`, and `CLAVENAR_LITE_TOKEN` respectively.

Auth tokens are independent: set neither for developer-laptop use,
set just `--token` to gate the agent surface, set both when there's a
real operator workflow.

### Slack alerts (optional)

Pass `--slack-webhook-url https://hooks.slack.com/services/...` (or
set `CLAVENAR_LITE_SLACK_WEBHOOK_URL`) to fire a one-way alert into a
Slack channel each time a tool call lands in the pendings table. The
message carries the correlation id, agent id, tool, the review reasons
that fired, and the exact `clavenar-lite pending decide` invocation an
operator would run to approve or deny:

```
:warning: Clavenar parked a tool call for review

*Tool:* `wire_transfer`
*Agent:* `bearer-agent`
*Correlation ID:* `8f1d-…`
*Reasons:*
  • Review: Wire transfers require human approval before execution.

Approve: `clavenar-lite pending decide 8f1d-… --allow`
Deny:    `clavenar-lite pending decide 8f1d-… --deny --note "…"`
```

Fire-and-forget by design: a slow or unreachable Slack never blocks
the agent's 202 response. The same generic-webhook shape (a JSON
`{ "text": "..." }` POST) works against Discord and Mattermost too;
MS Teams needs Adaptive Card markup which Lite does not emit. There is
no return path from Slack — operators decide via the CLI or curl. The
clickable-button approval flow lives in the full edition's HIL service.

## Customising policy

Drop additional `*.rego` files into `./policies/` (or wherever you
point `--policies`). The bundled `governance.rego` covers the
canonical denylist (`sql_execute`, `shell_exec`), the intent-score
threshold, the bulk-export business-hours rule, the velocity circuit
breaker, and the wire-transfer review tier. Add your own rules under
`package clavenar.authz`; they merge into the existing `allow` / `deny`
/ `review` rule sets at evaluation time.

The Rego input shape is the full edition's `PolicyInput`:

```json
{
  "tool_type": "search",
  "agent_history": { "last_tool": null },
  "intent_score": 0.05,
  "current_time": "2026-05-02T12:00:00Z",
  "agent_id": "anonymous",
  "method": "call_tool",
  "recent_request_count": 3,
  "correlation_id": null
}
```

## What Lite is *not*

Lite is for developer-laptop use. It deliberately omits:

- **Semantic LLM-based detection.** The full edition runs every
  request through a pluggable inspector LLM for intent classification
  + a separate-call indirect-injection detector — Claude Haiku 4.5 by
  default, with any provider (OpenAI, Google, Bedrock, Vertex, Ollama)
  swapped in via `CLAVENAR_BRAIN_MODELS_FILE`. Lite has only the
  heuristic regex matcher — it catches DAN-style jailbreaks and the
  obvious "ignore previous instructions" overrides, and misses
  everything subtle. If your threat model includes nation-state-grade
  prompt injection, you need the full edition.
- **mTLS.** Lite uses optional bearer-token auth over plain HTTP.
  Production deployments need certificate-based agent identity, which
  is what the full edition's `clavenar-proxy` provides.
- **Vault.** Upstream API keys are passed via env var. The full
  edition pulls per-agent credentials from HashiCorp Vault on every
  request, so a leaked agent process can't exfiltrate the upstream
  key.
- **Human-in-the-Loop (HIL).** Yellow-tier requests
  (e.g. `wire_transfer`) are *soft-denied* in Lite — the response
  carries the review reason and the request is rejected. The full
  edition's `clavenar-hil` orchestrator routes these to a Slack /
  Teams approval flow with a human approver and resumes upstream
  forward on Approved.
- **Multi-instance velocity tracking.** Lite's tracker is in-process.
  Run more than one Lite instance and per-agent counts don't share —
  a velocity-burst attacker can horizontally scale around the breaker.
  The full edition has a NATS-KV-backed shared tracker for this.
- **Cold-tier export** (Iceberg / S3), **regulatory export bundles**,
  and other long-term-retention features — all live in the full
  edition. Chain-version negotiation *is* in Lite: the ledger writes
  rows tagged with `chain_version`, and `verify` distinguishes a
  newer-version row (refuse to verify, prompt upgrade) from an actual
  tamper (point at the first bad seq).

If any of those bullets are critical to your deployment, ship to the
full Clavenar control plane. Lite is the OSS top-of-funnel
surface; the full edition is the production product.

## License

Apache-2.0. See `LICENSE`.
