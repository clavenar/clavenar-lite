# warden-lite

Single-binary OSS edition of [Agent Warden](https://github.com/vanteguardlabs).
A drop-in proxy that sits between an AI agent and the LLM/tool API it
calls — inspecting every request, evaluating policy, and writing a
hash-chained forensic ledger — without standing up a multi-service
control plane.

[![Deploy on Fly.io](https://fly.io/static/images/launch/deploy.svg)](https://fly.io/launch/?repo=https://github.com/vanteguardlabs/warden-lite)

```bash
cargo install warden-lite
warden-lite start --upstream https://api.openai.com/v1 --port 8088
```

Now point your agent at `http://localhost:8088/mcp` instead of the
upstream URL. Every request is inspected before it forwards.

## 60-second deploy

The repo ships a multi-stage `Dockerfile` and a `fly.toml` tuned for
the free tier — observe mode, shared-cpu-1x, auto-stop. Click the
button above or:

```bash
fly launch --copy-config --image $(docker build -q .)
fly secrets set WARDEN_LITE_UPSTREAM_URL=https://api.openai.com/v1/chat/completions
fly secrets set WARDEN_LITE_TOKEN=<random-bearer>     # optional ingress auth
fly deploy
```

That's it. The deployed proxy starts in observe mode (every request
forwards, ledger records what *would* have been denied). Once you've
watched the `X-Warden-Would-Deny` rate settle, flip the mode:

```bash
fly secrets set WARDEN_LITE_MODE=enforce
fly deploy --restart-only
```

See **Promoting to production** below for the ledger-persistence and
upstream-credential-injection knobs.

## Container

```bash
docker build -t warden-lite .
docker run -p 8088:8088 \
  -e WARDEN_LITE_UPSTREAM_URL=https://api.openai.com/v1/chat/completions \
  -e WARDEN_LITE_MODE=observe \
  warden-lite
```

The image:

- Runs as nonroot UID 65532.
- Bundles the default `governance.rego` at
  `/etc/warden-lite/policies`. Override with a bind-mount and
  `WARDEN_LITE_POLICY_DIR`.
- Defaults the ledger to `:memory:`. Set
  `WARDEN_LITE_LEDGER=/var/lib/warden-lite/ledger.db` and bind-mount
  a volume to persist the audit chain across restarts.
- Honours every `WARDEN_LITE_*` env in the table below.

### Promoting to production

For real traffic, layer these in on top of the default deploy:

- **Persistent ledger.** Mount a volume at `/var/lib/warden-lite` and
  set `WARDEN_LITE_LEDGER=/var/lib/warden-lite/ledger.db`. The hash
  chain survives restarts; `warden-lite verify` keeps validating.
- **Custom policies.** Bind-mount your own Rego directory at
  `/etc/warden-lite/policies` (or any path you prefer with
  `WARDEN_LITE_POLICY_DIR`). The bundled `governance.rego` is a
  starting baseline, not a finished policy.
- **Ingress auth.** Set `WARDEN_LITE_TOKEN`; partners then send
  `Authorization: Bearer <token>` and unauthenticated requests get
  401. Without it the proxy accepts every connection.
- **Upstream creds.** `WARDEN_LITE_UPSTREAM_API_KEY` injects the key
  into forwarded requests so your agent never sees it. Same shape
  as the full edition's Vault injection, minus Vault.
- **Enforce mode.** Flip `WARDEN_LITE_MODE=enforce` once the observe
  data is clean.

## What's in the box

| Layer                | What it does                                                              | Lite ships                                                     |
|----------------------|---------------------------------------------------------------------------|----------------------------------------------------------------|
| **Heuristic Brain**  | Scan payload for prompt injection / jailbreak / dangerous-tool signatures | Pure-Rust regex/substring matcher; ~14 needles                 |
| **Policy Engine**    | Evaluate Rego rules over `tool_type`, `intent_score`, time-of-day, velocity | `regorus` (pure-Rust Rego), in-process velocity tracker        |
| **Ledger**           | Append-only forensic store with SHA-256 hash chain                        | SQLite (bundled), `verify` and `audit` CLI subcommands         |
| **Proxy**            | HTTP ingress, security-first orchestration, upstream credential injection | axum + reqwest, optional bearer-token auth                     |

The chain format and policy input shape are byte-compatible with the
full Agent Warden edition. A chain produced by `warden-lite` verifies
under the production ledger; a `governance.rego` written for the full
edition runs verbatim under Lite.

## Quick start

### 1. Install

```bash
cargo install warden-lite
```

### 2. Run

```bash
# Minimal: forward every request to a local stub upstream.
warden-lite start --upstream http://localhost:9000/mcp

# Realistic: wrap OpenAI. Agent never sees the API key.
WARDEN_LITE_UPSTREAM_API_KEY=sk-... \
  warden-lite start \
  --upstream https://api.openai.com/v1/chat/completions \
  --port 8088
```

### 3. Audit

```bash
warden-lite verify
# ledger ./warden-lite.db verified — 47 entries OK

warden-lite audit anonymous
# [2026-05-02T14:23:01Z] seq=12 method=call_tool intent=PromptInjection
#   authorized=false reasoning=brain[PromptInjection]: Heuristic injection match: ...
```

## Subcommands

```
warden-lite start [--port N] [--upstream URL] [--policies DIR] [--ledger PATH]
                  [--velocity-window SECS] [--token TOKEN]
                  [--upstream-api-key KEY] [--upstream-timeout-secs SECS]
warden-lite verify [--ledger PATH]
warden-lite audit  [--ledger PATH] <agent_id>
```

Every flag falls back to a `WARDEN_LITE_*` env var:

| Flag                       | Env var                              | Default                   |
|----------------------------|--------------------------------------|---------------------------|
| `--port`                   | `WARDEN_LITE_PORT`                   | 8088                      |
| `--upstream`               | `WARDEN_LITE_UPSTREAM_URL`           | http://localhost:9000/mcp |
| `--policies`               | `WARDEN_LITE_POLICY_DIR`             | ./policies                |
| `--ledger`                 | `WARDEN_LITE_LEDGER`                 | ./warden-lite.db          |
| `--velocity-window`        | `WARDEN_LITE_VELOCITY_WINDOW_SECS`   | 60                        |
| `--token`                  | `WARDEN_LITE_TOKEN`                  | (none — open access)      |
| `--upstream-api-key`       | `WARDEN_LITE_UPSTREAM_API_KEY`       | (none — pass-through)     |
| `--upstream-timeout-secs`  | `WARDEN_LITE_UPSTREAM_TIMEOUT_SECS`  | 120                       |
| `--mode`                   | `WARDEN_LITE_MODE`                   | `enforce`                 |

The upstream URL is parsed at startup and a typo fails fast with exit
code `1` rather than 502-ing the first request through.

## Rollout: observe before enforce

`--mode observe` flips warden-lite into a pass-through observability
layer:

- Every request forwards upstream regardless of policy / Brain verdict.
- The ledger still records `authorized=false` for would-have-denied
  requests, so the audit trail of what enforce mode *would* have done
  stays accurate.
- Every response carries `X-Warden-Mode: observe`. Would-have-denied
  responses also carry `X-Warden-Would-Deny: true` — count those to
  size the blast radius of flipping enforce on.

Recommended rollout: deploy in observe for a week, watch the
`X-Warden-Would-Deny` rate per tool in your dashboards, tune policies
until the rate is on the floor of "things that genuinely should be
denied," then flip `WARDEN_LITE_MODE=enforce` and pop the gate.

```bash
warden-lite start --mode observe --upstream https://api.openai.com/v1
```

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

On a security veto, you get HTTP 403 + a structured JSON body:

```json
{
  "error": "security_violation",
  "reasons": ["Violation: Direct execution of SQL queries is prohibited for this agent."],
  "review_reasons": [],
  "intent_category": "DangerousTool"
}
```

Exit codes from the `verify` subcommand are CI-friendly: `0` valid, `2`
chain corruption detected, `1` runtime error (DB unreadable, etc.).

## Customising policy

Drop additional `*.rego` files into `./policies/` (or wherever you
point `--policies`). The bundled `governance.rego` covers the
canonical denylist (`sql_execute`, `shell_exec`), the intent-score
threshold, the bulk-export business-hours rule, the velocity circuit
breaker, and the wire-transfer review tier. Add your own rules under
`package warden.authz`; they merge into the existing `allow` / `deny`
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
  request through Claude 4.5 Haiku for intent classification + a
  separate-call indirect-injection detector. Lite has only the
  heuristic regex matcher — it catches DAN-style jailbreaks and the
  obvious "ignore previous instructions" overrides, and misses
  everything subtle. If your threat model includes nation-state-grade
  prompt injection, you need the full edition.
- **mTLS.** Lite uses optional bearer-token auth over plain HTTP.
  Production deployments need certificate-based agent identity, which
  is what the full edition's `warden-proxy` provides.
- **Vault.** Upstream API keys are passed via env var. The full
  edition pulls per-agent credentials from HashiCorp Vault on every
  request, so a leaked agent process can't exfiltrate the upstream
  key.
- **Human-in-the-Loop (HIL).** Yellow-tier requests
  (e.g. `wire_transfer`) are *soft-denied* in Lite — the response
  carries the review reason and the request is rejected. The full
  edition's `warden-hil` orchestrator routes these to a Slack /
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
full Agent Warden control plane. Lite is the OSS top-of-funnel
surface; the full edition is the production product.

## License

Apache-2.0. See `LICENSE`.
