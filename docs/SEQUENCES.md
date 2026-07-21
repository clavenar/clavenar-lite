# clavenar-lite sequence diagrams

Six sequence diagrams covering the wire-level behaviour of the
single-binary OSS edition: boot, the Green-tier `POST /mcp` fast path,
Yellow-tier park with optional Slack + outbound webhook, operator
decide + async-HIL callback, `clavenar-lite verify` chain-version
dispatch, and the MCP control-plane passthrough with its supply-chain
tool-pin shield. One flowchart at the end captures the Brain/policy tier
classification with its `enforce` / `observe` branching.

The wire shapes mirror `clavenar-proxy` + `clavenar-ledger` (the full
edition's Layer 1 + Layer 4) but collapse into one process, so the
diagrams emphasise the boundaries that stay HTTP — the agent, the
upstream LLM/tool API, the operator, the Slack channel, and the SIEM
sink — and treat the embedded `heuristics`, `policy`, `ledger`, and
`rate_limit` modules as in-process actors.

## 1. Boot — `clavenar-lite start`

The startup sequence walks every fail-fast check that lives between
`main` and the first byte served, in the order they run. A typo in
`--upstream`, a missing `*.rego` file, a malformed
`CLAVENAR_LITE_AGENTS` registry, a callback-allowlist entry that isn't
a URL, or a bad `--webhook-url` all surface as a non-zero exit code
here — never as a 5xx on the first inbound request.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator shell
    participant CLI as clavenar-lite (main)
    participant URL as reqwest::Url::parse
    participant Policy as PolicyEngine::from_dir
    participant Ledger as Ledger::open
    participant Reg as AgentRegistry::parse
    participant State as ArcAppState
    participant Prom as PrometheusBuilder
    participant Axum as axum::serve

    Op->>CLI: clavenar-lite start --upstream URL --policies DIR --ledger PATH ...
    CLI->>CLI: tracing_subscriber::fmt (JSON if CLAVENAR_LOG_FORMAT=json)
    CLI->>CLI: Cli::parse — flag/env merge via clap
    CLI->>URL: parse(cfg.upstream)
    alt parse error
        URL-->>CLI: Err
        CLI-->>Op: exit 1 (invalid upstream URL)
    end
    CLI->>Policy: from_dir(policies, velocity_window)
    Policy->>Policy: read_dir + add_policy for every *.rego
    alt no .rego files OR add_policy fails
        Policy-->>CLI: Err
        CLI-->>Op: exit 1 (policy load failed)
    end
    Policy-->>CLI: ArcPolicyEngine with regorus engine + VelocityTracker
    CLI->>Ledger: open(ledger_path)
    Ledger->>Ledger: pragma WAL + busy_timeout=5000
    Ledger->>Ledger: init_schema — CREATE TABLE entries + pendings
    Ledger->>Ledger: idempotent ALTERs — chain_version, correlation_id, callback_url
    Ledger-->>CLI: ArcLedger (or exit 1 on sqlite error)
    CLI->>CLI: reqwest::Client::builder().timeout(upstream_timeout).build
    alt --agents set
        CLI->>Reg: parse(spec)
        Reg-->>CLI: AgentRegistry with N entries (or exit 1 on duplicate/empty)
    else --token set
        CLI->>Reg: single(token)
        Reg-->>CLI: AgentRegistry with bearer-agent
    else neither
        CLI->>CLI: agents = None (open access, agent_id=anonymous)
    end
    CLI->>CLI: parse callback_allowlist — every prefix must be a valid URL
    CLI->>CLI: parse webhook_url — reqwest::Url::parse or exit 1
    CLI->>CLI: build RateLimiter from RateLimitConfig (None when qps==0)
    CLI->>State: assemble AppState (policy, ledger, agents, mode, slack, callbacks, webhook, rate_limiter)
    CLI->>Prom: install_recorder
    Prom-->>CLI: PrometheusHandle (single global recorder)
    CLI->>CLI: describe_counter for clavenar_lite_inspect_total / verdicts_total / rate_limit_denied_total
    CLI->>Axum: build_router(state).route(/metrics, prom.render)
    CLI->>CLI: tracing::info — boot banner with mode + upstream + auth posture
    CLI->>Axum: TcpListener::bind(0.0.0.0:port)
    CLI->>Axum: tokio::select! axum::serve OR ctrl_c
    Note over Axum: serves /, /health, /readyz, /mcp,<br/>/pending, /pending/{id}, /pending/{id}/decide, /metrics
    Op->>Axum: ctrl-c
    Axum-->>CLI: shutdown
    CLI-->>Op: exit 0
```

## 2. Green-tier `POST /mcp` — explicit server execution

The route is server-executed only when decision headers are absent. Any
complete, partial, unknown, or legacy decision/execution selector is rejected
before rate limiting, policy, ledger mutation, or upstream access, so an SDK
governed request cannot accidentally cause a Lite effect.

The fast path: an authenticated request whose tool name and payload
clear both the heuristic Brain and the Rego policy is forwarded
upstream and the response rides back through with `X-Clavenar-Mode` +
`X-Clavenar-Correlation-Id` stamped. Exactly one ledger row is written
per request at this orchestration step — Lite collapses the full
edition's two-row pattern (proxy + policy emitter) because Brain and
policy are the same process.

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant Proxy as handle_mcp
    participant Rate as RateLimiter
    participant Brain as heuristics::inspect
    participant Policy as PolicyEngine::evaluate
    participant Tracker as VelocityTracker
    participant Ledger as Ledger::append
    participant Hook as webhook::fire_event (spawned)
    participant Upstream

    Agent->>Proxy: POST /mcp + Authorization: Bearer <tok> + JSON-RPC body
    Proxy->>Proxy: clavenar_lite_inspect_total +1
    Proxy->>Proxy: correlation_id = Uuid::new_v4 (minted before any auth check)
    Proxy->>Proxy: AgentRegistry.lookup — constant_time_eq per entry
    alt no registry configured
        Proxy->>Proxy: agent_id = anonymous
    else token matched
        Proxy->>Proxy: agent_id = matched id
    else no match
        Proxy-->>Agent: 401 + X-Clavenar-Correlation-Id (no ledger row, no rate-limit hit)
    end
    opt rate_limiter present
        Proxy->>Rate: check(agent_id)
        Rate-->>Proxy: Allowed
    end
    Proxy->>Proxy: validate_callback_url(headers, state) — empty header skipped
    Proxy->>Proxy: serde_json::from_slice(body) -> McpRequest (method required, non-empty)
    Proxy->>Proxy: tool_type = params.name OR fall back to method
    Proxy->>Brain: inspect(tool_type, body_str)
    Brain->>Brain: detect_injection — lowercase scan of 14 needles
    Brain->>Brain: DANGEROUS_TOOL_NAMES contains tool_type?
    Brain-->>Proxy: HeuristicVerdict (Routine, intent_score=0.05, authorized=true)
    Proxy->>Policy: evaluate(PolicyInput with brain.intent_score, agent_id, ...)
    Policy->>Tracker: record_and_count(agent_id) — only when caller did not preload
    Tracker-->>Policy: recent_request_count
    Policy->>Policy: regorus set_input_json + eval allow/deny/review
    Policy-->>Proxy: PolicyDecision allow=true, reasons=[Deterministic OK], review_reasons=[]
    Proxy->>Proxy: classify(brain, policy) = Tier::Green
    Proxy->>Ledger: append LogRequest (intent_category from brain, authorized=true)
    Ledger->>Ledger: SELECT max seq + entry_hash, hash chain step, INSERT row
    Ledger-->>Proxy: LedgerEntry (write fire-and-forget on warn)
    Proxy->>Upstream: POST upstream_url (Bearer upstream_api_key if set)
    Upstream-->>Proxy: status + body
    opt webhook_url configured
        Proxy->>Hook: spawn fire_event(event=allow, correlation_id, agent_id, mode, ts)
    end
    Proxy-->>Agent: upstream status + body + X-Clavenar-Mode + X-Clavenar-Correlation-Id
```

## 3. Yellow-tier park — 202 + Slack alert + outbound webhook

When `policy.allow && !review_reasons.is_empty()` the request is
parked. The agent gets a 202 with `{status, correlation_id,
review_reasons}` immediately; Slack + the SIEM webhook are
fire-and-forget so the agent never waits on them. In `observe` mode
the same pipeline falls through to the upstream forward with
`X-Clavenar-Would-Pend: true` instead of returning 202.

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant Proxy as handle_mcp
    participant Brain as heuristics::inspect
    participant Policy as PolicyEngine::evaluate
    participant Ledger as Ledger
    participant SlackJob as crate::slack::notify_pending_parked (spawned)
    participant HookJob as webhook::fire_event (spawned)
    participant SlackHook as Slack incoming webhook
    participant SIEM as Outbound webhook sink

    Agent->>Proxy: POST /mcp { method:call_tool, params:{name:wire_transfer, ...} }
    Proxy->>Proxy: auth + rate-limit + callback-URL validate (Sec 2)
    Proxy->>Brain: inspect(wire_transfer, body)
    Brain-->>Proxy: authorized=true, intent_score=0.05, Routine
    Proxy->>Policy: evaluate(PolicyInput)
    Policy-->>Proxy: allow=true, review_reasons=[Review wire transfers require human approval]
    Proxy->>Proxy: classify = Tier::Yellow
    Proxy->>Ledger: append intent_category=PendingReview, authorized=false
    Ledger-->>Proxy: ok (warn on append fail)
    alt mode == Enforce
        Proxy->>Ledger: park_pending(ParkRequest with optional callback_url)
        Ledger->>Ledger: INSERT INTO pendings VALUES (correlation_id, agent_id, tool_type, method, review_reasons_json, requested_at, callback_url)
        Ledger-->>Proxy: Pending row
        opt slack_webhook_url set
            Proxy->>SlackJob: tokio::spawn notify_pending_parked
            SlackJob->>SlackHook: POST { text: format_pending_message(parked) }
            SlackHook-->>SlackJob: 200 (or warn on non-2xx)
        end
        opt webhook_url set
            Proxy->>HookJob: tokio::spawn fire_event(event=park)
            HookJob->>SIEM: POST WebhookEvent JSON (5s timeout)
            SIEM-->>HookJob: 2xx (or warn)
        end
        Proxy-->>Agent: 202 Accepted + PendingResponse { status:pending, correlation_id, review_reasons } + X-Clavenar-Correlation-Id
    else mode == Observe
        Note over Proxy: park branch skipped — falls through to forward
        Proxy->>Proxy: forward upstream as in Sec 2
        opt webhook_url set
            Proxy->>HookJob: spawn fire_event(event=would_park)
        end
        Proxy-->>Agent: upstream response + X-Clavenar-Would-Pend: true + X-Clavenar-Mode: observe
    end
```

## 4. Operator decide — token gate, second ledger row, async-HIL callback

`POST /pending/{id}/decide` is the only operator-write capability and
sits behind a distinct `--decide-token` so an agent bearer can never
approve its own pendings. The handler writes a second ledger row
(`PendingApproved` / `PendingDenied`) to close the audit story, fires
one SIEM `decide_allow`/`decide_deny` event, and — if the agent
registered an `X-Clavenar-Callback-URL` at park time — POSTs the
decision to that URL fire-and-forget so the SDK does not have to
poll.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator (CLI / curl)
    participant Proxy as handle_decide_pending
    participant Ledger as Ledger
    participant HookJob as webhook::fire_event (spawned)
    participant CbJob as fire_callback (spawned)
    participant SIEM as Outbound webhook sink
    participant Cb as Agent-supplied callback URL

    Op->>Proxy: POST /pending/{id}/decide + Authorization: Bearer <decide-token> + { decision, note? }
    Proxy->>Proxy: decide_corr = Uuid::new_v4 (separate from pending id)
    alt decide_token configured
        Proxy->>Proxy: constant_time_eq supplied vs expected
        alt mismatch
            Proxy-->>Op: 401 + X-Clavenar-Correlation-Id(decide_corr)
        end
    end
    Proxy->>Proxy: serde_json::from_slice(body) -> DecideRequest (400 on parse fail)
    Proxy->>Ledger: decide_pending(id, decision, note)
    Ledger->>Ledger: SELECT pendings WHERE correlation_id under Mutex<Connection>
    alt no row
        Ledger-->>Proxy: NotFound
        Proxy-->>Op: 404
    else pending.decision is Some
        Ledger-->>Proxy: AlreadyDecided
        Proxy-->>Op: 409
    else decision not in {allow,deny}
        Ledger-->>Proxy: InvalidDecision(d)
        Proxy-->>Op: 400
    end
    Ledger->>Ledger: UPDATE pendings SET decided_at, decision, decider_note WHERE decided_at IS NULL
    Ledger-->>Proxy: Pending (decision/note/decided_at populated)
    Proxy->>Proxy: format_decide_reasoning — review reasons + optional note
    Proxy->>Ledger: append LogRequest intent=PendingApproved|PendingDenied, authorized=decision==allow
    Ledger-->>Proxy: ok (warn-and-continue on append fail — decision is durable)
    opt webhook_url set
        Proxy->>HookJob: spawn fire_event(event=decide_allow|decide_deny, intent_category=OperatorDecide)
        HookJob->>SIEM: POST WebhookEvent JSON (5s timeout)
    end
    opt decided.callback_url set
        Proxy->>CbJob: spawn fire_callback(http, url, CallbackBody { correlation_id, decision, decider_note, decided_at })
        CbJob->>Cb: POST CallbackBody JSON (5s timeout)
        Cb-->>CbJob: 2xx (or warn on non-2xx / send error)
    end
    Proxy-->>Op: 200 + PendingView (Pending serialised as JSON)
```

## 5. `clavenar-lite verify` — chain walk + version dispatch + exit codes

`verify` is the CI-friendly subcommand: open the SQLite ledger,
recompute every row's hash through `recompute_for_version`, and
distinguish three outcomes — valid, tamper (`first_invalid_seq`
populated), or a row written under a newer chain version this binary
does not know how to verify. Exit codes are pinned: 0 valid, 2 chain
corruption OR unsupported version, 1 runtime/IO failure.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator shell
    participant Main as run_verify
    participant LedgerOpen as Ledger::open
    participant Verify as Ledger::verify
    participant Rec as recompute_for_version
    participant DB as SQLite (entries table)

    Op->>Main: clavenar-lite verify --ledger PATH
    Main->>LedgerOpen: open(path)
    LedgerOpen->>LedgerOpen: pragma WAL + busy_timeout
    LedgerOpen->>LedgerOpen: init_schema + idempotent ALTERs (chain_version, correlation_id)
    LedgerOpen-->>Main: Arc<Ledger> (or exit 1 on sqlite error)
    Main->>Verify: verify()
    Verify->>DB: SELECT entries ORDER BY seq ASC
    DB-->>Verify: row stream
    loop every row
        Verify->>Verify: row_to_entry
        Verify->>Rec: recompute_for_version(entry.chain_version, &entry)
        alt version == 1
            Rec->>Rec: hash = sha256(prev_hash || pipe || canonical(HashableEntryV1))
            Rec-->>Verify: Some(hex hash)
            alt prev_hash != expected_prev OR recomputed != entry_hash
                Verify->>Verify: first_invalid = Some(entry.seq) — break
            else
                Verify->>Verify: expected_prev = entry.entry_hash — count += 1
            end
        else version unknown to this binary
            Rec-->>Verify: None
            Verify->>Verify: unsupported_chain_version = Some(ver) — break
        end
    end
    Verify-->>Main: VerifyResult { valid, entries_checked, first_invalid_seq, unsupported_chain_version }
    alt v.valid
        Main-->>Op: stdout — ledger verified, N entries OK — exit 0
    else first_invalid_seq is Some(seq)
        Main-->>Op: stderr — tamper at seq, N valid before it — exit 2
    else unsupported_chain_version is Some(ver)
        Main-->>Op: stderr — unsupported chain_version ver — upgrade clavenar-lite — exit 2
    else
        Main-->>Op: stderr — verifier reported failure with no specific cause — exit 2
    end
```

## 6. MCP control-plane passthrough + supply-chain tool-pin shield

The MCP control plane — the handshake and catalog verbs an MCP client
issues before it ever calls a tool — carries no tool arguments to
inspect, so `handle_mcp` short-circuits the seven control methods
(`initialize`, `initialized`, `notifications/initialized`, `tools/list`,
`resources/list`, `prompts/list`, `ping`) straight to the upstream via
`forward_control` *before* any Brain/policy work — after the auth,
rate-limit, callback-validate, and parse gates still run (Sec 2). They
bypass the tiers and write no per-request ledger row: routing a
spec-compliant handshake through the deny/park tiers would block a
client from connecting at all. The one place the control plane still
touches the audit chain is `tools/list` — `forward_control` feeds the
response to `supply_chain::observe_tools_list`, which pins the first
catalog an agent sees and appends a `tool_schema_poisoned` forensic row
(`intent_category="SupplyChain"`, `authorized=false`) when a later list
diverges from the pin. That is the canonical MCP tool-poisoning /
rug-pull catch.

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant Proxy as handle_mcp
    participant Fwd as forward_control
    participant Pins as supply_chain::observe_tools_list
    participant Store as ToolPinStore
    participant Ledger as Ledger
    participant Upstream

    Agent->>Proxy: POST /mcp { method: initialize|tools/list|ping|... }
    Proxy->>Proxy: auth + rate-limit + callback validate + parse (Sec 2)
    Proxy->>Proxy: is_mcp_control_method(method) == true
    Note over Proxy: 7 control methods bypass brain/policy/classify —<br/>no tier, no per-request ledger row
    Proxy->>Fwd: forward_control(agent_id, correlation_id, method, body)
    Fwd->>Upstream: POST upstream_url (Bearer upstream_api_key if set), body verbatim
    Upstream-->>Fwd: status + body
    opt method == tools/list
        Fwd->>Pins: observe_tools_list(agent_id, body)
        Pins->>Pins: definition_hashes — sha256(canonical(description + inputSchema)) per tool (unparseable body returns early)
        Pins->>Store: lock pins, read agent_id catalog
        alt first tools/list for agent_id
            Store-->>Pins: None
            Pins->>Store: pin fresh catalog — return (no ledger row)
        else diverges from pin (mutated / added / removed)
            Store-->>Pins: pinned catalog
            Pins->>Pins: diff_against_pin — non-empty change set
            Pins->>Ledger: append method=tools/list, intent_category=SupplyChain, authorized=false, policy_decision={signal:tool_schema_poisoned}
            Ledger-->>Pins: ok (warn on append fail)
        else matches pin
            Store-->>Pins: pinned catalog
            Pins->>Pins: diff empty — no row
        end
    end
    Fwd-->>Agent: upstream status + body + X-Clavenar-Correlation-Id + X-Clavenar-Mode
```

## 7. Tier classification + mode branching (flowchart)

The classifier itself is three lines (`classify` in `src/proxy.rs`) but
the practical behavior of a single `/mcp` request fans out across the
heuristic / policy outcomes and the enforce / observe knob. This is the
decision tree that decides what HTTP status the agent sees and which
ledger rows + webhook events fire. The seven MCP control methods branch
off this tree before any tier is computed (Sec 6) — they forward
straight through and the tiers below never see them.

```mermaid
flowchart TD
    Start([POST /mcp]) --> Auth{AgentRegistry<br/>lookup}
    Auth -->|no match| H401[401 Unauthorized<br/>no ledger row]
    Auth -->|ok / open| Rate{rate_limiter<br/>check}
    Rate -->|Denied| H429[429 Too Many Requests<br/>ledger row<br/>RateLimitDenied]
    Rate -->|Allowed / off| CB{callback URL<br/>validate}
    CB -->|reject| H400CB[400 Bad Request<br/>callback URL outside allowlist]
    CB -->|ok / absent| Parse{JSON-RPC parse<br/>and method non-empty}
    Parse -->|fail| H400[400 Bad Request]
    Parse -->|ok| Ctrl{is_mcp_control_method}
    Ctrl -->|yes| Fwd[forward_control<br/>passthrough to upstream<br/>no tier, no per-request ledger row]
    Ctrl -->|no| Pipe[heuristics inspect<br/>+ policy evaluate]
    Fwd --> CtrlOut[relay upstream status + body<br/>X-Clavenar-Correlation-Id + X-Clavenar-Mode<br/>tools/list also feeds supply-chain pin]
    Pipe --> Tier{classify<br/>brain, policy}

    Tier -->|brain authorized=false<br/>OR policy allow=false| Red[Tier Red]
    Tier -->|allow=true<br/>review_reasons non-empty| Yellow[Tier Yellow]
    Tier -->|allow=true<br/>review_reasons empty| Green[Tier Green]

    Red --> ModeR{mode}
    ModeR -->|enforce| R403[403 Forbidden<br/>DenyResponse JSON<br/>webhook event=deny]
    ModeR -->|observe| RFwd[forward upstream<br/>X-Clavenar-Would-Deny: true<br/>webhook event=would_deny]

    Yellow --> ModeY{mode}
    ModeY -->|enforce| Y202[park_pending<br/>+ spawn Slack<br/>+ webhook event=park<br/>202 Accepted PendingResponse]
    ModeY -->|observe| YFwd[forward upstream<br/>X-Clavenar-Would-Pend: true<br/>webhook event=would_park]

    Green --> GFwd[forward upstream<br/>webhook event=allow]
    GFwd --> OK[200 OK + upstream body<br/>X-Clavenar-Mode<br/>X-Clavenar-Correlation-Id]
    RFwd --> OK
    YFwd --> OK

    R403 --> Ledger1[ledger row<br/>PolicyDeny or BrainDeny or PromptInjection<br/>authorized=false]
    Y202 --> Ledger2[ledger row<br/>PendingReview<br/>authorized=false]
    OK --> Ledger3[ledger row<br/>brain.intent_category<br/>authorized = Green only]
```
