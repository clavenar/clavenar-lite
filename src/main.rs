//! clavenar-lite — single-binary OSS edition of Clavenar.
//!
//! ```text
//! clavenar-lite start [--port 8088] [--upstream URL] [--policies DIR] [--ledger PATH]
//! clavenar-lite verify [--ledger PATH]
//! clavenar-lite audit  [--ledger PATH] <agent_id>
//! ```
//!
//! All flags fall back to env vars (`CLAVENAR_LITE_*`) so you can drop a
//! `.env` next to the binary and just `clavenar-lite start`. See
//! `README.md` for the full env-var matrix.

use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use clavenar_lite::ledger::Ledger;
use clavenar_lite::policy::PolicyEngine;
use clavenar_lite::proxy::{build_router, AgentRegistry, AppState, ClavenarMode};

#[derive(Parser, Debug)]
#[command(
    name = "clavenar-lite",
    about = "Clavenar Community Edition — single-binary OSS proxy.",
    version,
    long_about = "Embedded heuristic Brain + Rego policy engine + SHA-256 hash-chained SQLite ledger in one binary. \
                  Designed for developer-laptop use. \
                  For production deployments (mTLS, Vault, multi-instance, HIL, semantic LLM-based detection), \
                  see the full Clavenar edition."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the clavenar-lite proxy server.
    Start {
        /// HTTP listen port. Default 8088 (env `CLAVENAR_LITE_PORT`).
        #[arg(long, env = "CLAVENAR_LITE_PORT")]
        port: Option<u16>,

        /// Upstream URL the proxy forwards authorized requests to.
        /// Default `http://localhost:9000/mcp` (env `CLAVENAR_LITE_UPSTREAM_URL`).
        #[arg(long, env = "CLAVENAR_LITE_UPSTREAM_URL")]
        upstream: Option<String>,

        /// Directory containing `*.rego` policy files. Default `./policies`
        /// (env `CLAVENAR_LITE_POLICY_DIR`).
        #[arg(long, env = "CLAVENAR_LITE_POLICY_DIR")]
        policies: Option<PathBuf>,

        /// SQLite ledger path. Use `:memory:` for an ephemeral run.
        /// Default `./clavenar-lite.db` (env `CLAVENAR_LITE_LEDGER`).
        #[arg(long, env = "CLAVENAR_LITE_LEDGER")]
        ledger: Option<String>,

        /// Velocity-tracker window in seconds. Default 60.
        #[arg(long, env = "CLAVENAR_LITE_VELOCITY_WINDOW_SECS")]
        velocity_window: Option<u64>,

        /// Optional bearer token for inbound auth. If set, every
        /// `POST /mcp` must send `Authorization: Bearer <token>`.
        /// Read from `CLAVENAR_LITE_TOKEN` if not passed on the CLI.
        /// Mutually exclusive with `--agents`; the multi-agent
        /// registry takes precedence if both are set.
        #[arg(long, env = "CLAVENAR_LITE_TOKEN")]
        token: Option<String>,

        /// Multi-agent registry. Comma-separated `id:token` pairs;
        /// each token gets its own `agent_id` on the ledger and in
        /// policy input. e.g.
        /// `--agents agent-a:tok-a,agent-b:tok-b`. Env
        /// `CLAVENAR_LITE_AGENTS`. Mutually exclusive with `--token`.
        #[arg(long, env = "CLAVENAR_LITE_AGENTS")]
        agents: Option<String>,

        /// Optional bearer token gating `POST /pending/{id}/decide`.
        /// If set, every decide call must send `Authorization: Bearer
        /// <token>`. Held separately from `--token` because operator
        /// (approver) capability is strictly higher than agent capability —
        /// reusing the agent's bearer would let the agent approve its own
        /// pendings. Env `CLAVENAR_LITE_DECIDE_TOKEN`.
        #[arg(long, env = "CLAVENAR_LITE_DECIDE_TOKEN")]
        decide_token: Option<String>,

        /// Optional API key forwarded to the upstream as
        /// `Authorization: Bearer <key>`. Use this for OpenAI /
        /// Anthropic / etc. when the agent shouldn't see the key
        /// directly. Env: `CLAVENAR_LITE_UPSTREAM_API_KEY`.
        #[arg(long, env = "CLAVENAR_LITE_UPSTREAM_API_KEY")]
        upstream_api_key: Option<String>,

        /// Per-request timeout (in seconds) for the upstream forward.
        /// LLM completions can be slow, so the default is generous; set
        /// lower if you want a stalled upstream to surface as a 504 fast.
        /// Default 120. Env `CLAVENAR_LITE_UPSTREAM_TIMEOUT_SECS`.
        #[arg(long, env = "CLAVENAR_LITE_UPSTREAM_TIMEOUT_SECS")]
        upstream_timeout_secs: Option<u64>,

        /// Enforcement mode. `enforce` (default) returns 403 on
        /// would-deny; `observe` forwards every request upstream and
        /// surfaces the would-deny via the `X-Clavenar-Would-Deny`
        /// response header. Use observe for the rollout phase before
        /// you trust the policies. Env `CLAVENAR_LITE_MODE`.
        #[arg(long, env = "CLAVENAR_LITE_MODE", value_parser = parse_mode)]
        mode: Option<ClavenarMode>,

        /// Optional Slack-incoming-webhook URL. When set, every
        /// yellow-tier park fires a one-way alert with the
        /// correlation id, tool, agent, review reasons, and the
        /// `clavenar-lite pending decide` command-line. No return path
        /// — operators decide via CLI or curl. Env
        /// `CLAVENAR_LITE_SLACK_WEBHOOK_URL`.
        #[arg(long, env = "CLAVENAR_LITE_SLACK_WEBHOOK_URL")]
        slack_webhook_url: Option<String>,

        /// Async-HIL callback-URL allowlist. Comma-separated literal
        /// URL prefixes; an inbound `X-Clavenar-Callback-URL` header is
        /// accepted only if it starts with one of these. Unset (the
        /// default) means callback URLs are rejected — partners poll.
        /// e.g. `--callback-allowlist https://my-app.example.com/`.
        /// Env `CLAVENAR_LITE_CALLBACK_ALLOWLIST`.
        #[arg(long, env = "CLAVENAR_LITE_CALLBACK_ALLOWLIST")]
        callback_allowlist: Option<String>,

        /// Outbound verdict-webhook URL. When set, every terminal
        /// pipeline outcome (allow / deny / park; would_deny /
        /// would_park in observe mode) and every operator decide
        /// fires a fire-and-forget POST with a stable JSON event
        /// shape. Intended for SIEM / Datadog HTTP / generic webhook
        /// ingest — distinct from `--slack-webhook-url` (Markdown for
        /// humans). Env `CLAVENAR_LITE_WEBHOOK_URL`.
        #[arg(long, env = "CLAVENAR_LITE_WEBHOOK_URL")]
        webhook_url: Option<String>,

        /// Per-agent rate-limit refill rate, requests/second. Default
        /// 0 (disabled). When set, `/mcp` enforces a per-agent token
        /// bucket *before* the brain/policy pipeline runs; an over-
        /// limit agent gets HTTP 429 with a JSON body (`error`,
        /// `agent_id`, `retry_after_secs`, `correlation_id`) and a
        /// ledger row with `intent_category="RateLimitDenied"`. Env
        /// `CLAVENAR_LITE_RATE_LIMIT_QPS`.
        #[arg(long, env = "CLAVENAR_LITE_RATE_LIMIT_QPS")]
        rate_limit_qps: Option<f64>,

        /// Per-agent rate-limit bucket capacity (allows transient
        /// spikes above `--rate-limit-qps`). Defaults to `ceil(qps)`
        /// when unset; ignored when `--rate-limit-qps` is 0. Env
        /// `CLAVENAR_LITE_RATE_LIMIT_BURST`.
        #[arg(long, env = "CLAVENAR_LITE_RATE_LIMIT_BURST")]
        rate_limit_burst: Option<u32>,

        /// Enrich deny/park responses with the per-detector heuristic
        /// breakdown (`detail`). Off by default — a detailed denial
        /// leaks detection logic, so this is a dev knob. The
        /// `CLAVENAR_LITE_VERBOSE_VERDICTS` env var (`true`/`1`/`yes`)
        /// also enables it, matching the full edition's truthy set; an
        /// unrecognized value stays off rather than aborting boot.
        #[arg(long)]
        verbose_verdicts: bool,
    },

    /// Walk every entry in the ledger and confirm the hash chain is
    /// intact. Exits 0 if valid, 2 if any entry's hash doesn't match.
    Verify {
        /// SQLite ledger path. Default `./clavenar-lite.db`.
        #[arg(long, env = "CLAVENAR_LITE_LEDGER")]
        ledger: Option<String>,
    },

    /// Print every ledger entry for a given agent_id, oldest first.
    /// Useful for incident review.
    Audit {
        /// SQLite ledger path. Default `./clavenar-lite.db`.
        #[arg(long, env = "CLAVENAR_LITE_LEDGER")]
        ledger: Option<String>,

        /// The agent_id to audit (matched against the `agent_id` column).
        agent_id: String,
    },

    /// Operator commands for parked tool calls — list, inspect, decide.
    /// Talks to a running clavenar-lite over HTTP; not a local-DB
    /// operation. Use against the same `--endpoint` your agent posts to.
    Pending {
        #[command(subcommand)]
        action: PendingAction,
    },

    /// Snapshot the ledger DB to a portable file using SQLite's online-
    /// backup API. Safe to run against a live clavenar-lite process; the
    /// snapshot is a self-contained SQLite DB that opens with
    /// `Ledger::open` and verifies clean with `clavenar-lite verify`.
    /// The hash chain is re-verified after the copy completes.
    Backup {
        /// Source ledger path. Default `./clavenar-lite.db`. Env
        /// `CLAVENAR_LITE_LEDGER`.
        #[arg(long, env = "CLAVENAR_LITE_LEDGER")]
        ledger: Option<String>,

        /// Destination file. Overwritten if it already exists.
        #[arg(long)]
        output: PathBuf,
    },

    /// Restore the ledger from a snapshot file. Verifies the chain on
    /// the snapshot BEFORE replacing the target (fail-closed: an
    /// invalid snapshot never lands on disk). Refuses to overwrite an
    /// existing ledger without `--force`. Recommended workflow: stop
    /// the clavenar-lite process, restore, restart.
    Restore {
        /// Snapshot file produced by `clavenar-lite backup`.
        #[arg(long)]
        input: PathBuf,

        /// Target ledger path. Default `./clavenar-lite.db`. Env
        /// `CLAVENAR_LITE_LEDGER`.
        #[arg(long, env = "CLAVENAR_LITE_LEDGER")]
        ledger: Option<String>,

        /// Overwrite an existing target ledger. Without this flag,
        /// restoring onto a non-empty path errors out so an
        /// accidental restore can't replace a live DB.
        #[arg(long)]
        force: bool,
    },

    /// Observe→enforce graduation: summarize what enforce mode WOULD
    /// have blocked or parked (from the observe-mode ledger) and emit a
    /// signed, human-readable report. `report` generates; `verify`
    /// checks a report's signature offline.
    Graduate {
        #[command(subcommand)]
        action: GraduateAction,
    },
}

#[derive(Subcommand, Debug)]
enum GraduateAction {
    /// Generate a graduation report from the local ledger.
    Report {
        /// SQLite ledger path. Default `./clavenar-lite.db`.
        #[arg(long, env = "CLAVENAR_LITE_LEDGER")]
        ledger: Option<String>,

        /// Only summarize rows at or after this instant. Accepts RFC 3339
        /// (`2026-06-01T00:00:00Z`) or a relative duration (`24h`, `7d`,
        /// `90m`). Omit to summarize the whole ledger.
        #[arg(long)]
        since: Option<String>,

        /// PKCS#8 PEM Ed25519 signing key
        /// (`openssl genpkey -algorithm ed25519`). When omitted the
        /// report is emitted UNSIGNED (still useful, just not
        /// tamper-evident).
        #[arg(long, env = "CLAVENAR_LITE_SIGNING_KEY_PATH")]
        signing_key: Option<PathBuf>,

        /// Write the report here instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Output shape: `json` (the signed artifact) or `text` (a human
        /// summary).
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },

    /// Verify a graduation report's signature offline. Uses the public
    /// key embedded in the report unless `--pubkey` pins one.
    Verify {
        /// Path to a report produced by `graduate report`.
        #[arg(long)]
        report: PathBuf,

        /// SPKI PEM public key to verify against, overriding the
        /// report's embedded `pubkey_pem`.
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum ReportFormat {
    Json,
    Text,
}

#[derive(Subcommand, Debug)]
enum PendingAction {
    /// List parked (or decided, or all) pendings.
    List {
        /// Clavenar-lite base URL. Default `http://localhost:8088`.
        #[arg(long, env = "CLAVENAR_LITE_URL", default_value = "http://localhost:8088")]
        endpoint: String,
        /// Operator bearer token. Required if clavenar-lite was booted
        /// with `--decide-token`. Env `CLAVENAR_LITE_DECIDE_TOKEN`.
        #[arg(long, env = "CLAVENAR_LITE_DECIDE_TOKEN")]
        decide_token: Option<String>,
        /// `parked` (default) | `decided` | `all`.
        #[arg(long, default_value = "parked")]
        status: String,
        /// Max rows. Server caps at 500.
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Sort by `requested_at`: `oldest` (triage queue) or `newest`
        /// (history). When unset, defaults to `oldest` for the
        /// `parked` filter and `newest` for `decided`/`all`.
        #[arg(long)]
        sort: Option<String>,
        /// Print raw JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Look up one pending by correlation id.
    Get {
        /// Correlation id (returned in the 202 body and the
        /// `X-Clavenar-Correlation-Id` header).
        id: String,
        #[arg(long, env = "CLAVENAR_LITE_URL", default_value = "http://localhost:8088")]
        endpoint: String,
        /// Agent bearer token (poll path). Env `CLAVENAR_LITE_TOKEN`.
        #[arg(long, env = "CLAVENAR_LITE_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Resolve a pending — pick exactly one of `--allow` or `--deny`,
    /// with an optional free-text `--note` that lands in the audit
    /// ledger.
    Decide {
        id: String,
        #[arg(long, env = "CLAVENAR_LITE_URL", default_value = "http://localhost:8088")]
        endpoint: String,
        #[arg(long, env = "CLAVENAR_LITE_DECIDE_TOKEN")]
        decide_token: Option<String>,
        #[arg(long, conflicts_with = "deny")]
        allow: bool,
        #[arg(long, conflicts_with = "allow")]
        deny: bool,
        #[arg(long)]
        note: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    // `RUST_LOG` env var controls level. Default to "info" if unset so
    // `clavenar-lite start` shows the boot banner without extra config.
    // `CLAVENAR_LOG_FORMAT=json` switches to one structured event per
    // line (current span fields + active span stack) — same env knob
    // every other clavenar-* service exposes so one log-shipping config
    // ingests any component.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match std::env::var("CLAVENAR_LOG_FORMAT").as_deref() {
        Ok("json") => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .init(),
        _ => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }

    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Start {
            port,
            upstream,
            policies,
            ledger,
            velocity_window,
            token,
            agents,
            decide_token,
            upstream_api_key,
            upstream_timeout_secs,
            mode,
            slack_webhook_url,
            callback_allowlist,
            webhook_url,
            rate_limit_qps,
            rate_limit_burst,
            verbose_verdicts,
        } => {
            let port = port.unwrap_or(8088);
            let upstream = upstream.unwrap_or_else(|| "http://localhost:9000/mcp".into());
            let policies = policies.unwrap_or_else(|| PathBuf::from("./policies"));
            let ledger_path = ledger.unwrap_or_else(|| "./clavenar-lite.db".into());
            let velocity_window = velocity_window.unwrap_or(60);
            let upstream_timeout = Duration::from_secs(upstream_timeout_secs.unwrap_or(120));
            let mode = mode.unwrap_or(ClavenarMode::Enforce);
            // The flag enables it; so does a truthy env var. Mirrors the
            // full edition's `true|1|yes` set and fails closed (off) on
            // anything else, rather than clap's bool+env crash-on-`1`.
            let verbose_verdicts = verbose_verdicts
                || std::env::var("CLAVENAR_LITE_VERBOSE_VERDICTS")
                    .map(|v| matches!(v.trim(), "true" | "1" | "yes"))
                    .unwrap_or(false);

            run_start(StartConfig {
                port,
                upstream,
                policies,
                ledger_path,
                velocity_window,
                token,
                agents,
                decide_token,
                upstream_api_key,
                upstream_timeout,
                mode,
                slack_webhook_url,
                callback_allowlist,
                webhook_url,
                rate_limit_qps,
                rate_limit_burst,
                verbose_verdicts,
            })
            .await
        }
        Command::Verify { ledger } => {
            let path = ledger.unwrap_or_else(|| "./clavenar-lite.db".into());
            run_verify(path).await
        }
        Command::Audit { ledger, agent_id } => {
            let path = ledger.unwrap_or_else(|| "./clavenar-lite.db".into());
            run_audit(path, agent_id).await
        }
        Command::Pending { action } => run_pending(action).await,
        Command::Backup { ledger, output } => {
            let path = ledger.unwrap_or_else(|| "./clavenar-lite.db".into());
            run_backup(path, output).await
        }
        Command::Restore { input, ledger, force } => {
            let path = ledger.unwrap_or_else(|| "./clavenar-lite.db".into());
            run_restore(input, path, force).await
        }
        Command::Graduate { action } => run_graduate(action).await,
    };

    std::process::exit(exit_code);
}

async fn run_pending(action: PendingAction) -> i32 {
    let client = reqwest::Client::new();
    match action {
        PendingAction::List {
            endpoint,
            decide_token,
            status,
            limit,
            sort,
            json,
        } => {
            run_pending_list(
                &client,
                &endpoint,
                decide_token,
                &status,
                limit,
                sort.as_deref(),
                json,
            )
            .await
        }
        PendingAction::Get {
            id,
            endpoint,
            token,
            json,
        } => run_pending_get(&client, &endpoint, &id, token, json).await,
        PendingAction::Decide {
            id,
            endpoint,
            decide_token,
            allow,
            deny,
            note,
        } => {
            let decision = match (allow, deny) {
                (true, false) => "allow",
                (false, true) => "deny",
                _ => {
                    eprintln!("error: pass exactly one of --allow or --deny");
                    return 2;
                }
            };
            run_pending_decide(&client, &endpoint, &id, decide_token, decision, note).await
        }
    }
}

async fn run_pending_list(
    client: &reqwest::Client,
    endpoint: &str,
    decide_token: Option<String>,
    status: &str,
    limit: u32,
    sort: Option<&str>,
    json: bool,
) -> i32 {
    let mut url = format!(
        "{}/pending?status={}&limit={}",
        endpoint.trim_end_matches('/'),
        status,
        limit
    );
    if let Some(s) = sort {
        url.push_str("&sort=");
        url.push_str(s);
    }
    let mut req = client.get(&url);
    if let Some(t) = &decide_token {
        req = req.bearer_auth(t);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to reach {}: {}", endpoint, e);
            return 5;
        }
    };
    let status_code = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status_code != 200 {
        eprintln!("error: list pendings returned {}: {}", status_code, body);
        return match status_code {
            400 => 2,
            401 | 403 => 3,
            _ => 5,
        };
    }
    if json {
        println!("{}", body);
        return 0;
    }
    let rows: Vec<serde_json::Value> = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to parse list response: {}", e);
            return 5;
        }
    };
    if rows.is_empty() {
        println!("(no pendings matching status={})", status);
        return 0;
    }
    fn short_ts(t: &str) -> String {
        match t.find('.') {
            Some(i) => format!("{}Z", &t[..i]),
            None => t.to_string(),
        }
    }
    let color = use_color();
    println!(
        "{:<38} {:<16} {:<16} {:<20} STATUS",
        "CORRELATION_ID", "AGENT_ID", "TOOL_TYPE", "REQUESTED_AT"
    );
    for r in &rows {
        let decision = r["decision"].as_str().unwrap_or("parked");
        let ts = short_ts(r["requested_at"].as_str().unwrap_or(""));
        println!(
            "{:<38} {:<16} {:<16} {:<20} {}",
            r["correlation_id"].as_str().unwrap_or(""),
            r["agent_id"].as_str().unwrap_or(""),
            r["tool_type"].as_str().unwrap_or(""),
            ts,
            colorize_status(decision, color)
        );
    }
    0
}

async fn run_pending_get(
    client: &reqwest::Client,
    endpoint: &str,
    id: &str,
    token: Option<String>,
    json: bool,
) -> i32 {
    let url = format!("{}/pending/{}", endpoint.trim_end_matches('/'), id);
    let mut req = client.get(&url);
    if let Some(t) = &token {
        req = req.bearer_auth(t);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to reach {}: {}", endpoint, e);
            return 5;
        }
    };
    let status_code = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    match status_code {
        200 => {
            if json {
                println!("{}", body);
            } else {
                println!("{}", body); // pretty-print path not worth the bytes
            }
            0
        }
        404 => {
            eprintln!("not found: {}", id);
            4
        }
        401 | 403 => {
            eprintln!("auth: {}", body);
            3
        }
        _ => {
            eprintln!("error {}: {}", status_code, body);
            5
        }
    }
}

async fn run_pending_decide(
    client: &reqwest::Client,
    endpoint: &str,
    id: &str,
    decide_token: Option<String>,
    decision: &str,
    note: Option<String>,
) -> i32 {
    let url = format!("{}/pending/{}/decide", endpoint.trim_end_matches('/'), id);
    let body = match &note {
        Some(n) => serde_json::json!({ "decision": decision, "note": n }),
        None => serde_json::json!({ "decision": decision }),
    };
    let mut req = client.post(&url).json(&body);
    if let Some(t) = &decide_token {
        req = req.bearer_auth(t);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to reach {}: {}", endpoint, e);
            return 5;
        }
    };
    let status_code = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    match status_code {
        200 => {
            println!("ok: pending {} decided {}", id, decision);
            0
        }
        400 => {
            eprintln!("bad request: {}", body);
            2
        }
        401 | 403 => {
            eprintln!("auth: {}", body);
            3
        }
        404 => {
            eprintln!("not found: {}", id);
            4
        }
        409 => {
            eprintln!("conflict (already decided): {}", body);
            4
        }
        _ => {
            eprintln!("error {}: {}", status_code, body);
            5
        }
    }
}

fn open_ledger(path: &str) -> Result<Ledger, i32> {
    Ledger::open(path).map_err(|e| {
        eprintln!("error: failed to open ledger {}: {}", path, e);
        1
    })
}

/// Resolved configuration for the `start` subcommand. Bundled so
/// `run_start` stays under clippy's argument-count threshold and so
/// future flags can be added without thrashing call sites.
struct StartConfig {
    port: u16,
    upstream: String,
    policies: PathBuf,
    ledger_path: String,
    velocity_window: u64,
    token: Option<String>,
    agents: Option<String>,
    decide_token: Option<String>,
    upstream_api_key: Option<String>,
    upstream_timeout: Duration,
    mode: ClavenarMode,
    slack_webhook_url: Option<String>,
    callback_allowlist: Option<String>,
    webhook_url: Option<String>,
    rate_limit_qps: Option<f64>,
    rate_limit_burst: Option<u32>,
    verbose_verdicts: bool,
}

/// Parse `--mode` / `CLAVENAR_LITE_MODE` into a {@link ClavenarMode}.
/// Accepts `enforce` / `observe`, case-insensitive.
fn parse_mode(s: &str) -> Result<ClavenarMode, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "enforce" => Ok(ClavenarMode::Enforce),
        "observe" => Ok(ClavenarMode::Observe),
        other => Err(format!(
            "invalid mode {:?}: expected 'enforce' or 'observe'",
            other
        )),
    }
}

async fn run_start(cfg: StartConfig) -> i32 {
    // Validate the upstream URL at startup so a typo surfaces here
    // rather than as a 502 on the first request.
    if let Err(e) = reqwest::Url::parse(&cfg.upstream) {
        eprintln!("error: invalid --upstream URL {:?}: {}", cfg.upstream, e);
        return 1;
    }

    let policy = match PolicyEngine::from_dir(&cfg.policies, cfg.velocity_window) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("error: failed to load policies: {}", e);
            return 1;
        }
    };

    let ledger = match open_ledger(&cfg.ledger_path) {
        Ok(l) => Arc::new(l),
        Err(code) => return code,
    };

    let http = match reqwest::Client::builder()
        .timeout(cfg.upstream_timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to build HTTP client: {}", e);
            return 1;
        }
    };

    // Build the agent registry. `--agents` takes precedence over the
    // legacy single-token `--token` form; either alone activates
    // inbound bearer auth. Neither means accept all connections
    // (developer-laptop default).
    let agents = match (cfg.agents.as_deref(), cfg.token.as_deref()) {
        (Some(spec), _) => match AgentRegistry::parse(spec) {
            Ok(r) => {
                tracing::info!(
                    agent_count = r.len(),
                    agent_ids = ?r.agent_ids(),
                    "multi-agent registry loaded"
                );
                Some(r)
            }
            Err(e) => {
                eprintln!("error: failed to parse --agents: {}", e);
                return 1;
            }
        },
        (None, Some(t)) => Some(AgentRegistry::single(t.to_string())),
        (None, None) => None,
    };

    // Async-HIL callback allowlist. Empty list means callback URLs
    // are rejected at /mcp time — partners poll. We parse here so a
    // bad config fails boot rather than at first /mcp.
    let callback_allowlist: Vec<String> = match cfg.callback_allowlist.as_deref() {
        Some(spec) => spec
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    };
    if !callback_allowlist.is_empty() {
        // Reject prefixes that aren't valid URLs at boot — otherwise the
        // allowlist match would happily allow agents to point at
        // garbage URLs we'd silently fail to POST to.
        for prefix in &callback_allowlist {
            if reqwest::Url::parse(prefix).is_err() {
                eprintln!(
                    "error: --callback-allowlist prefix {:?} is not a valid URL",
                    prefix
                );
                return 1;
            }
        }
        tracing::info!(
            allowlist_count = callback_allowlist.len(),
            "async-HIL callbacks enabled"
        );
    }

    // Validate the outbound webhook URL at boot so a typo surfaces
    // here rather than as a silent `warn` log on the first verdict.
    if let Some(u) = &cfg.webhook_url
        && reqwest::Url::parse(u).is_err()
    {
        eprintln!("error: --webhook-url is not a valid URL: {:?}", u);
        return 1;
    }

    // Build the optional rate limiter. `--rate-limit-qps 0` (the
    // default) leaves it `None` — boot path skips the gate entirely
    // and the request fast-path stays a single Option::is_none check.
    let rate_limiter = {
        let qps = cfg.rate_limit_qps.unwrap_or(0.0).max(0.0);
        let burst = cfg.rate_limit_burst.unwrap_or_else(|| qps.ceil().max(1.0) as u32);
        let config = clavenar_lite::rate_limit::RateLimitConfig { qps, burst };
        if config.is_enabled() {
            tracing::info!(qps, burst, "rate-limit per-agent enabled");
        }
        clavenar_lite::rate_limit::RateLimiter::from_config(config).map(Arc::new)
    };

    if cfg.verbose_verdicts {
        tracing::warn!(
            "verbose verdicts ON (--verbose-verdicts / CLAVENAR_LITE_VERBOSE_VERDICTS) — \
             deny/park responses carry a per-detector breakdown. This leaks detection logic \
             to a caller; enable only in dev."
        );
    }

    let state = Arc::new(AppState {
        policy,
        ledger,
        tool_pins: Arc::new(clavenar_lite::supply_chain::ToolPinStore::new()),
        upstream_url: cfg.upstream.clone(),
        http,
        agents,
        decide_token: cfg.decide_token.clone(),
        upstream_api_key: cfg.upstream_api_key,
        mode: cfg.mode,
        slack_webhook_url: cfg.slack_webhook_url.clone(),
        callback_allowlist,
        webhook_url: cfg.webhook_url.clone(),
        rate_limiter,
        verbose_verdicts: cfg.verbose_verdicts,
    });

    // Install the Prometheus recorder once before any emit site fires.
    // The handle lives in the `/metrics` closure below; metric facades
    // (`metrics::counter!`, etc.) route to this global recorder
    // transparently. Same pattern as clavenar-brain / clavenar-policy-
    // engine / clavenar-ledger / clavenar-hil / clavenar-identity, so a
    // single Prometheus scrape config reads any clavenar component.
    let prom = match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to install prometheus recorder: {}", e);
            return 1;
        }
    };
    metrics::describe_counter!(
        "clavenar_lite_inspect_total",
        "Total /mcp requests received."
    );
    metrics::describe_counter!(
        "clavenar_lite_verdicts_total",
        "Terminal verdicts. verdict={allow,deny,pending,would_deny,would_pend}; the would_* family fires in observe mode."
    );
    metrics::describe_counter!(
        "clavenar_lite_rate_limit_denied_total",
        "Requests rejected at /mcp ingress by the per-agent token-bucket rate limiter. \
         Fires before brain/policy work runs; the denial also emits a ledger row \
         with intent_category=\"RateLimitDenied\"."
    );

    let app = build_router(state).route(
        "/metrics",
        axum::routing::get(move || {
            let prom = prom.clone();
            async move { prom.render() }
        }),
    );
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));

    tracing::info!(
        "clavenar-lite listening on http://{} (mode={}, upstream={}, policies={}, ledger={}, auth={}, decide_auth={}, slack_alerts={}, verdict_webhook={}, upstream_timeout={}s)",
        addr,
        match cfg.mode { ClavenarMode::Enforce => "enforce", ClavenarMode::Observe => "observe" },
        cfg.upstream,
        cfg.policies.display(),
        cfg.ledger_path,
        if cfg.token.is_some() { "bearer-token" } else { "open" },
        if cfg.decide_token.is_some() { "bearer-token" } else { "open" },
        if cfg.slack_webhook_url.is_some() { "enabled" } else { "off" },
        if cfg.webhook_url.is_some() { "enabled" } else { "off" },
        cfg.upstream_timeout.as_secs(),
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind {}: {}", addr, e);
            return 1;
        }
    };

    // Race the server against ctrl-c so the binary exits cleanly on a
    // user interrupt rather than printing the panic from a stuck await.
    tokio::select! {
        res = axum::serve(listener, app) => {
            if let Err(e) = res {
                eprintln!("server error: {}", e);
                return 1;
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received, shutting down");
        }
    }
    0
}

async fn run_backup(ledger_path: String, output: PathBuf) -> i32 {
    if !std::path::Path::new(&ledger_path).exists() {
        eprintln!("error: source ledger {} does not exist", ledger_path);
        return 1;
    }
    let ledger = match open_ledger(&ledger_path) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let output_str = match output.to_str() {
        Some(s) => s.to_string(),
        None => {
            eprintln!("error: --output path is not valid UTF-8");
            return 1;
        }
    };
    let pages = match ledger.backup_to(&output_str).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: backup failed: {}", e);
            // Clean up a partial snapshot — leaving it around is worse
            // than nothing because verify would happily declare an
            // empty file invalid.
            let _ = std::fs::remove_file(&output_str);
            return 1;
        }
    };

    // Verify the snapshot itself. A backup that doesn't pass verify is
    // not a backup. Open the snapshot fresh so we exercise the full
    // open + schema-migration path the operator's restore would hit.
    let snapshot = match Ledger::open(&output_str) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: snapshot opens but fails verify: {}", e);
            return 2;
        }
    };
    match snapshot.verify().await {
        Ok(v) if v.valid => {
            println!(
                "snapshot {} OK — {} pages, {} entr{} verified",
                output_str,
                pages,
                v.entries_checked,
                if v.entries_checked == 1 { "y" } else { "ies" }
            );
            0
        }
        Ok(_) => {
            eprintln!(
                "error: snapshot {} fails chain verification — refusing to leave a known-bad backup on disk",
                output_str
            );
            let _ = std::fs::remove_file(&output_str);
            2
        }
        Err(e) => {
            eprintln!("error: snapshot verify failed: {}", e);
            1
        }
    }
}

async fn run_restore(input: PathBuf, ledger_path: String, force: bool) -> i32 {
    if !input.exists() {
        eprintln!("error: --input {} does not exist", input.display());
        return 1;
    }
    let input_str = match input.to_str() {
        Some(s) => s.to_string(),
        None => {
            eprintln!("error: --input path is not valid UTF-8");
            return 1;
        }
    };

    // Verify the snapshot's chain BEFORE touching the target. An
    // invalid snapshot never lands on disk.
    let snapshot = match Ledger::open(&input_str) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: snapshot {} won't open: {}", input_str, e);
            return 1;
        }
    };
    match snapshot.verify().await {
        Ok(v) if v.valid => {}
        Ok(_) => {
            eprintln!(
                "error: snapshot {} fails chain verification — refusing to restore",
                input_str
            );
            return 2;
        }
        Err(e) => {
            eprintln!("error: snapshot verify failed: {}", e);
            return 1;
        }
    }
    drop(snapshot);

    if std::path::Path::new(&ledger_path).exists() && !force {
        eprintln!(
            "error: target ledger {} already exists. Pass --force to overwrite (this is destructive)",
            ledger_path
        );
        return 1;
    }

    // Atomic copy via std::fs::copy + rename onto target. Use a
    // sibling-temp so partial writes on copy failure don't leave the
    // target in a broken state.
    let parent = std::path::Path::new(&ledger_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let tmp = parent.join(format!(
        ".{}.restore-tmp",
        std::path::Path::new(&ledger_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("clavenar-lite.db")
    ));

    if let Err(e) = std::fs::copy(&input_str, &tmp) {
        eprintln!("error: copy {} -> {} failed: {}", input_str, tmp.display(), e);
        let _ = std::fs::remove_file(&tmp);
        return 1;
    }
    // Drop any stale WAL/SHM next to the target so SQLite doesn't
    // replay a journal that belongs to the previous DB on next open.
    let _ = std::fs::remove_file(format!("{}-wal", ledger_path));
    let _ = std::fs::remove_file(format!("{}-shm", ledger_path));
    if let Err(e) = std::fs::rename(&tmp, &ledger_path) {
        eprintln!("error: rename tmp -> {} failed: {}", ledger_path, e);
        let _ = std::fs::remove_file(&tmp);
        return 1;
    }

    // Re-verify the live target so the operator gets a clear
    // confirmation rather than just "no error".
    let restored = match Ledger::open(&ledger_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: target {} won't reopen post-restore: {}", ledger_path, e);
            return 2;
        }
    };
    match restored.verify().await {
        Ok(v) if v.valid => {
            println!(
                "restored {} from {} — {} entr{} verified",
                ledger_path,
                input_str,
                v.entries_checked,
                if v.entries_checked == 1 { "y" } else { "ies" }
            );
            0
        }
        Ok(_) => {
            eprintln!(
                "error: post-restore verify failed on {} — restored bytes did not survive the rename",
                ledger_path
            );
            2
        }
        Err(e) => {
            eprintln!("error: post-restore verify errored: {}", e);
            1
        }
    }
}

async fn run_verify(ledger_path: String) -> i32 {
    let ledger = match open_ledger(&ledger_path) {
        Ok(l) => l,
        Err(code) => return code,
    };
    match ledger.verify().await {
        Ok(v) => {
            if v.valid {
                println!(
                    "ledger {} verified — {} entr{} OK",
                    ledger_path,
                    v.entries_checked,
                    if v.entries_checked == 1 { "y" } else { "ies" }
                );
                0
            } else if let Some(seq) = v.first_invalid_seq {
                eprintln!(
                    "ledger {} INVALID — tamper detected at seq {} ({} valid entries before it)",
                    ledger_path, seq, v.entries_checked
                );
                2
            } else if let Some(ver) = v.unsupported_chain_version {
                eprintln!(
                    "ledger {} cannot be fully verified — entry written under chain_version {} which this binary does not know how to verify ({} earlier entries checked OK). Upgrade clavenar-lite.",
                    ledger_path, ver, v.entries_checked
                );
                2
            } else {
                // Defensive: if a future field flips valid=false without
                // populating either failure pointer, surface that
                // explicitly instead of pretending we know why.
                eprintln!(
                    "ledger {} INVALID — verifier reported failure with no specific cause",
                    ledger_path
                );
                2
            }
        }
        Err(e) => {
            eprintln!("error: verify failed: {}", e);
            1
        }
    }
}

async fn run_audit(ledger_path: String, agent_id: String) -> i32 {
    let ledger = match open_ledger(&ledger_path) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let entries = match ledger.entries_for_agent(&agent_id).await {
        Ok(es) => es,
        Err(e) => {
            eprintln!("error: read failed: {}", e);
            return 1;
        }
    };
    if entries.is_empty() {
        println!("no entries for agent_id={}", agent_id);
        return 0;
    }
    for entry in &entries {
        println!(
            "[{}] seq={} method={} intent={} authorized={} reasoning={}",
            entry.timestamp.to_rfc3339(),
            entry.seq,
            entry.method,
            entry.intent_category,
            entry.authorized,
            entry.reasoning
        );
    }
    println!("\n{} entries for agent_id={}", entries.len(), agent_id);
    0
}

async fn run_graduate(action: GraduateAction) -> i32 {
    match action {
        GraduateAction::Report {
            ledger,
            since,
            signing_key,
            output,
            format,
        } => {
            let path = ledger.unwrap_or_else(|| "./clavenar-lite.db".into());
            run_graduate_report(path, since, signing_key, output, format).await
        }
        GraduateAction::Verify { report, pubkey } => run_graduate_verify(report, pubkey).await,
    }
}

async fn run_graduate_report(
    ledger_path: String,
    since: Option<String>,
    signing_key: Option<PathBuf>,
    output: Option<PathBuf>,
    format: ReportFormat,
) -> i32 {
    use clavenar_lite::report::{GraduationReport, SignedGraduationReport, sign_report, unsigned_report};

    let since_dt = match since.as_deref().map(parse_since).transpose() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid --since: {e}");
            return 2;
        }
    };

    let ledger = match open_ledger(&ledger_path) {
        Ok(l) => l,
        Err(code) => return code,
    };

    let chain = match ledger.verify().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: verify failed: {e}");
            return 1;
        }
    };
    let stats = match ledger.graduation_stats(since_dt).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read failed: {e}");
            return 1;
        }
    };

    let report = GraduationReport::from_stats(&stats, chain.valid, Utc::now());

    let signed: SignedGraduationReport = match signing_key {
        Some(key_path) => {
            let pem = match std::fs::read_to_string(&key_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: read --signing-key {}: {e}", key_path.display());
                    return 2;
                }
            };
            let key = match SigningKey::from_pkcs8_pem(&pem) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: parse signing key (expected PKCS#8 Ed25519 PEM): {e}");
                    return 2;
                }
            };
            match sign_report(&report, &key, Utc::now()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: sign report: {e}");
                    return 1;
                }
            }
        }
        None => {
            eprintln!(
                "warning: no --signing-key configured; emitting UNSIGNED report (not tamper-evident)"
            );
            match unsigned_report(&report) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: build report: {e}");
                    return 1;
                }
            }
        }
    };

    let rendered = match format {
        ReportFormat::Json => match serde_json::to_string_pretty(&signed) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: serialize report: {e}");
                return 1;
            }
        },
        ReportFormat::Text => render_graduation_text(&signed),
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, format!("{rendered}\n")) {
                eprintln!("error: write {}: {e}", path.display());
                return 1;
            }
            eprintln!("graduation report written to {}", path.display());
        }
        None => println!("{rendered}"),
    }
    0
}

fn render_graduation_text(signed: &clavenar_lite::report::SignedGraduationReport) -> String {
    use std::fmt::Write;
    let r = &signed.report;
    let mut out = String::new();
    let _ = writeln!(out, "Clavenar graduation report");
    let _ = writeln!(out, "  generated: {}", r.generated_at.to_rfc3339());
    let _ = writeln!(
        out,
        "  chain:     {}",
        if r.ledger_chain_valid { "VALID" } else { "INVALID" }
    );
    let _ = writeln!(
        out,
        "  requests:  {} ({} allowed, {} would-deny, {} would-pend)",
        r.total_requests, r.allowed, r.would_deny, r.would_pend
    );
    if !r.by_intent_category.is_empty() {
        let _ = writeln!(out, "  by intent:");
        for ic in &r.by_intent_category {
            let _ = writeln!(out, "    {:<16} {}", ic.intent_category, ic.count);
        }
    }
    if !r.top_agents.is_empty() {
        let _ = writeln!(out, "  top agents:");
        for ac in &r.top_agents {
            let _ = writeln!(out, "    {:<24} {}", ac.agent_id, ac.count);
        }
    }
    let sig = match &signed.signature {
        Some(_) => format!("signed ({})", signed.key_id),
        None => "UNSIGNED".to_string(),
    };
    let _ = writeln!(out, "  signature: {sig}");
    let _ = writeln!(out, "\n  {}", r.recommendation);
    out
}

async fn run_graduate_verify(report_path: PathBuf, pubkey: Option<PathBuf>) -> i32 {
    use clavenar_lite::report::{SignedGraduationReport, VerifyOutcome, verify_report};

    let raw = match std::fs::read_to_string(&report_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read {}: {e}", report_path.display());
            return 2;
        }
    };
    let signed: SignedGraduationReport = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: parse report JSON: {e}");
            return 2;
        }
    };
    let pubkey_pem = match pubkey {
        Some(p) => match std::fs::read_to_string(&p) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("error: read --pubkey {}: {e}", p.display());
                return 2;
            }
        },
        None => None,
    };
    match verify_report(&signed, pubkey_pem.as_deref()) {
        VerifyOutcome::Valid => {
            println!(
                "OK — signature valid ({}); chain_valid={}",
                signed.key_id, signed.report.ledger_chain_valid
            );
            0
        }
        VerifyOutcome::Unsigned => {
            eprintln!("report is UNSIGNED — no tamper-evidence");
            2
        }
        VerifyOutcome::Forged(msg) => {
            eprintln!("FORGED — {msg}");
            2
        }
        VerifyOutcome::Malformed(msg) => {
            eprintln!("MALFORMED — {msg}");
            2
        }
    }
}

/// Parse a `--since` value: RFC 3339, or a relative duration suffix
/// (`<N>h` / `<N>d` / `<N>m`) subtracted from now.
fn parse_since(s: &str) -> Result<chrono::DateTime<Utc>, String> {
    let s = s.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| format!("not RFC 3339 and not a `<N>{{h,d,m}}` duration: {s:?}"))?;
    let dur = match unit {
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        "m" => chrono::Duration::minutes(n),
        _ => return Err(format!("unknown duration unit in {s:?} (use h, d, or m)")),
    };
    Ok(Utc::now() - dur)
}

/// Whether `pending list` should emit ANSI colors. False if stdout
/// isn't a TTY (pipe, redirect, CI logs) or if `NO_COLOR` is set —
/// the no-color convention at https://no-color.org. Partner-facing
/// CLI; we won't drag in `colored` or `termcolor` for one column's
/// worth of formatting.
fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// Wrap the pending status in ANSI color codes when `color` is true.
/// `parked` → yellow (waiting), `allow` → green, `deny` → red,
/// anything else → unstyled.
fn colorize_status(status: &str, color: bool) -> String {
    if !color {
        return status.to_string();
    }
    let code = match status {
        "parked" => "\x1b[33m",
        "allow" => "\x1b[32m",
        "deny" => "\x1b[31m",
        _ => return status.to_string(),
    };
    format!("{}{}\x1b[0m", code, status)
}
