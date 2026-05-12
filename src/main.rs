//! warden-lite — single-binary OSS edition of Agent Warden.
//!
//! ```text
//! warden-lite start [--port 8088] [--upstream URL] [--policies DIR] [--ledger PATH]
//! warden-lite verify [--ledger PATH]
//! warden-lite audit  [--ledger PATH] <agent_id>
//! ```
//!
//! All flags fall back to env vars (`WARDEN_LITE_*`) so you can drop a
//! `.env` next to the binary and just `warden-lite start`. See
//! `README.md` for the full env-var matrix.

use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use warden_lite::ledger::Ledger;
use warden_lite::policy::PolicyEngine;
use warden_lite::proxy::{build_router, AppState, WardenMode};

#[derive(Parser, Debug)]
#[command(
    name = "warden-lite",
    about = "Agent Warden Community Edition — single-binary OSS proxy.",
    version,
    long_about = "Embedded heuristic Brain + Rego policy engine + SHA-256 hash-chained SQLite ledger in one binary. \
                  Designed for developer-laptop use. \
                  For production deployments (mTLS, Vault, multi-instance, HIL, semantic LLM-based detection), \
                  see the full Agent Warden edition."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the warden-lite proxy server.
    Start {
        /// HTTP listen port. Default 8088 (env `WARDEN_LITE_PORT`).
        #[arg(long, env = "WARDEN_LITE_PORT")]
        port: Option<u16>,

        /// Upstream URL the proxy forwards authorized requests to.
        /// Default `http://localhost:9000/mcp` (env `WARDEN_LITE_UPSTREAM_URL`).
        #[arg(long, env = "WARDEN_LITE_UPSTREAM_URL")]
        upstream: Option<String>,

        /// Directory containing `*.rego` policy files. Default `./policies`
        /// (env `WARDEN_LITE_POLICY_DIR`).
        #[arg(long, env = "WARDEN_LITE_POLICY_DIR")]
        policies: Option<PathBuf>,

        /// SQLite ledger path. Use `:memory:` for an ephemeral run.
        /// Default `./warden-lite.db` (env `WARDEN_LITE_LEDGER`).
        #[arg(long, env = "WARDEN_LITE_LEDGER")]
        ledger: Option<String>,

        /// Velocity-tracker window in seconds. Default 60.
        #[arg(long, env = "WARDEN_LITE_VELOCITY_WINDOW_SECS")]
        velocity_window: Option<u64>,

        /// Optional bearer token for inbound auth. If set, every
        /// `POST /mcp` must send `Authorization: Bearer <token>`.
        /// Read from `WARDEN_LITE_TOKEN` if not passed on the CLI.
        #[arg(long, env = "WARDEN_LITE_TOKEN")]
        token: Option<String>,

        /// Optional bearer token gating `POST /pending/{id}/decide`.
        /// If set, every decide call must send `Authorization: Bearer
        /// <token>`. Held separately from `--token` because operator
        /// (approver) capability is strictly higher than agent capability —
        /// reusing the agent's bearer would let the agent approve its own
        /// pendings. Env `WARDEN_LITE_DECIDE_TOKEN`.
        #[arg(long, env = "WARDEN_LITE_DECIDE_TOKEN")]
        decide_token: Option<String>,

        /// Optional API key forwarded to the upstream as
        /// `Authorization: Bearer <key>`. Use this for OpenAI /
        /// Anthropic / etc. when the agent shouldn't see the key
        /// directly. Env: `WARDEN_LITE_UPSTREAM_API_KEY`.
        #[arg(long, env = "WARDEN_LITE_UPSTREAM_API_KEY")]
        upstream_api_key: Option<String>,

        /// Per-request timeout (in seconds) for the upstream forward.
        /// LLM completions can be slow, so the default is generous; set
        /// lower if you want a stalled upstream to surface as a 504 fast.
        /// Default 120. Env `WARDEN_LITE_UPSTREAM_TIMEOUT_SECS`.
        #[arg(long, env = "WARDEN_LITE_UPSTREAM_TIMEOUT_SECS")]
        upstream_timeout_secs: Option<u64>,

        /// Enforcement mode. `enforce` (default) returns 403 on
        /// would-deny; `observe` forwards every request upstream and
        /// surfaces the would-deny via the `X-Warden-Would-Deny`
        /// response header. Use observe for the rollout phase before
        /// you trust the policies. Env `WARDEN_LITE_MODE`.
        #[arg(long, env = "WARDEN_LITE_MODE", value_parser = parse_mode)]
        mode: Option<WardenMode>,

        /// Optional Slack-incoming-webhook URL. When set, every
        /// yellow-tier park fires a one-way alert with the
        /// correlation id, tool, agent, review reasons, and the
        /// `warden-lite pending decide` command-line. No return path
        /// — operators decide via CLI or curl. Env
        /// `WARDEN_LITE_SLACK_WEBHOOK_URL`.
        #[arg(long, env = "WARDEN_LITE_SLACK_WEBHOOK_URL")]
        slack_webhook_url: Option<String>,
    },

    /// Walk every entry in the ledger and confirm the hash chain is
    /// intact. Exits 0 if valid, 2 if any entry's hash doesn't match.
    Verify {
        /// SQLite ledger path. Default `./warden-lite.db`.
        #[arg(long, env = "WARDEN_LITE_LEDGER")]
        ledger: Option<String>,
    },

    /// Print every ledger entry for a given agent_id, oldest first.
    /// Useful for incident review.
    Audit {
        /// SQLite ledger path. Default `./warden-lite.db`.
        #[arg(long, env = "WARDEN_LITE_LEDGER")]
        ledger: Option<String>,

        /// The agent_id to audit (matched against the `agent_id` column).
        agent_id: String,
    },

    /// Operator commands for parked tool calls — list, inspect, decide.
    /// Talks to a running warden-lite over HTTP; not a local-DB
    /// operation. Use against the same `--endpoint` your agent posts to.
    Pending {
        #[command(subcommand)]
        action: PendingAction,
    },
}

#[derive(Subcommand, Debug)]
enum PendingAction {
    /// List parked (or decided, or all) pendings.
    List {
        /// Warden-lite base URL. Default `http://localhost:8088`.
        #[arg(long, env = "WARDEN_LITE_URL", default_value = "http://localhost:8088")]
        endpoint: String,
        /// Operator bearer token. Required if warden-lite was booted
        /// with `--decide-token`. Env `WARDEN_LITE_DECIDE_TOKEN`.
        #[arg(long, env = "WARDEN_LITE_DECIDE_TOKEN")]
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
        /// `X-Warden-Correlation-Id` header).
        id: String,
        #[arg(long, env = "WARDEN_LITE_URL", default_value = "http://localhost:8088")]
        endpoint: String,
        /// Agent bearer token (poll path). Env `WARDEN_LITE_TOKEN`.
        #[arg(long, env = "WARDEN_LITE_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        json: bool,
    },

    /// Resolve a pending — pick exactly one of `--allow` or `--deny`,
    /// with an optional free-text `--note` that lands in the audit
    /// ledger.
    Decide {
        id: String,
        #[arg(long, env = "WARDEN_LITE_URL", default_value = "http://localhost:8088")]
        endpoint: String,
        #[arg(long, env = "WARDEN_LITE_DECIDE_TOKEN")]
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
    // `warden-lite start` shows the boot banner without extra config.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Start {
            port,
            upstream,
            policies,
            ledger,
            velocity_window,
            token,
            decide_token,
            upstream_api_key,
            upstream_timeout_secs,
            mode,
            slack_webhook_url,
        } => {
            let port = port.unwrap_or(8088);
            let upstream = upstream.unwrap_or_else(|| "http://localhost:9000/mcp".into());
            let policies = policies.unwrap_or_else(|| PathBuf::from("./policies"));
            let ledger_path = ledger.unwrap_or_else(|| "./warden-lite.db".into());
            let velocity_window = velocity_window.unwrap_or(60);
            let upstream_timeout = Duration::from_secs(upstream_timeout_secs.unwrap_or(120));
            let mode = mode.unwrap_or(WardenMode::Enforce);

            run_start(StartConfig {
                port,
                upstream,
                policies,
                ledger_path,
                velocity_window,
                token,
                decide_token,
                upstream_api_key,
                upstream_timeout,
                mode,
                slack_webhook_url,
            })
            .await
        }
        Command::Verify { ledger } => {
            let path = ledger.unwrap_or_else(|| "./warden-lite.db".into());
            run_verify(path).await
        }
        Command::Audit { ledger, agent_id } => {
            let path = ledger.unwrap_or_else(|| "./warden-lite.db".into());
            run_audit(path, agent_id).await
        }
        Command::Pending { action } => run_pending(action).await,
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
    decide_token: Option<String>,
    upstream_api_key: Option<String>,
    upstream_timeout: Duration,
    mode: WardenMode,
    slack_webhook_url: Option<String>,
}

/// Parse `--mode` / `WARDEN_LITE_MODE` into a {@link WardenMode}.
/// Accepts `enforce` / `observe`, case-insensitive.
fn parse_mode(s: &str) -> Result<WardenMode, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "enforce" => Ok(WardenMode::Enforce),
        "observe" => Ok(WardenMode::Observe),
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

    let state = Arc::new(AppState {
        policy,
        ledger,
        upstream_url: cfg.upstream.clone(),
        http,
        bearer_token: cfg.token.clone(),
        decide_token: cfg.decide_token.clone(),
        upstream_api_key: cfg.upstream_api_key,
        mode: cfg.mode,
        slack_webhook_url: cfg.slack_webhook_url.clone(),
    });

    let app = build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));

    tracing::info!(
        "warden-lite listening on http://{} (mode={}, upstream={}, policies={}, ledger={}, auth={}, decide_auth={}, slack_alerts={}, upstream_timeout={}s)",
        addr,
        match cfg.mode { WardenMode::Enforce => "enforce", WardenMode::Observe => "observe" },
        cfg.upstream,
        cfg.policies.display(),
        cfg.ledger_path,
        if cfg.token.is_some() { "bearer-token" } else { "open" },
        if cfg.decide_token.is_some() { "bearer-token" } else { "open" },
        if cfg.slack_webhook_url.is_some() { "enabled" } else { "off" },
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
                    "ledger {} cannot be fully verified — entry written under chain_version {} which this binary does not know how to verify ({} earlier entries checked OK). Upgrade warden-lite.",
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
