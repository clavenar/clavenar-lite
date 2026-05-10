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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use warden_lite::ledger::Ledger;
use warden_lite::policy::PolicyEngine;
use warden_lite::proxy::{build_router, AppState};

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

        /// Optional API key forwarded to the upstream as
        /// `Authorization: Bearer <key>`. Use this for OpenAI /
        /// Anthropic / etc. when the agent shouldn't see the key
        /// directly. Env: `WARDEN_LITE_UPSTREAM_API_KEY`.
        #[arg(long, env = "WARDEN_LITE_UPSTREAM_API_KEY")]
        upstream_api_key: Option<String>,
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
            upstream_api_key,
        } => {
            let port = port.unwrap_or(8088);
            let upstream = upstream.unwrap_or_else(|| "http://localhost:9000/mcp".into());
            let policies = policies.unwrap_or_else(|| PathBuf::from("./policies"));
            let ledger_path = ledger.unwrap_or_else(|| "./warden-lite.db".into());
            let velocity_window = velocity_window.unwrap_or(60);

            run_start(
                port,
                upstream,
                policies,
                ledger_path,
                velocity_window,
                token,
                upstream_api_key,
            )
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
    };

    std::process::exit(exit_code);
}

async fn run_start(
    port: u16,
    upstream: String,
    policies: PathBuf,
    ledger_path: String,
    velocity_window: u64,
    token: Option<String>,
    upstream_api_key: Option<String>,
) -> i32 {
    let policy = match PolicyEngine::from_dir(&policies, velocity_window) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("error: failed to load policies: {}", e);
            return 1;
        }
    };

    let ledger = match Ledger::open(&ledger_path) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("error: failed to open ledger {}: {}", ledger_path, e);
            return 1;
        }
    };

    let state = Arc::new(AppState {
        policy,
        ledger,
        upstream_url: upstream.clone(),
        http: reqwest::Client::new(),
        bearer_token: token.clone(),
        upstream_api_key,
    });

    let app = build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!(
        "warden-lite listening on http://{} (upstream={}, policies={}, ledger={}, auth={})",
        addr,
        upstream,
        policies.display(),
        ledger_path,
        if token.is_some() {
            "bearer-token"
        } else {
            "open"
        },
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
    let ledger = match Ledger::open(&ledger_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to open ledger {}: {}", ledger_path, e);
            return 1;
        }
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
            } else {
                eprintln!(
                    "ledger {} INVALID — first invalid entry at seq {:?} ({}+ entries scanned)",
                    ledger_path, v.first_invalid_seq, v.entries_checked
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
    let ledger = match Ledger::open(&ledger_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to open ledger {}: {}", ledger_path, e);
            return 1;
        }
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
