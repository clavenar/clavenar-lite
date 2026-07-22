//! Embedded forensic ledger (Layer 4, OSS edition).
//!
//! Single SQLite file with the same SHA-256 hash chain shape as the full
//! `clavenar-ledger`. A chain produced here is byte-compatible with the
//! full edition's verifier, so an organisation that outgrows Lite can
//! point the full ledger at the same DB file (or `attach` it) and
//! continue the chain unbroken.
//!
//! Lite differs from the full edition in two ways:
//!   1. No NATS subscriber — Lite is single-process, the proxy calls
//!      `append_entry` directly.
//!   2. No cold-tier export — that's a Tier-3 follow-up filed against
//!      the full edition. If you need Iceberg/S3 export, ship to the
//!      full edition.
//!
//! # Hash chain
//!
//! ```text
//! genesis = 64 × "0"
//! entry_hash[n] = sha256( prev_hash[n] || "|" || canonical_json(hashable[n]) )
//! ```
//!
//! `hashable[n]` field order is `{ id, timestamp, agent_id, method,
//! intent_category, authorized, reasoning, policy_decision, seq,
//! prev_hash }`. **The order is the chain version** — reordering
//! silently invalidates every existing entry. Same order as the full
//! edition's `HashableEntry`; do not diverge.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Lite shares the chain format with the full edition; the constant
/// is duplicated here (rather than reaching into `clavenar-ledger`) so
/// Lite stays a single-binary, no-deps OSS edition. Keep it in sync
/// with `clavenar_ledger::CURRENT_CHAIN_VERSION` — the chains are
/// wire-compatible by construction.
pub const CURRENT_CHAIN_VERSION: i64 = 1;

fn default_chain_version() -> i64 {
    1
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LedgerEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub method: String,
    pub intent_category: String,
    pub authorized: bool,
    pub reasoning: String,
    pub policy_decision: Option<serde_json::Value>,
    pub seq: i64,
    pub prev_hash: String,
    pub entry_hash: String,
    /// Chain version under which `entry_hash` was computed.
    /// Defaults to 1 on the wire so legacy shapes still parse.
    #[serde(default = "default_chain_version")]
    pub chain_version: i64,
    /// Per-request correlation id surfaced in the `X-Clavenar-Correlation-Id`
    /// response header. Deliberately NOT part of {@link HashableEntryV1} —
    /// it's audit-trail metadata, not a forensic-chain invariant — so adding
    /// it leaves the chain byte-compatible with the full edition's verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogRequest {
    pub agent_id: String,
    pub method: String,
    pub intent_category: String,
    pub authorized: bool,
    pub reasoning: String,
    pub policy_decision: Option<serde_json::Value>,
    /// Caller-generated correlation id (proxy emits one per /mcp). When
    /// `None` the column is stored as NULL — old code paths that don't
    /// thread a correlation id continue to work.
    #[serde(default)]
    pub correlation_id: Option<String>,
}

/// Exact identity and payload binding for the opt-in durable server-execution
/// contract. The submitted and effective digests are separate so a future
/// approved modification can retain the caller's original retry identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerExecutionBinding {
    pub agent_id: String,
    pub idempotency_id: Uuid,
    pub correlation_id: String,
    pub route: String,
    pub method: String,
    pub tool_name: String,
    pub submitted_request_sha256: String,
    pub effective_request_sha256: String,
}

impl ServerExecutionBinding {
    fn execution_id(&self) -> Uuid {
        Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "clavenar.server-execution/v1\0{}\0{}",
                self.agent_id, self.idempotency_id
            )
            .as_bytes(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ServerExecutionCompleted {
    pub execution_id: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub result_sha256: String,
    pub receipt_json: String,
}

#[derive(Debug)]
pub enum ServerExecutionOutcome {
    Missing,
    Started,
    Completed(ServerExecutionCompleted),
    Uncertain,
    Conflict,
}

/// V1 hash input. Identical layout to `clavenar_ledger::HashableEntryV1`
/// so a chain produced by Lite verifies under the full edition.
/// **Do not edit** — bump `CURRENT_CHAIN_VERSION` and add a
/// `HashableEntryV2<'a>` instead.
#[derive(Serialize)]
struct HashableEntryV1<'a> {
    id: &'a Uuid,
    timestamp: &'a DateTime<Utc>,
    agent_id: &'a str,
    method: &'a str,
    intent_category: &'a str,
    authorized: bool,
    reasoning: &'a str,
    policy_decision: &'a Option<serde_json::Value>,
    seq: i64,
    prev_hash: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_invalid_seq: Option<i64>,
    /// Set when the verifier hits a row whose chain_version this
    /// binary doesn't know how to verify. Distinguishable
    /// from a tamper, which sets `first_invalid_seq` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_chain_version: Option<i64>,
}

/// A request that the security pipeline parked for human review
/// (yellow tier — `policy.allow && !review_reasons.is_empty()`). Lives
/// in its own SQLite table alongside the hash-chained ledger.
/// Deliberately NOT part of the hash chain: pendings are operational
/// state that flips when an operator decides, while the ledger is
/// append-only forensic history. The ledger gets a row at park time
/// (intent_category="PendingReview", authorized=false) and a second
/// row at decide time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub correlation_id: String,
    pub agent_id: String,
    pub tool_type: String,
    pub method: String,
    pub review_reasons: Vec<String>,
    pub requested_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    /// `"allow"` or `"deny"` when set; `None` while awaiting decision.
    pub decision: Option<String>,
    pub decider_note: Option<String>,
    /// Optional async-HIL callback. When set, the proxy fires a
    /// fire-and-forget `POST {url}` with the decision body on
    /// `decide_pending`, so the SDK doesn't have to poll. URLs are
    /// supplied by the agent at park time via the
    /// `X-Clavenar-Callback-URL` header and are validated against the
    /// configured allowlist before being stored.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub callback_url: Option<String>,
}

/// Status filter for `Ledger::list_pendings`. `Parked` is the default
/// operator triage view — undecided rows waiting on a human. `Decided`
/// surfaces history; `All` is a debug knob.
#[derive(Debug, Clone, Copy)]
pub enum PendingFilter {
    Parked,
    Decided,
    All,
}

/// Sort direction for `Ledger::list_pendings`. `Oldest` reads as a
/// triage queue (longest-waiting first), `Newest` reads as a
/// chronological history view (most recent first).
#[derive(Debug, Clone, Copy)]
pub enum PendingSort {
    Oldest,
    Newest,
}

#[derive(Debug, Clone)]
pub struct ParkRequest {
    pub correlation_id: String,
    pub agent_id: String,
    pub tool_type: String,
    pub method: String,
    pub review_reasons: Vec<String>,
    /// Validated callback URL for async-HIL webhooks. `None` means
    /// the agent did not request a callback (polling path).
    pub callback_url: Option<String>,
}

/// Failure modes for `Ledger::decide_pending`. Mapped 1:1 to HTTP
/// status by the proxy handler (404 / 409 / 400 / 500).
#[derive(Debug)]
pub enum DecideError {
    /// No pending row for that correlation id.
    NotFound,
    /// The pending row already has a decision recorded.
    AlreadyDecided,
    /// `decision` was neither `"allow"` nor `"deny"`.
    InvalidDecision(String),
    /// Underlying storage failure.
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for DecideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecideError::NotFound => write!(f, "pending not found"),
            DecideError::AlreadyDecided => write!(f, "pending already decided"),
            DecideError::InvalidDecision(d) => {
                write!(
                    f,
                    "invalid decision {:?}: expected \"allow\" or \"deny\"",
                    d
                )
            }
            DecideError::Sqlite(e) => write!(f, "sqlite error: {}", e),
        }
    }
}

impl std::error::Error for DecideError {}

impl From<rusqlite::Error> for DecideError {
    fn from(e: rusqlite::Error) -> Self {
        DecideError::Sqlite(e)
    }
}

pub struct Ledger {
    conn: Arc<Mutex<Connection>>,
    instance_id: String,
}

impl Ledger {
    /// Open (or create) a SQLite ledger at `path`. Use `":memory:"` to
    /// run an in-memory DB for tests. Creates the schema on first use.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        // WAL lets a second process (the `clavenar-lite audit` CLI) read
        // the DB while the proxy holds the writer lock; rollback-journal
        // mode would block both. busy_timeout backstops contention with
        // a short wait instead of an immediate SQLITE_BUSY. The `:memory:`
        // path silently falls back to a memory-mode journal — no error.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            instance_id: Uuid::new_v4().to_string(),
        })
    }

    /// Online backup of the live ledger to `dest_path` using SQLite's
    /// online-backup API (`sqlite3_backup_*`). Safe to call against a
    /// running proxy — the backup steps coexist with concurrent
    /// writes; the destination ends up as a consistent point-in-time
    /// snapshot.
    ///
    /// Returns the total page count copied. The destination is a
    /// stand-alone SQLite DB ready to be opened with `Ledger::open`;
    /// if the file exists at `dest_path` it is overwritten.
    pub async fn backup_to(&self, dest_path: &str) -> rusqlite::Result<i32> {
        // Overwrite any pre-existing file so a stale snapshot doesn't
        // contaminate the new one. Backup::run_to_completion handles
        // the chunking + busy retry loop internally.
        let _ = std::fs::remove_file(dest_path);
        let src = self.conn.lock().await;
        let mut dst = Connection::open(dest_path)?;
        let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
        // 50-page chunks, 50ms sleep between busy retries. Returns
        // `Ok(())` when the copy finishes; the page count is read off
        // the progress handle.
        backup.run_to_completion(50, std::time::Duration::from_millis(50), None)?;
        let pages = backup.progress().pagecount;
        Ok(pages)
    }

    /// Append one entry. Reads the latest seq + entry_hash, computes the
    /// new hash over the canonical body, inserts the row, returns the
    /// fully-populated entry. Same algorithm as
    /// `clavenar_ledger::append_entry`.
    pub async fn append(&self, req: LogRequest) -> rusqlite::Result<LedgerEntry> {
        let conn = self.conn.lock().await;
        append_on_connection(&conn, req)
    }

    /// Read a retained server execution without changing state. Used before
    /// policy/HIL work so completed retries return the original bytes and an
    /// interrupted attempt cannot enter another execution path.
    pub async fn inspect_server_execution(
        &self,
        binding: &ServerExecutionBinding,
    ) -> rusqlite::Result<ServerExecutionOutcome> {
        let conn = self.conn.lock().await;
        inspect_server_execution(&conn, binding)
    }

    /// Atomically commit exact intent plus the in-flight marker and its first
    /// hash-chain stage before the caller is allowed to contact the upstream.
    pub async fn begin_server_execution(
        &self,
        binding: &ServerExecutionBinding,
    ) -> rusqlite::Result<ServerExecutionOutcome> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        match inspect_server_execution(&tx, binding)? {
            ServerExecutionOutcome::Missing => {}
            outcome => return Ok(outcome),
        }
        let execution_id = binding.execution_id();
        tx.execute(
            "INSERT INTO server_executions
             (agent_id, idempotency_id, execution_id, correlation_id, route, method,
              tool_name, submitted_request_sha256, effective_request_sha256, state, created_at,
              reconciliation_state, owner_instance)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'in_flight', ?10,
                     'pending', ?11)",
            rusqlite::params![
                binding.agent_id,
                binding.idempotency_id.to_string(),
                execution_id.to_string(),
                binding.correlation_id,
                binding.route,
                binding.method,
                binding.tool_name,
                binding.submitted_request_sha256,
                binding.effective_request_sha256,
                Utc::now().to_rfc3339(),
                self.instance_id,
            ],
        )?;
        append_on_connection(
            &tx,
            LogRequest {
                agent_id: binding.agent_id.clone(),
                method: binding.method.clone(),
                intent_category: "ServerExecutionIntent".to_string(),
                authorized: false,
                reasoning: "durable server execution intent committed before upstream attempt"
                    .to_string(),
                policy_decision: Some(serde_json::json!({
                    "contract": "clavenar.server-execution/v1",
                    "stage": "execution.intent",
                    "execution_id": execution_id,
                    "idempotency_id": binding.idempotency_id,
                    "route": binding.route,
                    "tool_name": binding.tool_name,
                    "submitted_request_sha256": binding.submitted_request_sha256,
                    "effective_request_sha256": binding.effective_request_sha256,
                    "state": "in_flight",
                })),
                correlation_id: Some(binding.correlation_id.clone()),
            },
        )?;
        tx.commit()?;
        Ok(ServerExecutionOutcome::Started)
    }

    /// Commit the exact received response, terminal receipt, forensic outbox
    /// row, and completion chain stage in one SQLite transaction.
    pub async fn complete_server_execution(
        &self,
        binding: &ServerExecutionBinding,
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    ) -> rusqlite::Result<ServerExecutionCompleted> {
        let execution_id = binding.execution_id();
        let outbox_event_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("clavenar.server-execution/v1\0outbox\0{execution_id}").as_bytes(),
        );
        let result_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        let result = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&body).into_owned())
        });
        let receipt = serde_json::json!({
            "contract": "clavenar.server-execution/v1",
            "stage": "execution.completed",
            "execution_id": execution_id,
            "idempotency_id": binding.idempotency_id,
            "caller": binding.agent_id,
            "route": binding.route,
            "method": binding.method,
            "tool_name": binding.tool_name,
            "submitted_request_sha256": binding.submitted_request_sha256,
            "effective_request_sha256": binding.effective_request_sha256,
            "response_status": status,
            "result_sha256": result_sha256,
            "result": result,
            "outbox_event_id": outbox_event_id,
        });
        let receipt_json = receipt.to_string();
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE server_executions
             SET state = 'completed', response_status = ?1, response_content_type = ?2,
                 response_body = ?3, result_sha256 = ?4, receipt_json = ?5, completed_at = ?6,
                 reconciliation_state = 'resolved', last_reconciled_at = ?6,
                 reconciliation_error = NULL, reconciliation_resolved_at = ?6
             WHERE agent_id = ?7 AND idempotency_id = ?8 AND state = 'in_flight'
               AND effective_request_sha256 = ?9",
            rusqlite::params![
                status,
                content_type,
                body,
                result_sha256,
                receipt_json,
                now,
                binding.agent_id,
                binding.idempotency_id.to_string(),
                binding.effective_request_sha256,
            ],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        tx.execute(
            "INSERT INTO server_execution_outbox
             (event_id, execution_id, payload_json, created_at, delivered_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            rusqlite::params![
                outbox_event_id.to_string(),
                execution_id.to_string(),
                receipt_json,
                now,
            ],
        )?;
        append_on_connection(
            &tx,
            LogRequest {
                agent_id: binding.agent_id.clone(),
                method: binding.method.clone(),
                intent_category: "ServerExecutionCompleted".to_string(),
                authorized: true,
                reasoning: "durable server execution result and receipt committed".to_string(),
                policy_decision: Some(receipt),
                correlation_id: Some(binding.correlation_id.clone()),
            },
        )?;
        tx.commit()?;
        Ok(ServerExecutionCompleted {
            execution_id: execution_id.to_string(),
            status,
            content_type,
            body,
            result_sha256,
            receipt_json,
        })
    }

    /// Periodically classify only abandoned intents owned by a prior process.
    /// The worker records explicit uncertainty in the embedded authoritative
    /// ledger and never invokes the upstream effect.
    pub fn spawn_server_execution_reconciler(self: &Arc<Self>) {
        let ledger = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match ledger.reconcile_server_executions_once().await {
                    Ok(changed) if changed > 0 => {
                        metrics::counter!(
                            "clavenar_forensic_reconciliation_total",
                            "outcome" => "uncertain"
                        )
                        .increment(changed);
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        "Lite server-execution reconciliation failed without effect retry: {error}"
                    ),
                }
                if let Err(error) = ledger.refresh_forensic_metrics().await {
                    tracing::warn!("Lite forensic telemetry refresh failed: {error}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    async fn reconcile_server_executions_once(&self) -> rusqlite::Result<u64> {
        self.reconcile_server_executions_at(Utc::now()).await
    }

    async fn reconcile_server_executions_at(&self, now: DateTime<Utc>) -> rusqlite::Result<u64> {
        let cutoff = (now - chrono::Duration::seconds(300)).to_rfc3339();
        let now = now.to_rfc3339();
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let rows = {
            let mut stmt = tx.prepare(
                "SELECT execution_id, agent_id, idempotency_id, correlation_id, method,
                        tool_name, submitted_request_sha256, effective_request_sha256
                   FROM server_executions
                  WHERE state='in_flight' AND reconciliation_state='pending'
                    AND created_at <= ?1
                    AND owner_instance IS NOT NULL AND owner_instance <> ?2
                  ORDER BY created_at LIMIT 256",
            )?;
            stmt.query_map(rusqlite::params![cutoff, self.instance_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (
            execution_id,
            agent_id,
            idempotency_id,
            correlation_id,
            method,
            tool_name,
            submitted_request_sha256,
            effective_request_sha256,
        ) in &rows
        {
            let event_id = Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("clavenar.server-execution/v1\0reconciliation\0{execution_id}\0uncertain")
                    .as_bytes(),
            );
            let changed = tx.execute(
                "UPDATE server_executions
                    SET reconciliation_state='uncertain',
                        reconciliation_attempts=reconciliation_attempts + 1,
                        last_reconciled_at=?2,
                        reconciliation_error='authoritative upstream result unavailable; automatic effect retry forbidden',
                        reconciliation_resolved_at=?2
                  WHERE execution_id=?1 AND state='in_flight'
                    AND reconciliation_state='pending'",
                rusqlite::params![execution_id, now],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let receipt = serde_json::json!({
                "contract": "clavenar.server-execution/v1",
                "stage": "execution.uncertain",
                "execution_id": execution_id,
                "idempotency_id": idempotency_id,
                "route": "/mcp",
                "method": method,
                "tool_name": tool_name,
                "submitted_request_sha256": submitted_request_sha256,
                "effective_request_sha256": effective_request_sha256,
                "reconciliation": "uncertain",
            });
            tx.execute(
                "INSERT INTO server_execution_outbox
                    (event_id, execution_id, payload_json, created_at, delivered_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                rusqlite::params![event_id.to_string(), execution_id, receipt.to_string(), now],
            )?;
            append_on_connection(
                &tx,
                LogRequest {
                    agent_id: agent_id.clone(),
                    method: method.clone(),
                    intent_category: "ServerExecutionUncertain".to_string(),
                    authorized: false,
                    reasoning: "interrupted durable server execution has no authoritative retained result; automatic upstream retry forbidden".to_string(),
                    policy_decision: Some(receipt),
                    correlation_id: Some(correlation_id.clone()),
                },
            )?;
        }
        tx.commit()?;
        Ok(rows.len() as u64)
    }

    async fn refresh_forensic_metrics(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        let (ready, oldest): (i64, Option<String>) = conn.query_row(
            "SELECT COUNT(*), MIN(created_at) FROM server_execution_outbox
              WHERE delivered_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (pending, missing): (i64, i64) = conn.query_row(
            "SELECT COALESCE(SUM(CASE WHEN reconciliation_state='pending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN reconciliation_state='pending'
                        AND julianday(created_at) <= julianday('now', '-300 seconds') THEN 1 ELSE 0 END), 0)
               FROM server_executions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let age = oldest
            .as_deref()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| {
                Utc::now()
                    .signed_duration_since(value.with_timezone(&Utc))
                    .num_seconds()
                    .max(0) as f64
            })
            .unwrap_or(0.0);
        metrics::gauge!("clavenar_forensic_outbox_depth", "state" => "ready").set(ready as f64);
        metrics::gauge!("clavenar_forensic_outbox_depth", "state" => "retry").set(0.0);
        metrics::gauge!("clavenar_forensic_outbox_depth", "state" => "terminal").set(0.0);
        metrics::gauge!("clavenar_forensic_outbox_oldest_age_seconds").set(age);
        metrics::gauge!("clavenar_forensic_reconciliation_pending").set(pending as f64);
        metrics::gauge!(
            "clavenar_forensic_missing_stages",
            "family" => "lite",
            "stage" => "execution.completed"
        )
        .set(missing as f64);
        metrics::counter!("clavenar_forensic_outbox_retry_attempts_total").increment(0);
        metrics::counter!("clavenar_forensic_outbox_terminal_failures_total").increment(0);
        for outcome in ["resolved", "failed", "uncertain"] {
            metrics::counter!(
                "clavenar_forensic_reconciliation_total",
                "outcome" => outcome
            )
            .increment(0);
        }
        Ok(())
    }

    /// Walk every entry in seq order, recompute each hash, and confirm
    /// it matches the stored `entry_hash`. The full edition's
    /// `verify_chain` does the same; both share the canonical-JSON order
    /// in `HashableEntry` so they cross-validate.
    pub async fn verify(&self) -> rusqlite::Result<VerifyResult> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, seq, timestamp, agent_id, method, intent_category, authorized,
                    reasoning, policy_decision, prev_hash, entry_hash, chain_version,
                    correlation_id
             FROM entries ORDER BY seq ASC",
        )?;
        let mut rows = stmt.query([])?;

        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        let mut count = 0usize;
        let mut first_invalid: Option<i64> = None;
        let mut unsupported_chain_version: Option<i64> = None;

        while let Some(row) = rows.next()? {
            let entry = row_to_entry(row)?;
            // Chain-version dispatch: if this row was written under a chain
            // version this binary doesn't know, stop the walk and
            // surface the version separately. We can't validate any
            // row that chains off an unverifiable hash anyway.
            let recomputed = match recompute_for_version(entry.chain_version, &entry) {
                Some(h) => h,
                None => {
                    unsupported_chain_version = Some(entry.chain_version);
                    break;
                }
            };

            if entry.prev_hash != expected_prev || recomputed != entry.entry_hash {
                first_invalid = Some(entry.seq);
                break;
            }
            expected_prev = entry.entry_hash;
            count += 1;
        }

        Ok(VerifyResult {
            valid: first_invalid.is_none() && unsupported_chain_version.is_none(),
            entries_checked: count,
            first_invalid_seq: first_invalid,
            unsupported_chain_version,
        })
    }

    /// Park a yellow-tier request awaiting human review. Inserts one
    /// row in `pendings` keyed by `correlation_id`; returns the parked
    /// record. The caller is expected to also write a `LedgerEntry`
    /// with `intent_category="PendingReview", authorized=false` so the
    /// forensic chain reflects the park.
    pub async fn park_pending(&self, req: ParkRequest) -> rusqlite::Result<Pending> {
        let conn = self.conn.lock().await;
        let requested_at = Utc::now();
        let review_reasons_json =
            serde_json::to_string(&req.review_reasons).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO pendings (correlation_id, agent_id, tool_type, method,
                                   review_reasons_json, requested_at, callback_url)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                req.correlation_id,
                req.agent_id,
                req.tool_type,
                req.method,
                review_reasons_json,
                requested_at.to_rfc3339(),
                req.callback_url,
            ],
        )?;
        Ok(Pending {
            correlation_id: req.correlation_id,
            agent_id: req.agent_id,
            tool_type: req.tool_type,
            method: req.method,
            review_reasons: req.review_reasons,
            requested_at,
            decided_at: None,
            decision: None,
            decider_note: None,
            callback_url: req.callback_url,
        })
    }

    /// Record an operator decision against a pending row. Returns the
    /// updated record. Idempotent in the failure direction — a second
    /// call against the same correlation id returns
    /// {@link DecideError::AlreadyDecided}, never silently overwriting
    /// a prior decision. The caller is expected to write a follow-up
    /// {@link LedgerEntry} (intent_category=PendingApproved /
    /// PendingDenied) so the forensic chain shows both the park and
    /// the resolve.
    pub async fn decide_pending(
        &self,
        correlation_id: &str,
        decision: &str,
        note: Option<&str>,
    ) -> Result<Pending, DecideError> {
        if decision != "allow" && decision != "deny" {
            return Err(DecideError::InvalidDecision(decision.to_string()));
        }
        let conn = self.conn.lock().await;
        // SELECT + UPDATE under the single Mutex<Connection> lock is
        // serialised, so no race between read-decision-state and
        // write-decision. The `decided_at IS NULL` guard in the UPDATE
        // is belt-and-suspenders.
        let pending = {
            let mut stmt = conn.prepare(
                "SELECT correlation_id, agent_id, tool_type, method, review_reasons_json,
                        requested_at, decided_at, decision, decider_note, callback_url
                 FROM pendings WHERE correlation_id = ?1",
            )?;
            let mut rows = stmt.query([correlation_id])?;
            match rows.next()? {
                Some(row) => row_to_pending(row)?,
                None => return Err(DecideError::NotFound),
            }
        };
        if pending.decision.is_some() {
            return Err(DecideError::AlreadyDecided);
        }

        let decided_at = Utc::now();
        let rows_affected = conn.execute(
            "UPDATE pendings SET decided_at = ?1, decision = ?2, decider_note = ?3
             WHERE correlation_id = ?4 AND decided_at IS NULL",
            rusqlite::params![decided_at.to_rfc3339(), decision, note, correlation_id,],
        )?;
        if rows_affected == 0 {
            // Belt-and-suspenders: under the connection mutex this
            // should be unreachable, but if it ever fires it means a
            // concurrent decider got there first — surface as
            // AlreadyDecided rather than silently no-op'ing.
            return Err(DecideError::AlreadyDecided);
        }

        Ok(Pending {
            decided_at: Some(decided_at),
            decision: Some(decision.to_string()),
            decider_note: note.map(str::to_string),
            ..pending
        })
    }

    /// List pending rows filtered by decision state, ordered by
    /// `requested_at` in the direction the caller asked for. `limit`
    /// caps the result set — partner-facing CLI defaults to 50, server
    /// caps at 500 so a misconfigured client can't exhaust memory
    /// ordering a million rows.
    pub async fn list_pendings(
        &self,
        filter: PendingFilter,
        limit: u32,
        sort: PendingSort,
    ) -> rusqlite::Result<Vec<Pending>> {
        let conn = self.conn.lock().await;
        let where_clause = match filter {
            PendingFilter::Parked => "WHERE decided_at IS NULL",
            PendingFilter::Decided => "WHERE decided_at IS NOT NULL",
            PendingFilter::All => "",
        };
        let order_dir = match sort {
            PendingSort::Oldest => "ASC",
            PendingSort::Newest => "DESC",
        };
        let sql = format!(
            "SELECT correlation_id, agent_id, tool_type, method, review_reasons_json,
                    requested_at, decided_at, decision, decider_note, callback_url
             FROM pendings {} ORDER BY requested_at {} LIMIT ?1",
            where_clause, order_dir
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([limit], row_to_pending)?;
        rows.collect()
    }

    /// Look up a pending by correlation id. Returns `None` if no such
    /// row exists. The pending row may be already-decided — callers
    /// inspect `decision` to tell.
    pub async fn get_pending(&self, correlation_id: &str) -> rusqlite::Result<Option<Pending>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT correlation_id, agent_id, tool_type, method, review_reasons_json,
                    requested_at, decided_at, decision, decider_note, callback_url
             FROM pendings WHERE correlation_id = ?1",
        )?;
        let mut rows = stmt.query([correlation_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_pending(row)?)),
            None => Ok(None),
        }
    }

    /// Return every entry for `agent_id`, in seq order. Used by `audit`
    /// CLI subcommand.
    pub async fn entries_for_agent(&self, agent_id: &str) -> rusqlite::Result<Vec<LedgerEntry>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, seq, timestamp, agent_id, method, intent_category, authorized,
                    reasoning, policy_decision, prev_hash, entry_hash, chain_version,
                    correlation_id
             FROM entries WHERE agent_id = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([agent_id], row_to_entry)?;
        rows.collect()
    }

    /// Aggregate observe-mode verdict rows for the graduation report.
    /// `since` (when `Some`) bounds the scan to rows at or after that
    /// instant. Read-only — same shape as `verify`/`entries_for_agent`.
    pub async fn graduation_stats(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> rusqlite::Result<GraduationStats> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT intent_category, authorized, agent_id, timestamp
             FROM entries
             WHERE (?1 IS NULL OR timestamp >= ?1)
             ORDER BY seq ASC",
        )?;
        let since_str = since.map(|s| s.to_rfc3339());
        let rows = stmt.query_map([since_str], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut stats = GraduationStats {
            total: 0,
            would_deny: 0,
            would_pend: 0,
            allowed: 0,
            by_intent: Vec::new(),
            top_agents: Vec::new(),
            window_start: since,
            window_end: None,
        };
        let mut intent_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut agent_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut latest: Option<DateTime<Utc>> = None;

        for row in rows {
            let (intent, authorized, agent_id, ts) = row?;
            stats.total += 1;
            if authorized {
                stats.allowed += 1;
            }
            if WOULD_DENY_INTENTS.contains(&intent.as_str()) {
                stats.would_deny += 1;
            } else if intent == "PendingReview" {
                stats.would_pend += 1;
            }
            *intent_counts.entry(intent).or_insert(0) += 1;
            *agent_counts.entry(agent_id).or_insert(0) += 1;
            if let Ok(parsed) = DateTime::parse_from_rfc3339(&ts) {
                let parsed = parsed.with_timezone(&Utc);
                if latest.is_none_or(|cur| parsed > cur) {
                    latest = Some(parsed);
                }
            }
        }

        stats.window_end = latest;
        stats.by_intent = intent_counts.into_iter().collect();
        // Top agents by count desc, then agent_id asc for stable output.
        let mut agents: Vec<(String, u64)> = agent_counts.into_iter().collect();
        agents.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        agents.truncate(TOP_AGENTS_LIMIT);
        stats.top_agents = agents;
        Ok(stats)
    }
}

/// Intent categories the security pipeline stamps on a row it would
/// block in enforce mode. In observe mode the request still forwards,
/// but the ledger row carries one of these so the graduation report can
/// count "what enforce would have denied".
const WOULD_DENY_INTENTS: &[&str] = &[
    "PolicyDeny",
    "BrainDeny",
    "PromptInjection",
    "RateLimitDenied",
];

/// Cap on the per-agent breakdown in the graduation report.
const TOP_AGENTS_LIMIT: usize = 10;

/// Aggregated observe-mode verdict counts for the graduation report.
/// `would_deny`/`would_pend`/`allowed` are the headline numbers; the
/// per-intent and per-agent breakdowns give the operator the detail.
#[derive(Debug, Clone)]
pub struct GraduationStats {
    pub total: u64,
    pub would_deny: u64,
    pub would_pend: u64,
    pub allowed: u64,
    pub by_intent: Vec<(String, u64)>,
    pub top_agents: Vec<(String, u64)>,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
}

fn append_on_connection(conn: &Connection, req: LogRequest) -> rusqlite::Result<LedgerEntry> {
    let (next_seq, prev_hash): (i64, String) = conn
        .query_row(
            "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)? + 1, row.get::<_, String>(1)?)),
        )
        .unwrap_or((1, GENESIS_PREV_HASH.to_string()));
    let mut entry = LedgerEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        agent_id: req.agent_id,
        method: req.method,
        intent_category: req.intent_category,
        authorized: req.authorized,
        reasoning: req.reasoning,
        policy_decision: req.policy_decision,
        seq: next_seq,
        prev_hash,
        entry_hash: String::new(),
        chain_version: CURRENT_CHAIN_VERSION,
        correlation_id: req.correlation_id,
    };
    entry.entry_hash = recompute_for_version(entry.chain_version, &entry)
        .expect("CURRENT_CHAIN_VERSION must be supported by this binary");
    let policy_decision_json = entry
        .policy_decision
        .as_ref()
        .map(|value| serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()));
    conn.execute(
        "INSERT INTO entries (id, seq, timestamp, agent_id, method, intent_category,
                              authorized, reasoning, policy_decision, prev_hash, entry_hash,
                              chain_version, correlation_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            entry.id.to_string(),
            entry.seq,
            entry.timestamp.to_rfc3339(),
            entry.agent_id,
            entry.method,
            entry.intent_category,
            entry.authorized as i64,
            entry.reasoning,
            policy_decision_json,
            entry.prev_hash,
            entry.entry_hash,
            entry.chain_version,
            entry.correlation_id,
        ],
    )?;
    Ok(entry)
}

fn inspect_server_execution(
    conn: &Connection,
    binding: &ServerExecutionBinding,
) -> rusqlite::Result<ServerExecutionOutcome> {
    let row = conn
        .query_row(
            "SELECT route, method, tool_name, submitted_request_sha256,
                    effective_request_sha256, state, execution_id, response_status,
                    response_content_type, response_body, result_sha256, receipt_json
             FROM server_executions WHERE agent_id = ?1 AND idempotency_id = ?2",
            rusqlite::params![binding.agent_id, binding.idempotency_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        route,
        method,
        tool_name,
        submitted_digest,
        _effective_digest,
        state,
        execution_id,
        response_status,
        content_type,
        body,
        result_sha256,
        receipt_json,
    )) = row
    else {
        return Ok(ServerExecutionOutcome::Missing);
    };
    if route != binding.route
        || method != binding.method
        || tool_name != binding.tool_name
        || submitted_digest != binding.submitted_request_sha256
    {
        return Ok(ServerExecutionOutcome::Conflict);
    }
    if state != "completed" {
        return Ok(ServerExecutionOutcome::Uncertain);
    }
    let completed = ServerExecutionCompleted {
        execution_id,
        status: response_status
            .and_then(|status| u16::try_from(status).ok())
            .ok_or(rusqlite::Error::InvalidQuery)?,
        content_type,
        body: body.ok_or(rusqlite::Error::InvalidQuery)?,
        result_sha256: result_sha256.ok_or(rusqlite::Error::InvalidQuery)?,
        receipt_json: receipt_json.ok_or(rusqlite::Error::InvalidQuery)?,
    };
    Ok(ServerExecutionOutcome::Completed(completed))
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS entries (
            id TEXT PRIMARY KEY,
            seq INTEGER NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            method TEXT NOT NULL,
            intent_category TEXT NOT NULL,
            authorized INTEGER NOT NULL,
            reasoning TEXT NOT NULL,
            policy_decision TEXT,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            chain_version INTEGER NOT NULL DEFAULT 1,
            correlation_id TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_entries_agent_id ON entries(agent_id);
         CREATE INDEX IF NOT EXISTS idx_entries_seq ON entries(seq);
         CREATE INDEX IF NOT EXISTS idx_entries_correlation_id ON entries(correlation_id);
         CREATE TABLE IF NOT EXISTS pendings (
            correlation_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            tool_type TEXT NOT NULL,
            method TEXT NOT NULL,
            review_reasons_json TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            decided_at TEXT,
            decision TEXT,
            decider_note TEXT,
            callback_url TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_pendings_decided_at ON pendings(decided_at);
         CREATE TABLE IF NOT EXISTS server_executions (
            agent_id TEXT NOT NULL,
            idempotency_id TEXT NOT NULL,
            execution_id TEXT NOT NULL UNIQUE,
            correlation_id TEXT NOT NULL,
            route TEXT NOT NULL,
            method TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            submitted_request_sha256 TEXT NOT NULL,
            effective_request_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('in_flight', 'completed')),
            response_status INTEGER,
            response_content_type TEXT,
            response_body BLOB,
            result_sha256 TEXT,
            receipt_json TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            reconciliation_state TEXT NOT NULL DEFAULT 'legacy'
                CHECK(reconciliation_state IN ('legacy', 'pending', 'resolved', 'uncertain')),
            reconciliation_attempts INTEGER NOT NULL DEFAULT 0,
            last_reconciled_at TEXT,
            reconciliation_error TEXT,
            reconciliation_resolved_at TEXT,
            owner_instance TEXT,
            PRIMARY KEY (agent_id, idempotency_id)
         );
         CREATE TABLE IF NOT EXISTS server_execution_outbox (
            event_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            delivered_at TEXT
         );",
    )?;

    // Idempotent migrations for legacy DBs. Each ALTER adds one
    // column if missing; default values match the CREATE TABLE shape.
    // `chain_version` defaults to 1 (the only chain version legacy
    // rows could have been written under); `correlation_id` is
    // nullable because legacy rows never had one.
    fn has_column(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
        let mut stmt = conn.prepare("PRAGMA table_info(entries)")?;
        let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for n in names {
            if n? == name {
                return Ok(true);
            }
        }
        Ok(false)
    }
    if !has_column(conn, "chain_version")? {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN chain_version INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
    }
    if !has_column(conn, "correlation_id")? {
        conn.execute("ALTER TABLE entries ADD COLUMN correlation_id TEXT", [])?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entries_correlation_id ON entries(correlation_id)",
            [],
        )?;
    }

    // Pendings ALTER TABLE: callback_url is added for the async-HIL
    // webhook flow (0.5.0). Legacy rows (no callback) read as None.
    fn has_pending_column(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
        let mut stmt = conn.prepare("PRAGMA table_info(pendings)")?;
        let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for n in names {
            if n? == name {
                return Ok(true);
            }
        }
        Ok(false)
    }
    if !has_pending_column(conn, "callback_url")? {
        conn.execute("ALTER TABLE pendings ADD COLUMN callback_url TEXT", [])?;
    }
    fn has_server_execution_column(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
        let mut stmt = conn.prepare("PRAGMA table_info(server_executions)")?;
        let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for column in names {
            if column? == name {
                return Ok(true);
            }
        }
        Ok(false)
    }
    for (name, definition) in [
        (
            "reconciliation_state",
            "TEXT NOT NULL DEFAULT 'legacy' CHECK(reconciliation_state IN ('legacy', 'pending', 'resolved', 'uncertain'))",
        ),
        ("reconciliation_attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("last_reconciled_at", "TEXT"),
        ("reconciliation_error", "TEXT"),
        ("reconciliation_resolved_at", "TEXT"),
        ("owner_instance", "TEXT"),
    ] {
        if !has_server_execution_column(conn, name)? {
            conn.execute(
                &format!("ALTER TABLE server_executions ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    Ok(())
}

/// V1 hash function. **Do not edit** once a v2 ships — historical
/// rows must keep verifying through this exact path.
fn compute_entry_hash_v1(hashable: &HashableEntryV1<'_>) -> String {
    let canonical = serde_json::to_vec(hashable).expect("HashableEntryV1 always serializes");
    let mut hasher = Sha256::new();
    hasher.update(hashable.prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(&canonical);
    hex::encode(hasher.finalize())
}

/// Per-version dispatch shared by `append` (write) and `verify`
/// (read-back). `None` => the requested version is newer than this
/// binary; the caller surfaces that as `unsupported_chain_version`.
fn recompute_for_version(version: i64, entry: &LedgerEntry) -> Option<String> {
    match version {
        1 => {
            let hashable = HashableEntryV1 {
                id: &entry.id,
                timestamp: &entry.timestamp,
                agent_id: &entry.agent_id,
                method: &entry.method,
                intent_category: &entry.intent_category,
                authorized: entry.authorized,
                reasoning: &entry.reasoning,
                policy_decision: &entry.policy_decision,
                seq: entry.seq,
                prev_hash: &entry.prev_hash,
            };
            Some(compute_entry_hash_v1(&hashable))
        }
        _ => None,
    }
}

fn row_to_pending(row: &rusqlite::Row) -> rusqlite::Result<Pending> {
    let correlation_id: String = row.get(0)?;
    let agent_id: String = row.get(1)?;
    let tool_type: String = row.get(2)?;
    let method: String = row.get(3)?;
    let review_reasons_json: String = row.get(4)?;
    let requested_at_str: String = row.get(5)?;
    let decided_at_str: Option<String> = row.get(6)?;
    let decision: Option<String> = row.get(7)?;
    let decider_note: Option<String> = row.get(8)?;
    let callback_url: Option<String> = row.get(9)?;
    let review_reasons: Vec<String> =
        serde_json::from_str(&review_reasons_json).unwrap_or_default();
    let requested_at = DateTime::parse_from_rfc3339(&requested_at_str)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let decided_at = decided_at_str
        .map(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        6,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
        })
        .transpose()?;
    Ok(Pending {
        correlation_id,
        agent_id,
        tool_type,
        method,
        review_reasons,
        requested_at,
        decided_at,
        decision,
        decider_note,
        callback_url,
    })
}

fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<LedgerEntry> {
    let id_str: String = row.get(0)?;
    let timestamp_str: String = row.get(2)?;
    let policy_decision_str: Option<String> = row.get(8)?;

    Ok(LedgerEntry {
        id: Uuid::parse_str(&id_str).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        seq: row.get(1)?,
        timestamp: DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        agent_id: row.get(3)?,
        method: row.get(4)?,
        intent_category: row.get(5)?,
        authorized: row.get::<_, i64>(6)? != 0,
        reasoning: row.get(7)?,
        policy_decision: policy_decision_str
            .map(|s| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null)),
        prev_hash: row.get(9)?,
        entry_hash: row.get(10)?,
        // Column 11 is INTEGER NOT NULL DEFAULT 1 — the migration
        // backfills `1` for legacy rows.
        chain_version: row.get(11)?,
        // Column 12 is nullable; legacy rows return None.
        correlation_id: row.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(agent_id: &str, authorized: bool) -> LogRequest {
        LogRequest {
            agent_id: agent_id.to_string(),
            method: "call_tool".to_string(),
            intent_category: "Routine".to_string(),
            authorized,
            reasoning: "test".to_string(),
            policy_decision: None,
            correlation_id: None,
        }
    }

    #[tokio::test]
    async fn append_then_verify_passes() {
        let ledger = Ledger::open(":memory:").unwrap();
        for i in 0..5 {
            ledger
                .append(sample(&format!("agent-{}", i), true))
                .await
                .unwrap();
        }
        let v = ledger.verify().await.unwrap();
        assert!(v.valid);
        assert_eq!(v.entries_checked, 5);
    }

    #[tokio::test]
    async fn empty_ledger_verifies() {
        let ledger = Ledger::open(":memory:").unwrap();
        let v = ledger.verify().await.unwrap();
        assert!(v.valid);
        assert_eq!(v.entries_checked, 0);
    }

    #[tokio::test]
    async fn first_entry_uses_genesis_prev_hash() {
        let ledger = Ledger::open(":memory:").unwrap();
        let entry = ledger.append(sample("a", true)).await.unwrap();
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
    }

    #[tokio::test]
    async fn entries_for_agent_filters() {
        let ledger = Ledger::open(":memory:").unwrap();
        ledger.append(sample("alice", true)).await.unwrap();
        ledger.append(sample("bob", true)).await.unwrap();
        ledger.append(sample("alice", false)).await.unwrap();
        let alice_entries = ledger.entries_for_agent("alice").await.unwrap();
        assert_eq!(alice_entries.len(), 2);
        assert_eq!(alice_entries[0].agent_id, "alice");
        assert_eq!(alice_entries[1].agent_id, "alice");
    }

    #[tokio::test]
    async fn future_chain_version_surfaces_as_unsupported() {
        // A row written under a newer chain_version must not be
        // mis-reported as tampered — verify should set
        // `unsupported_chain_version` and leave `first_invalid_seq` None.
        let ledger = Ledger::open(":memory:").unwrap();
        ledger.append(sample("a", true)).await.unwrap();
        {
            let conn = ledger.conn.lock().await;
            conn.execute("UPDATE entries SET chain_version = 99 WHERE seq = 1", [])
                .unwrap();
        }
        let v = ledger.verify().await.unwrap();
        assert!(!v.valid);
        assert_eq!(v.first_invalid_seq, None);
        assert_eq!(v.unsupported_chain_version, Some(99));
    }

    #[tokio::test]
    async fn park_pending_round_trips_through_get() {
        let ledger = Ledger::open(":memory:").unwrap();
        let parked = ledger
            .park_pending(ParkRequest {
                correlation_id: "abc-123".to_string(),
                agent_id: "agent-1".to_string(),
                tool_type: "transfer_funds".to_string(),
                method: "call_tool".to_string(),
                review_reasons: vec!["Wire transfers require approval".to_string()],
                callback_url: None,
            })
            .await
            .unwrap();
        assert_eq!(parked.correlation_id, "abc-123");
        assert!(parked.decided_at.is_none());
        assert!(parked.decision.is_none());

        let fetched = ledger.get_pending("abc-123").await.unwrap().unwrap();
        assert_eq!(fetched.agent_id, "agent-1");
        assert_eq!(fetched.tool_type, "transfer_funds");
        assert_eq!(
            fetched.review_reasons,
            vec!["Wire transfers require approval"]
        );
        assert!(fetched.decision.is_none());
    }

    #[tokio::test]
    async fn get_pending_returns_none_for_unknown_correlation_id() {
        let ledger = Ledger::open(":memory:").unwrap();
        let missing = ledger.get_pending("does-not-exist").await.unwrap();
        assert!(missing.is_none());
    }

    async fn park_sample(ledger: &Ledger, correlation_id: &str) {
        ledger
            .park_pending(ParkRequest {
                correlation_id: correlation_id.to_string(),
                agent_id: "agent-1".to_string(),
                tool_type: "wire_transfer".to_string(),
                method: "call_tool".to_string(),
                review_reasons: vec!["Review: wire transfers".to_string()],
                callback_url: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decide_allow_updates_pending_row() {
        let ledger = Ledger::open(":memory:").unwrap();
        park_sample(&ledger, "p-1").await;
        let decided = ledger
            .decide_pending("p-1", "allow", Some("ok by sec"))
            .await
            .unwrap();
        assert_eq!(decided.decision.as_deref(), Some("allow"));
        assert!(decided.decided_at.is_some());
        assert_eq!(decided.decider_note.as_deref(), Some("ok by sec"));

        let refetched = ledger.get_pending("p-1").await.unwrap().unwrap();
        assert_eq!(refetched.decision.as_deref(), Some("allow"));
        assert!(refetched.decided_at.is_some());
    }

    #[tokio::test]
    async fn decide_deny_records_decision_string() {
        let ledger = Ledger::open(":memory:").unwrap();
        park_sample(&ledger, "p-2").await;
        let decided = ledger.decide_pending("p-2", "deny", None).await.unwrap();
        assert_eq!(decided.decision.as_deref(), Some("deny"));
        assert!(decided.decider_note.is_none());
    }

    #[tokio::test]
    async fn decide_twice_returns_already_decided() {
        let ledger = Ledger::open(":memory:").unwrap();
        park_sample(&ledger, "p-3").await;
        ledger.decide_pending("p-3", "allow", None).await.unwrap();
        let err = ledger
            .decide_pending("p-3", "deny", None)
            .await
            .expect_err("second decide must error");
        assert!(matches!(err, DecideError::AlreadyDecided));
    }

    #[tokio::test]
    async fn decide_unknown_correlation_id_returns_not_found() {
        let ledger = Ledger::open(":memory:").unwrap();
        let err = ledger
            .decide_pending("does-not-exist", "allow", None)
            .await
            .expect_err("missing pending must error");
        assert!(matches!(err, DecideError::NotFound));
    }

    #[tokio::test]
    async fn decide_rejects_unknown_decision_string() {
        let ledger = Ledger::open(":memory:").unwrap();
        park_sample(&ledger, "p-4").await;
        let err = ledger
            .decide_pending("p-4", "maybe", None)
            .await
            .expect_err("bogus decision must error");
        match err {
            DecideError::InvalidDecision(d) => assert_eq!(d, "maybe"),
            other => panic!("expected InvalidDecision, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tampering_breaks_verification() {
        let ledger = Ledger::open(":memory:").unwrap();
        for _ in 0..3 {
            ledger.append(sample("victim", true)).await.unwrap();
        }
        // Tamper with entry seq=2's reasoning. The recomputed hash will
        // no longer match the stored entry_hash, so verify must report
        // `valid=false` and pinpoint seq=2 as the first invalid row.
        {
            let conn = ledger.conn.lock().await;
            conn.execute(
                "UPDATE entries SET reasoning = 'tampered' WHERE seq = 2",
                [],
            )
            .unwrap();
        }
        let v = ledger.verify().await.unwrap();
        assert!(!v.valid);
        assert_eq!(v.first_invalid_seq, Some(2));
    }

    #[tokio::test]
    async fn backup_to_produces_verifiable_snapshot() {
        let src_dir = tempfile::tempdir().unwrap();
        let src_path = src_dir.path().join("ledger.db");
        let src = Ledger::open(src_path.to_str().unwrap()).unwrap();
        let mut originals = Vec::new();
        for i in 0..5 {
            originals.push(
                src.append(sample(&format!("agent-{}", i), true))
                    .await
                    .unwrap(),
            );
        }

        let dest_dir = tempfile::tempdir().unwrap();
        let dest_path = dest_dir.path().join("snapshot.db");
        let pages = src.backup_to(dest_path.to_str().unwrap()).await.unwrap();
        assert!(pages > 0, "expected at least one page copied");

        // Snapshot opens, verifies clean, and carries every entry the
        // source had at the moment of the backup call.
        let snapshot = Ledger::open(dest_path.to_str().unwrap()).unwrap();
        let v = snapshot.verify().await.unwrap();
        assert!(v.valid, "snapshot should verify");
        assert_eq!(v.entries_checked, 5);
        for orig in &originals {
            let row = snapshot
                .conn
                .lock()
                .await
                .query_row(
                    "SELECT entry_hash FROM entries WHERE seq = ?1",
                    [orig.seq],
                    |r| r.get::<_, String>(0),
                )
                .unwrap();
            assert_eq!(
                row, orig.entry_hash,
                "snapshot entry_hash diverges from source at seq={}",
                orig.seq
            );
        }
    }

    #[tokio::test]
    async fn backup_writes_overwrite_existing_dest() {
        let src = Ledger::open(":memory:").unwrap();
        src.append(sample("a", true)).await.unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let dest_path = dest_dir.path().join("snap.db");
        // Pre-existing garbage file should be overwritten cleanly.
        std::fs::write(&dest_path, b"junk").unwrap();
        let _ = src.backup_to(dest_path.to_str().unwrap()).await.unwrap();
        let snapshot = Ledger::open(dest_path.to_str().unwrap()).unwrap();
        assert!(snapshot.verify().await.unwrap().valid);
    }

    fn verdict(agent_id: &str, intent: &str, authorized: bool) -> LogRequest {
        LogRequest {
            agent_id: agent_id.to_string(),
            method: "call_tool".to_string(),
            intent_category: intent.to_string(),
            authorized,
            reasoning: "test".to_string(),
            policy_decision: None,
            correlation_id: None,
        }
    }

    #[tokio::test]
    async fn graduation_stats_counts_would_deny_and_pend() {
        let ledger = Ledger::open(":memory:").unwrap();
        ledger.append(verdict("a", "Routine", true)).await.unwrap();
        ledger
            .append(verdict("a", "PolicyDeny", false))
            .await
            .unwrap();
        ledger
            .append(verdict("b", "BrainDeny", false))
            .await
            .unwrap();
        ledger
            .append(verdict("a", "PendingReview", false))
            .await
            .unwrap();
        ledger
            .append(verdict("a", "RateLimitDenied", false))
            .await
            .unwrap();

        let s = ledger.graduation_stats(None).await.unwrap();
        assert_eq!(s.total, 5);
        assert_eq!(s.would_deny, 3); // PolicyDeny + BrainDeny + RateLimitDenied
        assert_eq!(s.would_pend, 1); // PendingReview
        assert_eq!(s.allowed, 1); // the single Routine
        // top_agents: a (4) before b (1).
        assert_eq!(s.top_agents.first().unwrap().0, "a");
        assert_eq!(s.top_agents.first().unwrap().1, 4);
    }

    #[tokio::test]
    async fn graduation_stats_respects_since_window() {
        let ledger = Ledger::open(":memory:").unwrap();
        ledger.append(verdict("a", "Routine", true)).await.unwrap();
        // A `since` far in the future excludes every existing row.
        let future = Utc::now() + chrono::Duration::days(365);
        let s = ledger.graduation_stats(Some(future)).await.unwrap();
        assert_eq!(s.total, 0);
        // A `since` in the past includes it.
        let past = Utc::now() - chrono::Duration::days(1);
        let s = ledger.graduation_stats(Some(past)).await.unwrap();
        assert_eq!(s.total, 1);
    }

    fn server_binding() -> ServerExecutionBinding {
        ServerExecutionBinding {
            agent_id: "agent-a".to_string(),
            idempotency_id: Uuid::parse_str("7a7adf0c-0ef7-45aa-a801-598e38095dfa").unwrap(),
            correlation_id: "7a7adf0c-0ef7-45aa-a801-598e38095dfa".to_string(),
            route: "/mcp".to_string(),
            method: "tools/call".to_string(),
            tool_name: "transfer".to_string(),
            submitted_request_sha256: "sha256:request".to_string(),
            effective_request_sha256: "sha256:request".to_string(),
        }
    }

    #[tokio::test]
    async fn durable_server_execution_replays_without_a_second_start() {
        let ledger = Ledger::open(":memory:").unwrap();
        let binding = server_binding();
        assert!(matches!(
            ledger.begin_server_execution(&binding).await.unwrap(),
            ServerExecutionOutcome::Started
        ));
        assert!(matches!(
            ledger.begin_server_execution(&binding).await.unwrap(),
            ServerExecutionOutcome::Uncertain
        ));
        ledger
            .complete_server_execution(
                &binding,
                200,
                Some("application/json".to_string()),
                br#"{"ok":true}"#.to_vec(),
            )
            .await
            .unwrap();
        assert!(matches!(
            ledger.inspect_server_execution(&binding).await.unwrap(),
            ServerExecutionOutcome::Completed(_)
        ));
        let conn = ledger.conn.lock().await;
        let state: String = conn
            .query_row(
                "SELECT reconciliation_state FROM server_executions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "resolved");
        drop(conn);
        assert!(ledger.verify().await.unwrap().valid);
    }

    #[tokio::test]
    async fn durable_server_execution_conflicts_on_payload_substitution() {
        let ledger = Ledger::open(":memory:").unwrap();
        let binding = server_binding();
        assert!(matches!(
            ledger.begin_server_execution(&binding).await.unwrap(),
            ServerExecutionOutcome::Started
        ));
        let mut substituted = binding;
        substituted.submitted_request_sha256 = "sha256:different".to_string();
        assert!(matches!(
            ledger.inspect_server_execution(&substituted).await.unwrap(),
            ServerExecutionOutcome::Conflict
        ));
    }

    #[tokio::test]
    async fn prior_process_execution_becomes_chain_recorded_uncertainty_without_retry() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let binding = server_binding();
        {
            let ledger = Ledger::open(file.path().to_str().unwrap()).unwrap();
            assert!(matches!(
                ledger.begin_server_execution(&binding).await.unwrap(),
                ServerExecutionOutcome::Started
            ));
        }
        let restarted = Ledger::open(file.path().to_str().unwrap()).unwrap();
        let changed = restarted
            .reconcile_server_executions_at(Utc::now() + chrono::Duration::minutes(10))
            .await
            .unwrap();
        assert_eq!(changed, 1);
        let conn = restarted.conn.lock().await;
        let retained: (String, i64, i64, i64) = conn
            .query_row(
                "SELECT reconciliation_state, reconciliation_attempts,
                        (SELECT COUNT(*) FROM server_execution_outbox),
                        (SELECT COUNT(*) FROM entries
                          WHERE intent_category='ServerExecutionUncertain')
                   FROM server_executions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(retained, ("uncertain".to_string(), 1, 1, 1));
        drop(conn);
        assert_eq!(
            restarted
                .reconcile_server_executions_at(Utc::now() + chrono::Duration::minutes(20))
                .await
                .unwrap(),
            0
        );
        assert!(restarted.verify().await.unwrap().valid);
    }
}
