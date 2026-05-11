//! Embedded forensic ledger (Layer 4, OSS edition).
//!
//! Single SQLite file with the same SHA-256 hash chain shape as the full
//! `warden-ledger`. A chain produced here is byte-compatible with the
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
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Lite shares the chain format with the full edition; the constant
/// is duplicated here (rather than reaching into `warden-ledger`) so
/// Lite stays a single-binary, no-deps OSS edition. Keep it in sync
/// with `warden_ledger::CURRENT_CHAIN_VERSION` — the chains are
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
    /// Per-request correlation id surfaced in the `X-Warden-Correlation-Id`
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

/// V1 hash input. Identical layout to `warden_ledger::HashableEntryV1`
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

#[derive(Debug, Clone)]
pub struct ParkRequest {
    pub correlation_id: String,
    pub agent_id: String,
    pub tool_type: String,
    pub method: String,
    pub review_reasons: Vec<String>,
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
                write!(f, "invalid decision {:?}: expected \"allow\" or \"deny\"", d)
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
}

impl Ledger {
    /// Open (or create) a SQLite ledger at `path`. Use `":memory:"` to
    /// run an in-memory DB for tests. Creates the schema on first use.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Append one entry. Reads the latest seq + entry_hash, computes the
    /// new hash over the canonical body, inserts the row, returns the
    /// fully-populated entry. Same algorithm as
    /// `warden_ledger::append_entry`.
    pub async fn append(&self, req: LogRequest) -> rusqlite::Result<LedgerEntry> {
        let conn = self.conn.lock().await;

        // Look up latest entry to seed seq + prev_hash. Empty table →
        // seq=1, genesis prev_hash.
        let (next_seq, prev_hash): (i64, String) = conn
            .query_row(
                "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)? + 1, row.get::<_, String>(1)?)),
            )
            .unwrap_or((1, GENESIS_PREV_HASH.to_string()));

        let id = Uuid::new_v4();
        let timestamp = Utc::now();

        // Build a typed entry first; `recompute_for_version` then hashes
        // off the same view that `verify_chain` will read back from
        // disk. Single source of truth for both write and verify paths.
        let mut entry = LedgerEntry {
            id,
            timestamp,
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
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "null".to_string()));

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
        let review_reasons_json = serde_json::to_string(&req.review_reasons)
            .unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO pendings (correlation_id, agent_id, tool_type, method,
                                   review_reasons_json, requested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                req.correlation_id,
                req.agent_id,
                req.tool_type,
                req.method,
                review_reasons_json,
                requested_at.to_rfc3339(),
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
                        requested_at, decided_at, decision, decider_note
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
            rusqlite::params![
                decided_at.to_rfc3339(),
                decision,
                note,
                correlation_id,
            ],
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

    /// List pending rows, newest-requested first, filtered by decision
    /// state. `limit` caps the result set — partner-facing CLI defaults
    /// to 50, server caps at 500 so a misconfigured client can't
    /// exhaust memory ordering a million rows.
    pub async fn list_pendings(
        &self,
        filter: PendingFilter,
        limit: u32,
    ) -> rusqlite::Result<Vec<Pending>> {
        let conn = self.conn.lock().await;
        let where_clause = match filter {
            PendingFilter::Parked => "WHERE decided_at IS NULL",
            PendingFilter::Decided => "WHERE decided_at IS NOT NULL",
            PendingFilter::All => "",
        };
        let sql = format!(
            "SELECT correlation_id, agent_id, tool_type, method, review_reasons_json,
                    requested_at, decided_at, decision, decider_note
             FROM pendings {} ORDER BY requested_at DESC LIMIT ?1",
            where_clause
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
                    requested_at, decided_at, decision, decider_note
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
            decider_note TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_pendings_decided_at ON pendings(decided_at);",
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
                rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
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
            ledger.append(sample(&format!("agent-{}", i), true)).await.unwrap();
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
            conn.execute(
                "UPDATE entries SET chain_version = 99 WHERE seq = 1",
                [],
            )
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
            })
            .await
            .unwrap();
        assert_eq!(parked.correlation_id, "abc-123");
        assert!(parked.decided_at.is_none());
        assert!(parked.decision.is_none());

        let fetched = ledger.get_pending("abc-123").await.unwrap().unwrap();
        assert_eq!(fetched.agent_id, "agent-1");
        assert_eq!(fetched.tool_type, "transfer_funds");
        assert_eq!(fetched.review_reasons, vec!["Wire transfers require approval"]);
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
}
