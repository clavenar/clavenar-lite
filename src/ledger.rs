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
         CREATE INDEX IF NOT EXISTS idx_entries_correlation_id ON entries(correlation_id);",
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
