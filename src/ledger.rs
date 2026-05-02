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
//!
//! # Rust idioms in this file
//!
//! * `Arc<Mutex<Connection>>` — same handle is shared between the proxy
//!   handler and any future background task. SQLite itself is fine with
//!   concurrent reads, but the rusqlite `Connection` is `!Sync`, so a
//!   mutex is the simplest safe-share path.
//! * `HashableEntry<'a>` with a lifetime — borrowed view used only long
//!   enough to be canonical-JSON-serialized + hashed. Same trick as the
//!   full edition's ledger; lets us hash without re-allocating every
//!   string.

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogRequest {
    pub agent_id: String,
    pub method: String,
    pub intent_category: String,
    pub authorized: bool,
    pub reasoning: String,
    pub policy_decision: Option<serde_json::Value>,
}

/// Body that participates in the hash. Field order here is the canonical
/// serialization order — do not reorder without bumping the chain
/// version. Identical layout to `warden_ledger::HashableEntry` so a
/// chain produced by Lite verifies under the full edition.
#[derive(Serialize)]
struct HashableEntry<'a> {
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

        let hashable = HashableEntry {
            id: &id,
            timestamp: &timestamp,
            agent_id: &req.agent_id,
            method: &req.method,
            intent_category: &req.intent_category,
            authorized: req.authorized,
            reasoning: &req.reasoning,
            policy_decision: &req.policy_decision,
            seq: next_seq,
            prev_hash: &prev_hash,
        };
        let entry_hash = compute_entry_hash(&hashable);

        let policy_decision_json = req
            .policy_decision
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "null".to_string()));

        conn.execute(
            "INSERT INTO entries (id, seq, timestamp, agent_id, method, intent_category,
                                  authorized, reasoning, policy_decision, prev_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                id.to_string(),
                next_seq,
                timestamp.to_rfc3339(),
                req.agent_id,
                req.method,
                req.intent_category,
                req.authorized as i64,
                req.reasoning,
                policy_decision_json,
                prev_hash,
                entry_hash,
            ],
        )?;

        Ok(LedgerEntry {
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
            entry_hash,
        })
    }

    /// Walk every entry in seq order, recompute each hash, and confirm
    /// it matches the stored `entry_hash`. The full edition's
    /// `verify_chain` does the same; both share the canonical-JSON order
    /// in `HashableEntry` so they cross-validate.
    pub async fn verify(&self) -> rusqlite::Result<VerifyResult> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, seq, timestamp, agent_id, method, intent_category, authorized,
                    reasoning, policy_decision, prev_hash, entry_hash
             FROM entries ORDER BY seq ASC",
        )?;
        let mut rows = stmt.query([])?;

        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        let mut count = 0usize;
        let mut first_invalid: Option<i64> = None;

        while let Some(row) = rows.next()? {
            let entry = row_to_entry(row)?;
            let policy_decision = entry.policy_decision.clone();
            let hashable = HashableEntry {
                id: &entry.id,
                timestamp: &entry.timestamp,
                agent_id: &entry.agent_id,
                method: &entry.method,
                intent_category: &entry.intent_category,
                authorized: entry.authorized,
                reasoning: &entry.reasoning,
                policy_decision: &policy_decision,
                seq: entry.seq,
                prev_hash: &entry.prev_hash,
            };
            let recomputed = compute_entry_hash(&hashable);
            count += 1;

            if entry.prev_hash != expected_prev || recomputed != entry.entry_hash {
                first_invalid = Some(entry.seq);
                break;
            }
            expected_prev = entry.entry_hash;
        }

        Ok(VerifyResult {
            valid: first_invalid.is_none(),
            entries_checked: count,
            first_invalid_seq: first_invalid,
        })
    }

    /// Return every entry for `agent_id`, in seq order. Used by `audit`
    /// CLI subcommand.
    pub async fn entries_for_agent(&self, agent_id: &str) -> rusqlite::Result<Vec<LedgerEntry>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, seq, timestamp, agent_id, method, intent_category, authorized,
                    reasoning, policy_decision, prev_hash, entry_hash
             FROM entries WHERE agent_id = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([agent_id], row_to_entry)?;
        rows.collect()
    }

    /// Total entries in the ledger. Used by the CLI `verify` summary.
    pub async fn count(&self) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().await;
        conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
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
            entry_hash TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_entries_agent_id ON entries(agent_id);
         CREATE INDEX IF NOT EXISTS idx_entries_seq ON entries(seq);",
    )
}

fn compute_entry_hash(hashable: &HashableEntry<'_>) -> String {
    let canonical = serde_json::to_vec(hashable).expect("HashableEntry always serializes");
    let mut hasher = Sha256::new();
    hasher.update(hashable.prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(&canonical);
    hex::encode(hasher.finalize())
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
