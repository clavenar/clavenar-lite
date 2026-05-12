//! Per-agent token-bucket rate limiting at `/mcp` ingress.
//!
//! Wire shape: a request that exceeds its agent's bucket is denied
//! with HTTP 429 + a JSON body carrying `error`, `retry_after_secs`,
//! and `correlation_id`. The denial emits a ledger row with
//! `intent_category = "RateLimitDenied"` so an auditor reading the
//! audit chain sees the throttle alongside Allow / Deny / Park.
//!
//! Lite is per-agent only — multi-tenant scoping is a full-stack
//! `warden-proxy` feature (it has SVID URIs to derive the tenant
//! segment from). For Lite, "per-agent" is the right axis because
//! `WARDEN_LITE_AGENTS` already partitions traffic by token.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_BUCKETS: usize = 10_000;
const IDLE_PRUNE_AFTER: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub qps: f64,
    pub burst: u32,
}

impl RateLimitConfig {
    pub fn disabled() -> Self {
        Self { qps: 0.0, burst: 0 }
    }

    pub fn is_enabled(&self) -> bool {
        self.qps > 0.0 && self.burst > 0
    }
}

#[derive(Debug, Clone)]
pub enum RateLimitOutcome {
    Allowed,
    Denied {
        agent_id: String,
        retry_after_secs: u64,
    },
}

#[derive(Debug)]
struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
    last_touch: Instant,
}

impl TokenBucket {
    fn new(cfg: RateLimitConfig, now: Instant) -> Self {
        let capacity = cfg.burst.max(1);
        Self {
            capacity,
            tokens: capacity as f64,
            refill_per_sec: cfg.qps,
            last_refill: now,
            last_touch: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let gained = elapsed * self.refill_per_sec;
        self.tokens = (self.tokens + gained).min(self.capacity as f64);
        self.last_refill = now;
    }

    fn try_consume(&mut self, now: Instant) -> Result<(), u64> {
        self.refill(now);
        self.last_touch = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            let seconds = if self.refill_per_sec > 0.0 {
                (deficit / self.refill_per_sec).ceil() as u64
            } else {
                1
            };
            Err(seconds.max(1))
        }
    }
}

pub struct RateLimiter {
    config: RateLimitConfig,
    inner: Mutex<HashMap<String, TokenBucket>>,
}

impl RateLimiter {
    pub fn from_config(config: RateLimitConfig) -> Option<Self> {
        if !config.is_enabled() {
            return None;
        }
        Some(Self {
            config,
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Try to consume one token for `agent_id`. Allowed if the bucket
    /// has at least one token; denied with `retry_after_secs` otherwise.
    pub fn check(&self, agent_id: &str) -> RateLimitOutcome {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("rate-limit map poisoned");
        maybe_prune(&mut guard, now);
        let bucket = guard
            .entry(agent_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.config, now));
        match bucket.try_consume(now) {
            Ok(()) => RateLimitOutcome::Allowed,
            Err(retry_after_secs) => RateLimitOutcome::Denied {
                agent_id: agent_id.to_string(),
                retry_after_secs,
            },
        }
    }
}

fn maybe_prune(map: &mut HashMap<String, TokenBucket>, now: Instant) {
    if map.len() < MAX_BUCKETS {
        return;
    }
    map.retain(|_, b| {
        let idle = now.saturating_duration_since(b.last_touch);
        let full = b.tokens >= b.capacity as f64;
        !(full && idle >= IDLE_PRUNE_AFTER)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(qps: f64, burst: u32) -> RateLimitConfig {
        RateLimitConfig { qps, burst }
    }

    #[test]
    fn allows_under_burst_then_denies() {
        let limiter = RateLimiter::from_config(cfg(1.0, 3)).unwrap();
        for _ in 0..3 {
            assert!(matches!(limiter.check("agent-a"), RateLimitOutcome::Allowed));
        }
        match limiter.check("agent-a") {
            RateLimitOutcome::Denied {
                ref agent_id,
                retry_after_secs,
            } => {
                assert_eq!(agent_id, "agent-a");
                assert!(retry_after_secs >= 1);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn agents_have_independent_buckets() {
        let limiter = RateLimiter::from_config(cfg(1.0, 1)).unwrap();
        assert!(matches!(limiter.check("agent-a"), RateLimitOutcome::Allowed));
        assert!(matches!(limiter.check("agent-a"), RateLimitOutcome::Denied { .. }));
        assert!(matches!(limiter.check("agent-b"), RateLimitOutcome::Allowed));
    }

    #[test]
    fn refill_restores_capacity() {
        let limiter = RateLimiter::from_config(cfg(100.0, 2)).unwrap();
        assert!(matches!(limiter.check("a"), RateLimitOutcome::Allowed));
        assert!(matches!(limiter.check("a"), RateLimitOutcome::Allowed));
        assert!(matches!(limiter.check("a"), RateLimitOutcome::Denied { .. }));
        std::thread::sleep(Duration::from_millis(50));
        assert!(matches!(limiter.check("a"), RateLimitOutcome::Allowed));
    }

    #[test]
    fn disabled_config_returns_none() {
        assert!(RateLimiter::from_config(RateLimitConfig::disabled()).is_none());
        assert!(RateLimiter::from_config(cfg(0.0, 5)).is_none());
        assert!(RateLimiter::from_config(cfg(5.0, 0)).is_none());
    }

    #[test]
    fn retry_after_floors_at_one_second() {
        let limiter = RateLimiter::from_config(cfg(1000.0, 1)).unwrap();
        assert!(matches!(limiter.check("a"), RateLimitOutcome::Allowed));
        match limiter.check("a") {
            RateLimitOutcome::Denied { retry_after_secs, .. } => {
                assert_eq!(retry_after_secs, 1);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
