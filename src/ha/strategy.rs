//! Failover strategy implementations (RHELBU-3536 R3).
//!
//! Each strategy defines how the [`super::pool::CaPool`] selects a CA
//! backend for an incoming enrollment request.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use super::pool::{CaConnection, CaStatus};

/// Strategy for selecting a CA backend (RHELBU-3536 R3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverStrategy {
    /// Ordered priority list; always prefer the highest-priority healthy CA.
    /// Falls back to the next CA only when the preferred one is unavailable.
    ActivePassive,

    /// Distribute requests evenly across all healthy CAs using a
    /// round-robin counter.
    RoundRobin,

    /// Distribute requests proportionally to configured weights.
    /// For example, weights [70, 30] route ~70% of traffic to the first CA.
    Weighted,

    /// Prefer the CA with the lowest recent response latency (exponential
    /// moving average). Automatically adapts to changing network conditions.
    LatencyBased,
}

/// Behavior when no CA is available (RHELBU-3536 R6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackBehavior {
    /// Reject the request immediately with HTTP 503.
    Reject,
    /// Queue the request and retry when a CA recovers.
    /// Not yet implemented; falls back to rejection.
    QueueAndRetry,
}

/// Selects a CA backend according to the configured strategy.
pub struct StrategySelector {
    strategy: FailoverStrategy,
    /// Round-robin counter (used only by `RoundRobin` strategy).
    rr_counter: AtomicUsize,
}

impl StrategySelector {
    /// Create a selector for the given strategy.
    pub fn new(strategy: FailoverStrategy) -> Self {
        Self {
            strategy,
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Choose a CA from the available (healthy) candidates.
    ///
    /// `candidates` must be non-empty; the caller filters out unhealthy CAs
    /// before invoking this method.
    pub fn select(&self, candidates: &[(&CaConnection, &CaStatus)]) -> Option<CaConnection> {
        if candidates.is_empty() {
            return None;
        }

        match &self.strategy {
            FailoverStrategy::ActivePassive => self.select_active_passive(candidates),
            FailoverStrategy::RoundRobin => self.select_round_robin(candidates),
            FailoverStrategy::Weighted => self.select_weighted(candidates),
            FailoverStrategy::LatencyBased => self.select_latency_based(candidates),
        }
    }

    /// Active-passive: return the candidate with the lowest priority number
    /// (highest priority).
    fn select_active_passive(
        &self,
        candidates: &[(&CaConnection, &CaStatus)],
    ) -> Option<CaConnection> {
        candidates
            .iter()
            .min_by_key(|(conn, _)| conn.priority)
            .map(|(conn, _)| (*conn).clone())
    }

    /// Round-robin: cycle through candidates sequentially.
    fn select_round_robin(
        &self,
        candidates: &[(&CaConnection, &CaStatus)],
    ) -> Option<CaConnection> {
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates.get(idx).map(|(conn, _)| (*conn).clone())
    }

    /// Weighted: select proportionally to configured weights using a
    /// simple weighted random approach.
    ///
    /// Uses a deterministic modular approach against the round-robin
    /// counter for reproducibility without requiring `rand` in this module.
    fn select_weighted(&self, candidates: &[(&CaConnection, &CaStatus)]) -> Option<CaConnection> {
        let total_weight: u32 = candidates.iter().map(|(c, _)| c.weight).sum();
        if total_weight == 0 {
            return self.select_round_robin(candidates);
        }

        let tick = self.rr_counter.fetch_add(1, Ordering::Relaxed) as u32 % total_weight;
        let mut cumulative = 0u32;
        for (conn, _) in candidates {
            cumulative += conn.weight;
            if tick < cumulative {
                return Some((*conn).clone());
            }
        }

        // Fallback (should not be reached).
        candidates.last().map(|(c, _)| (*c).clone())
    }

    /// Latency-based: return the candidate with the lowest latency EMA.
    fn select_latency_based(
        &self,
        candidates: &[(&CaConnection, &CaStatus)],
    ) -> Option<CaConnection> {
        candidates
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.latency_ema_ms
                    .partial_cmp(&b.latency_ema_ms)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(conn, _)| (*conn).clone())
    }
}
