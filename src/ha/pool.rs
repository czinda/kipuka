//! CA connection pool with circuit-breaker and priority weighting.
//!
//! Manages connections to multiple CA backends with per-CA health tracking.
//! Implements RHELBU-3536 R1 (multi-CA) and R2 (circuit breaker).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use super::health::HealthState;
use super::strategy::{FailoverStrategy, FallbackBehavior, StrategySelector};

/// Opaque identifier for a CA backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CaId(pub String);

impl std::fmt::Display for CaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::borrow::Borrow<str> for CaId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<String> for CaId {
    fn borrow(&self) -> &String {
        &self.0
    }
}

impl From<String> for CaId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for CaId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Runtime status of a single CA backend.
#[derive(Debug, Clone)]
pub struct CaStatus {
    /// Current health state from the health checker.
    pub health: HealthState,
    /// Number of consecutive probe failures.
    pub consecutive_failures: u32,
    /// Timestamp of the last successful probe.
    pub last_success: Option<Instant>,
    /// Timestamp when the circuit breaker tripped (CA marked unavailable).
    pub circuit_open_since: Option<Instant>,
    /// Recent response latency (exponential moving average in milliseconds).
    pub latency_ema_ms: f64,
    /// Last observed response latency (for admin display).
    pub last_latency: Option<Duration>,
}

impl CaStatus {
    fn new() -> Self {
        Self {
            health: HealthState::Healthy,
            consecutive_failures: 0,
            last_success: None,
            circuit_open_since: None,
            latency_ema_ms: 0.0,
            last_latency: None,
        }
    }
}

/// Registered CA backend with its configuration and connection info.
#[derive(Debug, Clone)]
pub struct CaConnection {
    /// Unique identifier.
    pub id: CaId,
    /// Base URL or endpoint for this CA.
    pub endpoint: String,
    /// Static priority weight (higher = preferred).
    pub weight: u32,
    /// Priority order for active-passive (lower = higher priority).
    pub priority: u32,
}

/// Circuit-breaker configuration (RHELBU-3536 R2).
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration to wait before re-probing an unavailable CA.
    pub cooldown: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            cooldown: Duration::from_secs(60),
        }
    }
}

/// Pool configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Failover strategy for CA selection.
    pub strategy: FailoverStrategy,
    /// Behavior when all CAs are unavailable.
    pub fallback: FallbackBehavior,
    /// Circuit-breaker settings.
    pub circuit_breaker: CircuitBreakerConfig,
}

/// Thread-safe pool of CA backend connections.
///
/// Routes enrollment requests to healthy CAs based on the configured
/// [`FailoverStrategy`]. The pool is updated by the [`super::health::HealthChecker`]
/// and read by request handlers concurrently.
pub struct CaPool {
    /// Registered CA backends (insertion-ordered by priority).
    connections: Vec<CaConnection>,
    /// Per-CA runtime status, protected by `RwLock` for concurrent reads.
    statuses: RwLock<HashMap<CaId, CaStatus>>,
    /// Pool configuration.
    config: PoolConfig,
    /// Strategy selector for CA routing.
    selector: StrategySelector,
}

impl CaPool {
    /// Create a new pool with the given backends and configuration.
    pub fn new(connections: Vec<CaConnection>, config: PoolConfig) -> Self {
        let mut statuses = HashMap::new();
        for conn in &connections {
            statuses.insert(conn.id.clone(), CaStatus::new());
        }
        let selector = StrategySelector::new(config.strategy.clone());

        Self {
            connections,
            statuses: RwLock::new(statuses),
            config,
            selector,
        }
    }

    /// Select the best available CA for an enrollment request.
    ///
    /// Returns `None` when no healthy CA is available and the fallback
    /// behavior is [`FallbackBehavior::Reject`].
    pub fn select(&self) -> Option<CaConnection> {
        let statuses = self.statuses.read();
        let healthy: Vec<&CaConnection> = self
            .connections
            .iter()
            .filter(|c| {
                statuses
                    .get(&c.id)
                    .map(|s| s.health.is_available())
                    .unwrap_or(false)
            })
            .collect();

        if healthy.is_empty() {
            warn!("no healthy CA backends available");
            return match self.config.fallback {
                FallbackBehavior::Reject => None,
                FallbackBehavior::QueueAndRetry => {
                    // In a full implementation this would enqueue the request.
                    // For now, return None and let the caller decide.
                    warn!("queue-and-retry fallback not yet implemented; rejecting");
                    None
                }
            };
        }

        let snapshot: Vec<(&CaConnection, &CaStatus)> = healthy
            .iter()
            .filter_map(|c| statuses.get(&c.id).map(|s| (*c, s)))
            .collect();

        self.selector.select(&snapshot)
    }

    /// Record a successful request to a CA, updating latency EMA.
    pub fn record_success(&self, id: &CaId, latency: Duration) {
        let mut statuses = self.statuses.write();
        if let Some(status) = statuses.get_mut(id) {
            status.consecutive_failures = 0;
            status.last_success = Some(Instant::now());
            status.circuit_open_since = None;
            status.last_latency = Some(latency);

            let ms = latency.as_secs_f64() * 1000.0;
            // Exponential moving average with alpha=0.3.
            status.latency_ema_ms = status.latency_ema_ms * 0.7 + ms * 0.3;

            if status.health != HealthState::Healthy {
                info!(ca = %id, "CA recovered, marking healthy");
                status.health = HealthState::Healthy;
            }
        }
    }

    /// Record a failed request, applying circuit-breaker logic (RHELBU-3536 R2).
    pub fn record_failure(&self, id: &CaId) {
        let mut statuses = self.statuses.write();
        if let Some(status) = statuses.get_mut(id) {
            status.consecutive_failures += 1;
            debug!(
                ca = %id,
                failures = status.consecutive_failures,
                "CA request failed"
            );

            if status.consecutive_failures >= self.config.circuit_breaker.failure_threshold {
                if status.health != HealthState::Unavailable {
                    warn!(
                        ca = %id,
                        failures = status.consecutive_failures,
                        "circuit breaker tripped, marking CA unavailable"
                    );
                    status.health = HealthState::Unavailable;
                    status.circuit_open_since = Some(Instant::now());
                }
            } else if status.health == HealthState::Healthy {
                status.health = HealthState::Degraded;
            }
        }
    }

    /// Check whether a tripped circuit breaker should allow a re-probe.
    pub fn should_reprobe(&self, id: &CaId) -> bool {
        let statuses = self.statuses.read();
        statuses.get(id).map_or(false, |s| {
            s.circuit_open_since.map_or(false, |opened| {
                opened.elapsed() >= self.config.circuit_breaker.cooldown
            })
        })
    }

    /// Update the health state for a CA (called by the health checker).
    pub fn set_health(&self, id: &CaId, state: HealthState) {
        let mut statuses = self.statuses.write();
        if let Some(status) = statuses.get_mut(id) {
            let prev = status.health.clone();
            status.health = state.clone();
            if prev != state {
                info!(ca = %id, from = ?prev, to = ?state, "CA health state transition");
            }
        }
    }

    /// Snapshot of current statuses for monitoring.
    pub fn status_snapshot(&self) -> HashMap<CaId, CaStatus> {
        self.statuses.read().clone()
    }

    /// All registered CA connections.
    pub fn connections(&self) -> &[CaConnection] {
        &self.connections
    }

    /// Pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }
}
