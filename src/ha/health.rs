//! Periodic health probing with state machine transitions.
//!
//! Implements RHELBU-3536 R4: health state machine
//! `Healthy -> Degraded -> Unavailable -> Recovering -> Healthy`
//! with configurable probe intervals and alert generation via audit log.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::pool::{CaId, CaPool};

/// Health state of a single CA backend (RHELBU-3536 R4).
///
/// Transitions follow the state machine:
/// ```text
/// Healthy -> Degraded -> Unavailable -> Recovering -> Healthy
///                ^                          |
///                +---- (probe failure) ------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    /// CA is responding normally within latency thresholds.
    Healthy,
    /// CA is responding but with elevated latency or intermittent errors.
    Degraded,
    /// CA is not responding; circuit breaker is open.
    Unavailable,
    /// CA was unavailable and is being re-probed after cooldown.
    Recovering,
}

impl HealthState {
    /// Whether this state allows routing requests to the CA.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Recovering)
    }
}

/// Configuration for the health checker.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between probe rounds (default: 30 seconds).
    pub probe_interval: Duration,
    /// Timeout for a single probe request.
    pub probe_timeout: Duration,
    /// Number of consecutive successes required to transition from
    /// `Recovering` back to `Healthy`.
    pub recovery_threshold: u32,
    /// Latency threshold (ms) above which a CA is considered degraded.
    pub degraded_latency_ms: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(5),
            recovery_threshold: 2,
            degraded_latency_ms: 2000,
        }
    }
}

/// Per-CA probe metrics tracked between probe rounds.
#[derive(Debug, Clone)]
pub struct ProbeMetrics {
    /// Timestamp of the last completed probe.
    pub last_check: Option<Instant>,
    /// Number of consecutive probe failures.
    pub consecutive_failures: u32,
    /// Number of consecutive probe successes (used during recovery).
    pub consecutive_successes: u32,
    /// Last observed response latency.
    pub last_latency: Option<Duration>,
}

impl ProbeMetrics {
    fn new() -> Self {
        Self {
            last_check: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_latency: None,
        }
    }
}

/// Runs periodic health probes against each CA backend.
///
/// The checker is cloneable (behind `Arc`) and designed to run in a
/// background tokio task managed by [`super::HaManager`].
#[derive(Clone)]
pub struct HealthChecker {
    pool: Arc<CaPool>,
    config: HealthConfig,
    /// Per-CA probe metrics, keyed by CaId.
    metrics: Arc<parking_lot::RwLock<std::collections::HashMap<CaId, ProbeMetrics>>>,
}

impl HealthChecker {
    /// Create a new health checker for the given pool.
    pub fn new(pool: Arc<CaPool>, config: HealthConfig) -> Self {
        let mut metrics = std::collections::HashMap::new();
        for conn in pool.connections() {
            metrics.insert(conn.id.clone(), ProbeMetrics::new());
        }

        Self {
            pool,
            config,
            metrics: Arc::new(parking_lot::RwLock::new(metrics)),
        }
    }

    /// Configured probe interval.
    pub fn interval(&self) -> Duration {
        self.config.probe_interval
    }

    /// Execute one round of probes against all registered CAs.
    pub async fn run_probes(&self) {
        debug!("starting health probe round");

        for conn in self.pool.connections() {
            let start = Instant::now();
            let result = self.probe_ca(&conn.id).await;
            let elapsed = start.elapsed();

            let mut metrics = self.metrics.write();
            let m = metrics
                .entry(conn.id.clone())
                .or_insert_with(ProbeMetrics::new);
            m.last_check = Some(Instant::now());
            m.last_latency = Some(elapsed);

            match result {
                Ok(()) => self.handle_probe_success(&conn.id, elapsed, m),
                Err(e) => self.handle_probe_failure(&conn.id, e, m),
            }
        }
    }

    /// Probe a single CA backend.
    ///
    /// In a full implementation this would issue an HTTP request to the
    /// CA's health endpoint or attempt a lightweight certificate status
    /// check. For now it checks whether the pool considers the CA should
    /// be re-probed after a circuit-breaker cooldown.
    async fn probe_ca(&self, id: &CaId) -> Result<(), String> {
        // If the CA is unavailable, check whether cooldown has elapsed.
        if self.pool.should_reprobe(id) {
            debug!(ca = %id, "cooldown elapsed, attempting re-probe");
            // TODO: issue actual health-check request to the CA endpoint.
            // For now, simulate success for circuit-breaker demonstration.
            return Ok(());
        }

        // TODO: implement actual health probe (HTTP GET to CA status endpoint,
        // or lightweight certificate issuance test).
        // Placeholder: always succeed for healthy/degraded CAs.
        Ok(())
    }

    /// Handle a successful probe, applying state transitions.
    fn handle_probe_success(&self, id: &CaId, latency: Duration, metrics: &mut ProbeMetrics) {
        metrics.consecutive_failures = 0;
        metrics.consecutive_successes += 1;

        let current_snapshot = self.pool.status_snapshot();
        let current_health = current_snapshot
            .get(id)
            .map(|s| s.health.clone())
            .unwrap_or(HealthState::Healthy);

        let latency_ms = latency.as_millis() as u64;

        let new_state = match current_health {
            HealthState::Unavailable => {
                info!(ca = %id, "CA responding again, entering recovery");
                metrics.consecutive_successes = 1;
                HealthState::Recovering
            }
            HealthState::Recovering => {
                if metrics.consecutive_successes >= self.config.recovery_threshold {
                    info!(ca = %id, "CA recovery confirmed, marking healthy");
                    HealthState::Healthy
                } else {
                    debug!(
                        ca = %id,
                        successes = metrics.consecutive_successes,
                        needed = self.config.recovery_threshold,
                        "CA still recovering"
                    );
                    HealthState::Recovering
                }
            }
            HealthState::Degraded | HealthState::Healthy => {
                if latency_ms > self.config.degraded_latency_ms {
                    debug!(ca = %id, latency_ms, "CA responding slowly, marking degraded");
                    HealthState::Degraded
                } else {
                    HealthState::Healthy
                }
            }
        };

        self.pool.set_health(id, new_state);
        self.pool.record_success(id, latency);
    }

    /// Handle a failed probe, applying state transitions.
    fn handle_probe_failure(&self, id: &CaId, error: String, metrics: &mut ProbeMetrics) {
        metrics.consecutive_failures += 1;
        metrics.consecutive_successes = 0;

        warn!(
            ca = %id,
            failures = metrics.consecutive_failures,
            error = %error,
            "health probe failed"
        );

        self.pool.record_failure(id);
    }

    /// Snapshot of probe metrics for monitoring.
    pub fn metrics_snapshot(&self) -> std::collections::HashMap<CaId, ProbeMetrics> {
        self.metrics.read().clone()
    }
}
