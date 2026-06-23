//! High-Availability subsystem for multi-CA failover.
//!
//! Implements RHELBU-3536 requirements R1 through R6:
//! - R1: Multiple CA backend support with independent health tracking
//! - R2: Circuit-breaker pattern with configurable cooldown
//! - R3: Pluggable failover strategies (active-passive, round-robin, weighted, latency)
//! - R4: Health probes with state machine transitions
//! - R5: Automatic failover on CA unavailability
//! - R6: Graceful degradation when all CAs are unhealthy

pub mod health;
pub mod pool;
pub mod strategy;

pub use health::{HealthChecker, HealthConfig, HealthState};
pub use pool::{CaConnection, CaId, CaPool, CaStatus};
pub use strategy::{FailoverStrategy, FallbackBehavior, StrategySelector};

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

/// Central coordinator for the HA subsystem.
///
/// Owns the [`CaPool`] and [`HealthChecker`], wiring health state updates
/// into pool availability decisions. The pool uses the configured
/// [`FailoverStrategy`] to select a CA for each enrollment request.
pub struct HaManager {
    pool: Arc<CaPool>,
    health_checker: HealthChecker,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl HaManager {
    /// Build a new HA manager from pool and health configuration.
    pub fn new(pool: Arc<CaPool>, health_config: HealthConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_checker = HealthChecker::new(Arc::clone(&pool), health_config);
        Self {
            pool,
            health_checker,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start background health checking.
    ///
    /// Spawns a tokio task that periodically probes each CA backend and
    /// updates the pool's availability map. The task runs until
    /// [`HaManager::shutdown`] is called.
    pub async fn start(&self) {
        let checker = self.health_checker.clone();
        let mut rx = self.shutdown_rx.clone();

        info!("HA manager starting health check loop");

        tokio::spawn(async move {
            loop {
                checker.run_probes().await;

                tokio::select! {
                    _ = tokio::time::sleep(checker.interval()) => {}
                    _ = rx.changed() => {
                        info!("HA manager received shutdown signal");
                        break;
                    }
                }
            }
        });
    }

    /// Signal the health checker to stop.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        warn!("HA manager shutting down");
    }

    /// Reference to the managed CA pool.
    pub fn pool(&self) -> &Arc<CaPool> {
        &self.pool
    }
}
