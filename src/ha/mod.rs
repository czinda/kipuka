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
    pub async fn start(&self) -> tokio::task::JoinHandle<()> {
        let checker = self.health_checker.clone();
        let mut rx = self.shutdown_rx.clone();

        info!("HA manager starting health check loop");

        tokio::spawn(async move {
            loop {
                if *rx.borrow() {
                    break;
                }
                checker.run_probes().await;

                tokio::select! {
                    _ = tokio::time::sleep(checker.interval()) => {}
                    _ = rx.changed() => {
                        info!("HA manager received shutdown signal");
                        break;
                    }
                }
            }
        })
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

/// Build explicitly configured HA routing and probes before server startup.
pub fn build_manager(
    config: Arc<crate::config::Config>,
    cas: Arc<indexmap::IndexMap<String, Arc<crate::state::CaState>>>,
    hsm: Option<Arc<kipuka_hsm::HsmContext>>,
) -> Option<Arc<HaManager>> {
    let ha = config.ha.as_ref().filter(|ha| ha.enabled)?;
    let connections = config
        .cas
        .iter()
        .enumerate()
        .map(|(priority, ca)| CaConnection {
            id: CaId(ca.id.clone()),
            endpoint: ha
                .endpoints
                .get(&ca.id)
                .cloned()
                .unwrap_or_else(|| format!("local:{}", ca.id)),
            weight: 1,
            priority: priority as u32,
        })
        .collect();
    let pool = Arc::new(CaPool::new(
        connections,
        pool::PoolConfig {
            strategy: ha.strategy.clone(),
            fallback: FallbackBehavior::Reject,
            circuit_breaker: pool::CircuitBreakerConfig {
                failure_threshold: ha.failure_threshold,
                cooldown: std::time::Duration::from_secs(ha.cooldown_secs),
            },
        },
    ));
    let health_config = HealthConfig {
        probe_interval: std::time::Duration::from_secs(ha.probe_interval_secs),
        probe_timeout: std::time::Duration::from_secs(ha.probe_timeout_secs),
        ..HealthConfig::default()
    };
    let mut manager = HaManager::new(pool, health_config);
    manager.health_checker = manager
        .health_checker
        .with_local(Arc::new(health::LocalProbeContext { config, cas, hsm }));
    Some(Arc::new(manager))
}
