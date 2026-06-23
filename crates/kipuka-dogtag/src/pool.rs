//! Multi-CA connection pool with health-based routing.
//!
//! Manages [`DogtagClient`] instances for multiple Dogtag CA backends,
//! integrating with kipuka's HA subsystem (`src/ha/`) for failover and
//! load balancing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::client::DogtagClient;
use crate::config::DogtagConfig;
use crate::{DogtagError, DogtagResult};

/// Health state of a CA backend in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealth {
    /// Backend is responding to health checks.
    Healthy,
    /// Backend is not responding or returning errors.
    Unhealthy,
    /// Health state has not been determined yet.
    Unknown,
}

/// A single CA backend entry in the pool.
struct PoolEntry {
    /// The HTTP client for this CA instance.
    client: Arc<DogtagClient>,
    /// Current health state.
    health: BackendHealth,
    /// Timestamp of the last successful health check.
    last_healthy: Option<Instant>,
    /// Number of consecutive health check failures.
    consecutive_failures: u32,
}

/// Connection pool managing multiple Dogtag CA instances.
///
/// Routes enrollment and certificate operations to healthy CA backends.
/// Integrates with kipuka's HA subsystem for consistent failover behavior
/// across all CA backend types.
///
/// # Health Checking
///
/// The pool periodically probes each backend via `GET /ca/rest/info`.
/// Backends that fail consecutive health checks are marked unhealthy
/// and excluded from request routing until they recover.
///
/// # Thread Safety
///
/// `DogtagPool` is `Send + Sync` and designed to be shared via
/// `Arc<DogtagPool>` across the async runtime.
pub struct DogtagPool {
    entries: parking_lot::RwLock<Vec<PoolEntry>>,
    /// Circuit breaker threshold: mark unhealthy after this many failures.
    failure_threshold: u32,
    /// Cooldown before re-checking an unhealthy backend.
    cooldown: Duration,
}

impl DogtagPool {
    /// Create a pool from multiple Dogtag configurations.
    ///
    /// Each configuration represents a separate CA instance. The pool
    /// creates a [`DogtagClient`] for each and begins tracking health.
    pub fn new(
        configs: &[DogtagConfig],
        failure_threshold: u32,
        cooldown_secs: u64,
    ) -> DogtagResult<Self> {
        if configs.is_empty() {
            return Err(DogtagError::ConfigError(
                "At least one CA backend is required".into(),
            ));
        }

        let mut entries = Vec::with_capacity(configs.len());
        for config in configs {
            let client = Arc::new(DogtagClient::new(config)?);
            info!(url = client.base_url(), "Added Dogtag CA backend to pool");
            entries.push(PoolEntry {
                client,
                health: BackendHealth::Unknown,
                last_healthy: None,
                consecutive_failures: 0,
            });
        }

        Ok(Self {
            entries: parking_lot::RwLock::new(entries),
            failure_threshold,
            cooldown: Duration::from_secs(cooldown_secs),
        })
    }

    /// Get a healthy client from the pool.
    ///
    /// Returns the first healthy backend. If no backend is healthy,
    /// returns [`DogtagError::NoHealthyBackend`].
    pub fn get_client(&self) -> DogtagResult<Arc<DogtagClient>> {
        let entries = self.entries.read();
        for entry in entries.iter() {
            if entry.health != BackendHealth::Unhealthy {
                return Ok(Arc::clone(&entry.client));
            }
        }
        Err(DogtagError::NoHealthyBackend)
    }

    /// Run a single health check pass across all backends.
    ///
    /// Probes each backend via `GET /ca/rest/info` and updates health
    /// state. Unhealthy backends in cooldown are skipped.
    pub async fn health_check_all(&self) {
        // Snapshot the client list to avoid holding the lock during I/O.
        let clients: Vec<(usize, Arc<DogtagClient>, bool)> = {
            let entries = self.entries.read();
            entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    // Skip unhealthy backends still in cooldown.
                    if e.health == BackendHealth::Unhealthy {
                        if let Some(last) = e.last_healthy {
                            if last.elapsed() < self.cooldown {
                                return None;
                            }
                        }
                    }
                    Some((
                        i,
                        Arc::clone(&e.client),
                        e.health == BackendHealth::Unhealthy,
                    ))
                })
                .collect()
        };

        for (index, client, was_unhealthy) in clients {
            let healthy = client.health_check().await.unwrap_or(false);

            let mut entries = self.entries.write();
            if let Some(entry) = entries.get_mut(index) {
                if healthy {
                    if was_unhealthy {
                        info!(url = client.base_url(), "Dogtag CA backend recovered");
                    }
                    entry.health = BackendHealth::Healthy;
                    entry.last_healthy = Some(Instant::now());
                    entry.consecutive_failures = 0;
                } else {
                    entry.consecutive_failures += 1;
                    if entry.consecutive_failures >= self.failure_threshold {
                        if entry.health != BackendHealth::Unhealthy {
                            warn!(
                                url = client.base_url(),
                                failures = entry.consecutive_failures,
                                "Dogtag CA backend marked unhealthy"
                            );
                        }
                        entry.health = BackendHealth::Unhealthy;
                    }
                }
            }
        }
    }

    /// Return the number of backends currently considered healthy.
    pub fn healthy_count(&self) -> usize {
        self.entries
            .read()
            .iter()
            .filter(|e| e.health == BackendHealth::Healthy)
            .count()
    }

    /// Return the total number of backends in the pool.
    pub fn total_count(&self) -> usize {
        self.entries.read().len()
    }
}
