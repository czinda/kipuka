//! System health check endpoints for the admin API.
//!
//! Provides health probes for the overall system and individual
//! subsystems (database, HSM, CA backends).  These endpoints are
//! designed for monitoring systems (Kubernetes readiness probes,
//! Prometheus health checks, etc.).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::AdminAuth;
use crate::state::AppState;

/// Overall system health status.
#[derive(Serialize)]
pub struct SystemHealth {
    /// Overall status: "healthy", "degraded", or "unhealthy".
    pub status: String,

    /// Server uptime in seconds.
    pub uptime_secs: u64,

    /// Database health.
    pub database: SubsystemHealth,

    /// HSM health (if configured).
    pub hsm: Option<SubsystemHealth>,

    /// Number of configured CAs.
    pub ca_count: usize,

    /// Number of healthy CAs.
    pub healthy_ca_count: usize,

    /// Server version.
    pub version: String,
}

/// Health status of an individual subsystem.
#[derive(Serialize)]
pub struct SubsystemHealth {
    /// Subsystem name.
    pub name: String,

    /// Status: "healthy", "degraded", or "unhealthy".
    pub status: String,

    /// Optional detail message.
    pub detail: Option<String>,

    /// Response latency in milliseconds (if measured).
    pub latency_ms: Option<u64>,
}

/// `GET /admin/health` — Overall system health.
///
/// Returns the aggregate health of all subsystems.  The HTTP status
/// code reflects the overall health:
///
/// - `200 OK` — all subsystems healthy
/// - `503 Service Unavailable` — one or more critical subsystems unhealthy
pub async fn get_health(_admin: AdminAuth, State(state): State<Arc<AppState>>) -> Response {
    let uptime = state.startup_time.elapsed().as_secs();

    // Check database health.
    let db_health = check_database_health(&state).await;

    // Check HSM health (if configured).
    let hsm_health = if state.config.hsm.is_some() {
        Some(check_hsm_health(&state).await)
    } else {
        None
    };

    // Count healthy CAs.
    let ca_count = state.config.cas.len();
    let healthy_ca_count = state
        .ha_manager
        .as_ref()
        .map(|ha| {
            ha.pool()
                .status_snapshot()
                .into_values()
                .filter(|s| s.health.is_available())
                .count()
        })
        .unwrap_or(ca_count);

    // Determine overall status.
    let overall_status =
        if db_health.status == "unhealthy" || (healthy_ca_count == 0 && ca_count > 0) {
            "unhealthy"
        } else if db_health.status == "degraded" || healthy_ca_count < ca_count {
            "degraded"
        } else {
            "healthy"
        };

    let health = SystemHealth {
        status: overall_status.to_string(),
        uptime_secs: uptime,
        database: db_health,
        hsm: hsm_health,
        ca_count,
        healthy_ca_count,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let status_code = if overall_status == "unhealthy" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    state
        .record_audit_event(
            "admin_health_check",
            &format!("status={overall_status}"),
        )
        .await;

    (status_code, Json(health)).into_response()
}

/// `GET /admin/health/db` — Database connectivity check.
///
/// Performs a lightweight query to verify database connectivity.
pub async fn get_health_db(_admin: AdminAuth, State(state): State<Arc<AppState>>) -> Response {
    let health = check_database_health(&state).await;

    let status = if health.status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    state
        .record_audit_event(
            "admin_health_check",
            &format!("subsystem=database, status={}", health.status),
        )
        .await;

    (status, Json(health)).into_response()
}

/// `GET /admin/health/hsm` — HSM connectivity check.
///
/// Verifies that the configured HSM is reachable and the PKCS#11
/// session is active.
pub async fn get_health_hsm(_admin: AdminAuth, State(state): State<Arc<AppState>>) -> Response {
    if state.config.hsm.is_none() {
        return (
            StatusCode::OK,
            Json(SubsystemHealth {
                name: "hsm".to_string(),
                status: "not_configured".to_string(),
                detail: Some("no HSM is configured".to_string()),
                latency_ms: None,
            }),
        )
            .into_response();
    }

    let health = check_hsm_health(&state).await;
    let status = if health.status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    state
        .record_audit_event(
            "admin_health_check",
            &format!("subsystem=hsm, status={}", health.status),
        )
        .await;

    (status, Json(health)).into_response()
}

/// `GET /admin/health/ca` — CA backend health for all configured CAs.
///
/// Returns the health status of each configured CA backend from the
/// HA subsystem.
pub async fn get_health_ca(_admin: AdminAuth, State(state): State<Arc<AppState>>) -> Response {
    let mut ca_health: Vec<serde_json::Value> = Vec::new();

    for ca_config in &state.config.cas {
        let (health, latency_ms) = state
            .ha_manager
            .as_ref()
            .and_then(|ha| {
                let ca_id_key = crate::ha::CaId(ca_config.id.clone());
                ha.pool().status_snapshot().get(&ca_id_key).map(|s| {
                    let h = format!("{:?}", s.health);
                    let l = Some(s.latency_ema_ms as u64);
                    (h, l)
                })
            })
            .unwrap_or(("unknown".to_string(), None));

        ca_health.push(serde_json::json!({
            "ca_id": ca_config.id,
            "health": health,
            "latency_ms": latency_ms,
            "hsm_backed": ca_config.is_hsm_backed(),
        }));
    }

    state
        .record_audit_event(
            "admin_health_check",
            &format!("subsystem=ca, count={}", ca_health.len()),
        )
        .await;

    (StatusCode::OK, Json(ca_health)).into_response()
}

// ── Internal health check implementations ────────────────────────────────────

/// Check database connectivity with a lightweight query.
///
/// A 2-second timeout prevents a hung database connection from stalling
/// the health endpoint (and upstream readiness probes).
async fn check_database_health(state: &AppState) -> SubsystemHealth {
    let start = std::time::Instant::now();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query("SELECT 1").execute(&state.db),
    )
    .await;

    match result {
        Ok(Ok(_)) => {
            let latency = start.elapsed().as_millis() as u64;
            SubsystemHealth {
                name: "database".to_string(),
                status: "healthy".to_string(),
                detail: None,
                latency_ms: Some(latency),
            }
        }
        Ok(Err(e)) => {
            let latency = start.elapsed().as_millis() as u64;
            tracing::error!(error = %e, "database health check failed");
            SubsystemHealth {
                name: "database".to_string(),
                status: "unhealthy".to_string(),
                detail: Some(format!("database unreachable: {e}")),
                latency_ms: Some(latency),
            }
        }
        Err(_elapsed) => {
            let latency = start.elapsed().as_millis() as u64;
            tracing::error!("database health check timed out after 2s");
            SubsystemHealth {
                name: "database".to_string(),
                status: "unhealthy".to_string(),
                detail: Some("database health check timed out (2s)".to_string()),
                latency_ms: Some(latency),
            }
        }
    }
}

/// Check HSM connectivity by verifying the PKCS#11 session is active.
async fn check_hsm_health(state: &AppState) -> SubsystemHealth {
    let start = std::time::Instant::now();

    if let Some(ref hsm) = state.hsm {
        match hsm.health_check() {
            Ok(()) => {
                let latency = start.elapsed().as_millis() as u64;
                SubsystemHealth {
                    name: "hsm".to_string(),
                    status: "healthy".to_string(),
                    detail: Some("HSM session active".to_string()),
                    latency_ms: Some(latency),
                }
            }
            Err(e) => {
                let latency = start.elapsed().as_millis() as u64;
                tracing::error!(error = %e, "HSM health check failed");
                SubsystemHealth {
                    name: "hsm".to_string(),
                    status: "unhealthy".to_string(),
                    detail: Some(format!("HSM unreachable: {e}")),
                    latency_ms: Some(latency),
                }
            }
        }
    } else {
        SubsystemHealth {
            name: "hsm".to_string(),
            status: "not_configured".to_string(),
            detail: Some("no HSM context available".to_string()),
            latency_ms: None,
        }
    }
}
