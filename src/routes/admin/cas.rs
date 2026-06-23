//! CA management endpoints for the admin API.
//!
//! Provides visibility into configured CA backends, their health status,
//! and key material metadata (without exposing private keys).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use super::AdminAuth;
use crate::state::AppState;

/// CA summary returned by `GET /admin/cas`.
#[derive(Serialize)]
pub struct CaSummary {
    /// Unique CA identifier.
    pub id: String,
    /// Whether this is the default CA.
    pub is_default: bool,
    /// Key type (e.g., "ec:P-256", "rsa:2048").
    pub key_type: String,
    /// Hash algorithm (e.g., "sha256").
    pub hash_algorithm: String,
    /// Default validity period in days.
    pub validity_days: u32,
    /// Health status from the HA subsystem.
    pub health: String,
    /// Whether the CA uses an HSM-backed key.
    pub hsm_backed: bool,
}

/// CA detail returned by `GET /admin/cas/{id}`.
#[derive(Serialize)]
pub struct CaDetail {
    #[serde(flatten)]
    pub summary: CaSummary,
    /// Subject CN of the CA certificate.
    pub subject_cn: String,
    /// CRL distribution point URL (if configured).
    pub crl_url: Option<String>,
    /// OCSP responder URL (if configured).
    pub ocsp_url: Option<String>,
    /// CA/B Forum compliance mode.
    pub cab_forum_compliant: bool,
}

/// `GET /admin/cas` — list all configured CAs with health status.
///
/// Returns an array of CA summaries including health status from the
/// HA subsystem.
pub async fn list_cas(
    _admin: AdminAuth,
    State(state): State<Arc<AppState>>,
) -> Response {
    let mut cas = Vec::new();

    for ca_config in &state.config.cas {
        // Determine health status from the HA pool if available.
        let health = state
            .ha_manager
            .as_ref()
            .and_then(|ha| {
                let ca_id = crate::ha::CaId(ca_config.id.clone());
                ha.pool()
                    .status_snapshot()
                    .get(&ca_id)
                    .map(|s| format!("{:?}", s.health))
            })
            .unwrap_or_else(|| "unknown".to_string());

        cas.push(CaSummary {
            id: ca_config.id.clone(),
            is_default: ca_config.is_default,
            key_type: ca_config.key_type.clone(),
            hash_algorithm: ca_config.hash_algorithm.clone(),
            validity_days: ca_config.validity_days,
            health,
            hsm_backed: ca_config.is_hsm_backed(),
        });
    }

    (StatusCode::OK, Json(cas)).into_response()
}

/// `GET /admin/cas/{id}` — CA details.
///
/// Returns detailed information about a specific CA, including
/// certificate metadata and configuration.
pub async fn get_ca(
    _admin: AdminAuth,
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let ca_config = match state.config.cas.iter().find(|c| c.id == id) {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, "CA not found").into_response(),
    };

    let health = state
        .ha_manager
        .as_ref()
        .and_then(|ha| {
            ha.pool()
                .status_snapshot()
                .get(&id)
                .map(|s| format!("{:?}", s.health))
        })
        .unwrap_or_else(|| "unknown".to_string());

    let detail = CaDetail {
        summary: CaSummary {
            id: ca_config.id.clone(),
            is_default: ca_config.is_default,
            key_type: ca_config.key_type.clone(),
            hash_algorithm: ca_config.hash_algorithm.clone(),
            validity_days: ca_config.validity_days,
            health,
            hsm_backed: ca_config.is_hsm_backed(),
        },
        subject_cn: ca_config.common_name.clone(),
        crl_url: ca_config.crl_url.clone(),
        ocsp_url: ca_config.ocsp_url.clone(),
        cab_forum_compliant: ca_config.cab_forum_compliant,
    };

    (StatusCode::OK, Json(detail)).into_response()
}

/// `GET /admin/cas/{id}/health` — CA health check.
///
/// Performs or retrieves an on-demand health check for the specified CA
/// backend.
pub async fn get_ca_health(
    _admin: AdminAuth,
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Verify the CA exists.
    if !state.config.cas.iter().any(|c| c.id == id) {
        return (StatusCode::NOT_FOUND, "CA not found").into_response();
    }

    let (health, latency_ms) = match state.ha_manager.as_ref() {
        Some(ha) => {
            let ca_id_key = crate::ha::CaId(id.clone());
            let snapshot = ha.pool().status_snapshot();
            match snapshot.get(&ca_id_key) {
                Some(status) => {
                    let health = format!("{:?}", status.health);
                    let latency = status.latency_ema_ms as u64;
                    (health, latency)
                }
                None => ("unknown".to_string(), 0),
            }
        }
        None => ("not_monitored".to_string(), 0),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ca_id": id,
            "health": health,
            "latency_ms": latency_ms,
        })),
    )
        .into_response()
}
