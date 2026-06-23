//! OTP management endpoints for the admin API.
//!
//! RHELBU-3536 R9: Administrators generate OTPs for EST enrollment
//! via the admin API.  Each OTP is bound to an entity-id and has
//! configurable expiry and usage limits.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::AdminAuth;
use crate::state::AppState;

/// Request body for `POST /admin/otp/generate`.
#[derive(Deserialize)]
pub struct GenerateOtpRequest {
    /// The entity identifier for which the OTP is valid.
    ///
    /// This is the device or service name that will present the OTP
    /// in the HTTP Basic `username` field during EST enrollment.
    pub entity_id: String,

    /// Optional override for OTP expiry (seconds from creation).
    /// Uses the global `[otp].ttl_seconds` when absent.
    pub ttl_seconds: Option<u64>,

    /// Optional override for maximum OTP usage count.
    /// Uses the global `[otp].max_usage` when absent.
    pub max_usage: Option<u32>,
}

/// Response for a successfully generated OTP.
#[derive(Serialize)]
pub struct OtpResponse {
    /// The generated OTP token value.
    ///
    /// This value is shown exactly once — it is not recoverable after
    /// this response.
    pub token: String,

    /// The entity identifier this OTP is bound to.
    pub entity_id: String,

    /// When the OTP expires (RFC 3339 timestamp).
    pub expires_at: String,

    /// Maximum number of times this OTP can be used.
    pub max_usage: u32,
}

/// OTP summary for listing.
#[derive(Serialize)]
pub struct OtpSummary {
    /// Opaque OTP identifier for management (not the OTP value).
    pub id: String,

    /// The entity identifier this OTP is bound to.
    pub entity_id: String,

    /// When the OTP expires (RFC 3339 timestamp).
    pub expires_at: String,

    /// Maximum allowed uses.
    pub max_usage: u32,

    /// How many times the OTP has been used so far.
    pub usage_count: u32,

    /// When the OTP was created (RFC 3339 timestamp).
    pub created_at: String,
}

/// `POST /admin/otp/generate` — Generate a new OTP.
///
/// RHELBU-3536 R9: Creates a new one-time password bound to the
/// specified entity identifier.
///
/// # Request
///
/// ```json
/// {
///   "entity_id": "device-001.example.com",
///   "ttl_seconds": 7200,
///   "max_usage": 1
/// }
/// ```
///
/// # Response
///
/// ```json
/// {
///   "token": "kE9x...",
///   "entity_id": "device-001.example.com",
///   "expires_at": "2026-06-22T20:00:00Z",
///   "max_usage": 1
/// }
/// ```
///
/// The `token` field contains the actual OTP value.  It is returned
/// exactly once and cannot be retrieved later.
pub async fn generate_otp(
    _admin: AdminAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<GenerateOtpRequest>,
) -> Response {
    let otp_config = &state.config.otp;

    // Check that OTP is enabled.
    if !otp_config.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "otp_disabled",
                "detail": "OTP authentication is not enabled in server configuration"
            })),
        )
            .into_response();
    }

    if req.entity_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_entity_id",
                "detail": "entity_id must not be empty"
            })),
        )
            .into_response();
    }

    let ttl = req.ttl_seconds.unwrap_or(otp_config.ttl_seconds);
    let max_usage = req.max_usage.unwrap_or(otp_config.max_usage);

    // Generate the OTP token.
    //
    // TODO: Generate a cryptographically random OTP with the configured
    // entropy bits via `kipuka_otp::generate`.
    //
    // let otp = kipuka_otp::generate(otp_config.entropy_bits)?;
    //
    // Store in the configured backend (DB or LDAP):
    // kipuka_otp::store::insert(&state.db, &req.entity_id, &otp, ttl, max_usage).await?;

    let _entropy_bits = otp_config.entropy_bits;
    let token = "placeholder-otp-token".to_string(); // Placeholder

    let expires_at = {
        let now = chrono::Utc::now();
        let expiry = now + chrono::Duration::seconds(ttl as i64);
        expiry.to_rfc3339()
    };

    // Audit log the OTP generation.
    state
        .record_audit_event("otp_generated", &format!("entity_id={}", req.entity_id))
        .await;

    (
        StatusCode::CREATED,
        Json(OtpResponse {
            token,
            entity_id: req.entity_id,
            expires_at,
            max_usage,
        }),
    )
        .into_response()
}

/// `GET /admin/otp` — List active OTPs.
///
/// Returns all non-expired, non-fully-consumed OTPs.  The actual OTP
/// token values are NOT included (they are one-time secrets shown only
/// at generation time).
pub async fn list_otps(_admin: AdminAuth, State(state): State<Arc<AppState>>) -> Response {
    if !state.config.otp.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "otp_disabled",
                "detail": "OTP authentication is not enabled"
            })),
        )
            .into_response();
    }

    // TODO: Query the OTP store for active (non-expired, non-consumed) OTPs.
    //
    // let otps = kipuka_otp::store::list_active(&state.db).await?;
    let otps: Vec<OtpSummary> = Vec::new(); // Placeholder

    (StatusCode::OK, Json(otps)).into_response()
}

/// `DELETE /admin/otp/{id}` — Revoke an OTP.
///
/// Immediately invalidates the specified OTP, preventing any further
/// enrollment attempts using it.
pub async fn revoke_otp(
    _admin: AdminAuth,
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if !state.config.otp.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "otp_disabled",
                "detail": "OTP authentication is not enabled"
            })),
        )
            .into_response();
    }

    // TODO: Delete or mark the OTP as revoked in the store.
    //
    // match kipuka_otp::store::revoke(&state.db, &id).await {
    //     Ok(true) => { /* deleted */ },
    //     Ok(false) => return (StatusCode::NOT_FOUND, "OTP not found").into_response(),
    //     Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    // }

    state
        .record_audit_event("otp_revoked", &format!("otp_id={id}"))
        .await;

    tracing::info!(otp_id = %id, "OTP revoked");

    StatusCode::NO_CONTENT.into_response()
}
