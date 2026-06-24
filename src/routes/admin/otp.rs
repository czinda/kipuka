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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

    // Generate the OTP token with configured entropy.
    let entropy_bytes = (otp_config.entropy_bits / 8) as usize;
    let mut raw = vec![0u8; entropy_bytes];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(&raw);

    // Hash the token with SHA-256 before storing (RHELBU-3536 R11).
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

    let expires_at = {
        let now = chrono::Utc::now();
        let expiry = now + chrono::Duration::seconds(ttl as i64);
        expiry.to_rfc3339()
    };

    // Insert the hashed token into the database.
    let insert_result = sqlx::query(crate::db::pg_sql(
        "INSERT INTO otp_tokens (token_hash, entity_id, current_uses, max_uses, expires_at) \
         VALUES (?, ?, 0, ?, ?)",
    ))
    .bind(&token_hash)
    .bind(&req.entity_id)
    .bind(max_usage as i64)
    .bind(&expires_at)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_result {
        tracing::error!(error = %e, "failed to store OTP token");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "storage_error",
                "detail": "Failed to store OTP token"
            })),
        )
            .into_response();
    }

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

    let now = chrono::Utc::now().to_rfc3339();

    let rows: Vec<OtpRow> = match sqlx::query_as(crate::db::pg_sql(
        "SELECT id, entity_id, expires_at, max_uses, current_uses, created_at \
         FROM otp_tokens WHERE revoked = 0 AND expires_at > ?",
    ))
    .bind(&now)
    .fetch_all(&state.db_ro)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "failed to list OTP tokens");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "storage_error",
                    "detail": "Failed to query OTP tokens"
                })),
            )
                .into_response();
        }
    };

    let otps: Vec<OtpSummary> = rows
        .into_iter()
        .map(|r| OtpSummary {
            id: r.id.to_string(),
            entity_id: r.entity_id.unwrap_or_default(),
            expires_at: r.expires_at,
            max_usage: r.max_uses as u32,
            usage_count: r.current_uses as u32,
            created_at: r.created_at,
        })
        .collect();

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

    // Parse the ID as an integer for the database lookup.
    let otp_id: i64 = match id.parse() {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_id",
                    "detail": "OTP id must be a valid integer"
                })),
            )
                .into_response();
        }
    };

    let result = sqlx::query(crate::db::pg_sql("UPDATE otp_tokens SET revoked = 1 WHERE id = ?"))
        .bind(otp_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "detail": "OTP not found"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to revoke OTP");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "storage_error",
                    "detail": "Failed to revoke OTP"
                })),
            )
                .into_response();
        }
        _ => {}
    }

    state
        .record_audit_event("otp_revoked", &format!("otp_id={id}"))
        .await;

    tracing::info!(otp_id = %id, "OTP revoked");

    StatusCode::NO_CONTENT.into_response()
}

/// Internal row type for reading OTP records from the database.
#[derive(sqlx::FromRow)]
struct OtpRow {
    id: i64,
    entity_id: Option<String>,
    expires_at: String,
    max_uses: i64,
    current_uses: i64,
    created_at: String,
}
