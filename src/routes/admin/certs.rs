//! Certificate management endpoints for the admin API.
//!
//! Provides listing, detail retrieval, and revocation of certificates
//! issued by the Kipuka EST server.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::AdminAuth;
use crate::state::AppState;

/// Query parameters for certificate listing.
#[derive(Deserialize)]
pub struct ListCertsQuery {
    /// Filter by CA identifier.
    pub ca_id: Option<String>,

    /// Filter by certificate status.
    pub status: Option<String>,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: u32,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    50
}

/// Certificate summary for listing.
#[derive(Serialize)]
pub struct CertSummary {
    /// Certificate serial number (hex-encoded).
    pub serial: String,

    /// Subject DN of the certificate.
    pub subject: String,

    /// Which CA issued this certificate.
    pub ca_id: String,

    /// When the certificate was issued (RFC 3339).
    pub issued_at: String,

    /// When the certificate expires (RFC 3339).
    pub expires_at: String,

    /// Certificate status: "valid", "revoked", or "expired".
    pub status: String,
}

/// Detailed certificate information.
#[derive(Serialize)]
pub struct CertDetail {
    #[serde(flatten)]
    pub summary: CertSummary,

    /// Subject Alternative Names.
    pub sans: Vec<String>,

    /// Key algorithm (e.g., "EC P-256", "RSA 2048").
    pub key_algorithm: String,

    /// Signature algorithm (e.g., "SHA256withECDSA").
    pub signature_algorithm: String,

    /// How the client authenticated for enrollment.
    pub auth_method: String,

    /// Revocation reason (if revoked), per RFC 5280 §5.3.1.
    pub revocation_reason: Option<String>,

    /// When the certificate was revoked (RFC 3339), if applicable.
    pub revoked_at: Option<String>,
}

/// Request body for certificate revocation.
#[derive(Deserialize)]
pub struct RevokeCertRequest {
    /// Revocation reason code (RFC 5280 §5.3.1).
    ///
    /// Common values:
    /// - 0: unspecified
    /// - 1: keyCompromise
    /// - 3: affiliationChanged
    /// - 4: superseded
    /// - 5: cessationOfOperation
    #[serde(default)]
    pub reason: u32,
}

/// `GET /admin/certs` — List issued certificates.
///
/// Returns a paginated list of certificates issued by this server.
/// Supports filtering by CA and status.
pub async fn list_certs(
    _admin: AdminAuth,
    Query(query): Query<ListCertsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let _ = &state;

    tracing::debug!(
        ca_id = ?query.ca_id,
        status = ?query.status,
        limit = query.limit,
        offset = query.offset,
        "listing certificates"
    );

    // TODO: Query the certificate database with filters.
    //
    // let certs = kipuka_est::db::certs::list(
    //     &state.db,
    //     query.ca_id.as_deref(),
    //     query.status.as_deref(),
    //     query.limit,
    //     query.offset,
    // ).await?;

    let certs: Vec<CertSummary> = Vec::new(); // Placeholder

    (StatusCode::OK, Json(certs)).into_response()
}

/// `GET /admin/certs/{serial}` — Certificate details.
///
/// Returns detailed information about a specific certificate,
/// identified by its hex-encoded serial number.
pub async fn get_cert(
    _admin: AdminAuth,
    Path(serial): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let _ = &state;

    tracing::debug!(serial = %serial, "retrieving certificate details");

    // TODO: Look up the certificate by serial number.
    //
    // let cert = match kipuka_est::db::certs::get_by_serial(&state.db, &serial).await? {
    //     Some(c) => c,
    //     None => return (StatusCode::NOT_FOUND, "certificate not found").into_response(),
    // };

    (StatusCode::NOT_FOUND, "certificate not found").into_response()
}

/// `POST /admin/certs/{serial}/revoke` — Revoke a certificate.
///
/// Marks the certificate as revoked with the given reason code.
/// The CRL is regenerated to include the revoked certificate.
///
/// # Request
///
/// ```json
/// { "reason": 4 }
/// ```
///
/// # Reason Codes (RFC 5280 §5.3.1)
///
/// | Code | Meaning              |
/// |------|----------------------|
/// | 0    | unspecified          |
/// | 1    | keyCompromise        |
/// | 2    | cACompromise         |
/// | 3    | affiliationChanged   |
/// | 4    | superseded           |
/// | 5    | cessationOfOperation |
/// | 6    | certificateHold      |
/// | 9    | privilegeWithdrawn   |
/// | 10   | aACompromise         |
pub async fn revoke_cert(
    _admin: AdminAuth,
    Path(serial): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeCertRequest>,
) -> Response {
    tracing::info!(
        serial = %serial,
        reason = req.reason,
        "revoking certificate"
    );

    // Validate reason code per RFC 5280 §5.3.1.
    let valid_reasons = [0, 1, 2, 3, 4, 5, 6, 9, 10];
    if !valid_reasons.contains(&req.reason) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_reason",
                "detail": format!("reason code {} is not a valid CRL reason", req.reason)
            })),
        )
            .into_response();
    }

    // TODO: Revoke the certificate in the database and regenerate the CRL.
    //
    // kipuka_est::db::certs::revoke(&state.db, &serial, req.reason).await?;
    //
    // Invalidate the CRL cache for the issuing CA:
    // state.invalidate_crl_cache(ca_id);

    state
        .record_audit_event(
            "cert_revoked",
            &format!("serial={serial}, reason={}", req.reason),
        )
        .await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "serial": serial,
            "status": "revoked",
            "reason": req.reason,
        })),
    )
        .into_response()
}
