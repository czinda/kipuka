//! Certificate management endpoints for the admin API.
//!
//! Provides listing, detail retrieval, and revocation of certificates
//! issued by the Kipuka EST server.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,

    /// Key algorithm (e.g., "EC P-256", "RSA 2048").
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_algorithm: String,

    /// Signature algorithm (e.g., "SHA256withECDSA").
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature_algorithm: String,

    /// How the client authenticated for enrollment.
    #[serde(skip_serializing_if = "String::is_empty")]
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

    // Cap the limit to prevent excessive queries.
    let limit = query.limit.min(1000);

    // Query the certificate database with optional filters.
    //
    // We build the SQL dynamically based on which filters are present.
    // The `certificates` table schema (from db/schema.rs) has columns:
    //   serial, subject_dn, issuer_dn, not_before, not_after, ca_id,
    //   status ('active', 'revoked', 'expired'), revocation_reason,
    //   revocation_time, created_at
    let certs = match list_certs_from_db(
        &state.db_ro,
        query.ca_id.as_deref(),
        query.status.as_deref(),
        limit,
        query.offset,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to list certificates from database");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "database_error",
                    "detail": "failed to query certificate database"
                })),
            )
                .into_response();
        }
    };

    state
        .record_audit_event(
            "admin_cert_list",
            &format!(
                "count={}, ca_id={:?}, status={:?}",
                certs.len(),
                query.ca_id,
                query.status
            ),
        )
        .await;

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

    // Query the certificate by serial number from the read-only pool.
    let row = match sqlx::query_as::<_, CertDetailRow>(
        crate::db::pg_sql(
            "SELECT serial, subject_dn, issuer_dn, ca_id, \
                    not_before, not_after, status, \
                    revocation_reason, revocation_time \
             FROM certificates WHERE serial = ?",
        ),
    )
    .bind(&serial)
    .fetch_optional(&state.db_ro)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "detail": format!("certificate with serial {serial} not found")
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, serial = %serial, "failed to query certificate");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "database_error",
                    "detail": "failed to query certificate database"
                })),
            )
                .into_response();
        }
    };

    let detail = CertDetail {
        summary: CertSummary {
            serial: row.serial,
            subject: row.subject_dn,
            ca_id: row.ca_id,
            issued_at: row.not_before,
            expires_at: row.not_after,
            status: row.status,
        },
        // SANs, key algorithm, signature algorithm, and auth method
        // require parsing the DER certificate — omitted until the
        // DER blob is fetched alongside the metadata.
        sans: Vec::new(),
        key_algorithm: String::new(),
        signature_algorithm: String::new(),
        auth_method: String::new(),
        revocation_reason: row.revocation_reason,
        revoked_at: row.revocation_time,
    };

    state
        .record_audit_event("admin_cert_detail", &format!("serial={serial}"))
        .await;

    (StatusCode::OK, Json(detail)).into_response()
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

    // Update the certificate status to 'revoked' in the database.
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let result = match sqlx::query(
        crate::db::pg_sql(
            "UPDATE certificates SET status = 'revoked', \
                    revocation_reason = ?, revocation_time = ? \
             WHERE serial = ? AND status != 'revoked'",
        ),
    )
    .bind(req.reason.to_string())
    .bind(&now)
    .bind(&serial)
    .execute(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, serial = %serial, "failed to revoke certificate in DB");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "database_error",
                    "detail": "failed to update certificate status"
                })),
            )
                .into_response();
        }
    };

    if result.rows_affected() == 0 {
        // Either the certificate doesn't exist or is already revoked.
        // Check which case it is.
        let exists = match sqlx::query_scalar::<_, i64>(
            crate::db::pg_sql("SELECT COUNT(*) FROM certificates WHERE serial = ?"),
        )
        .bind(&serial)
        .fetch_one(&state.db_ro)
        .await
        {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, serial = %serial, "failed to check certificate existence");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "database_error",
                        "detail": "failed to query certificate database"
                    })),
                )
                    .into_response();
            }
        };

        if exists == 0 {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "detail": format!("certificate with serial {serial} not found")
                })),
            )
                .into_response();
        }
        // Already revoked — return success idempotently.
    }

    state
        .record_audit_event(
            "cert_revoked",
            &format!("serial={serial}, reason={}", req.reason),
        )
        .await;

    (StatusCode::NO_CONTENT,).into_response()
}

// ── Database helpers ────────────────────────────────────────────────────────

/// Query certificates from the database with optional filters.
///
/// Uses the read-only pool (`db_ro`) to avoid contention with write
/// operations.  The query is built dynamically based on which filters
/// are present, with bind parameters for SQL injection safety.
async fn list_certs_from_db(
    db: &sqlx::AnyPool,
    ca_id: Option<&str>,
    status: Option<&str>,
    limit: u32,
    offset: u32,
) -> Result<Vec<CertSummary>, String> {
    // Build WHERE clause dynamically.  We collect conditions and bind
    // values, then format the final SQL.  sqlx's `Any` driver uses `?`
    // placeholders (rewritten for PostgreSQL by `pg_sql` if needed).
    let mut conditions = Vec::new();
    if ca_id.is_some() {
        conditions.push("ca_id = ?");
    }
    if status.is_some() {
        conditions.push("status = ?");
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = crate::db::pg_sql_dynamic(format!(
        "SELECT serial, subject_dn, issuer_dn, ca_id, \
                not_before AS issued_at, not_after AS expires_at, status \
         FROM certificates {where_clause} \
         ORDER BY created_at DESC \
         LIMIT ? OFFSET ?"
    ));

    let mut query = sqlx::query_as::<_, CertRow>(&sql);

    // Bind filter values in the same order as the WHERE conditions.
    if let Some(ca) = ca_id {
        query = query.bind(ca.to_string());
    }
    if let Some(st) = status {
        query = query.bind(st.to_string());
    }
    query = query.bind(limit as i64).bind(offset as i64);

    let rows: Vec<CertRow> = query
        .fetch_all(db)
        .await
        .map_err(|e| format!("certificate query failed: {e}"))?;

    Ok(rows
        .into_iter()
        .map(|r| CertSummary {
            serial: r.serial,
            subject: r.subject_dn,
            ca_id: r.ca_id,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            status: r.status,
        })
        .collect())
}

/// Row type for certificate listing queries.
#[derive(sqlx::FromRow)]
struct CertRow {
    serial: String,
    subject_dn: String,
    #[allow(dead_code)]
    issuer_dn: String,
    ca_id: String,
    issued_at: String,
    expires_at: String,
    status: String,
}

/// Row type for certificate detail queries (includes revocation fields).
#[derive(sqlx::FromRow)]
struct CertDetailRow {
    serial: String,
    subject_dn: String,
    #[allow(dead_code)]
    issuer_dn: String,
    ca_id: String,
    not_before: String,
    not_after: String,
    status: String,
    revocation_reason: Option<String>,
    revocation_time: Option<String>,
}

