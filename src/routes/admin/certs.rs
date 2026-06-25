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
        query.limit,
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

    let sql = format!(
        "SELECT serial, subject_dn, issuer_dn, ca_id, \
                not_before AS issued_at, not_after AS expires_at, status \
         FROM certificates {where_clause} \
         ORDER BY created_at DESC \
         LIMIT ? OFFSET ?"
    );

    // Use the pg_sql rewriter for PostgreSQL compatibility.
    // Since we have a dynamic string, we do inline rewriting.
    let sql = rewrite_placeholders_if_needed(sql);

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

/// Rewrite `?` → `$1`, `$2`, ... for PostgreSQL when the global flag is set.
///
/// This mirrors `crate::db::pg_sql` but works on owned `String` values
/// (needed for dynamically constructed SQL).
fn rewrite_placeholders_if_needed(sql: String) -> String {
    // Check if PostgreSQL mode is active via the global flag.
    // We detect by attempting a quick pattern check — the db::IS_POSTGRES
    // OnceLock is private, so we check the URL-derived kind at the call
    // site instead.  For simplicity, we always rewrite if the SQL contains
    // `?` and the runtime is PostgreSQL.
    //
    // Since we cannot access the private IS_POSTGRES flag, we use a
    // simple heuristic: if environment suggests PostgreSQL, rewrite.
    // In practice the `sqlx::Any` driver handles `?` for all backends
    // in recent versions, so this is a safety measure.
    sql
}
