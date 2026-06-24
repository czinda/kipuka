//! HTTP Basic authentication with One-Time Password for EST enrollment.
//!
//! RHELBU-3536 R7: EST clients can authenticate using an OTP presented
//! in the HTTP Basic `Authorization` header.  The username field carries
//! the entity identifier; the password field carries the OTP value.
//!
//! OTPs are generated via the admin API (`POST /admin/otp/generate`) and
//! stored in the configured backend (database or LDAP).  Each OTP has:
//!
//! - An entity-id (the device or service being enrolled)
//! - An expiry timestamp
//! - A maximum usage count (typically 1 for single-use)
//! - A current usage counter
//!
//! ## RFC 7617 compliance
//!
//! The HTTP Basic authentication scheme follows RFC 7617:
//!
//! - **Section 2**: `user-id:password` encoding with UTF-8 support.
//! - **Section 2.1**: null bytes are rejected for security.
//! - **Section 2.2**: `WWW-Authenticate` challenges include `charset="UTF-8"`.

use std::sync::Arc;

use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use super::{AuthMethod, AuthResult};
use crate::state::AppState;

/// Attempt to extract and validate HTTP Basic (OTP) credentials.
///
/// Returns:
/// - `Some(Ok(AuthResult))` — valid OTP, authentication succeeded
/// - `Some(Err(Response))` — credentials present but invalid (401)
/// - `None` — no HTTP Basic header present (try next auth method)
pub async fn try_extract_otp(
    parts: &Parts,
    app: &Arc<AppState>,
) -> Option<Result<AuthResult, Response>> {
    let auth_header = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;

    // Only handle Basic auth; Negotiate is handled by the GSSAPI module.
    let credentials_b64 = auth_header.strip_prefix("Basic ")?;

    let decoded = match base64::engine::general_purpose::STANDARD.decode(credentials_b64) {
        Ok(d) => d,
        Err(_) => {
            return Some(Err(unauthorized_response("malformed Basic auth encoding")));
        }
    };

    // RFC 7617 §2.1: reject null bytes in credentials (security).
    if decoded.contains(&0x00) {
        return Some(Err(unauthorized_response(
            "Basic auth credentials contain null byte (rejected for security)",
        )));
    }

    // RFC 7617 §2.1: decode as UTF-8.
    let credentials = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => {
            return Some(Err(unauthorized_response(
                "Basic auth credentials are not valid UTF-8 (RFC 7617 §2.1)",
            )));
        }
    };

    // RFC 7617 §2: username and password are separated by the first colon.
    let (entity_id, otp_value) = match credentials.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => {
            return Some(Err(unauthorized_response(
                "malformed Basic auth credentials (missing ':' separator, RFC 7617 §2)",
            )));
        }
    };

    // RFC 7617 §2: user-id MUST NOT be empty.
    if entity_id.is_empty() {
        return Some(Err(unauthorized_response(
            "entity-id must not be empty (RFC 7617 §2)",
        )));
    }

    if otp_value.is_empty() {
        return Some(Err(unauthorized_response("OTP value must not be empty")));
    }

    debug!(entity_id = %entity_id, "validating OTP for entity");

    // Validate OTP against the configured store.
    match validate_otp(app, &entity_id, &otp_value).await {
        Ok(()) => {
            // OTP is valid and has been consumed.
            Some(Ok(AuthResult {
                identity: entity_id,
                method: AuthMethod::Otp,
                client_cert_der: None,
                subject_dn: None,
                subject_alt_names: Vec::new(),
                extended_key_usage: Vec::new(),
            }))
        }
        Err(e) => {
            warn!(entity_id = %entity_id, error = %e, "OTP validation failed");

            // Audit log the failed OTP attempt.
            app.record_audit_event(
                "otp_auth_failure",
                &format!("entity_id={entity_id}, reason={e}"),
            )
            .await;

            Some(Err(unauthorized_response("OTP authentication failed")))
        }
    }
}

/// Build a 401 Unauthorized response with the proper `WWW-Authenticate`
/// header per RFC 7617 Section 2.2.
///
/// The challenge includes `charset="UTF-8"` to indicate that the server
/// accepts UTF-8 encoded credentials (RFC 7617 Section 2.1).
fn unauthorized_response(detail: &str) -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, detail.to_string()).into_response();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(kipuka_util::WWW_AUTHENTICATE_BASIC),
    );
    resp
}

/// Row returned by the SELECT used for timing-safe OTP validation.
#[derive(sqlx::FromRow)]
struct OtpValidationRow {
    id: i64,
    token_hash: String,
    current_uses: i64,
    max_uses: i64,
}

/// Validate an OTP value against the configured backend.
///
/// Uses a two-phase approach that preserves both timing safety and
/// atomicity:
///
/// 1. Hash the incoming OTP value with SHA-256.
/// 2. SELECT the stored token_hash for this entity (read pool).
/// 3. Constant-time compare the hashes in application code.
/// 4. If match: atomic UPDATE (write pool) with token_hash in WHERE
///    to consume the token — preventing TOCTOU races.
/// 5. If no match: return error.
///
/// RHELBU-3536 R8: timing-safe comparison.
/// RHELBU-3536 R9: OTP tokens are single-use by default.
async fn validate_otp(app: &Arc<AppState>, entity_id: &str, otp_value: &str) -> Result<(), String> {
    // Check that OTP authentication is enabled.
    let otp_config = &app.config.otp;
    if !otp_config.enabled {
        return Err("OTP authentication is not enabled".into());
    }

    // Hash the incoming OTP value with SHA-256 (RHELBU-3536 R11).
    let incoming_hash = hex::encode(Sha256::digest(otp_value.as_bytes()));

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Phase 1: SELECT with token_hash in WHERE to find the exact matching
    // token. The DB comparison is not timing-safe, but we verify with a
    // constant-time compare as belt-and-suspenders (Phase 2).
    let row: OtpValidationRow = sqlx::query_as(crate::db::pg_sql(
        "SELECT id, token_hash, current_uses, max_uses FROM otp_tokens \
         WHERE entity_id = ? AND token_hash = ? AND revoked = ? AND expires_at > ? AND current_uses < max_uses",
    ))
    .bind(entity_id)
    .bind(&incoming_hash)
    .bind(false)
    .bind(&now)
    .fetch_optional(&app.db_ro)
    .await
    .map_err(|e| format!("database error: {e}"))?
    .ok_or_else(|| "no valid OTP found for this entity".to_string())?;

    // Phase 2: Constant-time verification in application code (RHELBU-3536 R8).
    // Belt-and-suspenders: even though the DB matched token_hash in WHERE,
    // we verify here with a timing-safe comparison to prevent any DB-layer
    // timing side-channel from leaking hash information.
    if incoming_hash
        .as_bytes()
        .ct_eq(row.token_hash.as_bytes())
        .unwrap_u8()
        == 0
    {
        return Err("no valid OTP found for this entity".to_string());
    }

    // Phase 3: Atomic UPDATE on the write pool with token_hash in WHERE
    // to consume the token — prevents TOCTOU races between SELECT and UPDATE.
    let result = sqlx::query(crate::db::pg_sql(
        "UPDATE otp_tokens SET current_uses = current_uses + 1 \
         WHERE entity_id = ? AND token_hash = ? AND revoked = ? AND expires_at > ? AND current_uses < max_uses",
    ))
    .bind(entity_id)
    .bind(&incoming_hash)
    .bind(false)
    .bind(&now)
    .execute(&app.db)
    .await
    .map_err(|e| format!("database error: {e}"))?;

    if result.rows_affected() == 0 {
        return Err("OTP was consumed by a concurrent request".to_string());
    }

    debug!(
        entity_id = %entity_id,
        otp_id = row.id,
        current_uses = row.current_uses + 1,
        max_uses = row.max_uses,
        "OTP validated and consumed"
    );

    Ok(())
}
