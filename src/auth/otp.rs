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

use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
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
    let auth_header = parts
        .headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?;

    // Only handle Basic auth; Negotiate is handled by the GSSAPI module.
    let credentials_b64 = auth_header.strip_prefix("Basic ")?;

    let decoded = match base64::engine::general_purpose::STANDARD.decode(credentials_b64) {
        Ok(d) => d,
        Err(_) => {
            return Some(Err(
                (StatusCode::BAD_REQUEST, "malformed Basic auth encoding").into_response()
            ));
        }
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => {
            return Some(Err(
                (StatusCode::BAD_REQUEST, "Basic auth credentials are not valid UTF-8")
                    .into_response(),
            ));
        }
    };

    // RFC 7617 §2: username and password are separated by the first colon.
    let (entity_id, otp_value) = match credentials.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => {
            return Some(Err(
                (StatusCode::BAD_REQUEST, "malformed Basic auth credentials").into_response()
            ));
        }
    };

    if entity_id.is_empty() || otp_value.is_empty() {
        return Some(Err(
            (StatusCode::UNAUTHORIZED, "entity-id and OTP must not be empty").into_response()
        ));
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

            Some(Err(
                (StatusCode::UNAUTHORIZED, "OTP authentication failed").into_response()
            ))
        }
    }
}

/// Validate an OTP value against the configured backend.
///
/// On success, the OTP is atomically marked as consumed (usage count
/// incremented).  The OTP is rejected if:
///
/// - It does not exist for the given entity-id
/// - It has expired (past `ttl_seconds`)
/// - It has reached `max_usage` count
///
/// RHELBU-3536 R9: OTP tokens are single-use by default.  The admin
/// can configure `max_usage > 1` for retry scenarios.
async fn validate_otp(app: &Arc<AppState>, entity_id: &str, otp_value: &str) -> Result<(), String> {
    // Check that OTP authentication is enabled.
    let otp_config = &app.config.otp;
    if !otp_config.enabled {
        return Err("OTP authentication is not enabled".into());
    }

    // Look up the OTP in the database.
    // In a full implementation this calls into `kipuka_otp::validate_and_consume`.
    let _entity_id = entity_id;
    let _otp_value = otp_value;

    // TODO: Implement actual OTP lookup and consumption.
    //
    // The implementation should:
    // 1. Query the OTP store (DB or LDAP) for `entity_id`
    // 2. Verify the OTP value matches (constant-time comparison)
    // 3. Check expiry: `created_at + ttl_seconds > now`
    // 4. Check usage count: `usage_count < max_usage`
    // 5. Atomically increment `usage_count`
    // 6. Return Ok(()) on success
    //
    // kipuka_otp::OtpStore::validate_and_consume(entity_id, otp_value).await

    Err("OTP validation not yet implemented".into())
}
