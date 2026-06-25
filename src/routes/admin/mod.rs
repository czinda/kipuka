//! Admin API router with separate authentication.
//!
//! The admin interface is independent of the EST enrollment endpoints
//! and uses its own authentication (Bearer token, admin mTLS, or GSSAPI).
//!
//! Admin endpoints provide:
//! - OTP management for EST enrollment
//! - CA health monitoring and management
//! - Certificate listing and revocation
//! - System health checks

pub mod cas;
pub mod certs;
pub mod health;
pub mod otp;

use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};

use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Build the admin API sub-router.
///
/// All admin routes require admin authentication, which is separate
/// from the EST enrollment authentication.
///
/// # Route structure
///
/// ```text
/// /admin/
///     health           GET   — overall system health
///     health/db        GET   — database connectivity
///     health/hsm       GET   — HSM connectivity
///     health/ca        GET   — CA backend health
///     cas              GET   — list configured CAs
///     cas/{id}         GET   — CA details
///     cas/{id}/health  GET   — CA health check
///     otp/generate     POST  — generate new OTP
///     otp              GET   — list active OTPs
///     otp/{id}         DELETE — revoke OTP
///     certs            GET   — list issued certificates
///     certs/{serial}   GET   — certificate details
///     certs/{serial}/revoke POST — revoke certificate
/// ```
pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        // Health checks
        .route("/health", get(health::get_health))
        .route("/health/db", get(health::get_health_db))
        .route("/health/hsm", get(health::get_health_hsm))
        .route("/health/ca", get(health::get_health_ca))
        // CA management
        .route("/cas", get(cas::list_cas))
        .route("/cas/{id}", get(cas::get_ca))
        .route("/cas/{id}/health", get(cas::get_ca_health))
        // OTP management
        .route("/otp/generate", post(otp::generate_otp))
        .route("/otp", get(otp::list_otps))
        .route("/otp/{id}", delete(otp::revoke_otp))
        // Certificate management
        .route("/certs", get(certs::list_certs))
        .route("/certs/{serial}", get(certs::get_cert))
        .route("/certs/{serial}/revoke", post(certs::revoke_cert))
}

/// Authenticated admin context extracted from request headers.
///
/// Verifies admin credentials (Bearer token or admin mTLS) before
/// the handler runs.  On failure, returns 401 or 403.
///
/// This is intentionally simpler than Akamu's `OperatorContext` since
/// Kipuka's admin model is less complex (no RBAC roles yet).
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// The authenticated admin identity (username or cert subject).
    pub identity: String,
}

impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let _app = Arc::<AppState>::from_ref(state);

        // Check for Bearer token in the Authorization header.
        if let Some(auth_header) = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            && let Some(token) = auth_header.strip_prefix("Bearer ")
            && !token.is_empty()
        {
            // Validate against the configured admin bearer token.
            if let Some(ref admin_cfg) = _app.config.admin
                && let Some(ref configured_token) = admin_cfg.bearer_token
            {
                // Constant-time comparison to prevent timing attacks.
                // Do not pre-check lengths — ct_eq safely returns 0 for
                // mismatched lengths, and a length guard would leak the
                // configured token length via timing.
                let token_bytes = token.as_bytes();
                let configured_bytes = configured_token.as_bytes();
                if token_bytes.ct_eq(configured_bytes).into() {
                    return Ok(AdminAuth {
                        identity: "admin".to_string(),
                    });
                }
                // Token did not match — fall through to 401.
            }
            // No admin config or no bearer_token configured — reject Bearer auth.
        }

        // Check for admin mTLS client certificate.
        if let Some(cert) = parts.extensions.get::<crate::auth::mtls::PeerCertificate>()
            && !cert.0.is_empty()
        {
            // Validate the cert against the admin truststore
            // (separate from the EST truststore per RHELBU-3536 R18).
            if let Some(ref admin_cfg) = _app.config.admin {
                match validate_admin_cert(&cert.0, admin_cfg) {
                    Ok(identity) => {
                        return Ok(AdminAuth { identity });
                    }
                    Err(reason) => {
                        tracing::warn!(
                            reason = %reason,
                            "admin mTLS certificate validation failed"
                        );
                        return Err((
                            StatusCode::FORBIDDEN,
                            format!("admin mTLS validation failed: {reason}"),
                        )
                            .into_response());
                    }
                }
            }
            // No admin config — reject mTLS auth.
        }

        Err((
            StatusCode::UNAUTHORIZED,
            "admin authentication required: Bearer token or mTLS certificate",
        )
            .into_response())
    }
}

/// Validate an admin mTLS client certificate against the admin truststore.
///
/// RHELBU-3536 R18: the admin truststore is separate from the EST enrollment
/// truststore.  This function:
///
/// 1. Loads admin CA trust anchors from the configured PEM file.
/// 2. Verifies the client certificate signature chains to a trust anchor
///    using `synta_certificate::default_signature_verifier()`.
/// 3. Checks the client subject DN against `allowed_operators` patterns.
///
/// Returns the authenticated operator identity (subject DN) on success.
fn validate_admin_cert(
    client_cert_der: &[u8],
    admin_cfg: &crate::config::AdminConfig,
) -> Result<String, String> {
    use std::io::BufReader;
    use synta_certificate::SignatureVerifier;

    // 1. Parse the client certificate.
    let client_cert = synta_certificate::Certificate::from_der(client_cert_der)
        .map_err(|e| format!("failed to parse admin client certificate: {e}"))?;
    let client_dn = synta_certificate::format_dn(client_cert.tbs_certificate.subject.0);

    if client_dn.is_empty() || client_dn == "<invalid>" {
        return Err("admin client certificate has no valid subject DN".to_string());
    }

    // 2. Load admin CA trust anchors from the configured PEM file.
    let ca_file = admin_cfg
        .admin_ca_file
        .as_deref()
        .ok_or_else(|| "admin_ca_file not configured for mTLS validation".to_string())?;

    let pem_data = std::fs::read(ca_file)
        .map_err(|e| format!("cannot read admin CA file '{ca_file}': {e}"))?;

    let trust_certs_der: Vec<Vec<u8>> = {
        let mut reader = BufReader::new(&pem_data[..]);
        rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .map(|c| c.to_vec())
            .collect()
    };

    if trust_certs_der.is_empty() {
        return Err(format!("no CA certificates found in admin CA file '{ca_file}'"));
    }

    // 3. Verify the client certificate signature against trust anchors.
    //
    //    Extract the client cert's TBS and signature algorithm via
    //    `cert_byte_ranges()`, and the signature bits from the parsed
    //    `Certificate` struct.  Verify against each trust anchor's SPKI
    //    until one succeeds.
    let client_ranges = synta_certificate::cert_byte_ranges(client_cert_der)
        .ok_or_else(|| "failed to extract byte ranges from admin client certificate".to_string())?;

    let tbs_bytes = &client_cert_der[client_ranges.tbs.clone()];
    let sig_alg_bytes = &client_cert_der[client_ranges.signature_algorithm.clone()];
    let sig_bytes = client_cert.signature_value.as_bytes();

    let verifier = synta_certificate::default_signature_verifier();

    let mut verified = false;
    for anchor_der in &trust_certs_der {
        let anchor_ranges = match synta_certificate::cert_byte_ranges(anchor_der) {
            Some(r) => r,
            None => continue,
        };
        let anchor_spki = &anchor_der[anchor_ranges.subject_public_key_info.clone()];

        if verifier
            .verify_certificate_signature(tbs_bytes, sig_alg_bytes, sig_bytes, anchor_spki)
            .is_ok()
        {
            verified = true;
            break;
        }
    }

    if !verified {
        return Err(format!(
            "admin client certificate (subject: {client_dn}) does not chain \
             to any trust anchor in '{ca_file}'"
        ));
    }

    tracing::info!(
        subject = %client_dn,
        "admin mTLS certificate verified against admin truststore"
    );

    // 4. Check `allowed_operators` — client subject DN must match a pattern.
    if !admin_cfg.allowed_operators.is_empty() {
        let dn_lower = client_dn.to_lowercase();
        let matches = admin_cfg.allowed_operators.iter().any(|pattern| {
            let pat_lower = pattern.to_lowercase();
            // Support substring matching: the operator pattern can be a full DN
            // or a fragment (e.g., "admin@example.com", "CN=Admin").
            dn_lower.contains(&pat_lower)
        });

        if !matches {
            return Err(format!(
                "admin client DN '{client_dn}' does not match any allowed operator pattern"
            ));
        }

        tracing::debug!(
            subject = %client_dn,
            "admin operator identity matched allowed_operators"
        );
    }

    Ok(client_dn)
}
