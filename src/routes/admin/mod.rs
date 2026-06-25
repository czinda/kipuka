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
                let token_bytes = token.as_bytes();
                let configured_bytes = configured_token.as_bytes();
                if token_bytes.len() == configured_bytes.len()
                    && token_bytes.ct_eq(configured_bytes).into()
                {
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
            // TODO: Validate the cert against the admin truststore
            // (separate from the EST truststore per RHELBU-3536 R18).
            return Ok(AdminAuth {
                identity: "admin-cert".to_string(),
            });
        }

        Err((
            StatusCode::UNAUTHORIZED,
            "admin authentication required: Bearer token or mTLS certificate",
        )
            .into_response())
    }
}
