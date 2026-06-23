//! Authentication layer for the Kipuka EST server.
//!
//! RFC 7030 §3.2.3 defines several client authentication mechanisms for EST:
//!
//! - **mTLS** — client presents a certificate during the TLS handshake.
//! - **HTTP Basic (OTP)** — username=entity-id, password=one-time password.
//! - **HTTP Negotiate (GSSAPI)** — Kerberos/SPNEGO authentication.
//!
//! Each EST endpoint declares an authentication policy ([`AuthPolicy`]) that
//! the [`EstAuth`] extractor enforces before the handler runs.  Admin routes
//! use a separate authentication mechanism (see [`super::routes::admin`]).

pub mod gssapi;
pub mod mtls;
pub mod otp;

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::error::KipukaError;
use crate::state::AppState;

/// How a client authenticated to the EST server.
///
/// Stored in [`AuthResult`] so handlers can make authorization decisions
/// based on the authentication method used (e.g., `/simplereenroll`
/// requires mTLS, `/fullcmc` requires id-kp-cmcRA EKU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// mTLS client certificate presented during TLS handshake.
    Mtls,
    /// HTTP Basic authentication with a one-time password.
    Otp,
    /// GSSAPI/SPNEGO (Kerberos) via the `Authorization: Negotiate` header.
    Gssapi,
    /// No authentication (used for unauthenticated endpoints like `/cacerts`).
    None,
}

/// Result of a successful authentication.
///
/// Contains the authenticated identity, the method used, and any
/// attributes extracted from the credential (e.g., certificate subject,
/// SANs, EKU extensions).
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// The authenticated identity string.
    ///
    /// For mTLS: the certificate subject DN or SAN.
    /// For OTP: the entity-id from HTTP Basic username.
    /// For GSSAPI: the Kerberos principal name.
    pub identity: String,

    /// How the client authenticated.
    pub method: AuthMethod,

    /// DER-encoded client certificate (mTLS only).
    ///
    /// Available for POP linking validation in `/simpleenroll` and
    /// `/simplereenroll` handlers.
    pub client_cert_der: Option<Vec<u8>>,

    /// Subject DN from the client certificate (mTLS only).
    pub subject_dn: Option<String>,

    /// Subject Alternative Names from the client certificate (mTLS only).
    pub subject_alt_names: Vec<String>,

    /// Extended Key Usage OIDs from the client certificate (mTLS only).
    ///
    /// Used by `/fullcmc` to verify the signer holds id-kp-cmcRA
    /// (OID 1.3.6.1.5.5.7.3.28) per RHELBU-3536 R15.
    pub extended_key_usage: Vec<String>,
}

impl AuthResult {
    /// Create an unauthenticated result for endpoints that do not require auth.
    pub fn anonymous() -> Self {
        Self {
            identity: String::new(),
            method: AuthMethod::None,
            client_cert_der: None,
            subject_dn: None,
            subject_alt_names: Vec::new(),
            extended_key_usage: Vec::new(),
        }
    }

    /// Returns `true` if the client certificate carries the id-kp-cmcRA EKU.
    ///
    /// OID: 1.3.6.1.5.5.7.3.28 (RFC 6402 §2.10).
    pub fn has_cmc_ra_eku(&self) -> bool {
        const CMC_RA_OID: &str = "1.3.6.1.5.5.7.3.28";
        self.extended_key_usage.iter().any(|oid| oid == CMC_RA_OID)
    }
}

/// Authentication policy for an EST endpoint.
///
/// Determines which authentication methods are acceptable and whether
/// authentication is required at all.
#[derive(Debug, Clone)]
pub enum AuthPolicy {
    /// No authentication required (e.g., `/cacerts`, `/csrattrs`).
    None,
    /// At least one of the listed methods must succeed.
    AnyOf(Vec<AuthMethod>),
    /// A specific method is required (e.g., mTLS for `/simplereenroll`).
    Required(AuthMethod),
}

/// Axum extractor that authenticates EST requests.
///
/// Tries each configured authentication method in order:
/// 1. mTLS client certificate (from TLS session extensions)
/// 2. HTTP Basic (OTP)
/// 3. GSSAPI/SPNEGO (`Authorization: Negotiate`)
///
/// The extractor succeeds if the endpoint's [`AuthPolicy`] is satisfied.
/// On failure, returns an appropriate HTTP 401/403 response.
pub struct EstAuth(pub AuthResult);

impl<S> FromRequestParts<S> for EstAuth
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = Arc::<AppState>::from_ref(state);

        // Try mTLS first — the client certificate is available as a request extension
        // injected by the TLS accept loop.
        if let Some(auth) = mtls::try_extract_mtls(parts, &app).await {
            return Ok(EstAuth(auth));
        }

        // Try HTTP Basic (OTP) authentication.
        if let Some(result) = otp::try_extract_otp(parts, &app).await {
            match result {
                Ok(auth) => return Ok(EstAuth(auth)),
                Err(e) => return Err(e),
            }
        }

        // Try GSSAPI/SPNEGO authentication.
        if let Some(result) = gssapi::try_extract_gssapi(parts, &app).await {
            match result {
                Ok(auth) => return Ok(EstAuth(auth)),
                Err(e) => return Err(e),
            }
        }

        // No authentication method succeeded.
        Err(KipukaError::Auth("no valid credentials provided".into()).into_response())
    }
}

/// Axum extractor that allows unauthenticated access.
///
/// Used on endpoints like `/cacerts` and `/csrattrs` that do not require
/// authentication per RFC 7030 §4.1 and §4.5.  If credentials are
/// present they are validated; if absent, an anonymous result is returned.
pub struct OptionalAuth(pub AuthResult);

impl<S> FromRequestParts<S> for OptionalAuth
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = Arc::<AppState>::from_ref(state);

        // Try mTLS — if a client cert is present, validate it.
        if let Some(auth) = mtls::try_extract_mtls(parts, &app).await {
            return Ok(OptionalAuth(auth));
        }

        // No credentials — that is fine for optional-auth endpoints.
        Ok(OptionalAuth(AuthResult::anonymous()))
    }
}
