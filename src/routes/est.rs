//! EST operation router combining all RFC 7030 endpoints.
//!
//! Builds the sub-router for EST operations with:
//!
//! - Content-Type enforcement middleware (reject wrong content types per
//!   RFC 7030 §4)
//! - Base64 transfer encoding enforcement per RFC 8951
//! - Error response formatting per RFC 7030 §4.2.3

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::state::AppState;

use super::{cacerts, csrattrs, fullcmc, serverkeygen, simpleenroll, simplereenroll};

/// Build the EST sub-router with all RFC 7030 operation endpoints.
///
/// Each endpoint enforces its own authentication policy via the
/// [`crate::auth::EstAuth`] or [`crate::auth::OptionalAuth`] extractor.
///
/// Content-type enforcement is applied as middleware to all POST routes.
pub fn est_router() -> Router<Arc<AppState>> {
    Router::new()
        // RFC 7030 §4.1: Distribution of CA Certificates
        .route("/cacerts", get(cacerts::get_cacerts))
        // RFC 7030 §4.2: Enrollment (initial)
        .route(
            "/simpleenroll",
            post(simpleenroll::post_simpleenroll),
        )
        // RFC 7030 §4.2.2: Re-enrollment
        .route(
            "/simplereenroll",
            post(simplereenroll::post_simplereenroll),
        )
        // RFC 7030 §4.3: Full CMC
        .route("/fullcmc", post(fullcmc::post_fullcmc))
        // RFC 7030 §4.4: Server-Side Key Generation
        .route(
            "/serverkeygen",
            post(serverkeygen::post_serverkeygen),
        )
        // RFC 7030 §4.5: CSR Attributes
        .route("/csrattrs", get(csrattrs::get_csrattrs))
        // Content-Type enforcement on POST routes.
        .layer(middleware::from_fn(enforce_est_content_type))
}

/// EST content types defined in RFC 7030 §4.
pub mod content_types {
    /// PKCS#10 CSR: used by `/simpleenroll`, `/simplereenroll`, `/serverkeygen`.
    pub const PKCS10: &str = "application/pkcs10";

    /// PKCS#7 certs-only: returned by `/cacerts`, `/simpleenroll`, `/simplereenroll`.
    pub const PKCS7_CERTS: &str = "application/pkcs7-mime; smime-type=certs-only";

    /// PKCS#7 CMC request: used by `/fullcmc`.
    pub const CMC_REQUEST: &str = "application/pkcs7-mime; smime-type=CMC-request";

    /// PKCS#7 CMC response: returned by `/fullcmc`.
    pub const CMC_RESPONSE: &str = "application/pkcs7-mime; smime-type=CMC-response";

    /// CSR attributes: returned by `/csrattrs`.
    pub const CSR_ATTRS: &str = "application/csrattrs";

    /// PKCS#8 private key: returned as part of `/serverkeygen`.
    pub const PKCS8: &str = "application/pkcs8";

    /// Multipart/mixed: returned by `/serverkeygen` (cert + private key).
    pub const MULTIPART_MIXED: &str = "multipart/mixed";

    /// Transfer encoding for EST payloads per RFC 7030 §4.1.
    pub const TRANSFER_ENCODING_BASE64: &str = "base64";
}

/// Middleware that enforces Content-Type requirements for EST POST requests.
///
/// RFC 7030 §4 defines specific content types for each EST operation:
///
/// | Endpoint         | Expected Content-Type                                |
/// |------------------|------------------------------------------------------|
/// | /simpleenroll    | application/pkcs10                                   |
/// | /simplereenroll  | application/pkcs10                                   |
/// | /serverkeygen    | application/pkcs10                                   |
/// | /fullcmc         | application/pkcs7-mime; smime-type=CMC-request        |
///
/// GET requests are passed through without Content-Type validation.
async fn enforce_est_content_type(req: Request<Body>, next: Next) -> Response {
    // Only enforce on POST/PUT methods.
    if req.method() != Method::POST && req.method() != Method::PUT {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Determine the expected content type based on the path.
    let expected = if path.ends_with("/simpleenroll")
        || path.ends_with("/simplereenroll")
        || path.ends_with("/serverkeygen")
    {
        Some(content_types::PKCS10)
    } else if path.ends_with("/fullcmc") {
        // CMC requests: accept the full MIME type or just the base type.
        Some("application/pkcs7-mime")
    } else {
        None
    };

    if let Some(expected_prefix) = expected
        && !content_type.starts_with(expected_prefix)
    {
        tracing::debug!(
            path = %path,
            content_type = %content_type,
            expected = %expected_prefix,
            "rejecting request with wrong Content-Type"
        );
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Content-Type must be {expected_prefix}"),
        )
            .into_response();
    }

    next.run(req).await
}

/// Decode a base64-encoded EST request body.
///
/// RFC 7030 §4.1 and RFC 8951 specify that EST request and response
/// bodies use base64 encoding of the DER-encoded ASN.1 structures.
///
/// This function handles:
/// - Standard base64 (RFC 4648 §4)
/// - Base64 with line breaks (PEM-style)
/// - Stripping of whitespace
pub fn decode_est_base64(body: &[u8]) -> Result<Vec<u8>, String> {
    // Strip whitespace and line breaks per RFC 8951.
    let cleaned: Vec<u8> = body
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| format!("invalid base64 encoding: {e}"))
}

/// Encode DER bytes as base64 for an EST response body.
///
/// Produces standard base64 (RFC 4648 §4) with 76-character line wrapping
/// per RFC 8951 §3.
pub fn encode_est_base64(der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);

    // RFC 8951 §3: base64-encoded data SHOULD be line-wrapped at 76 chars.
    let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 76);
    for (i, ch) in encoded.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            wrapped.push('\r');
            wrapped.push('\n');
        }
        wrapped.push(ch);
    }
    wrapped
}

/// Build an EST error response per RFC 7030 §4.2.3.
///
/// EST error responses use HTTP status codes as the primary error indicator.
/// For enrollment failures, the server MAY return a CMC Full PKI Response
/// body with detailed error information.
///
/// For now, this returns a `text/plain` body with the error detail.  A
/// future enhancement will return a proper CMC error body for 4xx responses
/// on enrollment endpoints.
pub fn est_error_response(status: StatusCode, detail: &str) -> Response {
    let mut resp = (status, detail.to_string()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    // RFC 7030 §4.2.3: 401 responses include WWW-Authenticate.
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"EST\""),
        );
    }

    // RFC 7030 §4.2.3: 503 responses include Retry-After.
    if status == StatusCode::SERVICE_UNAVAILABLE
        && let Ok(hv) = HeaderValue::from_str("120")
    {
        resp.headers_mut().insert(header::RETRY_AFTER, hv);
    }

    resp
}

use base64::Engine as _;
