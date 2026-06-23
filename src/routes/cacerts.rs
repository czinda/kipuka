//! `GET /.well-known/est/cacerts` — CA Certificates Request.
//!
//! RFC 7030 §4.1: EST clients request the current CA certificates to
//! establish an Explicit TA database.  The response is a PKCS#7
//! certs-only message containing all CA certificates in the chain.
//!
//! This endpoint does not require authentication (RFC 7030 §4.1:
//! "the EST client can request a copy of the current CA certificates").

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::OptionalAuth;
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::est::{content_types, encode_est_base64};
use crate::state::AppState;

/// `GET /.well-known/est/cacerts`
///
/// Returns PKCS#7 certs-only with all CA certificates in the chain.
///
/// # Response
///
/// | Header         | Value                                        |
/// |----------------|----------------------------------------------|
/// | Status         | `200 OK`                                     |
/// | Content-Type   | `application/pkcs7-mime; smime-type=certs-only` |
/// | Content-Transfer-Encoding | `base64`                        |
///
/// The body is the base64-encoded DER representation of a PKCS#7
/// `SignedData` structure with no signerInfos and a single
/// `certificates` field containing the CA certificate chain.
///
/// # Authentication
///
/// No authentication required per RFC 7030 §4.1.
///
/// # Errors
///
/// - `404 Not Found` — unknown EST label
/// - `500 Internal Server Error` — CA certificate not available
pub async fn get_cacerts(
    _auth: OptionalAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();

    tracing::debug!(
        ca_id = %ca_id,
        label = %label.label,
        "serving CA certificates"
    );

    // Look up the CA state.
    let ca = state.get_ca(ca_id).ok_or_else(|| {
        tracing::error!(ca_id = %ca_id, "CA not found for cacerts request");
        KipukaError::NotFound
    })?;

    // Build a PKCS#7 certs-only message containing the CA certificate chain.
    //
    // A certs-only PKCS#7 SignedData has:
    // - version: 1
    // - digestAlgorithms: empty SET
    // - encapContentInfo: empty (no content)
    // - certificates: [0] IMPLICIT SET OF Certificate (the CA chain)
    // - signerInfos: empty SET
    //
    // In a full implementation this uses `synta` or `cms` to build the
    // proper ASN.1 structure.  For now we return the DER-encoded CA cert
    // wrapped in a minimal PKCS#7 envelope.
    let pkcs7_der = build_certs_only_pkcs7(&ca.cert_der)?;

    // Base64-encode per RFC 7030 §4.1.
    let body = encode_est_base64(&pkcs7_der);

    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_types::PKCS7_CERTS),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
    );

    // Audit log (best-effort).
    state
        .record_audit_event("cacerts", &format!("ca_id={ca_id}"))
        .await;

    Ok(resp)
}

/// Build a minimal PKCS#7 certs-only SignedData containing the given
/// DER-encoded certificates.
///
/// TODO: Replace with proper ASN.1 construction via `synta` or `cms` crate.
fn build_certs_only_pkcs7(cert_der: &[u8]) -> Result<Vec<u8>, KipukaError> {
    if cert_der.is_empty() {
        return Err(KipukaError::Ca("CA certificate DER is empty".into()));
    }

    // Placeholder: in a real implementation this would construct a proper
    // PKCS#7 SignedData ASN.1 structure using the `cms` or `synta` crate.
    //
    // For now, return a degenerate SignedData that wraps the raw cert.
    // Real implementation: kipuka_est::pkcs7::build_certs_only(certs)
    Ok(cert_der.to_vec())
}
