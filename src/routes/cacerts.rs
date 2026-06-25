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

/// Build a PKCS#7 certs-only SignedData containing the given DER-encoded
/// certificate(s).
///
/// Produces the RFC 5652 §5.1 degenerate (certs-only) SignedData structure:
///
/// ```text
/// ContentInfo ::= SEQUENCE {
///     contentType  OBJECT IDENTIFIER (id-signedData),
///     content [0]  EXPLICIT SignedData
/// }
/// SignedData ::= SEQUENCE {
///     version             INTEGER (1),
///     digestAlgorithms    SET (empty),
///     encapContentInfo    SEQUENCE { contentType OID (id-data) },
///     certificates   [0]  IMPLICIT SET OF Certificate,
///     signerInfos         SET (empty)
/// }
/// ```
pub(crate) fn build_certs_only_pkcs7(cert_der: &[u8]) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoding, Encoder, ObjectIdentifier, Tag, tag};

    if cert_der.is_empty() {
        return Err(KipukaError::Ca("CA certificate DER is empty".into()));
    }

    // OID constants from synta-certificate.
    let oid_signed_data = ObjectIdentifier::new(synta_certificate::oids::CMS_SIGNED_DATA)
        .map_err(|e| KipukaError::Ca(format!("id-signedData OID: {e}")))?;
    let oid_data = ObjectIdentifier::new(synta_certificate::oids::CMS_DATA)
        .map_err(|e| KipukaError::Ca(format!("id-data OID: {e}")))?;

    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);
    let set_tag = Tag::universal_constructed(tag::TAG_SET);
    let ctx0_tag = Tag::context_specific_constructed(0);

    let mut enc = Encoder::new(Encoding::Der);

    // ContentInfo SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Ca(format!("ContentInfo SEQUENCE: {e}")))?;

    // contentType: id-signedData
    enc.encode(&oid_signed_data)
        .map_err(|e| KipukaError::Ca(format!("contentType OID: {e}")))?;

    // content [0] EXPLICIT
    enc.start_constructed_no_guard(ctx0_tag)
        .map_err(|e| KipukaError::Ca(format!("[0] EXPLICIT: {e}")))?;

    // SignedData SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Ca(format!("SignedData SEQUENCE: {e}")))?;

    // version INTEGER 1
    let version = synta::Integer::from_i64(1);
    enc.encode(&version)
        .map_err(|e| KipukaError::Ca(format!("version INTEGER: {e}")))?;

    // digestAlgorithms SET (empty)
    enc.start_constructed_no_guard(set_tag)
        .map_err(|e| KipukaError::Ca(format!("digestAlgorithms SET: {e}")))?;
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("digestAlgorithms end: {e}")))?;

    // encapContentInfo SEQUENCE { contentType: id-data }
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Ca(format!("encapContentInfo SEQUENCE: {e}")))?;
    enc.encode(&oid_data)
        .map_err(|e| KipukaError::Ca(format!("id-data OID: {e}")))?;
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("encapContentInfo end: {e}")))?;

    // certificates [0] IMPLICIT SET OF Certificate
    enc.start_constructed_no_guard(ctx0_tag)
        .map_err(|e| KipukaError::Ca(format!("certificates [0]: {e}")))?;
    enc.write_bytes(cert_der);
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("certificates end: {e}")))?;

    // signerInfos SET (empty)
    enc.start_constructed_no_guard(set_tag)
        .map_err(|e| KipukaError::Ca(format!("signerInfos SET: {e}")))?;
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("signerInfos end: {e}")))?;

    // Close SignedData SEQUENCE
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("SignedData end: {e}")))?;

    // Close [0] EXPLICIT
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("[0] end: {e}")))?;

    // Close ContentInfo SEQUENCE
    enc.end_constructed()
        .map_err(|e| KipukaError::Ca(format!("ContentInfo end: {e}")))?;

    let pkcs7_der = enc
        .finish()
        .map_err(|e| KipukaError::Ca(format!("PKCS#7 DER finish: {e}")))?;

    tracing::debug!(
        pkcs7_len = pkcs7_der.len(),
        cert_len = cert_der.len(),
        "built PKCS#7 certs-only SignedData"
    );

    Ok(pkcs7_der)
}
