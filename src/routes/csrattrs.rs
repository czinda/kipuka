//! `GET /.well-known/est/csrattrs` — CSR Attributes Request.
//!
//! RFC 7030 §4.5: EST clients request the CSR attributes that the
//! server expects in enrollment requests.  The response tells the
//! client which algorithms, extensions, and subject fields to include
//! in its PKCS#10 CSR.
//!
//! No authentication required per RFC 7030 §4.5.
//!
//! Per-label attribute variation is supported (RHELBU-3536 R31):
//! different EST labels can advertise different required attributes
//! based on their enrollment profile.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::OptionalAuth;
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::est::{content_types, encode_est_base64};
use crate::state::AppState;

/// Well-known OIDs for CSR attributes.
pub mod oids {
    /// challengePassword (1.2.840.113549.1.9.7) — used for POP linking.
    pub const CHALLENGE_PASSWORD: &str = "1.2.840.113549.1.9.7";

    /// extensionRequest (1.2.840.113549.1.9.14) — certificate extension request.
    pub const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";

    /// ecPublicKey (1.2.840.10045.2.1) — EC key algorithm.
    pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

    /// rsaEncryption (1.2.840.113549.1.1.1) — RSA key algorithm.
    pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

    /// id-ecPublicKey secp256r1 (1.2.840.10045.3.1.7) — P-256 curve.
    pub const SECP256R1: &str = "1.2.840.10045.3.1.7";

    /// id-ecPublicKey secp384r1 (1.3.132.0.34) — P-384 curve.
    pub const SECP384R1: &str = "1.3.132.0.34";

    /// keyUsage (2.5.29.15).
    pub const KEY_USAGE: &str = "2.5.29.15";

    /// extKeyUsage (2.5.29.37).
    pub const EXT_KEY_USAGE: &str = "2.5.29.37";

    /// subjectAltName (2.5.29.17).
    pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
}

/// `GET /.well-known/est/csrattrs`
///
/// Returns the CSR attributes that the server expects in enrollment
/// requests for the resolved label.
///
/// # Response
///
/// | Header         | Value                 |
/// |----------------|-----------------------|
/// | Status         | `200 OK` or `204 No Content` |
/// | Content-Type   | `application/csrattrs` |
///
/// The body is a base64-encoded DER sequence of `AttrOrOID` values
/// (RFC 7030 §4.5.2):
///
/// ```asn1
/// CsrAttrs ::= SEQUENCE SIZE (1..MAX) OF AttrOrOID
/// AttrOrOID ::= CHOICE {
///     oid OBJECT IDENTIFIER,
///     attribute Attribute
/// }
/// ```
///
/// # Authentication
///
/// No authentication required per RFC 7030 §4.5.
///
/// # Errors
///
/// - `404 Not Found` — unknown EST label
/// - `500 Internal Server Error` — attribute encoding failure
pub async fn get_csrattrs(
    _auth: OptionalAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();

    tracing::debug!(
        ca_id = %ca_id,
        label = %label.label,
        "serving CSR attributes"
    );

    // Determine the attribute set: per-label overrides global.
    let attributes = if !label.csr_attributes.is_empty() {
        &label.csr_attributes
    } else {
        &state.config.est.csr_attributes
    };

    // If no attributes are configured, return 204 No Content per RFC 7030 §4.5.1.
    if attributes.is_empty() {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // Encode the attributes as a DER SEQUENCE of OIDs.
    //
    // TODO: Replace with proper ASN.1 encoding via `synta` or `der` crate.
    //
    // The proper implementation would:
    // 1. For each OID string, encode it as a DER OBJECT IDENTIFIER
    // 2. Wrap in a SEQUENCE
    // 3. Base64-encode the result
    //
    // For now, build a placeholder that encodes the OID strings.
    let csrattrs_der = encode_csr_attrs(attributes)?;

    let body = encode_est_base64(&csrattrs_der);

    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_types::CSR_ATTRS),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
    );

    Ok(resp)
}

/// Encode CSR attribute OID strings into DER format.
///
/// TODO: Replace with proper ASN.1 construction via `synta` or `der` crate.
fn encode_csr_attrs(oid_strings: &[String]) -> Result<Vec<u8>, KipukaError> {
    if oid_strings.is_empty() {
        return Ok(Vec::new());
    }

    // Placeholder: encode OID strings into a minimal DER SEQUENCE.
    //
    // Real implementation:
    //   let mut seq = der::asn1::SequenceOf::<der::asn1::ObjectIdentifier, MAX>::new();
    //   for oid_str in oid_strings {
    //       let oid = der::asn1::ObjectIdentifier::new(oid_str)?;
    //       seq.add(oid)?;
    //   }
    //   let der_bytes = seq.to_der()?;

    // For now, return an empty SEQUENCE (0x30 0x00).
    // This is technically valid ASN.1 but does not encode any OIDs.
    Ok(vec![0x30, 0x00])
}
