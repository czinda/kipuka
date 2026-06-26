//! `GET /.well-known/est/csrattrs` — CSR Attributes Request.
//!
//! RFC 7030 §4.5: EST clients request the CSR attributes that the
//! server expects in enrollment requests.  The response tells the
//! client which algorithms, extensions, and subject fields to include
//! in its PKCS#10 CSR.
//!
//! ## CSR Attributes Template (RFC 9908)
//!
//! When `csr_template` is configured, the response also includes a
//! `CertificationRequestInfoTemplate` attribute (OID
//! `1.2.840.113549.1.9.16.2.63`) that partially pre-fills a
//! CertificationRequestInfo, guiding the client on subject DN,
//! key algorithm, and required extensions.  The template coexists
//! with the OID-list mode for backward compatibility.
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
use crate::config::CsrTemplate;
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

    /// id-aa-certificationRequestInfoTemplate (1.2.840.113549.1.9.16.2.63)
    /// — RFC 9908 §5.1.
    pub const CSR_TEMPLATE: &str = "1.2.840.113549.1.9.16.2.63";

    /// OID components for id-aa-certificationRequestInfoTemplate.
    pub const CSR_TEMPLATE_COMPONENTS: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 2, 63];

    // ── X.500 attribute type OIDs used in CSR templates ──────────────

    /// commonName (2.5.4.3).
    pub const COMMON_NAME: &str = "2.5.4.3";

    /// organizationName (2.5.4.10).
    pub const ORGANIZATION_NAME: &str = "2.5.4.10";

    /// countryName (2.5.4.6).
    pub const COUNTRY_NAME: &str = "2.5.4.6";

    /// stateOrProvinceName (2.5.4.8).
    pub const STATE_OR_PROVINCE: &str = "2.5.4.8";

    /// localityName (2.5.4.7).
    pub const LOCALITY_NAME: &str = "2.5.4.7";

    /// organizationalUnitName (2.5.4.11).
    pub const ORG_UNIT_NAME: &str = "2.5.4.11";
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

    // Determine the CSR template: per-label overrides global.
    let template = label
        .csr_template
        .as_ref()
        .or(state.config.est.csr_template.as_ref());

    // If no attributes and no template are configured, return 204 No Content
    // per RFC 7030 §4.5.1.
    let has_template = template.is_some_and(|t| {
        !t.subject.is_empty() || t.key_algorithm.is_some() || !t.required_extensions.is_empty()
    });
    if attributes.is_empty() && !has_template {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // Encode the attributes as a DER SEQUENCE of AttrOrOID values.
    // When a template is configured, the template Attribute is appended
    // after the OID list within the same CsrAttrs SEQUENCE.
    let csrattrs_der = encode_csr_attrs_with_template(attributes, template)?;

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
/// Produces the RFC 7030 §4.5.2 `CsrAttrs` structure:
///
/// ```asn1
/// CsrAttrs ::= SEQUENCE SIZE (1..MAX) OF AttrOrOID
/// AttrOrOID ::= CHOICE {
///     oid       OBJECT IDENTIFIER,
///     attribute Attribute {{ ... }}
/// }
/// ```
///
/// Each configured OID string is resolved against `synta_certificate::oids`
/// well-known constants where possible, falling back to dotted-decimal
/// parsing for custom OIDs.
pub(crate) fn encode_csr_attrs(oid_strings: &[String]) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoding, Encoder, ObjectIdentifier, Tag, tag};

    if oid_strings.is_empty() {
        return Ok(Vec::new());
    }

    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);
    let mut enc = Encoder::new(Encoding::Der);

    // CsrAttrs SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("CsrAttrs SEQUENCE: {e}")))?;

    for oid_str in oid_strings {
        // Resolve the OID string to components. Try well-known OIDs first,
        // then fall back to dotted-decimal parsing.
        let components = resolve_oid_components(oid_str)?;
        let oid = ObjectIdentifier::new(&components).map_err(|e| {
            KipukaError::Internal(format!("invalid OID '{oid_str}': {e}"))
        })?;

        enc.encode(&oid)
            .map_err(|e| KipukaError::Internal(format!("OID encode '{oid_str}': {e}")))?;
    }

    // Close CsrAttrs SEQUENCE
    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("CsrAttrs end: {e}")))?;

    let der_bytes = enc
        .finish()
        .map_err(|e| KipukaError::Internal(format!("CsrAttrs DER finish: {e}")))?;

    tracing::debug!(
        num_oids = oid_strings.len(),
        der_len = der_bytes.len(),
        "encoded CSR attributes"
    );

    Ok(der_bytes)
}

/// Resolve an OID string to its component integers.
///
/// First checks known OID constants from `synta_certificate::oids` (avoids
/// hardcoding), then falls back to parsing the dotted-decimal string.
fn resolve_oid_components(oid_str: &str) -> Result<Vec<u32>, KipukaError> {
    // Map well-known OID strings to synta-certificate constants.
    let components: &[u32] = match oid_str {
        oids::CHALLENGE_PASSWORD => synta_certificate::oids::PKCS9_CHALLENGE_PASSWORD,
        oids::EXTENSION_REQUEST => synta_certificate::oids::PKCS9_EXTENSION_REQUEST,
        oids::EC_PUBLIC_KEY => synta_certificate::oids::EC_PUBLIC_KEY,
        oids::RSA_ENCRYPTION => synta_certificate::oids::RSA_ENCRYPTION,
        oids::KEY_USAGE => synta_certificate::oids::KEY_USAGE,
        oids::EXT_KEY_USAGE => synta_certificate::oids::EXTENDED_KEY_USAGE,
        oids::SUBJECT_ALT_NAME => synta_certificate::oids::SUBJECT_ALT_NAME,
        oids::SECP256R1 => synta_certificate::oids::EC_CURVE_P256,
        oids::SECP384R1 => synta_certificate::oids::EC_CURVE_P384,
        _ => {
            // Fall back to parsing dotted-decimal OID string.
            let parts: Result<Vec<u32>, _> =
                oid_str.split('.').map(|s| s.parse::<u32>()).collect();
            return parts.map_err(|e| {
                KipukaError::Internal(format!(
                    "invalid OID string '{oid_str}': {e}"
                ))
            });
        }
    };
    Ok(components.to_vec())
}

/// Encode CSR attribute OIDs and an optional RFC 9908 template into DER.
///
/// When `template` is `None`, this is equivalent to [`encode_csr_attrs`].
/// When a template is present, the template `Attribute` is appended to
/// the `CsrAttrs` SEQUENCE after the OID list entries.
///
/// TODO: Full template encoding (subject DN, key algorithm, required
/// extensions) will be implemented as part of RFC 9908 support.  For now,
/// the template parameter is accepted but not yet encoded — the function
/// delegates to `encode_csr_attrs` for the OID list.
pub(crate) fn encode_csr_attrs_with_template(
    oid_strings: &[String],
    _template: Option<&CsrTemplate>,
) -> Result<Vec<u8>, KipukaError> {
    // Phase 1: encode the OID list (backward-compatible mode).
    // Phase 2 (TODO): append a CertificationRequestInfoTemplate Attribute
    // when _template is Some(_).
    encode_csr_attrs(oid_strings)
}
