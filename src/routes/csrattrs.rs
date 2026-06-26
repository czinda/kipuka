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
//! `1.2.840.113549.1.9.16.2.61`) that partially pre-fills a
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
use crate::config::{CsrTemplate, CsrTemplateRdn};
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

    /// id-aa-certificationRequestInfoTemplate (1.2.840.113549.1.9.16.2.61)
    /// — RFC 9908 §3.4, IANA Table 2.
    pub const CSR_TEMPLATE: &str = "1.2.840.113549.1.9.16.2.61";

    /// OID components for id-aa-certificationRequestInfoTemplate.
    pub const CSR_TEMPLATE_COMPONENTS: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 2, 61];

    /// id-aa-extensionReqTemplate (1.2.840.113549.1.9.16.2.62)
    /// — RFC 9908 §3.4, IANA Table 2.
    pub const EXTENSION_REQ_TEMPLATE: &str = "1.2.840.113549.1.9.16.2.62";

    /// OID components for id-aa-extensionReqTemplate.
    pub const EXTENSION_REQ_TEMPLATE_COMPONENTS: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 2, 62];

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
    let has_template = template.is_some_and(|t| t.has_content());
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
    use synta::{Encoder, Encoding, ObjectIdentifier, Tag, tag};

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
        let oid = ObjectIdentifier::new(&components)
            .map_err(|e| KipukaError::Internal(format!("invalid OID '{oid_str}': {e}")))?;

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
            let parts: Result<Vec<u32>, _> = oid_str.split('.').map(|s| s.parse::<u32>()).collect();
            return parts.map_err(|e| {
                KipukaError::Internal(format!("invalid OID string '{oid_str}': {e}"))
            });
        }
    };
    Ok(components.to_vec())
}

/// Encode CSR attribute OIDs and an optional RFC 9908 template into DER.
///
/// When `template` is `None`, this is equivalent to [`encode_csr_attrs`].
/// When a template is present, the template `Attribute` is appended to
/// the `CsrAttrs` SEQUENCE after the OID list entries.  Clients that
/// understand the template use it exclusively; legacy clients ignore the
/// unrecognised Attribute and process only the OID list.
pub(crate) fn encode_csr_attrs_with_template(
    oid_strings: &[String],
    template: Option<&CsrTemplate>,
) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoder, Encoding, ObjectIdentifier, Tag, tag};

    // Filter to a template reference only when it has content.
    let template = template.filter(|t| t.has_content());

    if oid_strings.is_empty() && template.is_none() {
        return Ok(Vec::new());
    }

    // When there is no template, use the simpler OID-only encoder.
    let Some(template) = template else {
        return encode_csr_attrs(oid_strings);
    };

    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);
    let mut enc = Encoder::new(Encoding::Der);

    // CsrAttrs SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("CsrAttrs SEQUENCE: {e}")))?;

    // Encode OID list entries (backward-compatible with legacy clients).
    for oid_str in oid_strings {
        let components = resolve_oid_components(oid_str)?;
        let oid = ObjectIdentifier::new(&components)
            .map_err(|e| KipukaError::Internal(format!("invalid OID '{oid_str}': {e}")))?;
        enc.encode(&oid)
            .map_err(|e| KipukaError::Internal(format!("OID encode '{oid_str}': {e}")))?;
    }

    // Append the RFC 9908 template Attribute.
    let attr_der = encode_template_attribute(template)?;
    enc.write_bytes(&attr_der);

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("CsrAttrs end: {e}")))?;

    let der_bytes = enc
        .finish()
        .map_err(|e| KipukaError::Internal(format!("CsrAttrs DER finish: {e}")))?;

    tracing::debug!(
        num_oids = oid_strings.len(),
        has_template = true,
        der_len = der_bytes.len(),
        "encoded CSR attributes with template"
    );

    Ok(der_bytes)
}

/// Encode the RFC 9908 template as an ASN.1 `Attribute`:
///
/// ```asn1
/// Attribute ::= SEQUENCE {
///     type   OID (id-aa-certificationRequestInfoTemplate),
///     values SET OF CertificationRequestInfoTemplate
/// }
/// ```
fn encode_template_attribute(template: &CsrTemplate) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoder, Encoding, ObjectIdentifier, Tag, tag};

    let mut enc = Encoder::new(Encoding::Der);
    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);
    let set_tag = Tag::universal_constructed(tag::TAG_SET);

    // Attribute SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("Attribute SEQUENCE: {e}")))?;

    // attrType OID
    let oid = ObjectIdentifier::new(oids::CSR_TEMPLATE_COMPONENTS)
        .map_err(|e| KipukaError::Internal(format!("template OID: {e}")))?;
    enc.encode(&oid)
        .map_err(|e| KipukaError::Internal(format!("template OID encode: {e}")))?;

    // attrValues SET OF CertificationRequestInfoTemplate
    enc.start_constructed_no_guard(set_tag)
        .map_err(|e| KipukaError::Internal(format!("attrValues SET: {e}")))?;

    let cri_der = encode_cri_template(template)?;
    enc.write_bytes(&cri_der);

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("attrValues SET end: {e}")))?;

    // Close Attribute SEQUENCE
    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("Attribute end: {e}")))?;

    enc.finish()
        .map_err(|e| KipukaError::Internal(format!("Attribute DER finish: {e}")))
}

/// Encode the inner `CertificationRequestInfoTemplate` SEQUENCE:
///
/// ```asn1
/// CertificationRequestInfoTemplate ::= SEQUENCE {
///     version       INTEGER (0),
///     subject       NameTemplate OPTIONAL,
///     subjectPKInfo [0] SubjectPublicKeyInfoTemplate OPTIONAL,
///     attributes    [1] Attributes{{ CRIAttributes }}
/// }
/// ```
///
/// Note: `attributes` is **not** OPTIONAL per RFC 9908 — it is always
/// present.  When no extension templates are configured, an empty
/// `[1] {}` (DER `A1 00`) is emitted.
fn encode_cri_template(template: &CsrTemplate) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoder, Encoding, Integer, Tag, tag};

    let mut enc = Encoder::new(Encoding::Der);
    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);

    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("CRI template SEQUENCE: {e}")))?;

    // version INTEGER (0)
    let version = Integer::from_i64(0);
    enc.encode(&version)
        .map_err(|e| KipukaError::Internal(format!("CRI version: {e}")))?;

    // subject NameTemplate OPTIONAL
    if !template.subject.is_empty() {
        let name_der = encode_subject_template(&template.subject)?;
        enc.write_bytes(&name_der);
    }

    // subjectPKInfo [0] IMPLICIT SubjectPublicKeyInfoTemplate OPTIONAL
    if let Some(ref key_alg) = template.key_algorithm {
        let spki_der = encode_spki_template(key_alg)?;
        let ctx0 = Tag::context_specific_constructed(0);
        enc.start_constructed_no_guard(ctx0)
            .map_err(|e| KipukaError::Internal(format!("[0] SPKI tag: {e}")))?;
        enc.write_bytes(&spki_der);
        enc.end_constructed()
            .map_err(|e| KipukaError::Internal(format!("[0] SPKI end: {e}")))?;
    }

    // attributes [1] IMPLICIT SET OF Attribute — mandatory per RFC 9908.
    let ctx1 = Tag::context_specific_constructed(1);
    if !template.required_extensions.is_empty() {
        let ext_der = encode_extension_template(&template.required_extensions)?;
        enc.start_constructed_no_guard(ctx1)
            .map_err(|e| KipukaError::Internal(format!("[1] attrs tag: {e}")))?;
        enc.write_bytes(&ext_der);
        enc.end_constructed()
            .map_err(|e| KipukaError::Internal(format!("[1] attrs end: {e}")))?;
    } else {
        // Empty SET — still required by RFC 9908 (DER: A1 00).
        enc.start_constructed_no_guard(ctx1)
            .map_err(|e| KipukaError::Internal(format!("[1] empty attrs tag: {e}")))?;
        enc.end_constructed()
            .map_err(|e| KipukaError::Internal(format!("[1] empty attrs end: {e}")))?;
    }

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("CRI template end: {e}")))?;

    enc.finish()
        .map_err(|e| KipukaError::Internal(format!("CRI template DER finish: {e}")))
}

/// Encode a NameTemplate (RFC 9908 §3.4) as a DER `Name` SEQUENCE.
///
/// Unlike a standard X.509 Name, `SingleAttributeTemplate` allows the
/// `value` field to be absent — signalling that the client must supply
/// a value for that RDN type.
///
/// ```asn1
/// SingleAttributeTemplate ::= SEQUENCE {
///     type  OID,
///     value ANY OPTIONAL    -- absent = client fills in
/// }
/// ```
fn encode_subject_template(rdns: &[CsrTemplateRdn]) -> Result<Vec<u8>, KipukaError> {
    use synta::types::string::Utf8StringRef;
    use synta::{Encoder, Encoding, ObjectIdentifier, Tag, tag};

    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);
    let set_tag = Tag::universal_constructed(tag::TAG_SET);

    let mut enc = Encoder::new(Encoding::Der);

    // Name ::= SEQUENCE OF RelativeDistinguishedName
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("Name SEQUENCE: {e}")))?;

    for rdn in rdns {
        let components = resolve_oid_components(&rdn.oid)?;
        let oid = ObjectIdentifier::new(&components)
            .map_err(|e| KipukaError::Internal(format!("RDN OID '{}': {e}", rdn.oid)))?;

        // RDN ::= SET OF SingleAttributeTemplate
        enc.start_constructed_no_guard(set_tag)
            .map_err(|e| KipukaError::Internal(format!("RDN SET: {e}")))?;

        // SingleAttributeTemplate SEQUENCE
        enc.start_constructed_no_guard(seq_tag)
            .map_err(|e| KipukaError::Internal(format!("AttrTypeAndValue SEQUENCE: {e}")))?;

        enc.encode(&oid)
            .map_err(|e| KipukaError::Internal(format!("RDN OID encode: {e}")))?;

        // Value is optional per RFC 9908 — omit when None.
        if let Some(value) = &rdn.value {
            let val = Utf8StringRef::new(value.as_str());
            enc.encode(&val)
                .map_err(|e| KipukaError::Internal(format!("RDN value encode: {e}")))?;
        }

        enc.end_constructed()
            .map_err(|e| KipukaError::Internal(format!("AttrTypeAndValue end: {e}")))?;

        enc.end_constructed()
            .map_err(|e| KipukaError::Internal(format!("RDN SET end: {e}")))?;
    }

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("Name end: {e}")))?;

    enc.finish()
        .map_err(|e| KipukaError::Internal(format!("Name DER finish: {e}")))
}

/// Encode a `SubjectPublicKeyInfoTemplate` (RFC 9908 §3.4) body.
///
/// The encoded bytes are the *content* of the `[0] IMPLICIT` wrapper;
/// the caller adds the context tag.
///
/// ```asn1
/// SubjectPublicKeyInfoTemplate ::= SEQUENCE {
///     algorithm        AlgorithmIdentifier,
///     subjectPublicKey BIT STRING OPTIONAL
/// }
/// ```
///
/// For EC keys the AlgorithmIdentifier carries the curve OID as a
/// parameter.  For RSA keys the parameter is NULL.  The
/// `subjectPublicKey` field is omitted (clients generate their own key).
fn encode_spki_template(key_alg: &str) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoder, Encoding, Null, ObjectIdentifier, Tag, tag};

    let (alg_oid_components, param_oid_components) = parse_key_algorithm(key_alg)?;
    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);

    let mut enc = Encoder::new(Encoding::Der);

    // AlgorithmIdentifier SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("AlgId SEQUENCE: {e}")))?;

    let alg_oid = ObjectIdentifier::new(&alg_oid_components)
        .map_err(|e| KipukaError::Internal(format!("AlgId OID: {e}")))?;
    enc.encode(&alg_oid)
        .map_err(|e| KipukaError::Internal(format!("AlgId OID encode: {e}")))?;

    // Parameters: EC → curve OID, RSA → NULL.
    if let Some(ref param_comps) = param_oid_components {
        let param_oid = ObjectIdentifier::new(param_comps)
            .map_err(|e| KipukaError::Internal(format!("curve OID: {e}")))?;
        enc.encode(&param_oid)
            .map_err(|e| KipukaError::Internal(format!("curve OID encode: {e}")))?;
    } else {
        enc.encode(&Null)
            .map_err(|e| KipukaError::Internal(format!("NULL param encode: {e}")))?;
    }

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("AlgId end: {e}")))?;

    // subjectPublicKey BIT STRING is omitted — client generates its own.

    enc.finish()
        .map_err(|e| KipukaError::Internal(format!("SPKI DER finish: {e}")))
}

/// Parse a key algorithm spec string into OID components.
///
/// Supported formats:
/// - `"ec:P-256"` → (EC_PUBLIC_KEY, Some(EC_CURVE_P256))
/// - `"ec:P-384"` → (EC_PUBLIC_KEY, Some(EC_CURVE_P384))
/// - `"ec:P-521"` → (EC_PUBLIC_KEY, Some(EC_CURVE_P521))
/// - `"rsa:2048"`, `"rsa:4096"`, etc. → (RSA_ENCRYPTION, None)
///
/// Returns `(algorithm_oid, optional_parameter_oid)`.
fn parse_key_algorithm(spec: &str) -> Result<(Vec<u32>, Option<Vec<u32>>), KipukaError> {
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(KipukaError::Internal(format!(
            "invalid key_algorithm format '{spec}': expected 'ec:<curve>' or 'rsa:<bits>'"
        )));
    }

    match parts[0].to_lowercase().as_str() {
        "ec" | "ecdsa" => {
            let curve_oid = match parts[1] {
                "P-256" | "p-256" | "secp256r1" | "prime256v1" => {
                    synta_certificate::oids::EC_CURVE_P256.to_vec()
                }
                "P-384" | "p-384" | "secp384r1" => synta_certificate::oids::EC_CURVE_P384.to_vec(),
                "P-521" | "p-521" | "secp521r1" => synta_certificate::oids::EC_CURVE_P521.to_vec(),
                other => {
                    return Err(KipukaError::Internal(format!(
                        "unsupported EC curve '{other}'"
                    )));
                }
            };
            Ok((
                synta_certificate::oids::EC_PUBLIC_KEY.to_vec(),
                Some(curve_oid),
            ))
        }
        "rsa" => Ok((synta_certificate::oids::RSA_ENCRYPTION.to_vec(), None)),
        other => Err(KipukaError::Internal(format!(
            "unsupported key algorithm family '{other}'"
        ))),
    }
}

/// Encode an extension-request template as an Attribute wrapping
/// `id-aa-extensionReqTemplate` (OID 1.2.840.113549.1.9.16.2.62).
///
/// Each extension OID becomes an `ExtensionTemplate` with no value —
/// the client must fill in appropriate values.
///
/// ```asn1
/// Attribute ::= SEQUENCE {
///     type   OID (id-aa-extensionReqTemplate),
///     values SET OF ExtensionTemplates
/// }
/// ExtensionTemplate ::= SEQUENCE {
///     extnID    OID,
///     critical  BOOLEAN DEFAULT FALSE,   -- omitted
///     extnValue OCTET STRING OPTIONAL    -- omitted
/// }
/// ```
fn encode_extension_template(ext_oids: &[String]) -> Result<Vec<u8>, KipukaError> {
    use synta::{Encoder, Encoding, ObjectIdentifier, Tag, tag};

    let seq_tag = Tag::universal_constructed(tag::TAG_SEQUENCE);
    let set_tag = Tag::universal_constructed(tag::TAG_SET);

    let mut enc = Encoder::new(Encoding::Der);

    // Attribute SEQUENCE
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("ExtReq Attribute SEQUENCE: {e}")))?;

    // attrType = id-aa-extensionReqTemplate
    let ext_req_oid = ObjectIdentifier::new(oids::EXTENSION_REQ_TEMPLATE_COMPONENTS)
        .map_err(|e| KipukaError::Internal(format!("extensionReqTemplate OID: {e}")))?;
    enc.encode(&ext_req_oid)
        .map_err(|e| KipukaError::Internal(format!("extensionReqTemplate OID encode: {e}")))?;

    // attrValues SET OF ExtensionTemplates
    enc.start_constructed_no_guard(set_tag)
        .map_err(|e| KipukaError::Internal(format!("ExtReq SET: {e}")))?;

    // ExtensionTemplates SEQUENCE OF ExtensionTemplate
    enc.start_constructed_no_guard(seq_tag)
        .map_err(|e| KipukaError::Internal(format!("ExtensionTemplates SEQUENCE: {e}")))?;

    for ext_oid_str in ext_oids {
        let components = resolve_oid_components(ext_oid_str)?;
        let oid = ObjectIdentifier::new(&components)
            .map_err(|e| KipukaError::Internal(format!("ext OID '{ext_oid_str}': {e}")))?;

        // ExtensionTemplate SEQUENCE { extnID OID }
        // critical and extnValue are omitted — client fills in.
        enc.start_constructed_no_guard(seq_tag)
            .map_err(|e| KipukaError::Internal(format!("ExtensionTemplate SEQUENCE: {e}")))?;
        enc.encode(&oid)
            .map_err(|e| KipukaError::Internal(format!("ext OID encode: {e}")))?;
        enc.end_constructed()
            .map_err(|e| KipukaError::Internal(format!("ExtensionTemplate end: {e}")))?;
    }

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("ExtensionTemplates end: {e}")))?;

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("ExtReq SET end: {e}")))?;

    enc.end_constructed()
        .map_err(|e| KipukaError::Internal(format!("ExtReq Attribute end: {e}")))?;

    enc.finish()
        .map_err(|e| KipukaError::Internal(format!("ExtReq DER finish: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta::{Decoder, Encoding, Length, ObjectIdentifier, Tag, tag};

    fn decode_oid_at(decoder: &mut Decoder<'_>) -> ObjectIdentifier {
        decoder.decode::<ObjectIdentifier>().expect("decode OID")
    }

    fn read_tl(decoder: &mut Decoder<'_>) -> (Tag, Length) {
        let tag = decoder.read_tag().expect("read tag");
        let len = decoder.read_length().expect("read length");
        (tag, len)
    }

    #[test]
    fn oid_constant_matches_rfc9908() {
        assert_eq!(oids::CSR_TEMPLATE, "1.2.840.113549.1.9.16.2.61");
        assert_eq!(
            oids::CSR_TEMPLATE_COMPONENTS,
            &[1, 2, 840, 113549, 1, 9, 16, 2, 61]
        );
        assert_eq!(oids::EXTENSION_REQ_TEMPLATE, "1.2.840.113549.1.9.16.2.62");
    }

    #[test]
    fn encode_template_subject_only() {
        let template = CsrTemplate {
            subject: vec![
                CsrTemplateRdn {
                    oid: oids::ORGANIZATION_NAME.to_string(),
                    value: Some("Example Corp".to_string()),
                },
                CsrTemplateRdn {
                    oid: oids::COMMON_NAME.to_string(),
                    value: None,
                },
            ],
            key_algorithm: None,
            required_extensions: vec![],
        };

        let der = encode_csr_attrs_with_template(&[], Some(&template)).unwrap();
        assert!(!der.is_empty());

        // Outer SEQUENCE (CsrAttrs)
        let mut dec = Decoder::new(&der, Encoding::Der);
        let (tag, _len) = read_tl(&mut dec);
        assert!(tag.is_constructed());
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);

        // Inside: Attribute SEQUENCE
        let (tag, _len) = read_tl(&mut dec);
        assert!(tag.is_constructed());
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);

        // attrType = id-aa-certificationRequestInfoTemplate
        let attr_oid = decode_oid_at(&mut dec);
        let expected = ObjectIdentifier::new(oids::CSR_TEMPLATE_COMPONENTS).unwrap();
        assert_eq!(attr_oid, expected);
    }

    #[test]
    fn encode_template_ec_p256() {
        let template = CsrTemplate {
            subject: vec![],
            key_algorithm: Some("ec:P-256".to_string()),
            required_extensions: vec![],
        };

        let der = encode_csr_attrs_with_template(&[], Some(&template)).unwrap();
        assert!(!der.is_empty());

        // Verify the encoded DER is parseable — walk into the CRI template
        // and find the AlgorithmIdentifier.
        let inner = encode_cri_template(&template).unwrap();
        let mut dec = Decoder::new(&inner, Encoding::Der);

        // CRI SEQUENCE
        let (tag, _) = read_tl(&mut dec);
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);

        // version INTEGER (0)
        let version: synta::Integer = dec.decode().unwrap();
        assert_eq!(version.as_i64().unwrap(), 0);

        // [0] IMPLICIT SPKI template
        let (tag, _) = read_tl(&mut dec);
        assert_eq!(tag.class(), synta::TagClass::ContextSpecific);
        assert_eq!(tag.number(), 0);

        // AlgorithmIdentifier SEQUENCE
        let (tag, _) = read_tl(&mut dec);
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);

        // algorithm OID = ecPublicKey
        let alg_oid = decode_oid_at(&mut dec);
        let ec_pk = ObjectIdentifier::new(synta_certificate::oids::EC_PUBLIC_KEY).unwrap();
        assert_eq!(alg_oid, ec_pk);

        // parameters OID = P-256
        let curve_oid = decode_oid_at(&mut dec);
        let p256 = ObjectIdentifier::new(synta_certificate::oids::EC_CURVE_P256).unwrap();
        assert_eq!(curve_oid, p256);
    }

    #[test]
    fn encode_template_rsa() {
        let template = CsrTemplate {
            subject: vec![],
            key_algorithm: Some("rsa:2048".to_string()),
            required_extensions: vec![],
        };

        let inner = encode_cri_template(&template).unwrap();
        let mut dec = Decoder::new(&inner, Encoding::Der);

        // CRI SEQUENCE
        read_tl(&mut dec);
        // version
        let _: synta::Integer = dec.decode().unwrap();
        // [0] SPKI
        read_tl(&mut dec);
        // AlgId SEQUENCE
        read_tl(&mut dec);

        let alg_oid = decode_oid_at(&mut dec);
        let rsa = ObjectIdentifier::new(synta_certificate::oids::RSA_ENCRYPTION).unwrap();
        assert_eq!(alg_oid, rsa);

        // RSA params = NULL
        let null: synta::Null = dec.decode().unwrap();
        assert_eq!(null, synta::Null);
    }

    #[test]
    fn encode_template_extensions_only() {
        let template = CsrTemplate {
            subject: vec![],
            key_algorithm: None,
            required_extensions: vec![
                oids::SUBJECT_ALT_NAME.to_string(),
                oids::KEY_USAGE.to_string(),
            ],
        };

        let der = encode_csr_attrs_with_template(&[], Some(&template)).unwrap();
        assert!(!der.is_empty());

        // Verify the inner CRI template has [1] attributes.
        let inner = encode_cri_template(&template).unwrap();
        let mut dec = Decoder::new(&inner, Encoding::Der);

        // CRI SEQUENCE
        read_tl(&mut dec);
        // version
        let _: synta::Integer = dec.decode().unwrap();
        // [1] attributes
        let (tag, _) = read_tl(&mut dec);
        assert_eq!(tag.class(), synta::TagClass::ContextSpecific);
        assert_eq!(tag.number(), 1);
    }

    #[test]
    fn encode_template_combined_with_oids() {
        let template = CsrTemplate {
            subject: vec![CsrTemplateRdn {
                oid: oids::COMMON_NAME.to_string(),
                value: Some("test.example.com".to_string()),
            }],
            key_algorithm: Some("ec:P-384".to_string()),
            required_extensions: vec![oids::SUBJECT_ALT_NAME.to_string()],
        };

        let oid_list = vec![
            oids::CHALLENGE_PASSWORD.to_string(),
            oids::EXTENSION_REQUEST.to_string(),
        ];

        let der = encode_csr_attrs_with_template(&oid_list, Some(&template)).unwrap();
        assert!(!der.is_empty());

        // Outer CsrAttrs SEQUENCE should contain OIDs + Attribute.
        let mut dec = Decoder::new(&der, Encoding::Der);
        let (tag, _) = read_tl(&mut dec);
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);

        // First two elements: challengePassword and extensionRequest OIDs.
        let oid1 = decode_oid_at(&mut dec);
        let challenge =
            ObjectIdentifier::new(synta_certificate::oids::PKCS9_CHALLENGE_PASSWORD).unwrap();
        assert_eq!(oid1, challenge);

        let oid2 = decode_oid_at(&mut dec);
        let ext_req =
            ObjectIdentifier::new(synta_certificate::oids::PKCS9_EXTENSION_REQUEST).unwrap();
        assert_eq!(oid2, ext_req);

        // Third element: template Attribute SEQUENCE.
        let (tag, _) = read_tl(&mut dec);
        assert!(tag.is_constructed());
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);
    }

    #[test]
    fn absent_rdn_value_omits_value_field() {
        let rdns = vec![CsrTemplateRdn {
            oid: oids::COMMON_NAME.to_string(),
            value: None,
        }];
        let name_der = encode_subject_template(&rdns).unwrap();

        // Name SEQUENCE → RDN SET → AttrTypeAndValue SEQUENCE → OID only.
        let mut dec = Decoder::new(&name_der, Encoding::Der);
        // Name SEQUENCE
        read_tl(&mut dec);
        // RDN SET
        read_tl(&mut dec);
        // AttrTypeAndValue SEQUENCE
        let (_, atv_len) = read_tl(&mut dec);
        let atv_len = atv_len.definite().unwrap();

        // Decode the OID and measure its size.
        let oid = decode_oid_at(&mut dec);
        let cn = ObjectIdentifier::new(synta_certificate::oids::attr::COMMON_NAME).unwrap();
        assert_eq!(oid, cn);

        // The AttrTypeAndValue should contain only the OID — no value bytes.
        let oid_encoded_len = synta::ToDer::to_der(&oid).unwrap().len();
        assert_eq!(atv_len, oid_encoded_len);
    }

    #[test]
    fn present_rdn_value_includes_utf8string() {
        let rdns = vec![CsrTemplateRdn {
            oid: oids::ORGANIZATION_NAME.to_string(),
            value: Some("Test Org".to_string()),
        }];
        let name_der = encode_subject_template(&rdns).unwrap();

        let mut dec = Decoder::new(&name_der, Encoding::Der);
        // Name → RDN SET → ATV SEQUENCE
        read_tl(&mut dec);
        read_tl(&mut dec);
        let (_, atv_len) = read_tl(&mut dec);
        let atv_len = atv_len.definite().unwrap();

        let oid = decode_oid_at(&mut dec);
        let org = ObjectIdentifier::new(synta_certificate::oids::attr::ORGANIZATION).unwrap();
        assert_eq!(oid, org);

        // ATV length is larger than OID alone — value is present.
        let oid_len = synta::ToDer::to_der(&oid).unwrap().len();
        assert!(atv_len > oid_len);
    }

    #[test]
    fn parse_key_algorithm_valid() {
        let (alg, param) = parse_key_algorithm("ec:P-256").unwrap();
        assert_eq!(alg, synta_certificate::oids::EC_PUBLIC_KEY);
        assert_eq!(param.unwrap(), synta_certificate::oids::EC_CURVE_P256);

        let (alg, param) = parse_key_algorithm("ec:P-384").unwrap();
        assert_eq!(alg, synta_certificate::oids::EC_PUBLIC_KEY);
        assert_eq!(param.unwrap(), synta_certificate::oids::EC_CURVE_P384);

        let (alg, param) = parse_key_algorithm("ec:P-521").unwrap();
        assert_eq!(alg, synta_certificate::oids::EC_PUBLIC_KEY);
        assert_eq!(param.unwrap(), synta_certificate::oids::EC_CURVE_P521);

        let (alg, param) = parse_key_algorithm("rsa:2048").unwrap();
        assert_eq!(alg, synta_certificate::oids::RSA_ENCRYPTION);
        assert!(param.is_none());

        let (alg, param) = parse_key_algorithm("rsa:4096").unwrap();
        assert_eq!(alg, synta_certificate::oids::RSA_ENCRYPTION);
        assert!(param.is_none());
    }

    #[test]
    fn parse_key_algorithm_invalid() {
        assert!(parse_key_algorithm("dsa:1024").is_err());
        assert!(parse_key_algorithm("ec:P-999").is_err());
        assert!(parse_key_algorithm("no-colon").is_err());
    }

    #[test]
    fn empty_template_returns_empty() {
        let template = CsrTemplate {
            subject: vec![],
            key_algorithm: None,
            required_extensions: vec![],
        };
        let der = encode_csr_attrs_with_template(&[], Some(&template)).unwrap();
        assert!(der.is_empty());
    }

    #[test]
    fn none_template_delegates_to_oid_only() {
        let oid_list = vec![oids::CHALLENGE_PASSWORD.to_string()];
        let with_template = encode_csr_attrs_with_template(&oid_list, None).unwrap();
        let oid_only = encode_csr_attrs(&oid_list).unwrap();
        assert_eq!(with_template, oid_only);
    }

    #[test]
    fn mandatory_attributes_field_present_when_no_extensions() {
        let template = CsrTemplate {
            subject: vec![CsrTemplateRdn {
                oid: oids::COMMON_NAME.to_string(),
                value: None,
            }],
            key_algorithm: None,
            required_extensions: vec![],
        };

        let inner = encode_cri_template(&template).unwrap();
        let mut dec = Decoder::new(&inner, Encoding::Der);

        // CRI SEQUENCE
        read_tl(&mut dec);
        // version
        let _: synta::Integer = dec.decode().unwrap();
        // subject Name SEQUENCE
        let (tag, _) = read_tl(&mut dec);
        assert_eq!(tag.number(), tag::TAG_SEQUENCE);

        // Skip subject content — read remaining bytes for [1].
        // Re-decode from scratch and walk past subject.
        let inner2 = encode_cri_template(&template).unwrap();

        // The last two bytes should be A1 00 (empty [1] IMPLICIT SET).
        assert!(inner2.len() >= 2);
        let tail = &inner2[inner2.len() - 2..];
        assert_eq!(tail, &[0xA1, 0x00], "mandatory [1] empty SET missing");
    }
}
