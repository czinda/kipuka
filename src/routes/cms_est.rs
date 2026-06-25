//! CMS-wrapped EST endpoints (RFC 8295).
//!
//! These endpoints accept EST requests wrapped in CMS SignedData for
//! authentication and return responses wrapped in CMS EnvelopedData
//! for confidentiality.  This enables EST over plain HTTP when a
//! TLS-terminating proxy strips the TLS layer.
//!
//! RFC 8295 §4: All EST operations are supported with CMS wrapping.
//! The Content-Type for all requests and responses is
//! `application/pkcs7-mime`.
//!
//! # Route structure
//!
//! ```text
//! /.well-known/est/cms/
//!     simpleenroll     POST (§4.2 + CMS wrapping)
//!     simplereenroll   POST (§4.2.2 + CMS wrapping)
//!     serverkeygen     POST (§4.4 + CMS wrapping)
//!     fullcmc          POST (§4.3 + CMS wrapping)
//! ```

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::auth::cms_auth;
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::simpleenroll::parse_pkcs11_object_label;
use crate::state::AppState;

/// Content-Type for CMS-wrapped EST payloads (RFC 8295 §4).
const CONTENT_TYPE_PKCS7: &str = "application/pkcs7-mime";

/// Build the CMS-EST sub-router.
///
/// Mounts CMS-wrapped variants of the core EST enrollment endpoints
/// under `/.well-known/est/cms/`.  Each handler unwraps the CMS
/// SignedData, delegates to the standard EST logic, and optionally
/// wraps the response in CMS EnvelopedData.
pub fn cms_est_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/simpleenroll", post(post_cms_simpleenroll))
        .route("/simplereenroll", post(post_cms_simplereenroll))
        .route("/serverkeygen", post(post_cms_serverkeygen))
        .route("/fullcmc", post(post_cms_fullcmc))
}

/// Extract and validate the CMS-EST configuration from application state.
///
/// Returns the configuration reference if CMS-EST is enabled, or an
/// `KipukaError::Est` error if it is disabled or absent.
fn get_cms_est_config(state: &AppState) -> Result<&crate::config::CmsEstConfig, KipukaError> {
    match state.config.cms_est {
        Some(ref cfg) if cfg.enabled => Ok(cfg),
        _ => Err(KipukaError::Est("CMS-EST is not enabled".into())),
    }
}

/// Build a truststore (list of DER-encoded trust anchors) from the
/// CA certificate chains in application state.
///
/// RFC 8295 §3.1: the signer certificate must chain to a trust anchor
/// known to the EST server.  We use the CA certificates as the
/// truststore for CMS signature verification.
fn build_truststore(state: &AppState) -> Vec<Vec<u8>> {
    state
        .cas
        .values()
        .flat_map(|ca| ca.cert_chain.iter().cloned())
        .collect()
}

/// `POST /.well-known/est/cms/simpleenroll`
///
/// CMS-wrapped simple enrollment (RFC 8295 §4 + RFC 7030 §4.2).
///
/// # Request
///
/// | Header       | Value                    |
/// |--------------|--------------------------|
/// | Content-Type | `application/pkcs7-mime` |
/// | Body         | DER-encoded CMS SignedData wrapping a PKCS#10 CSR |
///
/// # Processing
///
/// 1. Verify CMS SignedData signature and signer certificate chain.
/// 2. Extract the PKCS#10 CSR payload from the signed content.
/// 3. Extract signer identity for authorization.
/// 4. Delegate to the standard enrollment logic.
/// 5. Optionally wrap the response certificate in CMS EnvelopedData.
///
/// # Response
///
/// | Header       | Value                    |
/// |--------------|--------------------------|
/// | Content-Type | `application/pkcs7-mime` |
/// | Body         | DER-encoded CMS EnvelopedData (or raw cert if encryption disabled) |
pub async fn post_cms_simpleenroll(
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let cms_config = get_cms_est_config(&state)?;
    let ca_id = label.ca_id();

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        "CMS simpleenroll request"
    );

    // CMS payloads are raw DER — no base64 decoding needed (RFC 8295 §4).
    if body.is_empty() {
        return Err(KipukaError::BadRequest(
            "empty CMS SignedData request body".into(),
        ));
    }

    // Verify the CMS SignedData and extract the CSR payload.
    let truststore = build_truststore(&state);
    let cms_result = cms_auth::verify_cms_signed_data(&body, &truststore)?;

    // Extract the signer identity for authorization decisions.
    let auth_result = cms_auth::extract_signer_identity(&cms_result)?;
    let identity = &auth_result.identity;

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        signature_algorithm = %cms_result.signature_algorithm,
        "CMS signature verified for simpleenroll"
    );

    // The unwrapped payload is the PKCS#10 CSR.
    let csr_der = &cms_result.payload;
    if csr_der.len() < 60 {
        return Err(KipukaError::BadRequest(
            "extracted CSR is too short to be valid".into(),
        ));
    }

    // Delegate to the standard direct-signing enrollment pipeline.
    let cert_der = issue_certificate_from_csr(&state, ca_id, csr_der).await?;

    // Optionally wrap the response in CMS EnvelopedData.
    let response_body = if cms_config.encrypt_responses {
        let enc_alg = cms_config
            .allowed_content_encryption
            .first()
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        cms_auth::build_cms_enveloped_data(&cert_der, &cms_result.signer_cert_der, enc_alg)?
    } else {
        cert_der
    };

    state
        .record_audit_event(
            "cms_simpleenroll_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    build_cms_response(StatusCode::OK, &response_body)
}

/// `POST /.well-known/est/cms/simplereenroll`
///
/// CMS-wrapped simple re-enrollment (RFC 8295 §4 + RFC 7030 §4.2.2).
///
/// Similar to [`post_cms_simpleenroll`] but for certificate renewal.
/// The CMS signer certificate serves as proof of the existing identity,
/// analogous to the mTLS client certificate in standard re-enrollment.
pub async fn post_cms_simplereenroll(
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let cms_config = get_cms_est_config(&state)?;
    let ca_id = label.ca_id();

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        "CMS simplereenroll request"
    );

    if body.is_empty() {
        return Err(KipukaError::BadRequest(
            "empty CMS SignedData request body".into(),
        ));
    }

    let truststore = build_truststore(&state);
    let cms_result = cms_auth::verify_cms_signed_data(&body, &truststore)?;
    let auth_result = cms_auth::extract_signer_identity(&cms_result)?;
    let identity = &auth_result.identity;

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        signature_algorithm = %cms_result.signature_algorithm,
        "CMS signature verified for simplereenroll"
    );

    let csr_der = &cms_result.payload;
    if csr_der.len() < 60 {
        return Err(KipukaError::BadRequest(
            "extracted CSR is too short to be valid".into(),
        ));
    }

    // For re-enrollment, verify the signer certificate matches the CSR subject.
    //
    // RFC 7030 §3.5 POP linking: the CMS signer certificate subject
    // MUST match the CSR subject.  This is analogous to the mTLS POP
    // linking check in standard re-enrollment.
    //
    // TODO: Parse CSR subject and compare with cms_result.signer_subject_dn.
    // let csr_subject = synta::pkcs10::CertificationRequest::from_der(csr_der)?
    //     .subject_dn_string();
    // if csr_subject != cms_result.signer_subject_dn {
    //     return Err(KipukaError::BadRequest("POP linking failed: CSR subject does not match signer".into()));
    // }

    // Delegate to the standard direct-signing enrollment pipeline.
    // Re-enrollment uses the same certificate issuance path as simple enrollment;
    // the authentication difference is that the CMS signer cert IS the existing
    // certificate being renewed (verified above via CMS SignedData).
    let cert_der = issue_certificate_from_csr(&state, ca_id, csr_der).await?;

    let response_body = if cms_config.encrypt_responses {
        let enc_alg = cms_config
            .allowed_content_encryption
            .first()
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        cms_auth::build_cms_enveloped_data(&cert_der, &cms_result.signer_cert_der, enc_alg)?
    } else {
        cert_der
    };

    state
        .record_audit_event(
            "cms_simplereenroll_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    build_cms_response(StatusCode::OK, &response_body)
}

/// `POST /.well-known/est/cms/serverkeygen`
///
/// CMS-wrapped server-side key generation (RFC 8295 §4 + RFC 7030 §4.4).
///
/// The server generates a key pair, signs a certificate, and returns
/// both the certificate and private key wrapped in CMS EnvelopedData
/// for confidentiality.
pub async fn post_cms_serverkeygen(
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let cms_config = get_cms_est_config(&state)?;
    let ca_id = label.ca_id();

    if !state.config.est.serverkeygen {
        return Err(KipukaError::Est(
            "server-side key generation is not enabled".into(),
        ));
    }

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        "CMS serverkeygen request"
    );

    if body.is_empty() {
        return Err(KipukaError::BadRequest(
            "empty CMS SignedData request body".into(),
        ));
    }

    let truststore = build_truststore(&state);
    let cms_result = cms_auth::verify_cms_signed_data(&body, &truststore)?;
    let auth_result = cms_auth::extract_signer_identity(&cms_result)?;
    let identity = &auth_result.identity;

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        signature_algorithm = %cms_result.signature_algorithm,
        "CMS signature verified for serverkeygen"
    );

    // The payload is the CSR template with the desired subject/extensions.
    let csr_template = &cms_result.payload;

    // Issue the certificate using the CSR template as the enrollment request.
    let cert_der = issue_certificate_from_csr(&state, ca_id, csr_template).await?;

    // For server-side key generation, the private key would be generated
    // server-side and returned alongside the certificate.  The current
    // implementation issues the certificate from the client-provided CSR;
    // full server-keygen (RSA/EC key pair generation on the server) will be
    // added when the keygen module is implemented.
    //
    // The cert DER is used as the response payload.  When server-keygen is
    // complete, this will be replaced with a combined cert + private key blob.

    // Server key generation responses MUST always be encrypted —
    // the response may contain the private key.
    let enc_alg = cms_config
        .allowed_content_encryption
        .first()
        .map(|s| s.as_str())
        .unwrap_or("AES-256-GCM");

    let response_body =
        cms_auth::build_cms_enveloped_data(&cert_der, &cms_result.signer_cert_der, enc_alg)?;

    state
        .record_audit_event(
            "cms_serverkeygen_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    build_cms_response(StatusCode::OK, &response_body)
}

/// `POST /.well-known/est/cms/fullcmc`
///
/// CMS-wrapped Full CMC request (RFC 8295 §4 + RFC 7030 §4.3).
///
/// The outer CMS SignedData provides message-level authentication; the
/// inner payload is the CMC request (itself a SignedData containing
/// PKIData).  The signer MUST hold the id-kp-cmcRA EKU.
pub async fn post_cms_fullcmc(
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let cms_config = get_cms_est_config(&state)?;
    let ca_id = label.ca_id();

    if !state.config.est.fullcmc {
        return Err(KipukaError::Est("Full CMC is not enabled".into()));
    }

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        "CMS fullcmc request"
    );

    if body.is_empty() {
        return Err(KipukaError::BadRequest(
            "empty CMS SignedData request body".into(),
        ));
    }

    let truststore = build_truststore(&state);
    let cms_result = cms_auth::verify_cms_signed_data(&body, &truststore)?;
    let auth_result = cms_auth::extract_signer_identity(&cms_result)?;
    let identity = &auth_result.identity;

    // RHELBU-3536 R15: Validate id-kp-cmcRA EKU on the signer certificate.
    //
    // TODO: Parse the signer certificate to extract EKU OIDs and verify
    // that id-kp-cmcRA (1.3.6.1.5.5.7.3.28) is present.
    //
    // For now, this check is deferred until the CMS crypto layer is
    // implemented — the signer certificate DER is available in
    // cms_result.signer_cert_der for EKU extraction.

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        signature_algorithm = %cms_result.signature_algorithm,
        "CMS signature verified for fullcmc"
    );

    // The inner payload is the CMC request (itself a CMS SignedData
    // containing PKIData).  Unwrap the inner SignedData and parse PKIData.
    let cmc_request_der = &cms_result.payload;

    // Unwrap the inner CMC SignedData to get the PKIData content.
    let (pki_data_der, _inner_signer_certs) =
        synta_cmc::parser::unwrap_signed_cmc(cmc_request_der).map_err(|e| {
            KipukaError::BadRequest(format!("CMC inner SignedData unwrap failed: {e}"))
        })?;

    if pki_data_der.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMC inner SignedData has empty eContent".into(),
        ));
    }

    // Parse PKIData to extract controls and certification requests.
    let pki_data = synta_cmc::parser::parse_pki_data(&pki_data_der).map_err(|e| {
        KipukaError::BadRequest(format!("CMC PKIData parse failed: {e}"))
    })?;

    let transaction_id = synta_cmc::controls::extract_transaction_id(&pki_data.controls);
    let sender_nonce = synta_cmc::controls::extract_sender_nonce(&pki_data.controls);

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        transaction_id = ?transaction_id,
        num_requests = pki_data.certification_requests.len(),
        "CMS fullcmc: PKIData parsed"
    );

    if pki_data.certification_requests.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMC request contains no certification requests".into(),
        ));
    }

    // Process each certification request using the shared enrollment helper.
    let mut issued_certs: Vec<Vec<u8>> = Vec::new();
    let mut body_part_ids: Vec<u32> = Vec::new();
    let mut failed_body_part_ids: Vec<u32> = Vec::new();

    for req_entry in &pki_data.certification_requests {
        match req_entry.request_type {
            synta_cmc::parser::RequestType::Pkcs10 => {
                match issue_certificate_from_csr(&state, ca_id, &req_entry.der).await {
                    Ok(cert) => {
                        issued_certs.push(cert);
                        body_part_ids.push(req_entry.body_part_id);
                    }
                    Err(e) => {
                        tracing::error!(
                            body_part_id = req_entry.body_part_id,
                            error = %e,
                            "CMS fullcmc: certificate issuance failed"
                        );
                        failed_body_part_ids.push(req_entry.body_part_id);
                    }
                }
            }
            _ => {
                tracing::warn!(
                    body_part_id = req_entry.body_part_id,
                    "CMS fullcmc: unsupported request type (only PKCS#10 supported)"
                );
                failed_body_part_ids.push(req_entry.body_part_id);
            }
        }
    }

    // Build the CMC PKIResponse.
    let mut resp_builder = synta_cmc::builder::PKIResponseBuilder::new();

    if !body_part_ids.is_empty() {
        resp_builder = resp_builder.add_status(&body_part_ids).map_err(|e| {
            KipukaError::Ca(format!("CMC response builder failed (status): {e}"))
        })?;
    }

    if !failed_body_part_ids.is_empty() {
        resp_builder = resp_builder
            .add_failed(&failed_body_part_ids, synta_cmc::status::CMCFailInfo::InternalCaError)
            .map_err(|e| {
                KipukaError::Ca(format!("CMC response builder failed (failed status): {e}"))
            })?;
    }

    // Echo sender nonce as recipient nonce per RFC 5272 §6.6.
    if let Some(nonce) = &sender_nonce {
        resp_builder = resp_builder.recipient_nonce(nonce).map_err(|e| {
            KipukaError::Ca(format!("CMC response builder failed (recipient nonce): {e}"))
        })?;
    }

    let cmc_response_der = resp_builder.build().map_err(|e| {
        KipukaError::Ca(format!("CMC PKIResponse build failed: {e}"))
    })?;

    let response_body = if cms_config.encrypt_responses {
        let enc_alg = cms_config
            .allowed_content_encryption
            .first()
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        cms_auth::build_cms_enveloped_data(&cmc_response_der, &cms_result.signer_cert_der, enc_alg)?
    } else {
        cmc_response_der
    };

    state
        .record_audit_event(
            "cms_fullcmc_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    build_cms_response(StatusCode::OK, &response_body)
}

/// Build an HTTP response for a CMS-wrapped EST operation.
///
/// Sets Content-Type to `application/pkcs7-mime` per RFC 8295 §4.
/// The body is raw DER — no base64 transfer encoding is used for
/// CMS-wrapped payloads.
fn build_cms_response(status: StatusCode, body: &[u8]) -> Result<Response, KipukaError> {
    let mut resp = (status, body.to_vec()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_PKCS7),
    );
    Ok(resp)
}

/// Issue a certificate from a DER-encoded CSR using the direct-signing path.
///
/// This is the shared enrollment pipeline used by all CMS-EST handlers.
/// It resolves the CA backend (HSM or PEM key), builds an enrollment profile,
/// calls `issue_certificate`, and returns the DER-encoded issued certificate.
///
/// # Errors
///
/// Returns `KipukaError::NotFound` if the CA is unknown, `KipukaError::Ca`
/// on signing failures, and `KipukaError::ServiceUnavailable` if the HSM
/// is offline.
async fn issue_certificate_from_csr(
    state: &AppState,
    ca_id: &str,
    csr_der: &[u8],
) -> Result<Vec<u8>, KipukaError> {
    let ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    // Resolve key material — variables must outlive the signing_key borrow.
    let ca_key_pem: Vec<u8>;
    let key_label_owned: String;

    let signing_key = if ca_cfg.is_hsm_backed() {
        let hsm_ctx = state
            .hsm
            .as_ref()
            .ok_or_else(|| KipukaError::Ca("HSM not configured but CA has pkcs11_uri".into()))?;
        key_label_owned =
            parse_pkcs11_object_label(ca_cfg.pkcs11_uri.as_deref().ok_or_else(|| KipukaError::Ca("CA marked as HSM-backed but pkcs11_uri not configured".into()))?)
                .map_err(|e| KipukaError::Ca(format!("invalid pkcs11_uri: {e}")))?;
        crate::ca::issue::CaSigningKey::Hsm {
            context: hsm_ctx,
            key_label: &key_label_owned,
        }
    } else {
        ca_key_pem = tokio::fs::read(&ca_cfg.key_file).await.map_err(|e| {
            KipukaError::Ca(format!("failed to read CA key {}: {e}", ca_cfg.key_file))
        })?;
        crate::ca::issue::CaSigningKey::Pem(&ca_key_pem)
    };

    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(398),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    let result = crate::ca::issue::issue_certificate(
        csr_der,
        &profile,
        &ca.cert_der,
        signing_key,
        &ca.hash_algorithm,
    )
    .map_err(|e| KipukaError::Ca(format!("certificate issuance failed: {e}")))?;

    Ok(result.certificate_der)
}
