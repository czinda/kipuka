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

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

use crate::auth::cms_auth;
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
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
fn get_cms_est_config(
    state: &AppState,
) -> Result<&crate::config::CmsEstConfig, KipukaError> {
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

    // Delegate to the standard enrollment logic.
    //
    // TODO: Call the same enrollment pipeline as simpleenroll::post_simpleenroll.
    //
    // let cert_der = kipuka_est::enroll::process_csr(
    //     &state, ca_id, csr_der, &auth_result, &label,
    // ).await?;
    let cert_der: Vec<u8> = Vec::new(); // Placeholder

    if cert_der.is_empty() {
        return Err(KipukaError::Ca(
            "CMS-EST enrollment not yet implemented".into(),
        ));
    }

    // Optionally wrap the response in CMS EnvelopedData.
    let response_body = if cms_config.encrypt_responses {
        let enc_alg = cms_config
            .allowed_content_encryption
            .first()
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        cms_auth::build_cms_enveloped_data(
            &cert_der,
            &cms_result.signer_cert_der,
            enc_alg,
        )?
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

    // Delegate to re-enrollment logic.
    //
    // TODO: Call the same re-enrollment pipeline as simplereenroll::post_simplereenroll.
    let cert_der: Vec<u8> = Vec::new(); // Placeholder

    if cert_der.is_empty() {
        return Err(KipukaError::Ca(
            "CMS-EST re-enrollment not yet implemented".into(),
        ));
    }

    let response_body = if cms_config.encrypt_responses {
        let enc_alg = cms_config
            .allowed_content_encryption
            .first()
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        cms_auth::build_cms_enveloped_data(
            &cert_der,
            &cms_result.signer_cert_der,
            enc_alg,
        )?
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
    let _csr_template = &cms_result.payload;

    // Delegate to server key generation logic.
    //
    // TODO: Generate key pair, build certificate, return both wrapped
    // in CMS EnvelopedData.  The response MUST be encrypted because
    // it contains the private key.
    //
    // let (cert_pkcs7_der, private_key_pkcs8) =
    //     kipuka_est::keygen::server_keygen(&state, ca_id, csr_template, &label).await?;
    // let combined = kipuka_est::multipart::build(&cert_pkcs7_der, &private_key_pkcs8);
    let combined: Vec<u8> = Vec::new(); // Placeholder

    if combined.is_empty() {
        return Err(KipukaError::Ca(
            "CMS-EST server key generation not yet implemented".into(),
        ));
    }

    // Server key generation responses MUST always be encrypted —
    // the response contains the private key.
    let enc_alg = cms_config
        .allowed_content_encryption
        .first()
        .map(|s| s.as_str())
        .unwrap_or("AES-256-GCM");

    let response_body = cms_auth::build_cms_enveloped_data(
        &combined,
        &cms_result.signer_cert_der,
        enc_alg,
    )?;

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

    // The inner payload is the CMC request.
    let _cmc_request_der = &cms_result.payload;

    // Delegate to CMC processing.
    //
    // TODO: Process the CMC request via the same path as fullcmc::post_fullcmc.
    let cmc_response_der: Vec<u8> = Vec::new(); // Placeholder

    if cmc_response_der.is_empty() {
        return Err(KipukaError::Ca(
            "CMS-EST Full CMC not yet implemented".into(),
        ));
    }

    let response_body = if cms_config.encrypt_responses {
        let enc_alg = cms_config
            .allowed_content_encryption
            .first()
            .map(|s| s.as_str())
            .unwrap_or("AES-256-GCM");

        cms_auth::build_cms_enveloped_data(
            &cmc_response_der,
            &cms_result.signer_cert_der,
            enc_alg,
        )?
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
fn build_cms_response(
    status: StatusCode,
    body: &[u8],
) -> Result<Response, KipukaError> {
    let mut resp = (status, body.to_vec()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_PKCS7),
    );
    Ok(resp)
}
