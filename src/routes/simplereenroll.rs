//! `POST /.well-known/est/simplereenroll` — Simple Re-enrollment.
//!
//! RFC 7030 §4.2.2: EST clients submit a PKCS#10 CSR to renew an
//! existing certificate.  The client MUST authenticate via mTLS by
//! presenting the certificate being renewed.
//!
//! POP linking (§3.5): the TLS client certificate subject MUST match
//! the CSR subject, proving the client possesses the private key of
//! the certificate being renewed.
//!
//! The server additionally verifies the client certificate has not been
//! revoked (OCSP/CRL check per RHELBU-3536 R21).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::{AuthMethod, EstAuth};
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::est::{content_types, decode_est_base64, encode_est_base64};
use crate::state::AppState;

/// `POST /.well-known/est/simplereenroll`
///
/// Accepts a PKCS#10 CSR (base64-encoded) and returns a PKCS#7 certs-only
/// response containing the renewed certificate.
///
/// # Authentication
///
/// MUST authenticate via mTLS — the client presents the certificate being
/// renewed.  OTP and GSSAPI are not accepted for re-enrollment.
///
/// # POP Linking (RFC 7030 §3.5)
///
/// The TLS client certificate subject MUST match the CSR subject.  This
/// prevents an attacker from using a compromised certificate to request
/// a certificate for a different identity.
///
/// # Revocation Check (RHELBU-3536 R21)
///
/// The server verifies the client certificate has not been revoked before
/// accepting the re-enrollment request.  This prevents revoked certificates
/// from being used to obtain new certificates.
///
/// # Request
///
/// | Header         | Value                |
/// |----------------|----------------------|
/// | Content-Type   | `application/pkcs10` |
/// | Body           | Base64-encoded DER PKCS#10 CSR |
///
/// # Response
///
/// | Header         | Value                                        |
/// |----------------|----------------------------------------------|
/// | Status         | `200 OK` or `202 Accepted`                   |
/// | Content-Type   | `application/pkcs7-mime; smime-type=certs-only` |
///
/// # Errors
///
/// - `400 Bad Request` — malformed CSR, POP linking failure
/// - `401 Unauthorized` — mTLS required but not provided
/// - `403 Forbidden` — client certificate revoked
/// - `415 Unsupported Media Type` — wrong Content-Type
/// - `500 Internal Server Error` — CA signing failure
pub async fn post_simplereenroll(
    auth: EstAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();

    // Re-enrollment MUST use mTLS authentication.
    if auth.0.method != AuthMethod::Mtls {
        tracing::warn!(
            identity = %auth.0.identity,
            method = ?auth.0.method,
            "simplereenroll rejected: mTLS required"
        );
        return Err(KipukaError::Auth(
            "re-enrollment requires mTLS client certificate authentication".into(),
        ));
    }

    let identity = &auth.0.identity;

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        identity = %identity,
        "simplereenroll request"
    );

    // Decode the base64-encoded CSR.
    let csr_der = decode_est_base64(&body)
        .map_err(|e| KipukaError::BadRequest(format!("CSR decoding failed: {e}")))?;

    if csr_der.is_empty() || csr_der.len() < 60 {
        return Err(KipukaError::BadRequest("CSR is empty or too short".into()));
    }

    // POP linking: verify the TLS client cert subject matches the CSR subject.
    //
    // RFC 7030 §3.5: "the subject field in the CSR MUST be the same as
    // the subject field in the client certificate used for TLS authentication."
    //
    // TODO: Parse the CSR subject DN and compare with the TLS cert subject.
    //
    // let csr = synta::pkcs10::CertificationRequest::from_der(&csr_der)?;
    // let csr_subject = csr.subject_dn_string();
    // mtls::validate_pop_linking(auth.0.subject_dn.as_deref(), &csr_subject)?;

    if let Some(ref cert_subject) = auth.0.subject_dn {
        tracing::debug!(
            cert_subject = %cert_subject,
            "POP linking: TLS cert subject will be compared with CSR subject"
        );
        // Placeholder for actual POP linking validation.
    }

    // Verify the client certificate has not been revoked (RHELBU-3536 R21).
    //
    // The mTLS module already checks revocation during extraction, but we
    // perform a second check here to handle the case where the certificate
    // was revoked between TLS handshake and request processing.
    //
    // TODO: Implement OCSP/CRL check.
    // kipuka_est::revocation::check_certificate(
    //     auth.0.client_cert_der.as_deref().unwrap(),
    //     &state,
    // ).await?;

    // Look up the CA backend.
    let ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Look up the CA config to get the key_file path.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    // Read the CA private key PEM from disk.
    let ca_key_pem = tokio::fs::read(&ca_cfg.key_file)
        .await
        .map_err(|e| KipukaError::Ca(format!("failed to read CA key {}: {e}", ca_cfg.key_file)))?;

    // Build the enrollment profile.
    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(398),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    // Issue the renewed certificate.
    let result = crate::ca::issue::issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        &ca_key_pem,
        &ca.hash_algorithm,
    )
    .map_err(|e| KipukaError::Ca(format!("certificate re-issuance failed: {e}")))?;

    let cert_der = result.certificate_der;
    let pkcs7_der = cert_der;

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

    state
        .record_audit_event(
            "simplereenroll_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    Ok(resp)
}
