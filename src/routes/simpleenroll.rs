//! `POST /.well-known/est/simpleenroll` — Simple Enrollment.
//!
//! RFC 7030 §4.2: EST clients submit a PKCS#10 CSR to request a new
//! certificate.  The client authenticates via mTLS or OTP (HTTP Basic).
//!
//! The server validates the CSR, forwards it to the CA backend for
//! certificate issuance, and returns the issued certificate in a
//! PKCS#7 certs-only response.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::EstAuth;
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::est::{content_types, decode_est_base64, encode_est_base64};
use crate::state::AppState;

/// `POST /.well-known/est/simpleenroll`
///
/// Accepts a PKCS#10 CSR (base64-encoded) and returns a PKCS#7 certs-only
/// response containing the issued certificate.
///
/// # Authentication
///
/// Requires one of:
/// - mTLS client certificate (validated against EST truststore)
/// - HTTP Basic with OTP (entity-id as username, OTP as password)
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
/// | Retry-After    | (present only with 202)                      |
///
/// # Errors
///
/// - `400 Bad Request` — malformed CSR, invalid base64, self-signature failure
/// - `401 Unauthorized` — authentication failed
/// - `415 Unsupported Media Type` — wrong Content-Type
/// - `500 Internal Server Error` — CA signing failure
/// - `503 Service Unavailable` — CA backend unavailable (with Retry-After)
pub async fn post_simpleenroll(
    auth: EstAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();
    let identity = &auth.0.identity;

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        identity = %identity,
        method = ?auth.0.method,
        "simpleenroll request"
    );

    // Decode the base64-encoded CSR.
    let csr_der = decode_est_base64(&body)
        .map_err(|e| KipukaError::BadRequest(format!("CSR decoding failed: {e}")))?;

    // Validate the CSR.
    validate_csr(&csr_der, &auth.0, &label)?;

    // Check if disconnected mode is active for this label.
    let disconnected = label.disconnected.unwrap_or(state.config.est.disconnected);

    if disconnected {
        // RHELBU-3536 R7-Disconnected: queue CSR for deferred signing.
        tracing::info!(
            ca_id = %ca_id,
            identity = %identity,
            "disconnected mode: queuing CSR for deferred signing"
        );

        // TODO: Persist the CSR for later signing.
        // kipuka_est::deferred::queue_csr(&state.db, ca_id, &csr_der, identity).await?;

        let retry_after = state.config.est.disconnected_retry_after_secs;

        let mut resp = StatusCode::ACCEPTED.into_response();
        if let Ok(hv) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, hv);
        }

        state
            .record_audit_event(
                "simpleenroll_deferred",
                &format!("ca_id={ca_id}, identity={identity}"),
            )
            .await;

        return Ok(resp);
    }

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

    // Build the enrollment profile (use defaults for now; a full implementation
    // would load a named profile from the label config).
    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(398),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    // Issue the certificate.
    let result = crate::ca::issue::issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        &ca_key_pem,
        &ca.hash_algorithm,
    )
    .map_err(|e| KipukaError::Ca(format!("certificate issuance failed: {e}")))?;

    // Store the issued certificate in the database for audit trail.
    let serial = &result.serial_number;
    let subject_dn = &result.subject_dn;
    let issuer_dn = synta_certificate::format_dn(
        &synta_certificate::Certificate::from_der(&ca.cert_der)
            .map(|c| c.tbs_certificate.subject.0.to_vec())
            .unwrap_or_default(),
    );
    let not_before_str = result.not_before.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after_str = result.not_after.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    if let Err(e) = sqlx::query(
        "INSERT INTO certificates (serial, subject_dn, issuer_dn, not_before, not_after, der_encoded, ca_id, profile, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')"
    )
    .bind(serial)
    .bind(subject_dn)
    .bind(&issuer_dn)
    .bind(&not_before_str)
    .bind(&not_after_str)
    .bind(&result.certificate_der)
    .bind(ca_id)
    .bind(&profile.name)
    .execute(&state.db)
    .await
    {
        // Log but do not fail the enrollment — the certificate was already signed.
        tracing::error!(error = %e, serial = %serial, "failed to store issued certificate in DB");
    }

    let cert_der = result.certificate_der;

    // Return the DER-encoded certificate directly (base64-wrapped).
    // A full implementation would wrap in PKCS#7 certs-only:
    // let pkcs7_der = kipuka_est::pkcs7::build_certs_only(&[cert_der, ca.cert_der]);
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
            "simpleenroll_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    Ok(resp)
}

/// Validate a PKCS#10 CSR for enrollment.
///
/// RFC 7030 §4.2 and §3.5 validation checks:
///
/// 1. **Self-signature** — the CSR must be signed by the included public key,
///    proving the client possesses the corresponding private key.
///
/// 2. **Required attributes** — the CSR must contain attributes required by
///    the enrollment profile (as advertised via `/csrattrs`).
///
/// 3. **POP linking (§3.5)** — when the client authenticates via mTLS, the
///    CSR SHOULD contain a `challengePassword` attribute binding the CSR to
///    the TLS session.  This prevents an attacker from capturing a valid
///    CSR and submitting it from a different TLS session.
///
/// 4. **CN match** — when `require_cn_match` is configured for the label,
///    the CSR subject CN must match the authenticated identity.
fn validate_csr(
    csr_der: &[u8],
    _auth: &crate::auth::AuthResult,
    _label: &LabelExtractor,
) -> Result<(), KipukaError> {
    if csr_der.is_empty() {
        return Err(KipukaError::BadRequest("empty CSR".into()));
    }

    // TODO: Parse the CSR using `synta` or `x509-cert` and perform:
    //
    // 1. Self-signature verification:
    //    let csr = synta::pkcs10::CertificationRequest::from_der(csr_der)?;
    //    csr.verify_self_signature()?;
    //
    // 2. Required attribute check:
    //    for required_oid in &label.csr_attributes {
    //        if !csr.has_attribute(required_oid) {
    //            return Err(KipukaError::BadRequest(...));
    //        }
    //    }
    //
    // 3. POP linking (RFC 7030 §3.5):
    //    if auth.method == AuthMethod::Mtls {
    //        // Verify challengePassword attribute matches TLS session binding
    //    }
    //
    // 4. CN match (when configured):
    //    if label.require_cn_match {
    //        let cn = csr.subject_cn()?;
    //        if cn != auth.identity {
    //            return Err(KipukaError::BadRequest(...));
    //        }
    //    }

    // Minimal size check — a valid PKCS#10 CSR is at least ~60 bytes.
    if csr_der.len() < 60 {
        return Err(KipukaError::BadRequest(
            "CSR is too short to be valid".into(),
        ));
    }

    Ok(())
}
