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
    let _ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Forward the CSR to the CA for signing.
    //
    // TODO: Implement actual certificate issuance via `kipuka_est::issue`.
    //
    // The implementation should:
    // 1. Parse the CSR and extract the public key and requested extensions
    // 2. Apply the enrollment profile (from label config)
    // 3. Build the TBSCertificate with the CA's issuer DN
    // 4. Sign with the CA's private key
    // 5. Return the DER-encoded certificate
    //
    // let cert_der = kipuka_est::issue::sign_csr(ca, &csr_der, &label).await?;
    let cert_der: Vec<u8> = Vec::new(); // Placeholder

    if cert_der.is_empty() {
        return Err(KipukaError::Ca(
            "certificate issuance not yet implemented".into(),
        ));
    }

    // Wrap the certificate in a PKCS#7 certs-only response.
    // In a full implementation: kipuka_est::pkcs7::build_certs_only(&[cert_der, ca.cert_der])
    let pkcs7_der = cert_der; // Placeholder

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
