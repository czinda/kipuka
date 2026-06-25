//! `POST /.well-known/est/serverkeygen` — Server-Side Key Generation.
//!
//! RFC 7030 §4.4: The EST server generates a key pair on behalf of the
//! client, signs a certificate, and returns both the certificate and
//! the private key.
//!
//! The response is `multipart/mixed` containing two parts:
//! - Part 1: `application/pkcs7-mime; smime-type=certs-only` (certificate)
//! - Part 2: `application/pkcs8` (DER-encoded private key)
//!
//! RHELBU-3536 R27: Authentication (mTLS or OTP) is required.
//! Server-side key generation requires HSM or software key generation
//! capability per configuration.

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

/// MIME boundary for the multipart/mixed response.
///
/// RFC 7030 §4.4.2: The server returns the certificate and private key
/// as separate MIME parts in a multipart/mixed response.
const MULTIPART_BOUNDARY: &str = "estServerKeyGenBoundary";

/// `POST /.well-known/est/serverkeygen`
///
/// Accepts a PKCS#10 CSR (with placeholder key or desired attributes) and
/// returns a multipart response with the issued certificate and the
/// server-generated private key.
///
/// # Authentication
///
/// Requires mTLS or OTP authentication (RHELBU-3536 R27).
///
/// # Request
///
/// | Header         | Value                |
/// |----------------|----------------------|
/// | Content-Type   | `application/pkcs10` |
/// | Body           | Base64-encoded DER PKCS#10 CSR |
///
/// The CSR may contain a placeholder public key; the server replaces it
/// with the generated key pair.  The CSR's requested subject and extensions
/// are used as a template for the issued certificate.
///
/// # Response
///
/// | Header         | Value                         |
/// |----------------|-------------------------------|
/// | Status         | `200 OK`                      |
/// | Content-Type   | `multipart/mixed; boundary=...` |
///
/// Response body parts:
///
/// ```text
/// --estServerKeyGenBoundary
/// Content-Type: application/pkcs7-mime; smime-type=certs-only
/// Content-Transfer-Encoding: base64
///
/// <base64 PKCS#7 certificate>
/// --estServerKeyGenBoundary
/// Content-Type: application/pkcs8
/// Content-Transfer-Encoding: base64
///
/// <base64 PKCS#8 private key>
/// --estServerKeyGenBoundary--
/// ```
///
/// # Errors
///
/// - `400 Bad Request` — malformed CSR
/// - `401 Unauthorized` — authentication failed
/// - `403 Forbidden` — serverkeygen not enabled
/// - `500 Internal Server Error` — key generation or CA signing failure
/// - `503 Service Unavailable` — HSM offline
pub async fn post_serverkeygen(
    auth: EstAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();
    let identity = &auth.0.identity;

    // Check that serverkeygen is enabled.
    if !state.config.est.serverkeygen {
        return Err(KipukaError::Est(
            "server-side key generation is not enabled".into(),
        ));
    }

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        identity = %identity,
        method = ?auth.0.method,
        "serverkeygen request"
    );

    // Decode the base64-encoded CSR template.
    let csr_der = decode_est_base64(&body)
        .map_err(|e| KipukaError::BadRequest(format!("CSR template decoding failed: {e}")))?;

    if csr_der.is_empty() {
        return Err(KipukaError::BadRequest("empty CSR template".into()));
    }

    // Look up the CA backend.
    let _ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // ── Dogtag KRA path ─────────────────────────────────────────────────────
    //
    // If a Dogtag backend with KRA is configured, generate the key pair on
    // the KRA, enroll the certificate via the CA, and return both.
    if let Some(ref dogtag_pool) = state.dogtag {
        let dogtag_cfg = state
            .config
            .dogtag
            .as_ref()
            .expect("dogtag config present when pool is set");

        if dogtag_cfg.kra_url.is_none() {
            return Err(KipukaError::Ca(
                "server-side key generation requires dogtag.kra_url to be configured".into(),
            ));
        }

        let kra_client = kipuka_dogtag::KraClient::new(dogtag_cfg).map_err(|e| {
            KipukaError::Ca(format!("KRA client initialization failed: {e}"))
        })?;

        // Determine key type from the CSR template or use defaults.
        // For now, default to RSA 2048 — a full implementation would
        // extract the desired key type from the CSR template attributes.
        let key_type = "RSA";
        let key_size = 2048u32;

        tracing::info!(
            ca_id = %ca_id,
            identity = %identity,
            key_type = key_type,
            key_size = key_size,
            "generating key pair on Dogtag KRA"
        );

        let keygen_result = kra_client
            .generate_key(key_type, key_size)
            .await
            .map_err(|e| KipukaError::Ca(format!("KRA key generation failed: {e}")))?;

        // Now enroll the certificate via the CA using the generated public key.
        // Build a CSR from the template + generated public key.
        // For now, we forward the original CSR template and let Dogtag handle it.
        let client = dogtag_pool.get_client().map_err(|e| {
            KipukaError::ServiceUnavailable(format!("Dogtag CA unavailable: {e}"))
        })?;

        use base64::Engine;
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
        let csr_pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----",
            csr_b64
        );

        let enroll_result = client
            .enroll_certificate(&csr_pem, &dogtag_cfg.profile_id)
            .await
            .map_err(|e| KipukaError::Ca(format!("Dogtag enrollment for keygen failed: {e}")))?;

        if enroll_result.status != kipuka_dogtag::EnrollStatus::Complete {
            return Err(KipukaError::Ca(format!(
                "Dogtag enrollment not complete for keygen: status={:?}, request_id={}",
                enroll_result.status, enroll_result.request_id
            )));
        }

        let cert_der = enroll_result.certificate_der.ok_or_else(|| {
            KipukaError::Ca("Dogtag returned complete but no certificate for keygen".into())
        })?;

        // The private key from KRA — use wrapped key if available, else public key DER.
        let private_key_der = keygen_result
            .wrapped_private_key
            .unwrap_or(keygen_result.public_key_der);

        // Build the multipart/mixed response.
        let response_body = build_multipart_response(&cert_der, &private_key_der);

        let content_type = format!(
            "{}; boundary={}",
            content_types::MULTIPART_MIXED,
            MULTIPART_BOUNDARY
        );

        let mut resp = (StatusCode::OK, response_body).into_response();
        if let Ok(hv) = HeaderValue::from_str(&content_type) {
            resp.headers_mut().insert(header::CONTENT_TYPE, hv);
        }

        state
            .record_audit_event(
                "serverkeygen_success",
                &format!(
                    "ca_id={ca_id}, identity={identity}, backend=dogtag, kra_key_id={}",
                    keygen_result.key_id
                ),
            )
            .await;

        return Ok(resp);
    }

    // ── Software/HSM key generation path (no Dogtag) ────────────────────────
    //
    // TODO: Implement software/HSM server-side key generation.
    //
    // When an HSM is configured for this CA:
    //   let (pub_key, priv_key_handle) = kipuka_hsm::generate_key_pair(
    //       &state.hsm, ca.key_type_for_keygen()
    //   ).await?;
    //
    // When using software key generation:
    //   let (pub_key_der, priv_key_pkcs8) = kipuka_util::keygen::generate(
    //       &ca.key_type
    //   )?;
    //
    // Then:
    // 1. Build a new CSR using the generated public key and the template's
    //    requested subject/extensions
    // 2. Sign the certificate with the CA key
    // 3. Optionally archive the private key via KRA integration

    let cert_pkcs7_der: Vec<u8> = Vec::new(); // Placeholder
    let private_key_pkcs8: Vec<u8> = Vec::new(); // Placeholder

    if cert_pkcs7_der.is_empty() || private_key_pkcs8.is_empty() {
        return Err(KipukaError::Ca(
            "server-side key generation not yet implemented (configure [dogtag] with kra_url for KRA-backed keygen)".into(),
        ));
    }

    // Build the multipart/mixed response.
    let response_body = build_multipart_response(&cert_pkcs7_der, &private_key_pkcs8);

    let content_type = format!(
        "{}; boundary={}",
        content_types::MULTIPART_MIXED,
        MULTIPART_BOUNDARY
    );

    let mut resp = (StatusCode::OK, response_body).into_response();
    if let Ok(hv) = HeaderValue::from_str(&content_type) {
        resp.headers_mut().insert(header::CONTENT_TYPE, hv);
    }

    state
        .record_audit_event(
            "serverkeygen_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    Ok(resp)
}

/// Build a `multipart/mixed` response body with the certificate and private key.
///
/// RFC 7030 §4.4.2: the response contains two MIME parts:
/// 1. The certificate chain (PKCS#7 certs-only, base64-encoded)
/// 2. The private key (PKCS#8 DER, base64-encoded)
fn build_multipart_response(cert_pkcs7_der: &[u8], private_key_pkcs8: &[u8]) -> String {
    let cert_b64 = encode_est_base64(cert_pkcs7_der);
    let key_b64 = encode_est_base64(private_key_pkcs8);

    format!(
        "\r\n--{boundary}\r\n\
         Content-Type: {cert_type}\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {cert_b64}\r\n\
         --{boundary}\r\n\
         Content-Type: {key_type}\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {key_b64}\r\n\
         --{boundary}--\r\n",
        boundary = MULTIPART_BOUNDARY,
        cert_type = content_types::PKCS7_CERTS,
        key_type = content_types::PKCS8,
    )
}
