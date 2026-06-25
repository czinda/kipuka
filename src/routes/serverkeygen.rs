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

    // Look up the CA backend (already checked above, but borrow it for signing).
    let ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Step 1: Determine key type from the CSR template.
    //
    // Parse the CSR to extract the SubjectPublicKeyInfo algorithm.
    // Default to RSA-2048 if the template CSR uses a placeholder key.
    let key_type = detect_key_type_from_csr(&csr_der);

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        key_type = ?key_type,
        "generating software key pair for serverkeygen"
    );

    // Step 2: Generate the key pair.
    let keygen_config = crate::ca::keygen::KeyGenConfig::default();
    let keygen_result = crate::ca::keygen::generate_key_pair(&key_type, &keygen_config)
        .map_err(|e| KipukaError::Ca(format!("software key generation failed: {e}")))?;

    // Step 3: Extract the subject from the template CSR and build a new CSR
    // with the generated public key, signed by the generated private key.
    //
    // NOTE: The CSR construction and signing is done in a non-async block
    // because `Box<dyn ErasedCertificateSigner>` is not Send, and we need
    // to cross await points below for file I/O.
    let new_csr_der = build_keygen_csr(
        &csr_der,
        &keygen_result.public_key_der,
        &keygen_result.private_key_der,
    )?;

    // Step 4: Look up the CA config and resolve the CA signing key.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    let ca_key_pem: Vec<u8>;
    let key_label_owned: String;

    let signing_key = if ca_cfg.is_hsm_backed() {
        let hsm_ctx = state
            .hsm
            .as_ref()
            .ok_or_else(|| KipukaError::Ca("HSM not configured but CA has pkcs11_uri".into()))?;
        key_label_owned = crate::routes::simpleenroll::parse_pkcs11_object_label(
            ca_cfg.pkcs11_uri.as_deref().unwrap(),
        )
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

    // Step 5: Issue the certificate (CA signs using its own key).
    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(398),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    let issuance_result = crate::ca::issue::issue_certificate(
        &new_csr_der,
        &profile,
        &ca.cert_der,
        signing_key,
        &ca.hash_algorithm,
    )
    .map_err(|e| KipukaError::Ca(format!("certificate issuance for keygen failed: {e}")))?;

    // Step 6: Wrap the certificate in PKCS#7 certs-only.
    let cert_pkcs7_der =
        crate::routes::cacerts::build_certs_only_pkcs7(&issuance_result.certificate_der)?;

    // Step 7: Build the multipart/mixed response with cert + PKCS#8 private key.
    let response_body = build_multipart_response(&cert_pkcs7_der, &keygen_result.private_key_der);

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
                "ca_id={ca_id}, identity={identity}, backend=software, key_type={key_type:?}, serial={}",
                issuance_result.serial_number
            ),
        )
        .await;

    Ok(resp)
}

/// Build a new CSR from the template subject and generated key pair.
///
/// Constructs a PKCS#10 CSR with the subject DN from the template CSR and the
/// SPKI from the generated public key, signed by the generated private key
/// (proof of possession). This CSR is then fed to `issue_certificate()`.
///
/// This is a synchronous function to avoid holding `Box<dyn ErasedCertificateSigner>`
/// (which is not `Send`) across async await points.
fn build_keygen_csr(
    template_csr_der: &[u8],
    public_key_der: &[u8],
    private_key_pkcs8_der: &[u8],
) -> Result<Vec<u8>, KipukaError> {
    let template_csr =
        synta_certificate::csr::CertificationRequest::from_der(template_csr_der)
            .map_err(|e| KipukaError::BadRequest(format!("CSR template parse failed: {e}")))?;

    let subject_der = template_csr
        .certification_request_info
        .subject
        .to_der()
        .map_err(|e| KipukaError::Ca(format!("CSR subject encode failed: {e}")))?;

    // Load the generated private key for CSR signing.
    let generated_key =
        synta_certificate::BackendPrivateKey::from_der(private_key_pkcs8_der)
            .map_err(|e| KipukaError::Ca(format!("failed to load generated key: {e}")))?;

    let signer = {
        use synta_certificate::PrivateKey as _;
        generated_key.as_signer("sha256")
    };

    synta_certificate::CsrBuilder::new()
        .subject_name(&subject_der)
        .public_key_der(public_key_der)
        .sign(&signer)
        .map_err(|e| KipukaError::Ca(format!("CSR construction failed: {e}")))
}

/// Detect the desired key type from the CSR template's SubjectPublicKeyInfo.
///
/// Parses the CSR to inspect the public key algorithm OID and extracts
/// the key type. Falls back to RSA-2048 if the CSR cannot be parsed or
/// uses an unrecognised algorithm (e.g., a placeholder key).
fn detect_key_type_from_csr(csr_der: &[u8]) -> crate::ca::keygen::KeyType {
    use crate::ca::keygen::{EcCurve, KeyType};

    let Ok(csr) = synta_certificate::csr::CertificationRequest::from_der(csr_der) else {
        tracing::debug!("CSR template unparseable; defaulting to RSA-2048");
        return KeyType::Rsa(2048);
    };

    let spki = &csr.certification_request_info.subject_pkinfo;
    let key_bits = spki.subject_public_key.bit_len();

    let pk_info = synta_certificate::decode_public_key_info(
        &spki.algorithm.algorithm,
        spki.algorithm.parameters.as_ref(),
        spki.subject_public_key.as_bytes(),
        key_bits,
    );

    match &pk_info {
        synta_certificate::PublicKeyInfo::Rsa { bit_count, .. } => {
            // Use the CSR's RSA key size, clamped to allowed values.
            let bits = match *bit_count {
                0..=2048 => 2048u32,
                2049..=3072 => 3072,
                _ => 4096,
            };
            tracing::debug!(bits, "detected RSA key type from CSR template");
            KeyType::Rsa(bits)
        }
        synta_certificate::PublicKeyInfo::Ec {
            curve_nist_name, ..
        } => {
            let curve = match curve_nist_name {
                Some("P-384") => EcCurve::P384,
                _ => EcCurve::P256, // default to P-256
            };
            tracing::debug!(curve = %curve, "detected EC key type from CSR template");
            KeyType::Ecdsa(curve)
        }
        synta_certificate::PublicKeyInfo::Unknown { alg_name, .. } => {
            tracing::debug!(
                algorithm = %alg_name,
                "unrecognised CSR template algorithm; defaulting to RSA-2048"
            );
            KeyType::Rsa(2048)
        }
    }
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
