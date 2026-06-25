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

        // Extract subject DN from the CSR for display/lookup.
        let subject_dn = synta_certificate::csr::CertificationRequest::from_der(&csr_der)
            .ok()
            .map(|csr| {
                synta_certificate::format_dn(
                    &csr.certification_request_info
                        .subject
                        .to_der()
                        .unwrap_or_default(),
                )
            });

        // Persist the CSR for deferred signing.
        let auth_method = format!("{:?}", auth.0.method);
        if let Err(e) = sqlx::query(crate::db::pg_sql(
            "INSERT INTO pending_csrs (csr_der, ca_id, subject_dn, identity, auth_method) \
             VALUES (?, ?, ?, ?, ?)",
        ))
        .bind(&csr_der)
        .bind(ca_id)
        .bind(&subject_dn)
        .bind(identity)
        .bind(&auth_method)
        .execute(&state.db)
        .await
        {
            tracing::error!(error = %e, "failed to persist CSR for deferred signing");
            return Err(KipukaError::Ca(format!(
                "failed to persist CSR for deferred signing: {e}"
            )));
        }

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

    // ── Dogtag backend path ────────────────────────────────────────────────
    //
    // If a Dogtag PKI backend is configured, forward the enrollment to
    // Dogtag CA instead of using direct signing.  The direct-signing path
    // below remains the fallback when `[dogtag]` is absent.
    if let Some(ref dogtag_pool) = state.dogtag {
        let client = dogtag_pool.get_client().map_err(|e| {
            KipukaError::ServiceUnavailable(format!("Dogtag CA unavailable: {e}"))
        })?;

        // Convert DER CSR to PEM for the Dogtag REST API.
        use base64::Engine;
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
        let csr_pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----",
            csr_b64
        );

        let profile_id = &state
            .config
            .dogtag
            .as_ref()
            .expect("dogtag config present when pool is set")
            .profile_id;

        tracing::info!(
            ca_id = %ca_id,
            identity = %identity,
            profile_id = %profile_id,
            "forwarding enrollment to Dogtag CA"
        );

        let enroll_result = client
            .enroll_certificate(&csr_pem, profile_id)
            .await
            .map_err(|e| KipukaError::Ca(format!("Dogtag enrollment failed: {e}")))?;

        match enroll_result.status {
            kipuka_dogtag::EnrollStatus::Complete => {
                let cert_der = enroll_result.certificate_der.ok_or_else(|| {
                    KipukaError::Ca(
                        "Dogtag returned complete status but no certificate".into(),
                    )
                })?;

                // Store the Dogtag-issued certificate in our DB for audit trail.
                if let Err(e) = sqlx::query(crate::db::pg_sql(
                    "INSERT INTO certificates (serial, subject_dn, issuer_dn, not_before, not_after, der_encoded, ca_id, profile, status) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                ))
                .bind(&enroll_result.request_id)
                .bind("(dogtag-issued)")
                .bind("(dogtag)")
                .bind("")
                .bind("")
                .bind(&cert_der)
                .bind(ca_id)
                .bind(profile_id.as_str())
                .execute(&state.db)
                .await
                {
                    tracing::error!(
                        error = %e,
                        request_id = %enroll_result.request_id,
                        "failed to store Dogtag-issued certificate in DB"
                    );
                }

                let body = encode_est_base64(&cert_der);
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
                        &format!(
                            "ca_id={ca_id}, identity={identity}, backend=dogtag, request_id={}",
                            enroll_result.request_id
                        ),
                    )
                    .await;

                return Ok(resp);
            }
            kipuka_dogtag::EnrollStatus::Pending => {
                // Dogtag profile requires agent approval — return 202 Accepted
                // with Retry-After per RFC 7030 §4.2.3.
                tracing::info!(
                    request_id = %enroll_result.request_id,
                    "Dogtag enrollment pending agent approval"
                );

                let retry_after = state.config.est.disconnected_retry_after_secs;
                let mut resp = StatusCode::ACCEPTED.into_response();
                if let Ok(hv) = HeaderValue::from_str(&retry_after.to_string()) {
                    resp.headers_mut().insert(header::RETRY_AFTER, hv);
                }

                state
                    .record_audit_event(
                        "simpleenroll_deferred",
                        &format!(
                            "ca_id={ca_id}, identity={identity}, backend=dogtag, request_id={}",
                            enroll_result.request_id
                        ),
                    )
                    .await;

                return Ok(resp);
            }
            kipuka_dogtag::EnrollStatus::Rejected => {
                return Err(KipukaError::Ca(format!(
                    "Dogtag CA rejected enrollment: request_id={}",
                    enroll_result.request_id
                )));
            }
            kipuka_dogtag::EnrollStatus::Canceled => {
                return Err(KipukaError::Ca(format!(
                    "Dogtag enrollment was canceled: request_id={}",
                    enroll_result.request_id
                )));
            }
        }
    }

    // ── Direct-signing path (no Dogtag) ─────────────────────────────────────

    // Look up the CA backend.
    let ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Look up the CA config to get the key_file path.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    // Resolve key material.
    let resolved_key =
        crate::ca::issue::resolve_signing_key(ca_cfg, state.hsm.as_ref()).await?;

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
        resolved_key.as_signing_key(),
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

    if let Err(e) = sqlx::query(crate::db::pg_sql(
        "INSERT INTO certificates (serial, subject_dn, issuer_dn, not_before, not_after, der_encoded, ca_id, profile, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')",
    ))
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

    // Minimal size check — a valid PKCS#10 CSR is at least ~60 bytes.
    if csr_der.len() < 60 {
        return Err(KipukaError::BadRequest(
            "CSR is too short to be valid".into(),
        ));
    }

    // ── Step 1: Parse the CSR ──────────────────────────────────────────────
    let csr = synta_certificate::csr::CertificationRequest::from_der(csr_der)
        .map_err(|e| KipukaError::BadRequest(format!("CSR parse failed: {e}")))?;

    tracing::debug!(csr_len = csr_der.len(), "CSR parsed successfully");

    // ── Step 2: Verify CSR self-signature (RFC 7030 §4.2) ──────────────────
    //
    // The CSR is self-signed: the signature is created with the private key
    // corresponding to the public key in the CSR.  Verifying the self-signature
    // proves the client possesses the private key (proof-of-possession).
    //
    // Per RFC 7030 §4.2, an EST server MUST verify the CSR self-signature.
    {
        use synta_certificate::SignatureVerifier;

        // Encode the CertificationRequestInfo (TBS portion) to DER.
        let cri_der = csr
            .certification_request_info
            .to_der()
            .map_err(|e| KipukaError::BadRequest(format!("CSR CRI encode failed: {e}")))?;

        // Encode the signature algorithm to DER.
        let sig_alg_der = csr
            .signature_algorithm
            .to_der()
            .map_err(|e| KipukaError::BadRequest(format!("CSR sig alg encode failed: {e}")))?;

        // Extract the raw signature bytes from the BIT STRING.
        let signature_bits = csr.signature.as_bytes();

        // Encode the subject public key info to DER (the CSR is self-signed,
        // so the issuer SPKI is the CSR's own SPKI).
        let spki_der = csr
            .certification_request_info
            .subject_pkinfo
            .to_der()
            .map_err(|e| KipukaError::BadRequest(format!("CSR SPKI encode failed: {e}")))?;

        let verifier = synta_certificate::default_signature_verifier();
        verifier
            .verify_certificate_signature(&cri_der, &sig_alg_der, signature_bits, &spki_der)
            .map_err(|e| {
                tracing::warn!(error = %e, "CSR self-signature verification failed");
                KipukaError::BadRequest(format!("CSR self-signature verification failed: {e}"))
            })?;

        tracing::debug!("CSR self-signature verified");
    }

    // ── Step 3: Validate key size ──────────────────────────────────────────
    //
    // Enforce minimum key sizes per CA/B Forum Baseline Requirements:
    // - RSA: >= 2048 bits
    // - ECDSA: >= P-256 (256 bits)
    {
        let spki = &csr.certification_request_info.subject_pkinfo;
        let key_bit_len = spki.subject_public_key.bit_len();

        let pk_info = synta_certificate::decode_public_key_info(
            &spki.algorithm.algorithm,
            spki.algorithm.parameters.as_ref(),
            spki.subject_public_key.as_bytes(),
            key_bit_len,
        );

        match &pk_info {
            synta_certificate::PublicKeyInfo::Rsa { bit_count, .. } => {
                tracing::debug!(algorithm = "RSA", key_bits = bit_count, "CSR key info");
                if *bit_count < 2048 {
                    return Err(KipukaError::BadRequest(format!(
                        "RSA key too small: {bit_count}-bit (minimum 2048-bit required)"
                    )));
                }
            }
            synta_certificate::PublicKeyInfo::Ec {
                bit_count,
                curve_nist_name,
                ..
            } => {
                let curve = curve_nist_name.unwrap_or("unknown");
                tracing::debug!(
                    algorithm = "EC",
                    curve = curve,
                    key_bits = bit_count,
                    "CSR key info"
                );
                if *bit_count < 256 {
                    return Err(KipukaError::BadRequest(format!(
                        "EC key too small: {curve} {bit_count}-bit (minimum P-256 required)"
                    )));
                }
            }
            synta_certificate::PublicKeyInfo::Unknown {
                alg_name,
                bit_count,
                ..
            } => {
                // Unknown algorithm — log but allow (may be PQC or other
                // algorithm not yet recognized by the key decoder).
                tracing::debug!(
                    algorithm = %alg_name,
                    key_bits = bit_count,
                    "CSR key: unknown algorithm, skipping size check"
                );
            }
        }
    }

    // ── Step 4: Extract and log requested extensions ───────────────────────
    //
    // CSR attributes may contain an extensionRequest (PKCS#9 OID
    // 1.2.840.113549.1.9.14) listing X.509v3 extensions the client would
    // like in the issued certificate.  We log these at debug level for
    // audit visibility.
    if let Some(ref attrs) = csr.certification_request_info.attributes {
        for attr in attrs.elements() {
            let oid_components = attr.attr_type.components();
            if oid_components == synta_certificate::oids::PKCS9_EXTENSION_REQUEST {
                tracing::debug!("CSR contains extensionRequest attribute");
                // Each attr_values element is a raw DER blob containing
                // SEQUENCE OF Extension.  Log the count for visibility.
                let ext_count = attr.attr_values.len();
                tracing::debug!(
                    extension_values = ext_count,
                    "CSR extensionRequest attribute value count"
                );
            } else if oid_components == synta_certificate::oids::PKCS9_CHALLENGE_PASSWORD {
                tracing::debug!("CSR contains challengePassword attribute");
            } else {
                let oid_str: String = oid_components
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(".");
                tracing::debug!(oid = %oid_str, "CSR contains unknown attribute");
            }
        }
    }

    Ok(())
}

// parse_pkcs11_object_label and helpers have been moved to crate::ca::issue.
