//! `POST /.well-known/est/fullcmc` — Full CMC Request.
//!
//! RFC 7030 §4.3: EST clients submit a Full CMC request (PKCS#7 SignedData
//! containing a CMC PKIData) for complex enrollment scenarios that require
//! RA intermediation.
//!
//! The signer of the CMC request MUST hold the id-kp-cmcRA EKU
//! (OID 1.3.6.1.5.5.7.3.28) per RHELBU-3536 R15.
//!
//! The server parses the CMC PKIData, extracts certification requests,
//! issues certificates for each one (or proxies to Dogtag if configured),
//! and returns a CMC PKIResponse.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use synta_cmc::builder::PKIResponseBuilder;
use synta_cmc::controls::{extract_sender_nonce, extract_transaction_id};
use synta_cmc::parser;
use synta_cmc::status::CMCFailInfo;

use crate::auth::{AuthMethod, EstAuth};
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::est::{content_types, decode_est_base64, encode_est_base64};
use crate::state::AppState;

/// Map a `CMCFailInfo` to a `KipukaError`.
///
/// Uses `CMCFailInfo::http_status()` to determine the HTTP status code,
/// then selects the appropriate `KipukaError` variant.
///
/// Currently used by tests; will be used in future CMC validation paths.
#[allow(dead_code)]
fn cmc_fail_to_error(fail: CMCFailInfo, detail: &str) -> KipukaError {
    let http_status = fail.http_status();
    match http_status {
        400 => KipukaError::BadRequest(format!("CMC error ({fail:?}): {detail}")),
        403 => KipukaError::Auth(format!("CMC error ({fail:?}): {detail}")),
        404 => KipukaError::NotFound,
        503 => KipukaError::ServiceUnavailable(format!("CMC error ({fail:?}): {detail}")),
        _ => KipukaError::Ca(format!("CMC error ({fail:?}): {detail}")),
    }
}

/// `POST /.well-known/est/fullcmc`
///
/// Accepts a CMC request (PKCS#7 SignedData) and returns a CMC response.
///
/// # Authentication
///
/// Requires mTLS with a certificate carrying the id-kp-cmcRA EKU
/// (OID 1.3.6.1.5.5.7.3.28, RHELBU-3536 R15).
///
/// # Request
///
/// | Header         | Value                                        |
/// |----------------|----------------------------------------------|
/// | Content-Type   | `application/pkcs7-mime; smime-type=CMC-request` |
/// | Body           | Base64-encoded DER PKCS#7 SignedData (CMC PKIData) |
///
/// # Response
///
/// | Header         | Value                                        |
/// |----------------|----------------------------------------------|
/// | Status         | `200 OK`                                     |
/// | Content-Type   | `application/pkcs7-mime; smime-type=CMC-response` |
///
/// # Errors
///
/// - `400 Bad Request` — malformed CMC request
/// - `401 Unauthorized` — authentication failed
/// - `403 Forbidden` — signer lacks id-kp-cmcRA EKU
/// - `500 Internal Server Error` — CA backend error
pub async fn post_fullcmc(
    auth: EstAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();
    let identity = &auth.0.identity;

    // Check that fullcmc is enabled in the configuration.
    if !state.config.est.fullcmc {
        return Err(KipukaError::Est("Full CMC is not enabled".into()));
    }

    // Full CMC requires mTLS authentication.
    if auth.0.method != AuthMethod::Mtls {
        return Err(KipukaError::Auth(
            "Full CMC requires mTLS client certificate authentication".into(),
        ));
    }

    // RHELBU-3536 R15: Validate that the signer certificate carries the
    // id-kp-cmcRA Extended Key Usage.
    if !auth.0.has_cmc_ra_eku() {
        tracing::warn!(
            identity = %identity,
            "fullcmc rejected: signer lacks id-kp-cmcRA EKU"
        );
        return Err(KipukaError::Auth(format!(
            "CMC signer certificate must have id-kp-cmcRA EKU ({})",
            crate::auth::CMC_RA_EKU_OID,
        )));
    }

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        identity = %identity,
        "fullcmc request"
    );

    // Decode the base64-encoded CMC request.
    let cmc_request_der = decode_est_base64(&body).map_err(|_e| {
        tracing::debug!(error = %_e, "CMC request base64 decoding failed");
        KipukaError::BadRequest("malformed CMC request".into())
    })?;

    if cmc_request_der.is_empty() {
        return Err(KipukaError::BadRequest("empty CMC request".into()));
    }

    // ── Dogtag CMC passthrough ──────────────────────────────────────────────
    //
    // If a Dogtag backend is configured, forward the raw CMC request to
    // Dogtag's profileSubmitCMCFull endpoint and relay the response.
    // This is a pure passthrough: kipuka does not interpret the CMC
    // message content when Dogtag handles it.
    if let Some(ref dogtag_pool) = state.dogtag {
        let client = dogtag_pool
            .get_client()
            .map_err(|e| KipukaError::ServiceUnavailable(format!("Dogtag CA unavailable: {e}")))?;

        tracing::info!(
            ca_id = %ca_id,
            identity = %identity,
            cmc_size = cmc_request_der.len(),
            "forwarding Full CMC request to Dogtag CA"
        );

        let response_der = client
            .submit_cmc_request(&cmc_request_der)
            .await
            .map_err(|e| KipukaError::Ca(format!("Dogtag CMC passthrough failed: {e}")))?;

        let body = encode_est_base64(&response_der);
        let mut resp = (StatusCode::OK, body).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_types::CMC_RESPONSE),
        );
        resp.headers_mut().insert(
            header::HeaderName::from_static("content-transfer-encoding"),
            HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
        );

        state
            .record_audit_event(
                "fullcmc_success",
                &format!("ca_id={ca_id}, identity={identity}, backend=dogtag"),
            )
            .await;

        return Ok(resp);
    }

    // ── Direct-signing path (no Dogtag) ─────────────────────────────────────

    // Look up the CA backend.
    let ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Step 1: Verify the CMS SignedData signature and extract the PKIData content.
    //
    // RFC 5272 §5 requires RA signature verification against the CA's
    // truststore.  When `cmc_truststore_file` is configured, RA certs
    // issued by a different CA or intermediate are accepted. Otherwise
    // the target CA cert is the sole trust anchor.
    let truststore: Vec<Vec<u8>> = if let Some(ref ts_file) = state.config.est.cmc_truststore_file {
        let pem_data = tokio::fs::read(ts_file).await.map_err(|e| {
            KipukaError::Ca(format!("failed to read CMC truststore {ts_file}: {e}"))
        })?;
        let certs: Vec<Vec<u8>> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(&pem_data[..]))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    KipukaError::Ca(format!(
                        "malformed PEM certificate in CMC truststore {ts_file}: {e}"
                    ))
                })?
                .into_iter()
                .map(|c| c.to_vec())
                .collect();
        if certs.is_empty() {
            return Err(KipukaError::Ca(format!(
                "CMC truststore {ts_file} contains no certificates"
            )));
        }
        certs
    } else {
        vec![ca.cert_der.clone()]
    };
    let cms_result = crate::auth::cms_auth::verify_cms_signed_data(&cmc_request_der, &truststore)?;
    let pki_data_der = cms_result.payload;

    tracing::info!(
        signer_dn = %cms_result.signer_subject_dn,
        sig_alg = %cms_result.signature_algorithm,
        "CMC SignedData signature verified"
    );

    if pki_data_der.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMC SignedData has empty eContent".into(),
        ));
    }

    // Step 2: Parse the PKIData to extract controls and certification requests.
    let pki_data = parser::parse_pki_data(&pki_data_der).map_err(|e| {
        tracing::warn!(error = %e, "CMC PKIData parse failed");
        KipukaError::BadRequest("malformed CMC request".into())
    })?;

    // Step 3: Extract control attributes for audit and response construction.
    let transaction_id = extract_transaction_id(&pki_data.controls);
    let sender_nonce = extract_sender_nonce(&pki_data.controls);

    let control_names: Vec<String> = pki_data
        .controls
        .iter()
        .map(|c| format!("{:?}", c.oid))
        .collect();

    tracing::info!(
        ca_id = %ca_id,
        identity = %identity,
        transaction_id = ?transaction_id,
        num_requests = pki_data.certification_requests.len(),
        num_controls = pki_data.controls.len(),
        controls = ?control_names,
        "CMC PKIData parsed"
    );

    if pki_data.certification_requests.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMC request contains no certification requests".into(),
        ));
    }

    // Step 4: Process each certification request.
    //
    // The direct signing path iterates PKCS#10 CSRs and issues certificates
    // using the same `issue_certificate()` function as simpleenroll.
    // CRMF requests are not yet supported for direct signing.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    // Resolve key material.
    let resolved_key = crate::ca::issue::resolve_signing_key(ca_cfg, state.hsm.as_ref()).await?;

    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(crate::ca::issue::cab_forum_max_validity_days()),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    let mut issued_certs: Vec<Vec<u8>> = Vec::new();
    let mut body_part_ids: Vec<u32> = Vec::new();
    let mut failed_body_part_ids: Vec<u32> = Vec::new();

    for entry in &pki_data.certification_requests {
        let body_part_id = entry.body_part_id;

        if entry.request_type == synta_cmc::parser::RequestType::Pkcs10 {
            match crate::ca::issue::issue_certificate(
                &entry.der,
                &profile,
                &ca.cert_der,
                resolved_key.as_signing_key(),
                &ca.hash_algorithm,
                ca.ocsp_url.as_deref(),
                ca.crl_url.as_deref(),
            ) {
                Ok(result) => {
                    tracing::info!(
                        body_part_id,
                        serial = %result.serial_number,
                        subject = %result.subject_dn,
                        "CMC: certificate issued for PKCS#10 request"
                    );

                    let serial = &result.serial_number;
                    let subject_dn = &result.subject_dn;
                    let issuer_dn = match synta_certificate::Certificate::from_der(&ca.cert_der) {
                        Ok(c) => synta_certificate::format_dn(c.tbs_certificate.subject.0),
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to parse CA certificate for issuer DN");
                            String::from("unknown")
                        }
                    };
                    let not_before_str = result.not_before.format("%Y-%m-%dT%H:%M:%SZ").to_string();
                    let not_after_str = result.not_after.format("%Y-%m-%dT%H:%M:%SZ").to_string();

                    match sqlx::query(crate::db::pg_sql(
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
                        Ok(_) => {
                            issued_certs.push(result.certificate_der);
                            body_part_ids.push(body_part_id);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, serial = %serial, "failed to store CMC-issued certificate in DB");
                            failed_body_part_ids.push(body_part_id);
                            state.record_audit_event(
                                "fullcmc_db_error",
                                &format!("ca_id={ca_id}, serial={serial}, error={e}"),
                            ).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(body_part_id, error = %e, "CMC: certificate issuance failed");
                    failed_body_part_ids.push(body_part_id);
                    state.record_audit_event(
                        "fullcmc_request_failed",
                        &format!("ca_id={ca_id}, identity={identity}, body_part_id={body_part_id}, error={e}"),
                    ).await;
                }
            }
        } else {
            tracing::warn!(body_part_id, request_type = ?entry.request_type, "CMC: non-PKCS#10 requests not yet supported");
            failed_body_part_ids.push(body_part_id);
            state.record_audit_event(
                "fullcmc_request_failed",
                &format!("ca_id={ca_id}, identity={identity}, body_part_id={body_part_id}, reason=unsupported request type {:?}", entry.request_type),
            ).await;
        }
    }

    // Step 5: Build the PKIResponse.
    let mut resp_builder = PKIResponseBuilder::new();

    if !body_part_ids.is_empty() {
        resp_builder = resp_builder
            .add_status(&body_part_ids)
            .map_err(|e| KipukaError::Ca(format!("CMC response builder failed (status): {e}")))?;
    }

    if !failed_body_part_ids.is_empty() {
        resp_builder = resp_builder
            .add_failed(&failed_body_part_ids, CMCFailInfo::InternalCaError)
            .map_err(|e| {
                KipukaError::Ca(format!("CMC response builder failed (failed status): {e}"))
            })?;
    }

    // Echo the sender nonce as recipient nonce per RFC 5272 §6.6.
    if let Some(nonce) = &sender_nonce {
        resp_builder = resp_builder.recipient_nonce(nonce).map_err(|e| {
            KipukaError::Ca(format!(
                "CMC response builder failed (recipient nonce): {e}"
            ))
        })?;
    }

    // Generate a fresh sender nonce for the response.
    let response_nonce: Vec<u8> = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut n = vec![0u8; 16];
        rng.fill(&mut n[..]);
        n
    };
    resp_builder = resp_builder
        .sender_nonce(&response_nonce)
        .map_err(|e| KipukaError::Ca(format!("CMC response builder failed (sender nonce): {e}")))?;

    let pki_response_der = resp_builder
        .build()
        .map_err(|e| KipukaError::Ca(format!("CMC PKIResponse build failed: {e}")))?;

    // Step 6: Encode the response as base64.
    let body = encode_est_base64(&pki_response_der);

    let status_code = if body_part_ids.is_empty() && !failed_body_part_ids.is_empty() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    let mut resp = (status_code, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_types::CMC_RESPONSE),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
    );

    let audit_event = if failed_body_part_ids.is_empty() {
        "fullcmc_success"
    } else if body_part_ids.is_empty() {
        "fullcmc_failed"
    } else {
        "fullcmc_partial"
    };

    state
        .record_audit_event(
            audit_event,
            &format!(
                "ca_id={ca_id}, identity={identity}, transaction_id={:?}, requests={}, issued={}, failed={}",
                transaction_id,
                pki_data.certification_requests.len(),
                issued_certs.len(),
                failed_body_part_ids.len()
            ),
        )
        .await;

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_cmc::status::CMCFailInfo;

    #[test]
    fn cmc_fail_bad_request_maps_to_400() {
        let err = cmc_fail_to_error(CMCFailInfo::BadRequest, "test");
        assert!(
            matches!(err, KipukaError::BadRequest(_)),
            "BadRequest should map to KipukaError::BadRequest"
        );
    }

    #[test]
    fn cmc_fail_bad_alg_maps_to_400() {
        let err = cmc_fail_to_error(CMCFailInfo::BadAlg, "test");
        assert!(
            matches!(err, KipukaError::BadRequest(_)),
            "BadAlg should map to KipukaError::BadRequest"
        );
    }

    #[test]
    fn cmc_fail_bad_message_check_maps_to_400() {
        let err = cmc_fail_to_error(CMCFailInfo::BadMessageCheck, "test");
        assert!(
            matches!(err, KipukaError::BadRequest(_)),
            "BadMessageCheck should map to KipukaError::BadRequest"
        );
    }

    #[test]
    fn cmc_fail_bad_time_maps_to_400() {
        let err = cmc_fail_to_error(CMCFailInfo::BadTime, "test");
        assert!(
            matches!(err, KipukaError::BadRequest(_)),
            "BadTime should map to KipukaError::BadRequest"
        );
    }

    #[test]
    fn cmc_fail_bad_identity_maps_to_403() {
        let err = cmc_fail_to_error(CMCFailInfo::BadIdentity, "test");
        assert!(
            matches!(err, KipukaError::Auth(_)),
            "BadIdentity should map to KipukaError::Auth (403)"
        );
    }

    #[test]
    fn cmc_fail_pop_failed_maps_to_403() {
        let err = cmc_fail_to_error(CMCFailInfo::PopFailed, "test");
        assert!(
            matches!(err, KipukaError::Auth(_)),
            "PopFailed should map to KipukaError::Auth (403)"
        );
    }

    #[test]
    fn cmc_fail_pop_required_maps_to_403() {
        let err = cmc_fail_to_error(CMCFailInfo::PopRequired, "test");
        assert!(
            matches!(err, KipukaError::Auth(_)),
            "PopRequired should map to KipukaError::Auth (403)"
        );
    }

    #[test]
    fn cmc_fail_auth_data_fail_maps_to_403() {
        let err = cmc_fail_to_error(CMCFailInfo::AuthDataFail, "test");
        assert!(
            matches!(err, KipukaError::Auth(_)),
            "AuthDataFail should map to KipukaError::Auth (403)"
        );
    }

    #[test]
    fn cmc_fail_bad_cert_id_maps_to_404() {
        let err = cmc_fail_to_error(CMCFailInfo::BadCertId, "test");
        assert!(
            matches!(err, KipukaError::NotFound),
            "BadCertId should map to KipukaError::NotFound"
        );
    }

    #[test]
    fn cmc_fail_internal_ca_error_maps_to_500() {
        let err = cmc_fail_to_error(CMCFailInfo::InternalCaError, "test");
        assert!(
            matches!(err, KipukaError::Ca(_)),
            "InternalCaError should map to KipukaError::Ca (500)"
        );
    }

    #[test]
    fn cmc_fail_try_later_maps_to_503() {
        let err = cmc_fail_to_error(CMCFailInfo::TryLater, "test");
        assert!(
            matches!(err, KipukaError::ServiceUnavailable(_)),
            "TryLater should map to KipukaError::ServiceUnavailable (503)"
        );
    }
}
