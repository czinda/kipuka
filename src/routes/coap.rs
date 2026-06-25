//! EST-over-CoAP bridge (RFC 9483).
//!
//! This module implements the [`kipuka_coap::EstHandler`] trait, bridging
//! parsed CoAP EST requests to the shared EST enrollment logic.  It lives
//! in the main crate (not in `kipuka-coap`) so that it can access
//! [`AppState`], CA signing functions, and the database.
//!
//! The handler is synchronous (matching the `EstHandler` trait contract),
//! using [`crate::ca::issue::resolve_signing_key_sync`] for key material
//! and [`crate::ca::issue::issue_certificate`] for certificate issuance.

use std::sync::Arc;

use kipuka_coap::dtls::ClientCertInfo;
use kipuka_coap::server::EstOperation;
use kipuka_coap::CoapError;

use crate::state::AppState;

/// EST handler implementation that bridges CoAP requests to shared
/// enrollment logic.
///
/// Constructed with a reference to the application state and passed
/// to [`CoapDtlsServer::run()`](kipuka_coap::CoapDtlsServer::run)
/// at startup.
pub struct CoapEstHandler {
    state: Arc<AppState>,
}

impl CoapEstHandler {
    /// Create a new CoAP EST handler wrapping the application state.
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl kipuka_coap::EstHandler for CoapEstHandler {
    fn handle(
        &self,
        operation: EstOperation,
        payload: &[u8],
        _content_format: Option<u16>,
        client_cert: Option<&ClientCertInfo>,
    ) -> Result<(Vec<u8>, u16), CoapError> {
        match operation {
            EstOperation::CaCerts => handle_cacerts(&self.state),
            EstOperation::SimpleEnroll => handle_simpleenroll(payload, &self.state),
            EstOperation::SimpleReenroll => handle_simplereenroll(payload, client_cert, &self.state),
            EstOperation::CsrAttrs => handle_csrattrs(&self.state),
            EstOperation::ServerKeygen => Err(CoapError::Internal(
                "server key generation not yet implemented for CoAP transport".into(),
            )),
        }
    }
}

/// Handle GET /cacerts — return the CA certificate chain as PKCS#7 certs-only.
///
/// RFC 9483 §5.1: The response Content-Format is 281
/// (`application/pkcs7-mime; smime-type=certs-only`).
///
/// Unlike the HTTP handler, the CoAP response is raw DER (not base64).
fn handle_cacerts(state: &Arc<AppState>) -> Result<(Vec<u8>, u16), CoapError> {
    let ca = state.default_ca();

    let pkcs7_der = crate::routes::cacerts::build_certs_only_pkcs7(&ca.cert_der)
        .map_err(|e| CoapError::Internal(format!("PKCS#7 build failed: {e}")))?;

    tracing::debug!(ca_id = %ca.id, "CoAP /cacerts served");

    Ok((
        pkcs7_der,
        kipuka_coap::content_format::APPLICATION_PKCS7_MIME_CERTS_ONLY,
    ))
}

/// Handle POST /simpleenroll — issue a certificate from a PKCS#10 CSR.
///
/// RFC 9483 §5.3: The request Content-Format is 285 (`application/pkcs10`),
/// carrying the DER-encoded CSR directly (no base64 wrapping).
///
/// Uses the synchronous key resolution path
/// ([`crate::ca::issue::resolve_signing_key_sync`]) since the `EstHandler`
/// trait is synchronous.
fn handle_simpleenroll(
    csr_der: &[u8],
    state: &Arc<AppState>,
) -> Result<(Vec<u8>, u16), CoapError> {
    if csr_der.is_empty() {
        return Err(CoapError::InvalidMessage("empty CSR payload".into()));
    }

    let ca = state.default_ca();
    let ca_id = &ca.id;

    // Find the CA config entry.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == *ca_id)
        .ok_or_else(|| CoapError::Internal(format!("CA config not found for id={ca_id}")))?;

    // Resolve the signing key synchronously (filesystem read or HSM lookup).
    let resolved_key =
        crate::ca::issue::resolve_signing_key_sync(ca_cfg, state.hsm.as_ref())
            .map_err(|e| CoapError::Internal(format!("signing key resolution failed: {e}")))?;

    // Build a default enrollment profile.
    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(398),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    // Issue the certificate using the shared issuance logic.
    let result = crate::ca::issue::issue_certificate(
        csr_der,
        &profile,
        &ca.cert_der,
        resolved_key.as_signing_key(),
        &ca.hash_algorithm,
    )
    .map_err(|e| CoapError::Internal(format!("certificate issuance failed: {e}")))?;

    tracing::info!(
        ca_id = %ca_id,
        serial = %result.serial_number,
        subject = %result.subject_dn,
        "CoAP simpleenroll: certificate issued"
    );

    // Wrap the issued certificate in PKCS#7 certs-only (reuses cacerts builder).
    let pkcs7_der = crate::routes::cacerts::build_certs_only_pkcs7(&result.certificate_der)
        .map_err(|e| CoapError::Internal(format!("PKCS#7 wrap failed: {e}")))?;

    Ok((
        pkcs7_der,
        kipuka_coap::content_format::APPLICATION_PKCS7_MIME_CERTS_ONLY,
    ))
}

/// Handle POST /simplereenroll — re-enroll using existing DTLS client certificate.
///
/// RFC 9483 §5.3: For re-enrollment, the client authenticates using its
/// existing certificate via DTLS client auth, and submits a new CSR.
fn handle_simplereenroll(
    csr_der: &[u8],
    client_cert: Option<&ClientCertInfo>,
    state: &Arc<AppState>,
) -> Result<(Vec<u8>, u16), CoapError> {
    // Re-enrollment requires a client certificate from the DTLS handshake.
    let _cert = client_cert.ok_or_else(|| {
        CoapError::Internal(
            "simplereenroll requires DTLS client certificate authentication".into(),
        )
    })?;

    // The certificate issuance logic is the same as simpleenroll — the auth
    // difference is in the DTLS layer (client cert vs. PSK/OTP).
    handle_simpleenroll(csr_der, state)
}

/// Handle GET /csrattrs — return CSR attributes the server expects.
///
/// RFC 9483 §5.1: The response Content-Format is 287
/// (`application/csrattrs`).
fn handle_csrattrs(state: &Arc<AppState>) -> Result<(Vec<u8>, u16), CoapError> {
    let attributes = &state.config.est.csr_attributes;

    if attributes.is_empty() {
        // No attributes configured — return empty payload.
        return Ok((
            Vec::new(),
            kipuka_coap::content_format::APPLICATION_CSRATTRS,
        ));
    }

    let csrattrs_der = crate::routes::csrattrs::encode_csr_attrs(attributes)
        .map_err(|e| CoapError::Internal(format!("CSR attributes encoding failed: {e}")))?;

    Ok((
        csrattrs_der,
        kipuka_coap::content_format::APPLICATION_CSRATTRS,
    ))
}
