//! mTLS client certificate authentication for EST endpoints.
//!
//! RFC 7030 §3.3.2: EST servers that support certificate-based client
//! authentication extract the client certificate from the TLS session
//! and validate it against the EST-dedicated truststore.
//!
//! This module handles:
//!
//! - Certificate extraction from the TLS session (request extension)
//! - Validation against the EST truststore (separate from admin truststore,
//!   per RHELBU-3536 R18)
//! - Subject DN and SAN extraction for identity matching
//! - EKU validation (id-kp-cmcRA for `/fullcmc`, per RHELBU-3536 R15)
//! - OCSP/CRL revocation checking (RHELBU-3536 R21)
//! - POP linking: extracting TLS client cert identity for CSR subject matching

use std::sync::Arc;

use axum::http::request::Parts;
use tracing::{debug, warn};

use super::{AuthMethod, AuthResult};
use crate::state::AppState;

/// DER-encoded client certificate injected into request extensions by the
/// TLS accept loop.
///
/// Absent when the TLS listener has no client-cert requirement or the client
/// presented no certificate.
#[derive(Clone, Debug)]
pub struct PeerCertificate(pub Vec<u8>);

/// Attempt to extract and validate an mTLS client certificate.
///
/// Returns `Some(AuthResult)` if a valid client certificate is present,
/// `None` if no certificate was presented (allowing fallback to other
/// auth methods).
///
/// # Certificate validation
///
/// The TLS layer (rustls `ClientCertVerifier`) has already validated the
/// certificate chain against the EST truststore by the time this function
/// runs.  This function performs additional EST-specific checks:
///
/// - Subject DN pattern matching (if configured per label)
/// - SAN extraction for identity resolution
/// - EKU extraction for CMC RA authorization
/// - Revocation status check via OCSP stapling or CRL (RHELBU-3536 R21)
pub async fn try_extract_mtls(parts: &Parts, _app: &Arc<AppState>) -> Option<AuthResult> {
    let peer_cert = parts.extensions.get::<PeerCertificate>()?;

    debug!("mTLS client certificate present, extracting identity");

    // Parse the DER-encoded certificate to extract subject DN, SANs, and EKU.
    //
    // In a full implementation this would use `synta_certificate` or `x509-cert`
    // to parse the certificate.  For now we extract a placeholder identity
    // from the raw DER.
    let cert_der = &peer_cert.0;

    // Extract subject DN (placeholder — real implementation uses ASN.1 parsing).
    let subject_dn = extract_subject_dn(cert_der);
    let sans = extract_subject_alt_names(cert_der);
    let ekus = extract_extended_key_usage(cert_der);

    // Build the identity string: prefer the first SAN if available,
    // otherwise fall back to the subject DN.
    let identity = sans
        .first()
        .cloned()
        .or_else(|| subject_dn.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // TODO: OCSP/CRL revocation check (RHELBU-3536 R21).
    // When the CA has an OCSP responder URL configured, send an OCSP
    // request to verify the certificate has not been revoked.  Fall back
    // to CRL checking when OCSP is unavailable.
    if let Err(e) = check_revocation(cert_der, _app).await {
        warn!(error = %e, identity = %identity, "certificate revocation check failed");
        return None;
    }

    Some(AuthResult {
        identity,
        method: AuthMethod::Mtls,
        client_cert_der: Some(cert_der.to_vec()),
        subject_dn,
        subject_alt_names: sans,
        extended_key_usage: ekus,
    })
}

/// Validate that the mTLS client certificate subject matches the CSR subject.
///
/// RFC 7030 §3.5 (Proof-of-Possession): for `/simplereenroll`, the TLS
/// client certificate subject MUST match the CSR subject to prove the
/// client possesses the private key corresponding to the certificate
/// being renewed.
///
/// Returns `Ok(())` if subjects match, `Err` with a description if not.
pub fn validate_pop_linking(
    client_cert_subject: Option<&str>,
    csr_subject: &str,
) -> Result<(), String> {
    let cert_subject = client_cert_subject
        .ok_or_else(|| "mTLS certificate has no subject DN for POP linking".to_string())?;

    // Canonicalize for comparison: trim whitespace and compare case-insensitively.
    let cert_norm = cert_subject.trim().to_lowercase();
    let csr_norm = csr_subject.trim().to_lowercase();

    if cert_norm != csr_norm {
        return Err(format!(
            "POP linking failed: TLS cert subject {cert_subject:?} does not match CSR subject {csr_subject:?}"
        ));
    }

    Ok(())
}

/// Validate certificate attribute matching against configured patterns.
///
/// RHELBU-3536 R19: the EST server MAY enforce that the client certificate
/// matches configured subject DN patterns, SAN patterns, or issuer constraints.
pub fn validate_cert_attributes(
    auth: &AuthResult,
    allowed_subject_patterns: &[String],
    allowed_issuer_patterns: &[String],
) -> Result<(), String> {
    // If no patterns are configured, all certificates are accepted.
    if allowed_subject_patterns.is_empty() && allowed_issuer_patterns.is_empty() {
        return Ok(());
    }

    // Check subject DN patterns.
    if !allowed_subject_patterns.is_empty() {
        let subject = auth
            .subject_dn
            .as_deref()
            .unwrap_or("");
        let matches = allowed_subject_patterns
            .iter()
            .any(|pattern| subject.contains(pattern.as_str()));
        if !matches {
            return Err(format!(
                "certificate subject {subject:?} does not match any allowed pattern"
            ));
        }
    }

    // Issuer pattern matching would require parsing the issuer DN from the
    // certificate.  Not yet implemented.
    let _ = allowed_issuer_patterns;

    Ok(())
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Extract the subject DN from a DER-encoded certificate.
///
/// TODO: Replace with real ASN.1 parsing via `synta_certificate`.
fn extract_subject_dn(cert_der: &[u8]) -> Option<String> {
    // Placeholder: in a real implementation this would parse the X.509
    // TBSCertificate and extract the subject field.
    if cert_der.is_empty() {
        None
    } else {
        Some("CN=placeholder,O=EST Client".to_string())
    }
}

/// Extract Subject Alternative Names from a DER-encoded certificate.
///
/// TODO: Replace with real ASN.1 parsing via `synta_certificate`.
fn extract_subject_alt_names(cert_der: &[u8]) -> Vec<String> {
    let _ = cert_der;
    // Placeholder: real implementation parses the SAN extension.
    Vec::new()
}

/// Extract Extended Key Usage OIDs from a DER-encoded certificate.
///
/// TODO: Replace with real ASN.1 parsing via `synta_certificate`.
fn extract_extended_key_usage(cert_der: &[u8]) -> Vec<String> {
    let _ = cert_der;
    // Placeholder: real implementation parses the EKU extension.
    Vec::new()
}

/// Check certificate revocation status via OCSP or CRL.
///
/// RHELBU-3536 R21: the EST server SHOULD check the revocation status of
/// client certificates presented for authentication.
///
/// TODO: Implement OCSP stapled response check and CRL download/cache.
async fn check_revocation(cert_der: &[u8], _app: &Arc<AppState>) -> Result<(), String> {
    let _ = cert_der;
    // Placeholder: real implementation queries OCSP responder or checks CRL.
    Ok(())
}
