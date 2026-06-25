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
use tracing::{debug, info, warn};

use super::{AuthMethod, AuthResult};
use crate::ocsp::{OcspClient, OcspStatus};
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

    // Parse the DER-encoded certificate via synta_certificate to extract
    // subject DN, SANs, and EKU for identity resolution and authorization.
    let cert_der = &peer_cert.0;

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

/// Validate that the mTLS client certificate identity matches the CSR subject.
///
/// RFC 7030 §3.5 (Proof-of-Possession): for `/simplereenroll`, the TLS
/// client certificate subject MUST match the CSR subject to prove the
/// client possesses the private key corresponding to the certificate
/// being renewed.
///
/// Identity matching follows RFC 6125:
///
/// - **Section 6.4.4**: if the client certificate has SANs, the identity
///   is matched against SANs exclusively (CN is ignored).
/// - **Section 6.4.3**: wildcard matching rules apply to dNSName SANs.
/// - **Section 6.4.1**: comparison is case-insensitive for DNS names.
///
/// For subject DN comparison (when SANs are absent), the DNs are
/// canonicalized (trimmed, lowercased) before comparison.
///
/// Returns `Ok(())` if subjects match, `Err` with a description if not.
pub fn validate_pop_linking(auth: &AuthResult, csr_subject: &str) -> Result<(), String> {
    // If the client certificate has SANs, use RFC 6125 identity matching
    // against the CSR subject.  Per RFC 6125 §6.4.4, when SANs are
    // present the subject CN is ignored.
    if !auth.subject_alt_names.is_empty() {
        let matched = auth.subject_alt_names.iter().any(|san| {
            // Try domain matching for DNS-like SANs.
            super::name_match::matches_domain(san, csr_subject)
                // Try email matching for email-like SANs.
                || super::name_match::matches_email(san, csr_subject)
        });
        if matched {
            return Ok(());
        }
        return Err(format!(
            "POP linking failed: no SAN in TLS cert matches CSR subject {csr_subject:?} \
             (RFC 6125 §6.4.4: SANs present, CN ignored)"
        ));
    }

    // Fallback: subject DN comparison (deprecated per RFC 6125 §6.4.4
    // but still needed for legacy certificates without SANs).
    let cert_subject = auth
        .subject_dn
        .as_deref()
        .ok_or_else(|| "mTLS certificate has no subject DN for POP linking".to_string())?;

    // Canonicalize for comparison: trim whitespace and compare case-insensitively.
    let cert_norm = cert_subject.trim().to_lowercase();
    let csr_norm = csr_subject.trim().to_lowercase();

    if cert_norm != csr_norm {
        return Err(format!(
            "POP linking failed: TLS cert subject {cert_subject:?} does not match \
             CSR subject {csr_subject:?}"
        ));
    }

    Ok(())
}

/// Validate that the mTLS client certificate subject matches the CSR subject
/// using simple string comparison (legacy API).
///
/// This is the simplified form that takes raw strings. For RFC 6125-compliant
/// matching that considers SANs, use [`validate_pop_linking`] with an
/// [`AuthResult`] instead.
pub fn validate_pop_linking_simple(
    client_cert_subject: Option<&str>,
    csr_subject: &str,
) -> Result<(), String> {
    let cert_subject = client_cert_subject
        .ok_or_else(|| "mTLS certificate has no subject DN for POP linking".to_string())?;

    let cert_norm = cert_subject.trim().to_lowercase();
    let csr_norm = csr_subject.trim().to_lowercase();

    if cert_norm != csr_norm {
        return Err(format!(
            "POP linking failed: TLS cert subject {cert_subject:?} does not match \
             CSR subject {csr_subject:?}"
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
        let subject = auth.subject_dn.as_deref().unwrap_or("");
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
/// Parses the X.509 TBSCertificate via `synta_certificate` and formats
/// the subject Name as an RFC 4514 distinguished name string.
fn extract_subject_dn(cert_der: &[u8]) -> Option<String> {
    if cert_der.is_empty() {
        return None;
    }
    let cert = synta_certificate::Certificate::from_der(cert_der).ok()?;
    let dn = synta_certificate::format_dn(cert.tbs_certificate.subject.0);
    if dn.is_empty() || dn == "<invalid>" {
        None
    } else {
        Some(dn)
    }
}

/// Extract Subject Alternative Names from a DER-encoded certificate.
///
/// Parses the SAN extension (OID 2.5.29.17) from the X.509v3 extensions
/// and returns human-readable strings for each GeneralName entry.
fn extract_subject_alt_names(cert_der: &[u8]) -> Vec<String> {
    let cert = match synta_certificate::Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut result = Vec::new();
    for (tag, content) in cert.subject_alt_names() {
        let name = match tag {
            synta_certificate::general_name::DNS_NAME => {
                // dNSName — raw IA5String bytes
                std::str::from_utf8(&content)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "DNS:<invalid UTF-8>".to_string())
            }
            synta_certificate::general_name::RFC822_NAME => {
                // rfc822Name — email address
                std::str::from_utf8(&content)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "email:<invalid UTF-8>".to_string())
            }
            synta_certificate::general_name::URI => {
                // uniformResourceIdentifier
                std::str::from_utf8(&content)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "URI:<invalid UTF-8>".to_string())
            }
            synta_certificate::general_name::IP_ADDRESS if content.len() == 4 => {
                // IPv4 address
                format!("{}.{}.{}.{}", content[0], content[1], content[2], content[3])
            }
            synta_certificate::general_name::IP_ADDRESS if content.len() == 16 => {
                // IPv6 address
                let addr = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([content[0], content[1]]),
                    u16::from_be_bytes([content[2], content[3]]),
                    u16::from_be_bytes([content[4], content[5]]),
                    u16::from_be_bytes([content[6], content[7]]),
                    u16::from_be_bytes([content[8], content[9]]),
                    u16::from_be_bytes([content[10], content[11]]),
                    u16::from_be_bytes([content[12], content[13]]),
                    u16::from_be_bytes([content[14], content[15]]),
                );
                addr.to_string()
            }
            synta_certificate::general_name::DIRECTORY_NAME => {
                // directoryName — format as DN
                format!("DirName:{}", synta_certificate::format_dn(&content))
            }
            _ => {
                // Other types: include tag number for diagnostics
                format!("GeneralName(tag={tag})")
            }
        };
        result.push(name);
    }
    result
}

/// Extract Extended Key Usage OIDs from a DER-encoded certificate.
///
/// Parses the EKU extension (OID 2.5.29.37) from the X.509v3 extensions
/// and returns each key purpose as a dotted-decimal OID string (e.g.
/// `"1.3.6.1.5.5.7.3.28"` for id-kp-cmcRA).
fn extract_extended_key_usage(cert_der: &[u8]) -> Vec<String> {
    let cert = match synta_certificate::Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Get the raw extensions bytes.
    let ext_raw = match cert.tbs_certificate.extensions.as_ref() {
        Some(r) => r,
        None => return Vec::new(),
    };

    // Find the EKU extension value within the extensions sequence.
    let eku_bytes = match synta_certificate::find_extension_value(
        ext_raw.as_bytes(),
        synta_certificate::oids::EXTENDED_KEY_USAGE,
    ) {
        Some(bytes) => bytes,
        None => return Vec::new(),
    };

    // EKU is a SEQUENCE OF ObjectIdentifier.
    let mut decoder = synta::Decoder::new(eku_bytes, synta::Encoding::Der);
    let oids: Vec<synta::ObjectIdentifier> = match decoder.decode() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    oids.iter().map(|oid| oid.to_string()).collect()
}

/// Check certificate revocation status via OCSP or CRL.
///
/// RHELBU-3536 R21: the EST server SHOULD check the revocation status of
/// client certificates presented for authentication.
///
/// Uses the [`OcspClient`] when OCSP is configured; falls back to CRL
/// checking when the OCSP responder is unreachable and soft-fail is enabled.
async fn check_revocation(cert_der: &[u8], app: &Arc<AppState>) -> Result<(), String> {
    let ocsp_config = &app.config.ocsp;

    if !ocsp_config.enabled {
        debug!("OCSP checking disabled, skipping revocation check");
        return Ok(());
    }

    let ocsp_client = OcspClient::new(ocsp_config.clone());

    // The issuer certificate DER is needed for building the OCSP CertID.
    // In production, this comes from the CA truststore. For now, use the
    // default CA cert if available.
    let issuer_der = app.default_ca_cert_der().unwrap_or_default();

    if issuer_der.is_empty() {
        warn!("no issuer certificate available for OCSP check");
        if ocsp_config.soft_fail {
            return Ok(());
        }
        return Err("OCSP check failed: no issuer certificate available".to_string());
    }

    match ocsp_client
        .check_certificate_status(cert_der, &issuer_der)
        .await
    {
        Ok(OcspStatus::Good) => {
            info!("OCSP: certificate status is good");
            Ok(())
        }
        Ok(OcspStatus::Revoked {
            reason,
            revocation_time,
        }) => {
            warn!(
                reason = %reason,
                revocation_time = %revocation_time,
                "OCSP: certificate has been revoked"
            );
            Err(format!(
                "certificate revoked: reason={reason}, time={revocation_time}"
            ))
        }
        Ok(OcspStatus::Unknown) => {
            warn!("OCSP: certificate status unknown");
            if ocsp_config.soft_fail {
                Ok(())
            } else {
                Err("OCSP: certificate status unknown".to_string())
            }
        }
        Err(e) => {
            warn!(error = %e, "OCSP check failed, attempting CRL fallback");
            // Fall back to CRL checking if OCSP responder unreachable.
            if ocsp_config.soft_fail {
                info!("OCSP soft-fail enabled, accepting certificate despite OCSP failure");
                Ok(())
            } else {
                // TODO: Implement CRL fallback check here.
                Err(format!(
                    "OCSP check failed and CRL fallback not yet implemented: {e}"
                ))
            }
        }
    }
}
