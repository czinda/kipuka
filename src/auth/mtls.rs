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

use synta_certificate::{
    cert_byte_ranges, crl::CertificateList, default_signature_verifier, SignatureVerifier,
};

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
                // CRL fallback: try to fetch and check a CRL before giving up.
                match check_crl_fallback(cert_der, app).await {
                    Ok(()) => {
                        info!("CRL fallback: certificate is not revoked");
                        Ok(())
                    }
                    Err(crl_err) => {
                        warn!(
                            ocsp_error = %e,
                            crl_error = %crl_err,
                            "both OCSP and CRL revocation checks failed"
                        );
                        Err(format!(
                            "OCSP check failed ({e}) and CRL fallback also failed ({crl_err})"
                        ))
                    }
                }
            }
        }
    }
}

/// Fallback revocation check via CRL Distribution Points.
///
/// Extracts the CDP extension from the client certificate, fetches the CRL
/// via HTTP, verifies the CRL signature against the issuer, and checks
/// whether the client cert's serial number appears in the revoked list.
async fn check_crl_fallback(cert_der: &[u8], app: &Arc<AppState>) -> Result<(), String> {
    // 1. Parse the client certificate and extract CDP URLs.
    let cdp_urls = extract_cdp_http_urls(cert_der)?;
    if cdp_urls.is_empty() {
        return Err("certificate has no CRL Distribution Point HTTP URLs".to_string());
    }

    // 2. Extract the client cert serial number for revocation lookup.
    let client_cert = synta_certificate::Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse client certificate: {e}"))?;
    let client_serial = client_cert.tbs_certificate.serial_number.clone();

    // 3. Get the issuer certificate for CRL signature verification.
    let issuer_der = app
        .default_ca_cert_der()
        .ok_or_else(|| "no issuer certificate available for CRL verification".to_string())?;
    if issuer_der.is_empty() {
        return Err("issuer certificate is empty".to_string());
    }
    let issuer_ranges = cert_byte_ranges(&issuer_der)
        .ok_or_else(|| "failed to extract byte ranges from issuer certificate".to_string())?;
    let issuer_spki = &issuer_der[issuer_ranges.subject_public_key_info.clone()];

    // 4. Try each CDP URL until one succeeds.
    let mut last_err = String::new();
    for url in &cdp_urls {
        debug!(url = %url, "fetching CRL from distribution point");
        match fetch_and_check_crl(url, &client_serial, issuer_spki).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(url = %url, error = %e, "CRL check failed for this distribution point");
                last_err = e;
            }
        }
    }

    Err(format!("all CRL distribution points failed; last error: {last_err}"))
}

/// Fetch a CRL from the given URL, verify its signature, and check
/// whether the given serial number is in the revoked list.
async fn fetch_and_check_crl(
    url: &str,
    client_serial: &synta::Integer,
    issuer_spki_der: &[u8],
) -> Result<(), String> {
    // Fetch the CRL via HTTP.
    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("HTTP fetch failed for {url}: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "HTTP {} fetching CRL from {url}",
            response.status()
        ));
    }

    let crl_der = response
        .bytes()
        .await
        .map_err(|e| format!("failed to read CRL response body: {e}"))?;

    // Parse the CRL.
    let crl = CertificateList::from_der(&crl_der)
        .map_err(|e| format!("failed to parse CRL DER: {e}"))?;

    // Verify the CRL signature against the issuer's SPKI.
    // The CRL has the same outer SEQUENCE { TBS, AlgId, Sig } structure
    // as a Certificate, so we use the same byte-range extraction logic.
    let crl_ranges = crl_byte_ranges(&crl_der)
        .ok_or_else(|| "failed to extract byte ranges from CRL DER".to_string())?;

    let tbs_bytes = &crl_der[crl_ranges.tbs];
    let sig_alg_bytes = &crl_der[crl_ranges.sig_alg];
    let sig_bits = &crl_der[crl_ranges.signature];

    let verifier = default_signature_verifier();
    verifier
        .verify_certificate_signature(tbs_bytes, sig_alg_bytes, sig_bits, issuer_spki_der)
        .map_err(|e| format!("CRL signature verification failed: {e}"))?;

    info!("CRL signature verified successfully");

    // Check if the client cert serial is in the revoked list.
    if let Some(ref revoked_certs) = crl.tbs_cert_list.revoked_certificates {
        for entry in revoked_certs {
            if entry.user_certificate == *client_serial {
                return Err(format!(
                    "certificate serial {} is revoked (revocation date: {:?})",
                    format_serial_hex(client_serial),
                    entry.revocation_date,
                ));
            }
        }
    }

    Ok(())
}

/// Extract HTTP URLs from the CRL Distribution Points extension.
///
/// Parses the CDP extension (OID 2.5.29.31) from the certificate's
/// extensions and returns all `uniformResourceIdentifier` entries that
/// use the `http://` or `https://` scheme.
fn extract_cdp_http_urls(cert_der: &[u8]) -> Result<Vec<String>, String> {
    let cert = synta_certificate::Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse certificate for CDP extraction: {e}"))?;

    let ext_raw = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| "certificate has no extensions".to_string())?;

    let cdp_bytes = synta_certificate::find_extension_value(
        ext_raw.as_bytes(),
        synta_certificate::oids::CRL_DISTRIBUTION_POINTS,
    )
    .ok_or_else(|| "CRL Distribution Points extension not found".to_string())?;

    // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
    // DistributionPoint ::= SEQUENCE {
    //   distributionPoint [0] DistributionPointName OPTIONAL,
    //   reasons           [1] ReasonFlags OPTIONAL,
    //   cRLIssuer         [2] GeneralNames OPTIONAL
    // }
    // DistributionPointName ::= CHOICE {
    //   fullName          [0] GeneralNames,
    //   nameRelativeToCRLIssuer [1] RelativeDistinguishedName
    // }
    use synta::tag::TAG_SEQUENCE;
    use synta::{Tag, TagClass};

    let mut urls = Vec::new();
    let seq_tag = Tag::universal_constructed(TAG_SEQUENCE);
    let mut decoder = synta::Decoder::new(cdp_bytes, synta::Encoding::Der);
    let mut outer = decoder
        .enter_constructed(seq_tag)
        .map_err(|e| format!("CDP outer SEQUENCE decode error: {e}"))?;

    while !outer.is_empty() {
        // Each element is a DistributionPoint SEQUENCE.
        let mut dp = match outer.enter_constructed(seq_tag) {
            Ok(d) => d,
            Err(_) => break,
        };
        while !dp.is_empty() {
            let dp_tag = match dp.read_tag() {
                Ok(t) => t,
                Err(_) => break,
            };
            let dp_len = match dp.read_length() {
                Ok(l) => match l.definite() {
                    Ok(n) => n,
                    Err(_) => break,
                },
                Err(_) => break,
            };
            let dp_content = match dp.read_bytes(dp_len) {
                Ok(c) => c,
                Err(_) => break,
            };

            // distributionPoint is [0] — a DistributionPointName CHOICE.
            if dp_tag.class() == TagClass::ContextSpecific && dp_tag.number() == 0 {
                // fullName [0] IMPLICIT GeneralNames
                let mut gn_dec = synta::Decoder::new(dp_content, synta::Encoding::Der);
                while !gn_dec.is_empty() {
                    let gn_tag = match gn_dec.read_tag() {
                        Ok(t) => t,
                        Err(_) => break,
                    };
                    let gn_len = match gn_dec.read_length() {
                        Ok(l) => match l.definite() {
                            Ok(n) => n,
                            Err(_) => break,
                        },
                        Err(_) => break,
                    };
                    let gn_content = match gn_dec.read_bytes(gn_len) {
                        Ok(c) => c,
                        Err(_) => break,
                    };

                    // uniformResourceIdentifier [6] IMPLICIT IA5String
                    if gn_tag.class() == TagClass::ContextSpecific
                        && gn_tag.number() == 6
                        && let Ok(uri) = std::str::from_utf8(gn_content)
                        && (uri.starts_with("http://") || uri.starts_with("https://"))
                    {
                        urls.push(uri.to_string());
                    }
                }
            }
            // reasons [1] and cRLIssuer [2] are skipped.
        }
    }

    Ok(urls)
}

/// Byte ranges within a DER-encoded CRL (same outer structure as Certificate).
struct CrlByteRanges {
    /// The complete `TBSCertList` TLV.
    tbs: std::ops::Range<usize>,
    /// The outer `signatureAlgorithm` TLV.
    sig_alg: std::ops::Range<usize>,
    /// The raw signature bytes from the `signatureValue` BIT STRING
    /// (with the unused-bits byte stripped).
    signature: std::ops::Range<usize>,
}

/// Extract byte ranges from a DER-encoded CRL for signature verification.
///
/// A CRL has the same `SEQUENCE { TBS, AlgorithmIdentifier, BIT STRING }`
/// layout as a Certificate.
fn crl_byte_ranges(crl_der: &[u8]) -> Option<CrlByteRanges> {
    use synta::{Decoder, Encoding};

    let mut d = Decoder::new(crl_der, Encoding::Der);

    // Outer CertificateList SEQUENCE header.
    d.read_tag().ok()?;
    d.read_length().ok()?.definite().ok()?;

    // TBSCertList: record start, skip.
    let tbs_start = d.position();
    d.read_tag().ok()?;
    let tbs_content_len = d.read_length().ok()?.definite().ok()?;
    let tbs_end = d.position() + tbs_content_len;
    d.read_bytes(tbs_content_len).ok()?;

    // signatureAlgorithm: record start, skip.
    let sig_alg_start = d.position();
    d.read_tag().ok()?;
    let sig_alg_content_len = d.read_length().ok()?.definite().ok()?;
    let sig_alg_end = d.position() + sig_alg_content_len;
    d.read_bytes(sig_alg_content_len).ok()?;

    // signatureValue BIT STRING: read tag+length, then skip unused-bits byte.
    d.read_tag().ok()?;
    let sig_len = d.read_length().ok()?.definite().ok()?;
    if sig_len == 0 {
        return None;
    }
    // The first byte of the BIT STRING content is the unused-bits count
    // (always 0 for signatures). The actual signature starts at +1.
    let sig_start = d.position() + 1;
    let sig_end = d.position() + sig_len;

    Some(CrlByteRanges {
        tbs: tbs_start..tbs_end,
        sig_alg: sig_alg_start..sig_alg_end,
        signature: sig_start..sig_end,
    })
}

/// Format a serial number as a colon-separated hex string for diagnostics.
fn format_serial_hex(serial: &synta::Integer) -> String {
    serial
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
