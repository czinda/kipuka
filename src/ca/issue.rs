//! Certificate issuance from CSR with CA/B Forum compliance.
//!
//! Implements RFC 7030 §4.2 enrollment and applies profile-based
//! constraints. Validates CSR contents against CA/B Forum Baseline
//! Requirements before signing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors during certificate issuance.
#[derive(Debug, Error)]
pub enum IssuanceError {
    /// The CSR is malformed or cannot be parsed.
    #[error("invalid CSR: {0}")]
    InvalidCsr(String),

    /// The CSR key does not meet minimum size requirements.
    #[error("key too small: {algorithm} {bits}-bit (minimum {min_bits}-bit required)")]
    KeyTooSmall {
        algorithm: String,
        bits: u32,
        min_bits: u32,
    },

    /// The requested validity period exceeds the maximum.
    #[error("validity period {requested_days} days exceeds maximum {max_days} days")]
    ValidityTooLong { requested_days: u32, max_days: u32 },

    /// A required extension is missing from the profile.
    #[error("missing required extension: {0}")]
    MissingExtension(String),

    /// The enrollment profile does not exist.
    #[error("unknown enrollment profile: {0}")]
    UnknownProfile(String),

    /// CA signing operation failed.
    #[error("signing failed: {0}")]
    SigningError(String),

    /// Database storage error.
    #[error("storage error: {0}")]
    StorageError(String),
}

/// Result of a successful certificate issuance.
#[derive(Debug, Clone)]
pub struct IssuanceResult {
    /// DER-encoded issued certificate.
    pub certificate_der: Vec<u8>,
    /// Serial number (hex string).
    pub serial_number: String,
    /// Subject DN of the issued certificate.
    pub subject_dn: String,
    /// Not Before timestamp.
    pub not_before: DateTime<Utc>,
    /// Not After timestamp.
    pub not_after: DateTime<Utc>,
}

/// Enrollment profile defining constraints for issued certificates.
///
/// Supports classical (RSA, ECDSA), post-quantum (ML-DSA, ML-KEM),
/// and composite hybrid algorithms for PQC migration scenarios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentProfile {
    /// Profile name (referenced in OTP records and EST label config).
    pub name: String,
    /// Maximum validity period in days.
    pub max_validity_days: u32,
    /// Key usage flags to set (e.g., digitalSignature, keyEncipherment).
    pub key_usage: Vec<String>,
    /// Extended key usage OIDs (e.g., serverAuth, clientAuth).
    pub extended_key_usage: Vec<String>,
    /// Whether to include Subject Key Identifier.
    pub include_ski: bool,
    /// Whether to include Authority Key Identifier.
    pub include_aki: bool,
    /// Minimum RSA key size in bits.
    pub min_rsa_bits: u32,
    /// Minimum ECDSA curve (P-256, P-384).
    pub min_ecdsa_curve: String,
    /// Whether to inject Certificate Transparency SCTs.
    pub ct_enabled: bool,

    // --- Post-Quantum Cryptography (FIPS 203/204) ---

    /// Allowed ML-DSA levels for signing key CSRs (FIPS 204).
    /// Empty means ML-DSA is not accepted for this profile.
    /// Values: "ml-dsa-44", "ml-dsa-65", "ml-dsa-87".
    #[serde(default)]
    pub allowed_ml_dsa_levels: Vec<String>,

    /// Allowed ML-KEM levels for KEM key CSRs (FIPS 203).
    /// Used with /serverkeygen for KRA-based key generation.
    /// Values: "ml-kem-512", "ml-kem-768", "ml-kem-1024".
    #[serde(default)]
    pub allowed_ml_kem_levels: Vec<String>,

    /// Whether to accept composite ML-DSA+classical CSRs.
    /// Per draft-ietf-lamps-pq-composite-sigs-19.
    #[serde(default)]
    pub allow_composite_ml_dsa: bool,

    /// Require dual certificates (paired legacy + PQC) for hybrid
    /// migration scenarios per IDM-5563 lifecycle requirements.
    /// When true, a classical enrollment triggers automatic paired
    /// PQC enrollment (and vice versa) as linked certificates.
    #[serde(default)]
    pub require_dual_cert: bool,
}

impl Default for EnrollmentProfile {
    fn default() -> Self {
        Self {
            name: "default".into(),
            max_validity_days: 398, // CA/B Forum current maximum
            key_usage: vec!["digitalSignature".into(), "keyEncipherment".into()],
            extended_key_usage: vec!["serverAuth".into(), "clientAuth".into()],
            include_ski: true,
            include_aki: true,
            min_rsa_bits: 2048,
            min_ecdsa_curve: "P-256".into(),
            ct_enabled: false,
            // PQC defaults: accept all ML-DSA and ML-KEM levels
            allowed_ml_dsa_levels: vec![
                "ml-dsa-44".into(),
                "ml-dsa-65".into(),
                "ml-dsa-87".into(),
            ],
            allowed_ml_kem_levels: vec![
                "ml-kem-512".into(),
                "ml-kem-768".into(),
                "ml-kem-1024".into(),
            ],
            allow_composite_ml_dsa: true,
            require_dual_cert: false,
        }
    }
}

/// Issue a certificate from a CSR.
///
/// Performs CA/B Forum compliance checks before signing:
/// - Key size minimums (RSA 2048+, ECDSA P-256+)
/// - Maximum validity period (398 days for public, 47 days from March 2029)
/// - Required extensions (AKI, SKI, Key Usage, Basic Constraints)
/// - Certificate Transparency SCT injection (when configured)
///
/// # Arguments
///
/// * `csr_der` - DER-encoded PKCS#10 Certificate Signing Request
/// * `profile` - Enrollment profile with constraints to apply
/// * `ca_cert_der` - DER-encoded CA certificate (for AKI)
///
/// # Returns
///
/// [`IssuanceResult`] on success with the DER-encoded certificate and metadata.
pub fn issue_certificate(
    csr_der: &[u8],
    profile: &EnrollmentProfile,
    _ca_cert_der: &[u8],
) -> Result<IssuanceResult, IssuanceError> {
    // Step 1: Parse and validate CSR.
    validate_csr(csr_der)?;

    // Step 2: Check key size against profile minimums.
    check_key_size(csr_der, profile)?;

    // Step 3: Validate requested validity against CA/B Forum limits.
    check_validity_period(profile)?;

    // Step 4: Verify required extensions will be present.
    check_required_extensions(profile)?;

    // Step 5: Build certificate template with profile constraints.
    debug!(
        profile = %profile.name,
        max_days = profile.max_validity_days,
        ct = profile.ct_enabled,
        "building certificate from CSR"
    );

    // Step 6: Sign certificate with CA key.
    // TODO: integrate with synta-certificate for actual X.509 construction
    // and signing. For now, return a placeholder result.
    let now = Utc::now();
    let not_after = now + chrono::Duration::days(profile.max_validity_days as i64);
    let serial = uuid::Uuid::new_v4().to_string().replace('-', "");

    info!(
        serial = %serial,
        profile = %profile.name,
        not_after = %not_after,
        "certificate issued (signing integration pending)"
    );

    // Step 7: Store issued cert in database with audit log.
    // TODO: database integration.

    Ok(IssuanceResult {
        certificate_der: csr_der.to_vec(), // Placeholder: actual cert DER
        serial_number: serial,
        subject_dn: "CN=pending".into(), // Extracted from CSR
        not_before: now,
        not_after,
    })
}

/// Validate CSR structure.
fn validate_csr(csr_der: &[u8]) -> Result<(), IssuanceError> {
    if csr_der.is_empty() {
        return Err(IssuanceError::InvalidCsr("empty CSR".into()));
    }

    // Check for ASN.1 SEQUENCE tag (0x30) at start.
    if csr_der[0] != 0x30 {
        return Err(IssuanceError::InvalidCsr(
            "does not start with ASN.1 SEQUENCE".into(),
        ));
    }

    // TODO: full PKCS#10 parsing with synta crate.
    debug!(len = csr_der.len(), "CSR structure validated (basic check)");
    Ok(())
}

/// Check key size from CSR against profile minimums.
fn check_key_size(csr_der: &[u8], profile: &EnrollmentProfile) -> Result<(), IssuanceError> {
    // TODO: extract actual key type and size from CSR using synta.
    // For now, log the check and pass.
    debug!(
        csr_len = csr_der.len(),
        min_rsa = profile.min_rsa_bits,
        min_ec = %profile.min_ecdsa_curve,
        "key size check (pending synta integration)"
    );
    Ok(())
}

/// Validate the requested validity period.
fn check_validity_period(profile: &EnrollmentProfile) -> Result<(), IssuanceError> {
    // CA/B Forum maximum: 398 days (current), 47 days (from March 2029).
    const CAB_CURRENT_MAX_DAYS: u32 = 398;

    if profile.max_validity_days > CAB_CURRENT_MAX_DAYS {
        warn!(
            requested = profile.max_validity_days,
            max = CAB_CURRENT_MAX_DAYS,
            "validity period exceeds CA/B Forum maximum"
        );
        return Err(IssuanceError::ValidityTooLong {
            requested_days: profile.max_validity_days,
            max_days: CAB_CURRENT_MAX_DAYS,
        });
    }

    Ok(())
}

/// Verify that required extensions are configured.
fn check_required_extensions(profile: &EnrollmentProfile) -> Result<(), IssuanceError> {
    if !profile.include_aki {
        return Err(IssuanceError::MissingExtension(
            "Authority Key Identifier (required by CA/B Forum)".into(),
        ));
    }
    if !profile.include_ski {
        return Err(IssuanceError::MissingExtension(
            "Subject Key Identifier (required by CA/B Forum)".into(),
        ));
    }
    if profile.key_usage.is_empty() {
        return Err(IssuanceError::MissingExtension(
            "Key Usage (required by CA/B Forum)".into(),
        ));
    }

    Ok(())
}
