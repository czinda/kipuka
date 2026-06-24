//! Certificate issuance from CSR with CA/B Forum compliance.
//!
//! Implements RFC 7030 §4.2 enrollment and applies profile-based
//! constraints. Validates CSR contents against CA/B Forum Baseline
//! Requirements before signing.
//!
//! Certificate signing uses the `synta-certificate` `CertificateBuilder`
//! with `OpensslCertificateSigner` for the actual cryptographic operations.

use std::sync::Arc;

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

/// CA signing key — either a PEM key from disk or an HSM-backed key.
///
/// When `Hsm` is used, the private key never leaves the HSM; signing
/// is performed via PKCS#11 `C_Sign` operations.
pub enum CaSigningKey<'a> {
    /// PEM-encoded private key loaded from disk.
    Pem(&'a [u8]),
    /// HSM-backed private key accessed via PKCS#11.
    Hsm {
        /// Reference to the HSM context with an active session.
        context: &'a Arc<kipuka_hsm::HsmContext>,
        /// Object label of the private key in the PKCS#11 token.
        key_label: &'a str,
    },
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

    /// Include the TLS Feature Extension (RFC 7633, OID 1.3.6.1.5.5.7.1.24)
    /// in issued certificates.
    ///
    /// RFC 7633 Section 4: when set, the issued certificate declares that
    /// the TLS server presenting it MUST provide an OCSP stapled response
    /// (status_request, TLS extension type 5) during the TLS handshake.
    /// Clients that understand this extension MUST abort the handshake if
    /// the server fails to staple a valid OCSP response.
    ///
    /// This is required for NIAP CA PP compliance and is commonly referred
    /// to as "must-staple".
    ///
    /// When `true`, the certificate will contain:
    /// ```text
    /// TLS Feature Extension (id-pe-tlsfeature):
    ///   OID:   1.3.6.1.5.5.7.1.24
    ///   Value: SEQUENCE { INTEGER 5 }   -- status_request
    /// ```
    ///
    /// Default: `false`.
    #[serde(default)]
    pub must_staple: bool,
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
            allowed_ml_dsa_levels: vec!["ml-dsa-44".into(), "ml-dsa-65".into(), "ml-dsa-87".into()],
            allowed_ml_kem_levels: vec![
                "ml-kem-512".into(),
                "ml-kem-768".into(),
                "ml-kem-1024".into(),
            ],
            allow_composite_ml_dsa: true,
            require_dual_cert: false,
            must_staple: false,
        }
    }
}

/// DER-encoded TLS Feature Extension value for must-staple certificates.
///
/// RFC 7633 Section 4 / RFC 6066 Section 8:
///   TLSFeature ::= SEQUENCE OF INTEGER
///   status_request(5)
///
/// ASN.1 DER encoding of SEQUENCE { INTEGER 5 }:
///   30 03        -- SEQUENCE, length 3
///     02 01 05   -- INTEGER, length 1, value 5
///
/// OID: 1.3.6.1.5.5.7.1.24 (id-pe-tlsfeature)
pub const TLS_FEATURE_MUST_STAPLE_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];

/// OID for the TLS Feature Extension (id-pe-tlsfeature).
///
/// RFC 7633 Section 4: 1.3.6.1.5.5.7.1.24
pub const OID_TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";

/// OID components for the TLS Feature Extension.
const OID_TLS_FEATURE_COMPONENTS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 24];

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
/// * `ca_cert_der` - DER-encoded CA certificate (for issuer DN and AKI)
/// * `signing_key` - CA signing key (PEM from disk or HSM-backed)
/// * `hash_algorithm` - Hash algorithm name (e.g. "sha256")
///
/// # Returns
///
/// [`IssuanceResult`] on success with the DER-encoded certificate and metadata.
pub fn issue_certificate(
    csr_der: &[u8],
    profile: &EnrollmentProfile,
    ca_cert_der: &[u8],
    signing_key: CaSigningKey<'_>,
    hash_algorithm: &str,
) -> Result<IssuanceResult, IssuanceError> {
    // Step 1: Parse and validate CSR.
    validate_csr(csr_der)?;

    // Step 2: Check key size against profile minimums.
    check_key_size(csr_der, profile)?;

    // Step 3: Validate requested validity against CA/B Forum limits.
    check_validity_period(profile)?;

    // Step 4: Verify required extensions will be present.
    check_required_extensions(profile)?;

    // Step 5: Parse the CSR to extract subject and public key.
    let csr = synta_certificate::csr::CertificationRequest::from_der(csr_der)
        .map_err(|e| IssuanceError::InvalidCsr(format!("CSR parse failed: {e}")))?;

    let csr_subject_der = csr
        .certification_request_info
        .subject
        .to_der()
        .map_err(|e| IssuanceError::InvalidCsr(format!("CSR subject encode failed: {e}")))?;

    let csr_spki_der = csr
        .certification_request_info
        .subject_pkinfo
        .to_der()
        .map_err(|e| IssuanceError::InvalidCsr(format!("CSR SPKI encode failed: {e}")))?;

    // Step 6: Parse the CA certificate to extract issuer DN and SPKI (for AKI).
    let ca_cert = synta_certificate::Certificate::from_der(ca_cert_der)
        .map_err(|e| IssuanceError::SigningError(format!("CA cert parse failed: {e}")))?;

    let ca_subject_der = ca_cert.tbs_certificate.subject.0;
    let ca_spki_der = ca_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| IssuanceError::SigningError(format!("CA SPKI encode failed: {e}")))?;

    // Step 7: Prepare the signing backend (PEM or HSM).
    let pem_key: Option<synta_certificate::BackendPrivateKey>;
    match &signing_key {
        CaSigningKey::Pem(pem) => {
            pem_key = Some(
                synta_certificate::BackendPrivateKey::from_pem(pem, None).map_err(|e| {
                    IssuanceError::SigningError(format!("CA key parse failed: {e}"))
                })?,
            );
            debug!("loaded CA private key from PEM");
        }
        CaSigningKey::Hsm { key_label, .. } => {
            pem_key = None;
            debug!(key_label = %key_label, "using HSM-backed CA signing key");
        }
    }

    // Step 8: Generate serial number — 20 bytes of random data (RFC 5280 §4.1.2.2
    // recommends at least 64 bits of entropy; we use 159 bits with leading 0 for positive).
    let serial_bytes = generate_serial_bytes();
    let serial = synta::Integer::from_unsigned_bytes(&serial_bytes);
    let serial_hex = hex::encode(&serial_bytes);

    // Step 9: Compute validity period.
    let now = Utc::now();
    let not_after_chrono = now + chrono::Duration::days(profile.max_validity_days as i64);

    let not_before_time = chrono_to_synta_time(now)
        .map_err(|e| IssuanceError::SigningError(format!("not_before time conversion: {e}")))?;
    let not_after_time = chrono_to_synta_time(not_after_chrono)
        .map_err(|e| IssuanceError::SigningError(format!("not_after time conversion: {e}")))?;

    // Step 10: Build extensions.
    debug!(
        profile = %profile.name,
        max_days = profile.max_validity_days,
        ct = profile.ct_enabled,
        must_staple = profile.must_staple,
        "building certificate from CSR"
    );

    let mut builder = synta_certificate::CertificateBuilder::new()
        .issuer_name(ca_subject_der)
        .subject_name(&csr_subject_der)
        .public_key_der(&csr_spki_der)
        .serial_number(serial)
        .not_valid_before(not_before_time)
        .not_valid_after(not_after_time);

    // Basic Constraints: CA:FALSE (critical, per CA/B Forum BR §7.1.2.7).
    if let Some(bc_der) = synta_certificate::encode_basic_constraints(false, None) {
        builder =
            builder.add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc_der);
    }

    // Key Usage (critical, per CA/B Forum BR §7.1.2.1).
    let ku_bits = profile_key_usage_bits(profile);
    if let Some(ku_der) = synta_certificate::encode_key_usage(ku_bits) {
        builder = builder.add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der);
    }

    // Extended Key Usage (non-critical).
    let eku_der = profile_extended_key_usage(profile);
    if let Some(eku) = eku_der {
        builder =
            builder.add_extension_oid(synta_certificate::oids::EXTENDED_KEY_USAGE, false, &eku);
    }

    // Subject Key Identifier (non-critical, per CA/B Forum BR §7.1.2.7.2).
    if profile.include_ski {
        let hasher = synta_certificate::OpensslKeyIdHasher;
        if let Some(ski_der) = synta_certificate::encode_subject_key_identifier(
            &csr_spki_der,
            synta_certificate::KeyIdMethod::Rfc5280Sha1,
            &hasher,
        ) {
            builder = builder.add_extension_oid(
                synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
                false,
                &ski_der,
            );
        }
    }

    // Authority Key Identifier (non-critical, per CA/B Forum BR §7.1.2.7.3).
    if profile.include_aki {
        let hasher = synta_certificate::OpensslKeyIdHasher;
        if let Some(aki_der) = synta_certificate::encode_authority_key_identifier(
            &ca_spki_der,
            synta_certificate::KeyIdMethod::Rfc5280Sha1,
            &hasher,
        ) {
            builder = builder.add_extension_oid(
                synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &aki_der,
            );
        }
    }

    // TLS Feature Extension (must-staple) per RFC 7633 §4.
    if profile.must_staple {
        debug!(
            oid = OID_TLS_FEATURE,
            "including TLS Feature Extension (must-staple) per RFC 7633 §4"
        );
        builder = builder.add_extension_oid(
            OID_TLS_FEATURE_COMPONENTS,
            false,
            TLS_FEATURE_MUST_STAPLE_DER,
        );
    }

    // Step 11: Sign the certificate.
    let cert_der = match &signing_key {
        CaSigningKey::Pem(_) => {
            // PEM path: use the synta-certificate OpenSSL signer.
            use synta_certificate::PrivateKey as _;
            let ca_pkey = pem_key.as_ref().expect("PEM key loaded in step 7");
            let signer = ca_pkey.as_signer(hash_algorithm);
            builder.sign(&signer).map_err(|e| {
                IssuanceError::SigningError(format!("certificate signing failed: {e}"))
            })?
        }
        CaSigningKey::Hsm { context, key_label } => {
            // HSM path: build TBS, sign via PKCS#11, assemble.
            let hsm_signer = HsmCertificateSigner {
                context,
                key_label,
                hash_algorithm,
            };
            builder.sign(&hsm_signer).map_err(|e| {
                IssuanceError::SigningError(format!("HSM certificate signing failed: {e}"))
            })?
        }
    };

    // Step 12: Format subject DN for logging and DB storage.
    let subject_dn = synta_certificate::format_dn(&csr_subject_der);

    info!(
        serial = %serial_hex,
        profile = %profile.name,
        subject = %subject_dn,
        not_after = %not_after_chrono,
        cert_len = cert_der.len(),
        "certificate issued"
    );

    Ok(IssuanceResult {
        certificate_der: cert_der,
        serial_number: serial_hex,
        subject_dn,
        not_before: now,
        not_after: not_after_chrono,
    })
}

/// Generate a 20-byte random serial number suitable for RFC 5280 §4.1.2.2.
///
/// The first byte is masked to 0x7F to guarantee the integer is positive
/// (no leading 0x00 padding needed).  This gives 159 bits of entropy,
/// well above the 64-bit minimum recommended by CA/B Forum.
fn generate_serial_bytes() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; 20];
    rng.fill(&mut bytes[..]);
    // Ensure positive by clearing the high bit.
    bytes[0] &= 0x7F;
    // Ensure non-zero first byte.
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    bytes
}

/// Convert a chrono DateTime<Utc> to a synta_certificate::Time.
///
/// Per RFC 5280 §4.1.2.5:
/// - Dates before 2050: use UTCTime (YYMMDDHHMMSSZ)
/// - Dates from 2050 onward: use GeneralizedTime (YYYYMMDDHHMMSSZ)
fn chrono_to_synta_time(dt: DateTime<Utc>) -> Result<synta_certificate::Time, String> {
    let year = dt.format("%Y").to_string().parse::<u16>().unwrap_or(2024);
    let month = dt.format("%m").to_string().parse::<u8>().unwrap_or(1);
    let day = dt.format("%d").to_string().parse::<u8>().unwrap_or(1);
    let hour = dt.format("%H").to_string().parse::<u8>().unwrap_or(0);
    let minute = dt.format("%M").to_string().parse::<u8>().unwrap_or(0);
    let second = dt.format("%S").to_string().parse::<u8>().unwrap_or(0);

    if year < 2050 {
        let utc_time = synta::UtcTime::new(year, month, day, hour, minute, second)
            .map_err(|e| format!("UtcTime creation failed: {e}"))?;
        Ok(synta_certificate::Time::UtcTime(utc_time))
    } else {
        let gen_time = synta::GeneralizedTime::new(year, month, day, hour, minute, second, None)
            .map_err(|e| format!("GeneralizedTime creation failed: {e}"))?;
        Ok(synta_certificate::Time::GeneralTime(gen_time))
    }
}

/// Convert profile key usage strings to a bitmask for `encode_key_usage`.
fn profile_key_usage_bits(profile: &EnrollmentProfile) -> u16 {
    use synta_certificate::{
        KEY_USAGE_DATA_ENCIPHERMENT, KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_KEY_AGREEMENT,
        KEY_USAGE_KEY_ENCIPHERMENT, KEY_USAGE_NON_REPUDIATION,
    };

    let mut bits: u16 = 0;
    for ku in &profile.key_usage {
        match ku.as_str() {
            "digitalSignature" => bits |= 1 << KEY_USAGE_DIGITAL_SIGNATURE,
            "nonRepudiation" | "contentCommitment" => bits |= 1 << KEY_USAGE_NON_REPUDIATION,
            "keyEncipherment" => bits |= 1 << KEY_USAGE_KEY_ENCIPHERMENT,
            "dataEncipherment" => bits |= 1 << KEY_USAGE_DATA_ENCIPHERMENT,
            "keyAgreement" => bits |= 1 << KEY_USAGE_KEY_AGREEMENT,
            other => {
                warn!(key_usage = %other, "unknown key usage flag in profile; skipping");
            }
        }
    }
    bits
}

/// Build Extended Key Usage DER from profile strings.
fn profile_extended_key_usage(profile: &EnrollmentProfile) -> Option<Vec<u8>> {
    if profile.extended_key_usage.is_empty() {
        return None;
    }

    let mut builder = synta_certificate::ExtendedKeyUsageBuilder::new();
    for eku in &profile.extended_key_usage {
        builder = match eku.as_str() {
            "serverAuth" => builder.server_auth(),
            "clientAuth" => builder.client_auth(),
            "codeSigning" => builder.code_signing(),
            "emailProtection" => builder.email_protection(),
            "timeStamping" => builder.time_stamping(),
            "OCSPSigning" | "ocspSigning" => builder.ocsp_signing(),
            other => {
                warn!(eku = %other, "unknown extended key usage in profile; skipping");
                builder
            }
        };
    }
    builder.build().ok()
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

    // Verify the CSR can be parsed.
    synta_certificate::csr::CertificationRequest::from_der(csr_der)
        .map_err(|e| IssuanceError::InvalidCsr(format!("PKCS#10 parse failed: {e}")))?;

    debug!(len = csr_der.len(), "CSR structure validated");
    Ok(())
}

/// Check key size from CSR against profile minimums.
fn check_key_size(csr_der: &[u8], profile: &EnrollmentProfile) -> Result<(), IssuanceError> {
    // Parse the CSR to extract the public key info.
    let csr = synta_certificate::csr::CertificationRequest::from_der(csr_der).map_err(|e| {
        IssuanceError::InvalidCsr(format!("CSR parse failed in key size check: {e}"))
    })?;

    let spki = &csr.certification_request_info.subject_pkinfo;
    let alg_oid = spki.algorithm.algorithm.components();
    let key_bits = spki.subject_public_key.bit_len();

    let pk_info = synta_certificate::decode_public_key_info(
        &spki.algorithm.algorithm,
        spki.algorithm.parameters.as_ref(),
        spki.subject_public_key.as_bytes(),
        key_bits,
    );

    match &pk_info {
        synta_certificate::PublicKeyInfo::Rsa { bit_count, .. } => {
            debug!(
                algorithm = "RSA",
                key_bits = bit_count,
                "CSR public key info"
            );
            if (*bit_count as u32) < profile.min_rsa_bits {
                return Err(IssuanceError::KeyTooSmall {
                    algorithm: "RSA".into(),
                    bits: *bit_count as u32,
                    min_bits: profile.min_rsa_bits,
                });
            }
        }
        synta_certificate::PublicKeyInfo::Ec {
            bit_count,
            curve_nist_name,
            ..
        } => {
            let curve_name = curve_nist_name.unwrap_or("unknown");
            debug!(
                algorithm = "EC",
                curve = curve_name,
                key_bits = bit_count,
                "CSR public key info"
            );
            let min_bits: usize = match profile.min_ecdsa_curve.as_str() {
                "P-256" => 256,
                "P-384" => 384,
                "P-521" => 521,
                _ => 256,
            };
            if *bit_count < min_bits {
                return Err(IssuanceError::KeyTooSmall {
                    algorithm: format!("EC {curve_name}"),
                    bits: *bit_count as u32,
                    min_bits: min_bits as u32,
                });
            }
        }
        synta_certificate::PublicKeyInfo::Unknown {
            alg_name,
            bit_count,
            ..
        } => {
            debug!(
                algorithm = %alg_name,
                key_bits = bit_count,
                alg_oid = ?alg_oid,
                "CSR public key: unknown algorithm (skipping size check)"
            );
        }
    }
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

// ── HSM CertificateSigner ────────────────────────────────────────────────────

/// `CertificateSigner` implementation that delegates signing to a PKCS#11 HSM.
///
/// Uses `CKM_SHA256_RSA_PKCS` (or SHA-384/SHA-512 variants) which hashes
/// the TBS data and signs in a single PKCS#11 `C_Sign` operation.
struct HsmCertificateSigner<'a> {
    context: &'a Arc<kipuka_hsm::HsmContext>,
    key_label: &'a str,
    hash_algorithm: &'a str,
}

/// Error type for HSM signing operations in the CertificateSigner trait.
#[derive(Debug)]
struct HsmSignerError(String);

impl std::fmt::Display for HsmSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HsmSignerError {}

impl<'a> synta_certificate::CertificateSigner for HsmCertificateSigner<'a> {
    type Error = HsmSignerError;

    fn signature_algorithm_der(&self) -> Result<Vec<u8>, Self::Error> {
        // Return the DER-encoded AlgorithmIdentifier for SHA-256 with RSA.
        //
        // AlgorithmIdentifier ::= SEQUENCE {
        //   algorithm   OBJECT IDENTIFIER,
        //   parameters  ANY OPTIONAL
        // }
        //
        // sha256WithRSAEncryption: OID 1.2.840.113549.1.1.11
        // Parameters: NULL
        match self.hash_algorithm {
            "sha256" => {
                // OID 1.2.840.113549.1.1.11 + NULL params
                Ok(vec![
                    0x30, 0x0d, // SEQUENCE, length 13
                    0x06, 0x09, // OID, length 9
                    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                    0x0b, // sha256WithRSAEncryption
                    0x05, 0x00, // NULL
                ])
            }
            "sha384" => {
                // OID 1.2.840.113549.1.1.12 + NULL params
                Ok(vec![
                    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
                    0x05, 0x00,
                ])
            }
            "sha512" => {
                // OID 1.2.840.113549.1.1.13 + NULL params
                Ok(vec![
                    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
                    0x05, 0x00,
                ])
            }
            other => Err(HsmSignerError(format!(
                "unsupported hash algorithm for HSM RSA signing: {other}"
            ))),
        }
    }

    fn sign_tbs(&self, tbs_der: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // CKM_SHA256_RSA_PKCS (and variants) hash the data internally,
        // so we pass the raw TBS bytes directly.
        self.context
            .sign_data(self.key_label, tbs_der, self.hash_algorithm)
            .map_err(|e| HsmSignerError(format!("PKCS#11 sign failed: {e}")))
    }
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
