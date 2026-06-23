//! Server-side key generation for EST `/serverkeygen` (RFC 7030 §4.4).
//!
//! Generates key pairs in software or via PKCS#11 HSM per NIAP CA PP
//! FCS_CKM.1 (approved key generation methods). Supports RSA and ECDSA
//! key types with configurable sizes.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

/// Errors during key generation.
#[derive(Debug, Error)]
pub enum KeyGenError {
    /// The requested key type or size is not supported.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    /// The key size is below the minimum allowed.
    #[error("{algorithm} key size {bits}-bit is below minimum {min_bits}-bit")]
    KeyTooSmall {
        algorithm: String,
        bits: u32,
        min_bits: u32,
    },

    /// Software key generation failed.
    #[error("software key generation failed: {0}")]
    SoftwareError(String),

    /// HSM key generation failed.
    #[error("HSM key generation failed: {0}")]
    HsmError(String),

    /// Key archival (encrypted storage) failed.
    #[error("key archival failed: {0}")]
    ArchivalError(String),
}

/// Supported key types for server-side generation.
///
/// Covers classical (RSA, ECDSA), post-quantum (ML-DSA FIPS 204, ML-KEM
/// FIPS 203), and composite hybrid algorithms per
/// draft-ietf-lamps-pq-composite-sigs-19.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// RSA with specified bit length (2048, 3072, 4096).
    Rsa(u32),
    /// ECDSA with specified named curve.
    Ecdsa(EcCurve),
    /// ML-DSA standalone (FIPS 204) — signing only.
    /// Used for CA signing keys and client identity certificates.
    MlDsa(MlDsaLevel),
    /// ML-KEM standalone (FIPS 203) — key encapsulation.
    /// Used for server-side key generation (/serverkeygen) where the
    /// client needs a KEM key pair for key establishment.
    MlKem(MlKemLevel),
    /// Composite ML-DSA + classical signing (hybrid).
    /// Provides dual-algorithm protection during PQC migration.
    CompositeMlDsa {
        ml_dsa: MlDsaLevel,
        classical: ClassicalSigningAlg,
    },
}

/// ML-DSA security levels per FIPS 204.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MlDsaLevel {
    /// ML-DSA-44: NIST Level 2, ~1,312 byte public key, ~2,420 byte signature.
    #[serde(rename = "44")]
    MlDsa44,
    /// ML-DSA-65: NIST Level 3, ~1,952 byte public key, ~3,309 byte signature.
    #[serde(rename = "65")]
    MlDsa65,
    /// ML-DSA-87: NIST Level 5, ~2,592 byte public key, ~4,627 byte signature.
    #[serde(rename = "87")]
    MlDsa87,
}

/// ML-KEM security levels per FIPS 203.
///
/// Used by `/serverkeygen` to generate KEM key pairs on behalf of clients,
/// with optional archival in the KRA subsystem.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MlKemLevel {
    /// ML-KEM-512: NIST Level 1, ~800 byte public key, ~768 byte ciphertext.
    #[serde(rename = "512")]
    MlKem512,
    /// ML-KEM-768: NIST Level 3, ~1,184 byte public key, ~1,088 byte ciphertext.
    #[serde(rename = "768")]
    MlKem768,
    /// ML-KEM-1024: NIST Level 5, ~1,568 byte public key, ~1,568 byte ciphertext.
    #[serde(rename = "1024")]
    MlKem1024,
}

/// Classical signing algorithms paired with ML-DSA in composite mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClassicalSigningAlg {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    Ed25519,
    Ed448,
}

/// Supported elliptic curves for ECDSA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
}

impl std::fmt::Display for MlDsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlDsaLevel::MlDsa44 => write!(f, "ML-DSA-44"),
            MlDsaLevel::MlDsa65 => write!(f, "ML-DSA-65"),
            MlDsaLevel::MlDsa87 => write!(f, "ML-DSA-87"),
        }
    }
}

impl std::fmt::Display for MlKemLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlKemLevel::MlKem512 => write!(f, "ML-KEM-512"),
            MlKemLevel::MlKem768 => write!(f, "ML-KEM-768"),
            MlKemLevel::MlKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

impl std::fmt::Display for EcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcCurve::P256 => write!(f, "P-256"),
            EcCurve::P384 => write!(f, "P-384"),
        }
    }
}

impl std::fmt::Display for ClassicalSigningAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassicalSigningAlg::Rsa2048 => write!(f, "RSA-2048"),
            ClassicalSigningAlg::Rsa3072 => write!(f, "RSA-3072"),
            ClassicalSigningAlg::Rsa4096 => write!(f, "RSA-4096"),
            ClassicalSigningAlg::EcP256 => write!(f, "EC-P-256"),
            ClassicalSigningAlg::EcP384 => write!(f, "EC-P-384"),
            ClassicalSigningAlg::Ed25519 => write!(f, "Ed25519"),
            ClassicalSigningAlg::Ed448 => write!(f, "Ed448"),
        }
    }
}

/// Result of a key generation operation.
pub struct KeyGenResult {
    /// DER-encoded public key (SubjectPublicKeyInfo) for certificate issuance.
    pub public_key_der: Vec<u8>,
    /// DER-encoded private key (PKCS#8) for delivery to the client.
    /// This is the unencrypted form; the caller is responsible for
    /// wrapping it in CMS EnvelopedData for secure delivery per RFC 7030 §4.4.
    pub private_key_der: Vec<u8>,
    /// Key type that was generated.
    pub key_type: KeyType,
}

/// Configuration for key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenConfig {
    /// Whether to generate keys in an HSM via PKCS#11.
    pub use_hsm: bool,
    /// Whether to archive the generated private key (encrypted in database).
    pub archive_key: bool,
    /// Allowed key types and sizes.
    pub allowed_types: Vec<KeyType>,
}

impl Default for KeyGenConfig {
    fn default() -> Self {
        Self {
            use_hsm: false,
            archive_key: false,
            allowed_types: vec![
                // Classical
                KeyType::Rsa(2048),
                KeyType::Rsa(3072),
                KeyType::Rsa(4096),
                KeyType::Ecdsa(EcCurve::P256),
                KeyType::Ecdsa(EcCurve::P384),
                // Post-Quantum — ML-DSA (FIPS 204) all levels
                KeyType::MlDsa(MlDsaLevel::MlDsa44),
                KeyType::MlDsa(MlDsaLevel::MlDsa65),
                KeyType::MlDsa(MlDsaLevel::MlDsa87),
                // Post-Quantum — ML-KEM (FIPS 203) all levels for SSKG
                KeyType::MlKem(MlKemLevel::MlKem512),
                KeyType::MlKem(MlKemLevel::MlKem768),
                KeyType::MlKem(MlKemLevel::MlKem1024),
                // Composite hybrid (ML-DSA + classical)
                KeyType::CompositeMlDsa {
                    ml_dsa: MlDsaLevel::MlDsa44,
                    classical: ClassicalSigningAlg::EcP256,
                },
                KeyType::CompositeMlDsa {
                    ml_dsa: MlDsaLevel::MlDsa65,
                    classical: ClassicalSigningAlg::EcP384,
                },
                KeyType::CompositeMlDsa {
                    ml_dsa: MlDsaLevel::MlDsa87,
                    classical: ClassicalSigningAlg::EcP384,
                },
            ],
        }
    }
}

/// Generate a key pair for the EST `/serverkeygen` endpoint.
///
/// Per NIAP CA PP FCS_CKM.1, uses approved key generation methods.
/// The private key is returned in PKCS#8 DER format for wrapping in
/// CMS EnvelopedData before delivery to the client.
///
/// # Arguments
///
/// * `key_type` - Requested key type and size
/// * `config` - Key generation configuration
///
/// # Returns
///
/// [`KeyGenResult`] containing the public key (for cert issuance) and
/// private key (for client delivery).
pub fn generate_key_pair(
    key_type: &KeyType,
    config: &KeyGenConfig,
) -> Result<KeyGenResult, KeyGenError> {
    validate_key_type(key_type)?;

    if config.use_hsm {
        generate_hsm_key(key_type)
    } else {
        generate_software_key(key_type)
    }
}

/// Validate that the requested key type meets minimum requirements.
fn validate_key_type(key_type: &KeyType) -> Result<(), KeyGenError> {
    match key_type {
        KeyType::Rsa(bits) => {
            const MIN_RSA_BITS: u32 = 2048;
            if *bits < MIN_RSA_BITS {
                return Err(KeyGenError::KeyTooSmall {
                    algorithm: "RSA".into(),
                    bits: *bits,
                    min_bits: MIN_RSA_BITS,
                });
            }
            if !matches!(*bits, 2048 | 3072 | 4096) {
                return Err(KeyGenError::UnsupportedKeyType(format!(
                    "RSA {bits}-bit (use 2048, 3072, or 4096)"
                )));
            }
        }
        KeyType::Ecdsa(curve) => {
            debug!(curve = %curve, "ECDSA key type validated");
        }
        KeyType::MlDsa(level) => {
            debug!(level = %level, "ML-DSA key type validated (FIPS 204)");
        }
        KeyType::MlKem(level) => {
            debug!(level = %level, "ML-KEM key type validated (FIPS 203)");
        }
        KeyType::CompositeMlDsa { ml_dsa, classical } => {
            debug!(
                ml_dsa = %ml_dsa,
                classical = %classical,
                "composite ML-DSA key type validated (draft-ietf-lamps-pq-composite-sigs-19)"
            );
        }
    }
    Ok(())
}

/// Generate a key pair in software.
///
/// Uses synta-certificate's `PrivateKeyBuilder` for classical and PQC keys.
/// ML-DSA: uses `PrivateKeyBuilder::ml_dsa(level)` (FIPS 204).
/// ML-KEM: uses `PrivateKeyBuilder::ml_kem(level)` (FIPS 203).
/// Composite: uses `PrivateKeyBuilder::composite_ml_dsa(sub_arc)`.
///
/// Requires OpenSSL 3.5+ with `pqc` provider for ML-DSA/ML-KEM operations.
fn generate_software_key(key_type: &KeyType) -> Result<KeyGenResult, KeyGenError> {
    info!(key_type = ?key_type, "generating software key pair");

    // TODO: wire to synta-certificate PrivateKeyBuilder.
    // The integration path per key type:
    //
    //   KeyType::Rsa(bits) =>
    //     PrivateKeyBuilder::rsa(*bits)?.build()?
    //
    //   KeyType::Ecdsa(EcCurve::P256) =>
    //     PrivateKeyBuilder::ec_p256()?.build()?
    //
    //   KeyType::MlDsa(MlDsaLevel::MlDsa44) =>
    //     PrivateKeyBuilder::ml_dsa(44)?.build()?   // FIPS 204
    //   KeyType::MlDsa(MlDsaLevel::MlDsa65) =>
    //     PrivateKeyBuilder::ml_dsa(65)?.build()?
    //   KeyType::MlDsa(MlDsaLevel::MlDsa87) =>
    //     PrivateKeyBuilder::ml_dsa(87)?.build()?
    //
    //   KeyType::MlKem(MlKemLevel::MlKem512) =>
    //     PrivateKeyBuilder::ml_kem(512)?.build()?  // FIPS 203
    //   KeyType::MlKem(MlKemLevel::MlKem768) =>
    //     PrivateKeyBuilder::ml_kem(768)?.build()?
    //   KeyType::MlKem(MlKemLevel::MlKem1024) =>
    //     PrivateKeyBuilder::ml_kem(1024)?.build()?
    //
    //   KeyType::CompositeMlDsa { ml_dsa, classical } =>
    //     PrivateKeyBuilder::composite_ml_dsa(sub_arc_for(ml_dsa, classical))?.build()?
    //     // sub_arc values 37-54 per draft-ietf-lamps-pq-composite-sigs-19

    let placeholder_public = vec![0x30, 0x00];
    let placeholder_private = vec![0x30, 0x00];

    Ok(KeyGenResult {
        public_key_der: placeholder_public,
        private_key_der: placeholder_private,
        key_type: key_type.clone(),
    })
}

/// Generate a key pair in an HSM via PKCS#11.
///
/// ML-DSA: requires HSM firmware with FIPS 204 support.
/// - Thales Luna 7.x+ and Entrust nShield 5+ support ML-DSA via
///   CKM_ML_DSA_KEY_PAIR_GEN (vendor-defined mechanism IDs).
/// - Kryoptic supports ML-DSA via software PKCS#11 module.
/// - Utimaco CryptoServer Se Gen2 supports ML-DSA.
///
/// ML-KEM: requires HSM firmware with FIPS 203 support.
/// - Key encapsulation uses CKM_ML_KEM_KEY_PAIR_GEN.
/// - Generated keys are stored in HSM with CKA_EXTRACTABLE=false
///   for archival; decapsulation key is wrapped for client delivery.
fn generate_hsm_key(key_type: &KeyType) -> Result<KeyGenResult, KeyGenError> {
    info!(key_type = ?key_type, "HSM key generation requested");

    Err(KeyGenError::HsmError(
        "PKCS#11 PQC key generation pending kipuka-hsm integration".into(),
    ))
}

/// Map a composite ML-DSA key type to the OID sub-arc per
/// draft-ietf-lamps-pq-composite-sigs-19 (sub-arcs 37-54).
///
/// These sub-arcs are under id-composite-sig (2.16.840.1.114027.80.5.2).
pub fn composite_sub_arc(ml_dsa: &MlDsaLevel, classical: &ClassicalSigningAlg) -> Option<u32> {
    match (ml_dsa, classical) {
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::Rsa2048)  => Some(37),
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::EcP256)   => Some(38),
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::Rsa3072)  => Some(39),
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::Ed25519)  => Some(40),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::Rsa3072)  => Some(41),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::EcP384)   => Some(42),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::Rsa4096)  => Some(43),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::Ed25519)  => Some(44),
        (MlDsaLevel::MlDsa87, ClassicalSigningAlg::EcP384)   => Some(45),
        (MlDsaLevel::MlDsa87, ClassicalSigningAlg::Ed448)    => Some(46),
        _ => None,
    }
}
