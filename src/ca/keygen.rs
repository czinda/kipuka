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

    // For classical key types (RSA, ECDSA), generate via native-ossl directly
    // so we can extract both the SPKI DER (public key) and PKCS#8 DER (private key).
    //
    // For PQC and composite key types, use synta-certificate's BackendPrivateKey
    // which has public to_der() for PKCS#8 extraction.
    match key_type {
        KeyType::Rsa(bits) => generate_classical_key(key_type, c"RSA", |pb| {
            pb.push_uint(c"bits", *bits)?
                .push_uint(c"e", 65537u32)
        }),
        KeyType::Ecdsa(curve) => {
            let curve_cstr: &std::ffi::CStr = match curve {
                EcCurve::P256 => c"P-256",
                EcCurve::P384 => c"P-384",
            };
            generate_classical_key(key_type, c"EC", |pb| {
                pb.push_utf8_string(c"group", curve_cstr)
            })
        }
        KeyType::MlDsa(level) => {
            let param = match level {
                MlDsaLevel::MlDsa44 => "ML-DSA-44",
                MlDsaLevel::MlDsa65 => "ML-DSA-65",
                MlDsaLevel::MlDsa87 => "ML-DSA-87",
            };
            generate_pqc_key(key_type, || {
                synta_certificate::BackendPrivateKey::generate_ml_dsa(param)
            })
        }
        KeyType::MlKem(level) => {
            let param = match level {
                MlKemLevel::MlKem512 => "ML-KEM-512",
                MlKemLevel::MlKem768 => "ML-KEM-768",
                MlKemLevel::MlKem1024 => "ML-KEM-1024",
            };
            generate_pqc_key(key_type, || {
                synta_certificate::BackendPrivateKey::generate_ml_kem(param)
            })
        }
        KeyType::CompositeMlDsa { ml_dsa, classical } => {
            let sub_arc = composite_sub_arc(ml_dsa, classical).ok_or_else(|| {
                KeyGenError::UnsupportedKeyType(format!(
                    "unsupported composite ML-DSA combination: {ml_dsa}+{classical}"
                ))
            })?;
            generate_pqc_key(key_type, || {
                synta_certificate::BackendPrivateKey::generate_composite_ml_dsa(sub_arc)
            })
        }
    }
}

/// Generate a classical key (RSA or ECDSA) via native-ossl `KeygenCtx`.
///
/// Returns both the SubjectPublicKeyInfo DER (for certificate issuance) and
/// the PKCS#8 DER (for client delivery).
fn generate_classical_key<F>(
    key_type: &KeyType,
    algorithm: &std::ffi::CStr,
    configure: F,
) -> Result<KeyGenResult, KeyGenError>
where
    F: FnOnce(
        native_ossl::params::ParamBuilder,
    ) -> Result<native_ossl::params::ParamBuilder, native_ossl::error::ErrorStack>,
{
    use native_ossl::pkey::KeygenCtx;
    use native_ossl::params::ParamBuilder;

    let pb = ParamBuilder::new()
        .map_err(|e| KeyGenError::SoftwareError(format!("param builder init: {e}")))?;

    let pb = configure(pb)
        .map_err(|e| KeyGenError::SoftwareError(format!("param configure: {e}")))?;

    let params = pb
        .build()
        .map_err(|e| KeyGenError::SoftwareError(format!("param build: {e}")))?;

    let mut kgen = KeygenCtx::new(algorithm)
        .map_err(|e| KeyGenError::SoftwareError(format!("keygen ctx init: {e}")))?;

    kgen.set_params(&params)
        .map_err(|e| KeyGenError::SoftwareError(format!("keygen set params: {e}")))?;

    let pkey = kgen
        .generate()
        .map_err(|e| KeyGenError::SoftwareError(format!("key generation: {e}")))?;

    // SPKI DER = SubjectPublicKeyInfo (public key for certificate).
    let public_key_der = pkey
        .public_key_to_der()
        .map_err(|e| KeyGenError::SoftwareError(format!("SPKI extraction: {e}")))?;

    // PKCS#8 DER = unencrypted private key for client delivery.
    let private_key_der = pkey
        .to_pkcs8_der()
        .map_err(|e| KeyGenError::SoftwareError(format!("PKCS#8 extraction: {e}")))?;

    info!(
        key_type = ?key_type,
        public_key_len = public_key_der.len(),
        private_key_len = private_key_der.len(),
        "classical software key pair generated"
    );

    Ok(KeyGenResult {
        public_key_der,
        private_key_der,
        key_type: key_type.clone(),
    })
}

/// Generate a PQC key (ML-DSA, ML-KEM, or composite) via synta-certificate's
/// `BackendPrivateKey`, which provides `to_der()` for PKCS#8 extraction and
/// implements the `PrivateKey` trait for SPKI extraction.
fn generate_pqc_key<F>(
    key_type: &KeyType,
    generator: F,
) -> Result<KeyGenResult, KeyGenError>
where
    F: FnOnce() -> Result<synta_certificate::BackendPrivateKey, synta_certificate::PrivateKeyError>,
{
    use synta_certificate::PrivateKey as _;

    let backend_key = generator()
        .map_err(|e| KeyGenError::SoftwareError(format!("PQC key generation: {e}")))?;

    // SPKI DER via the PrivateKey trait.
    let public_key_der = backend_key
        .public_key_spki_der()
        .map_err(|e| KeyGenError::SoftwareError(format!("PQC SPKI extraction: {e}")))?;

    // PKCS#8 DER via BackendPrivateKey::to_der().
    let private_key_der = backend_key
        .to_der()
        .map_err(|e| KeyGenError::SoftwareError(format!("PQC PKCS#8 extraction: {e}")))?;

    info!(
        key_type = ?key_type,
        public_key_len = public_key_der.len(),
        private_key_len = private_key_der.len(),
        "PQC software key pair generated"
    );

    Ok(KeyGenResult {
        public_key_der,
        private_key_der,
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
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::Rsa2048) => Some(37),
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::EcP256) => Some(38),
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::Rsa3072) => Some(39),
        (MlDsaLevel::MlDsa44, ClassicalSigningAlg::Ed25519) => Some(40),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::Rsa3072) => Some(41),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::EcP384) => Some(42),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::Rsa4096) => Some(43),
        (MlDsaLevel::MlDsa65, ClassicalSigningAlg::Ed25519) => Some(44),
        (MlDsaLevel::MlDsa87, ClassicalSigningAlg::EcP384) => Some(45),
        (MlDsaLevel::MlDsa87, ClassicalSigningAlg::Ed448) => Some(46),
        _ => None,
    }
}
