//! PKCS#11-backed signing key for rustls TLS handshakes.
//!
//! Implements [`rustls::sign::SigningKey`] and [`rustls::sign::Signer`] by
//! delegating all signing operations to [`HsmContext::sign_data`].  The
//! private key never leaves the HSM — only the signature bytes are returned.

use std::sync::Arc;

use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use tracing::{debug, error};

use crate::HsmContext;
use crate::key::KeyAlgorithm;

/// A rustls [`SigningKey`] backed by a PKCS#11 token in Kryoptic.
#[derive(Debug)]
pub struct Pkcs11SigningKey {
    hsm: Arc<HsmContext>,
    key_label: String,
    algorithm: KeyAlgorithm,
}

impl Pkcs11SigningKey {
    pub fn new(
        hsm: Arc<HsmContext>,
        key_label: impl Into<String>,
        algorithm: KeyAlgorithm,
    ) -> Self {
        Self {
            hsm,
            key_label: key_label.into(),
            algorithm,
        }
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Each advertised scheme maps to its exact PKCS#11 mechanism.
        let supported = match &self.algorithm {
            KeyAlgorithm::Rsa(_) => &[
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ][..],
            KeyAlgorithm::Ecdsa(curve) => match curve {
                crate::key::EcdsaCurve::P256 => &[SignatureScheme::ECDSA_NISTP256_SHA256][..],
                crate::key::EcdsaCurve::P384 => &[SignatureScheme::ECDSA_NISTP384_SHA384][..],
                _ => &[SignatureScheme::ECDSA_NISTP521_SHA512][..],
            },
            _ => {
                error!(algorithm = ?self.algorithm, "unsupported key algorithm for PKCS#11 TLS");
                return None;
            }
        };

        for scheme in offered {
            if supported.contains(scheme) {
                debug!(
                    key_label = %self.key_label,
                    scheme = ?scheme,
                    "PKCS#11 signing key: chose scheme"
                );
                return Some(Box::new(Pkcs11Signer {
                    hsm: Arc::clone(&self.hsm),
                    key_label: self.key_label.clone(),
                    scheme: *scheme,
                }));
            }
        }

        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match &self.algorithm {
            KeyAlgorithm::Rsa(_) => SignatureAlgorithm::RSA,
            KeyAlgorithm::Ecdsa(_) => SignatureAlgorithm::ECDSA,
            other => {
                error!(algorithm = ?other, "unsupported algorithm for PKCS#11 TLS SigningKey");
                SignatureAlgorithm::RSA
            }
        }
    }
}

/// Performs a single TLS signature via PKCS#11.
#[derive(Debug)]
struct Pkcs11Signer {
    hsm: Arc<HsmContext>,
    key_label: String,
    scheme: SignatureScheme,
}

impl Signer for Pkcs11Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.hsm
            .sign_tls(&self.key_label, message, self.scheme)
            .map_err(|e| {
                error!(
                    key_label = %self.key_label,
                    error = %e,
                    "PKCS#11 TLS signing failed"
                );
                Error::General(format!("PKCS#11 sign failed: {e}"))
            })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Derive TLS algorithms from certified public-key material, never URI spelling.
pub fn certificate_algorithm(der: &[u8]) -> crate::HsmResult<KeyAlgorithm> {
    let cert = openssl::x509::X509::from_der(der)
        .map_err(|e| crate::HsmError::KeyNotFound(e.to_string()))?;
    let key = cert
        .public_key()
        .map_err(|e| crate::HsmError::KeyNotFound(e.to_string()))?;
    if key.id() == openssl::pkey::Id::RSA {
        return Ok(KeyAlgorithm::Rsa(key.bits()));
    }
    let ec = key.ec_key().map_err(|_| {
        crate::HsmError::UnsupportedMechanism("TLS HSM key must be RSA or ECDSA".into())
    })?;
    let curve = match ec.group().curve_name() {
        Some(openssl::nid::Nid::X9_62_PRIME256V1) => crate::key::EcdsaCurve::P256,
        Some(openssl::nid::Nid::SECP384R1) => crate::key::EcdsaCurve::P384,
        Some(openssl::nid::Nid::SECP521R1) => crate::key::EcdsaCurve::P521,
        _ => {
            return Err(crate::HsmError::UnsupportedMechanism(
                "unsupported TLS EC curve".into(),
            ));
        }
    };
    Ok(KeyAlgorithm::Ecdsa(curve))
}

/// Validate key possession and signature-mechanism support before serving TLS.
pub fn verify_tls_key(hsm: &HsmContext, label: &str, cert_der: &[u8]) -> crate::HsmResult<()> {
    use openssl::{
        hash::MessageDigest,
        rsa::Padding,
        sign::{RsaPssSaltlen, Verifier},
    };
    let algorithm = certificate_algorithm(cert_der)?;
    let (scheme, digest) = match algorithm {
        KeyAlgorithm::Rsa(_) => (SignatureScheme::RSA_PSS_SHA256, MessageDigest::sha256()),
        KeyAlgorithm::Ecdsa(crate::key::EcdsaCurve::P256) => (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            MessageDigest::sha256(),
        ),
        KeyAlgorithm::Ecdsa(crate::key::EcdsaCurve::P384) => (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            MessageDigest::sha384(),
        ),
        KeyAlgorithm::Ecdsa(crate::key::EcdsaCurve::P521) => (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            MessageDigest::sha512(),
        ),
        _ => {
            return Err(crate::HsmError::UnsupportedMechanism(
                "unsupported TLS key".into(),
            ));
        }
    };
    let map = |e: openssl::error::ErrorStack| crate::HsmError::SigningFailure(e.to_string());
    let mut challenge = [0u8; 32];
    openssl::rand::rand_bytes(&mut challenge).map_err(map)?;
    let signature = hsm.sign_tls(label, &challenge, scheme)?;
    let public = openssl::x509::X509::from_der(cert_der)
        .map_err(map)?
        .public_key()
        .map_err(map)?;
    let mut verifier = Verifier::new(digest, &public).map_err(map)?;
    if matches!(algorithm, KeyAlgorithm::Rsa(_)) {
        verifier.set_rsa_padding(Padding::PKCS1_PSS).map_err(map)?;
        verifier.set_rsa_mgf1_md(digest).map_err(map)?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(map)?;
    }
    if !verifier
        .verify_oneshot(&signature, &challenge)
        .map_err(map)?
    {
        return Err(crate::HsmError::SigningFailure(
            "HSM key does not match TLS certificate".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    #[test]
    fn tls13_rsa_pss_and_exact_ec_curve_schemes() {
        let hsm = Arc::new(HsmContext::placeholder());
        let rsa = Pkcs11SigningKey::new(hsm.clone(), "synthetic", KeyAlgorithm::Rsa(2048));
        assert!(
            rsa.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_some()
        );
        for (curve, scheme) in [
            (
                crate::key::EcdsaCurve::P256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ),
            (
                crate::key::EcdsaCurve::P384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ),
            (
                crate::key::EcdsaCurve::P521,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ),
        ] {
            let ec = Pkcs11SigningKey::new(hsm.clone(), "synthetic", KeyAlgorithm::Ecdsa(curve));
            assert_eq!(ec.choose_scheme(&[scheme]).unwrap().scheme(), scheme);
            assert!(
                ec.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                    .is_none()
            );
        }
    }
}
