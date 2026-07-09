//! PKCS#11-backed signing key for rustls TLS handshakes.
//!
//! Implements [`rustls::sign::SigningKey`] and [`rustls::sign::Signer`] by
//! delegating all signing operations to [`HsmContext::sign_data`].  The
//! private key never leaves the HSM — only the signature bytes are returned.

use std::sync::Arc;

use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use tracing::{debug, error};

use crate::key::KeyAlgorithm;
use crate::HsmContext;

/// A rustls [`SigningKey`] backed by a PKCS#11 token in Kryoptic.
#[derive(Debug)]
pub struct Pkcs11SigningKey {
    hsm: Arc<HsmContext>,
    key_label: String,
    algorithm: KeyAlgorithm,
}

impl Pkcs11SigningKey {
    pub fn new(hsm: Arc<HsmContext>, key_label: impl Into<String>, algorithm: KeyAlgorithm) -> Self {
        Self {
            hsm,
            key_label: key_label.into(),
            algorithm,
        }
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Only advertise PKCS#1 v1.5 schemes — sign_data() uses CKM_SHA*_RSA_PKCS
        // which produces PKCS#1 v1.5 signatures. Advertising PSS without PSS
        // padding support would cause TLS 1.3 handshake failures.
        let supported = match &self.algorithm {
            KeyAlgorithm::Rsa(_) => &[
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ][..],
            KeyAlgorithm::Ecdsa(curve) => match curve {
                crate::key::EcdsaCurve::P256 => {
                    &[SignatureScheme::ECDSA_NISTP256_SHA256][..]
                }
                crate::key::EcdsaCurve::P384 => {
                    &[SignatureScheme::ECDSA_NISTP384_SHA384][..]
                }
                _ => &[SignatureScheme::ECDSA_NISTP384_SHA384][..],
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
        let hash_alg = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::ECDSA_NISTP256_SHA256 => "sha256",

            SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::ECDSA_NISTP384_SHA384 => "sha384",

            SignatureScheme::RSA_PKCS1_SHA512 => "sha512",

            _ => {
                error!(scheme = ?self.scheme, "unsupported signature scheme for PKCS#11");
                return Err(Error::General("unsupported PKCS#11 signature scheme".into()));
            }
        };

        self.hsm
            .sign_data(&self.key_label, message, hash_alg)
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
