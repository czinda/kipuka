//! PQ-aware TLS client authentication: WebPKI retains the existing classical
//! policy; Synta validates algorithms WebPKI cannot handle. The native-OpenSSL
//! provider verifies handshake signatures.
//! EST's request authentication layer continues to enforce revocation policy.

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use synta_certificate::{Certificate, OpensslSignatureVerifier, oids};
use synta_x509_verification::{
    OwnedStore, RevocationChecks, ops::VerificationCertificate, policy::PolicyDefinition,
};

use crate::error::KipukaError;
use std::sync::Arc;

pub(super) struct SyntaClientCertVerifier {
    store: OwnedStore,
    classical: Arc<dyn ClientCertVerifier>,
}

impl std::fmt::Debug for SyntaClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntaClientCertVerifier")
            .field("required", &self.client_auth_mandatory())
            .field("trust_anchors", &self.store.len())
            .finish()
    }
}

impl SyntaClientCertVerifier {
    pub(super) fn new(roots: &[CertificateDer<'_>], required: bool) -> Result<Self, KipukaError> {
        let store = OwnedStore::try_new(roots.iter().map(|der| der.as_ref()))
            .map_err(|e| KipukaError::Tls(format!("client trust store: {e}")))?;
        let mut root_store = rustls::RootCertStore::empty();
        for root in roots {
            root_store
                .add(root.clone().into_owned())
                .map_err(|e| KipukaError::Tls(format!("invalid CA certificate: {e}")))?;
        }
        let builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store));
        let builder = if required {
            builder
        } else {
            builder.allow_unauthenticated()
        };
        let classical = builder
            .build()
            .map_err(|e| KipukaError::Tls(format!("client verifier build: {e}")))?;
        Ok(Self { store, classical })
    }
}

impl ClientCertVerifier for SyntaClientCertVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.classical.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.classical.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Do not tighten the established classical policy (for example, WebPKI
        // accepts clients without an AKI), or bypass a validation rejection.
        // Only an unsupported signature algorithm enters the PQ-aware policy.
        match self
            .classical
            .verify_client_cert(end_entity, intermediates, now)
        {
            Err(Error::InvalidCertificate(
                CertificateError::UnsupportedSignatureAlgorithmContext { .. }
                | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. },
            )) => {}
            result => return result,
        }
        let parse_error = |_| Error::InvalidCertificate(CertificateError::BadEncoding);
        let leaf = Certificate::from_der(end_entity.as_ref()).map_err(parse_error)?;
        let leaf = VerificationCertificate::new(leaf, end_entity.as_ref());
        let intermediates = intermediates
            .iter()
            .map(|der| {
                Certificate::from_der(der.as_ref())
                    .map(|cert| VerificationCertificate::new(cert, der.as_ref()))
                    .map_err(parse_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let validation_time = i64::try_from(now.as_secs())
            .map_err(|_| Error::General("TLS validation time out of range".into()))?;
        let policy = PolicyDefinition::new_client_pq(OpensslSignatureVerifier, validation_time);
        self.store
            .verify(&leaf, &intermediates, &policy, RevocationChecks::default())
            .map_err(|e| Error::General(format!("client certificate validation failed: {e}")))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls_native_ossl::SUPPORTED_SIG_ALGS,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let expected_oid = match dss.scheme {
            SignatureScheme::ML_DSA_44 => oids::ML_DSA_44,
            SignatureScheme::ML_DSA_65 => oids::ML_DSA_65,
            SignatureScheme::ML_DSA_87 => oids::ML_DSA_87,
            _ => {
                return rustls::crypto::verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &rustls_native_ossl::SUPPORTED_SIG_ALGS,
                );
            }
        };
        let certificate = Certificate::from_der(cert.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .algorithm
            .components()
            != expected_oid
        {
            return Err(Error::InvalidCertificate(CertificateError::BadSignature));
        }
        rustls_native_ossl::verify_ml_dsa_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes = rustls_native_ossl::SUPPORTED_SIG_ALGS.supported_schemes();
        schemes.extend([
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]);
        schemes
    }
}
