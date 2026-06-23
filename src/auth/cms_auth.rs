//! CMS message-level authentication for EST (RFC 8295).
//!
//! When TLS termination happens at a proxy, EST can still provide
//! message-level security using CMS (Cryptographic Message Syntax):
//!
//! - **Request authentication**: CMS SignedData wraps the PKCS#10 CSR.
//!   The signer certificate is verified against the EST truststore.
//!
//! - **Response confidentiality**: CMS EnvelopedData encrypts the issued
//!   certificate to the client's public key extracted from the CSR or
//!   the CMS SignedData signer certificate.
//!
//! RFC 8295 §3: The EST server MUST verify the CMS SignedData signature
//! and extract the signer's certificate for identity verification.

use crate::auth::{AuthMethod, AuthResult};
use crate::error::KipukaError;

/// Result of verifying a CMS SignedData message (RFC 8295 §3.1).
///
/// After successful verification, the signer's certificate and the
/// unwrapped payload (typically a PKCS#10 CSR) are available for
/// further processing by the EST handler.
#[derive(Debug, Clone)]
pub struct CmsVerificationResult {
    /// DER-encoded signer certificate extracted from the SignedData.
    ///
    /// RFC 8295 §3.1: The signer's certificate is included in the
    /// `certificates` field of the SignedData and MUST chain to a
    /// trust anchor in the EST truststore.
    pub signer_cert_der: Vec<u8>,

    /// Subject DN of the signer certificate as a string.
    ///
    /// Used for identity extraction and audit logging.
    pub signer_subject_dn: String,

    /// The unwrapped payload extracted from the SignedData `encapContentInfo`.
    ///
    /// For EST operations this is typically a DER-encoded PKCS#10 CSR.
    pub payload: Vec<u8>,

    /// Signature algorithm OID or name used to sign the CMS message.
    ///
    /// Verified against the server's allowed algorithm list to reject
    /// weak algorithms (e.g., MD5, SHA-1).
    pub signature_algorithm: String,
}

/// Content encryption algorithms supported for CMS EnvelopedData.
///
/// RFC 8295 §3.2: The EST server encrypts the response to the client's
/// public key.  Only AEAD or CBC modes with NIST-approved ciphers are
/// permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedContentEncryption {
    /// AES-256-GCM (OID 2.16.840.1.101.3.4.1.46).
    Aes256Gcm,
    /// AES-128-GCM (OID 2.16.840.1.101.3.4.1.6).
    Aes128Gcm,
    /// AES-256-CBC (OID 2.16.840.1.101.3.4.1.42).
    Aes256Cbc,
    /// AES-128-CBC (OID 2.16.840.1.101.3.4.1.2).
    Aes128Cbc,
}

/// Validate a content encryption algorithm string and map it to a
/// supported variant.
///
/// Accepts OID strings or short names (e.g., `"aes-256-gcm"`,
/// `"2.16.840.1.101.3.4.1.46"`).
///
/// # Errors
///
/// Returns `KipukaError::BadRequest` if the algorithm is not recognised
/// or not permitted by policy.
pub fn validate_content_encryption(alg: &str) -> Result<SupportedContentEncryption, KipukaError> {
    match alg.to_ascii_lowercase().as_str() {
        "aes-256-gcm" | "aes256gcm" | "2.16.840.1.101.3.4.1.46" => {
            Ok(SupportedContentEncryption::Aes256Gcm)
        }
        "aes-128-gcm" | "aes128gcm" | "2.16.840.1.101.3.4.1.6" => {
            Ok(SupportedContentEncryption::Aes128Gcm)
        }
        "aes-256-cbc" | "aes256cbc" | "2.16.840.1.101.3.4.1.42" => {
            Ok(SupportedContentEncryption::Aes256Cbc)
        }
        "aes-128-cbc" | "aes128cbc" | "2.16.840.1.101.3.4.1.2" => {
            Ok(SupportedContentEncryption::Aes128Cbc)
        }
        _ => Err(KipukaError::BadRequest(format!(
            "unsupported content encryption algorithm: {alg}"
        ))),
    }
}

/// Verify a CMS SignedData message and extract the payload.
///
/// RFC 8295 §3.1: The EST server performs the following steps:
///
/// 1. Parse the outer ContentInfo (DER) and verify `contentType` is
///    `id-signedData` (OID 1.2.840.113549.1.7.2).
/// 2. Extract the `SignerInfo` — exactly one signer is expected for EST.
/// 3. Locate the signer's certificate in the `certificates` field.
/// 4. Verify the signature using the signer's public key and the
///    `digestAlgorithm` + `signatureAlgorithm` from `SignerInfo`.
/// 5. Validate the signer's certificate chain against `truststore`:
///    - Build a chain from the signer cert to a trust anchor.
///    - Check validity periods (notBefore/notAfter).
///    - Check revocation status (CRL/OCSP) if configured.
/// 6. Extract the `eContent` from `encapContentInfo` — the unwrapped
///    payload (CSR).
///
/// # Arguments
///
/// * `signed_data_der` — DER-encoded CMS ContentInfo containing SignedData.
/// * `truststore` — DER-encoded trust anchor certificates to verify
///   the signer's certificate chain against.
///
/// # Errors
///
/// - `KipukaError::BadRequest` — malformed CMS, missing signer, empty payload.
/// - `KipukaError::Auth` — signature verification failure, untrusted signer.
/// - `KipukaError::Internal` — crypto operations not yet implemented.
pub fn verify_cms_signed_data(
    signed_data_der: &[u8],
    truststore: &[Vec<u8>],
) -> Result<CmsVerificationResult, KipukaError> {
    // Input validation.
    if signed_data_der.is_empty() {
        return Err(KipukaError::BadRequest("CMS SignedData is empty".into()));
    }

    // A minimal CMS ContentInfo with SignedData is at least ~100 bytes:
    // ContentInfo SEQUENCE header + OID + SignedData structure.
    if signed_data_der.len() < 100 {
        return Err(KipukaError::BadRequest(
            "CMS SignedData is too short to be valid".into(),
        ));
    }

    if truststore.is_empty() {
        return Err(KipukaError::Auth(
            "CMS truststore is empty — cannot verify signer certificate".into(),
        ));
    }

    // TODO: Implement CMS SignedData verification.
    //
    // Implementation plan:
    //
    // 1. Parse ContentInfo from `signed_data_der`:
    //    let content_info = cms::ContentInfo::from_der(signed_data_der)?;
    //    assert content_info.content_type == id_signedData;
    //
    // 2. Parse SignedData from content_info.content:
    //    let signed_data = cms::SignedData::from_der(&content_info.content)?;
    //
    // 3. Extract signer info (exactly one signer for EST):
    //    let signer_info = signed_data.signer_infos.first()
    //        .ok_or(KipukaError::BadRequest("no signer in CMS"))?;
    //
    // 4. Resolve signer certificate from the certificates field:
    //    let signer_cert = signed_data.certificates
    //        .find_by_sid(&signer_info.sid)?;
    //
    // 5. Verify signature:
    //    signer_info.verify_signature(
    //        &signer_cert.public_key(),
    //        &signed_data.encap_content_info,
    //    )?;
    //
    // 6. Validate signer cert chain against truststore:
    //    x509::verify_chain(&signer_cert, &signed_data.certificates, truststore)?;
    //
    // 7. Extract payload:
    //    let payload = signed_data.encap_content_info.econtent
    //        .ok_or(KipukaError::BadRequest("no encapsulated content"))?;
    //
    // 8. Return result:
    //    Ok(CmsVerificationResult {
    //        signer_cert_der: signer_cert.to_der()?,
    //        signer_subject_dn: signer_cert.subject().to_string(),
    //        payload,
    //        signature_algorithm: signer_info.signature_algorithm.oid.to_string(),
    //    })

    Err(KipukaError::Internal(
        "CMS SignedData verification not yet implemented".into(),
    ))
}

/// Build a CMS EnvelopedData message to encrypt a response payload.
///
/// RFC 8295 §3.2: The EST server encrypts the response (issued
/// certificate) to the client's public key so that only the client
/// can decrypt it, even if the transport layer is plain HTTP.
///
/// The construction follows RFC 5652 §6 (EnvelopedData):
///
/// 1. Generate a random content-encryption key (CEK) for the selected
///    algorithm (`content_encryption_alg`).
/// 2. Encrypt `payload` with the CEK to produce the `encryptedContent`.
/// 3. Encrypt the CEK to the recipient's public key (from
///    `recipient_cert_der`) using `KeyTransRecipientInfo` (ktri).
/// 4. Assemble the EnvelopedData:
///    - `version`: 0 (ktri with issuerAndSerialNumber)
///    - `recipientInfos`: one KeyTransRecipientInfo
///    - `encryptedContentInfo`: the encrypted payload
/// 5. Wrap in ContentInfo with `contentType` = `id-envelopedData`
///    (OID 1.2.840.113549.1.7.3).
/// 6. Return the DER-encoded ContentInfo.
///
/// # Arguments
///
/// * `payload` — the plaintext to encrypt (e.g., DER-encoded certificate).
/// * `recipient_cert_der` — DER-encoded certificate of the recipient;
///   the public key is extracted for key transport.
/// * `content_encryption_alg` — algorithm name or OID for content
///   encryption (validated via [`validate_content_encryption`]).
///
/// # Errors
///
/// - `KipukaError::BadRequest` — empty payload, invalid certificate,
///   unsupported algorithm.
/// - `KipukaError::Internal` — crypto operations not yet implemented.
pub fn build_cms_enveloped_data(
    payload: &[u8],
    recipient_cert_der: &[u8],
    content_encryption_alg: &str,
) -> Result<Vec<u8>, KipukaError> {
    if payload.is_empty() {
        return Err(KipukaError::BadRequest(
            "cannot encrypt empty payload".into(),
        ));
    }

    if recipient_cert_der.is_empty() {
        return Err(KipukaError::BadRequest(
            "recipient certificate is empty".into(),
        ));
    }

    // A valid DER-encoded X.509 certificate is at least ~200 bytes.
    if recipient_cert_der.len() < 100 {
        return Err(KipukaError::BadRequest(
            "recipient certificate is too short to be valid".into(),
        ));
    }

    // Validate the requested content encryption algorithm.
    let _alg = validate_content_encryption(content_encryption_alg)?;

    // TODO: Implement CMS EnvelopedData construction.
    //
    // Implementation plan:
    //
    // 1. Parse recipient certificate:
    //    let cert = x509::Certificate::from_der(recipient_cert_der)?;
    //    let pub_key = cert.subject_public_key_info();
    //
    // 2. Generate random CEK for the content encryption algorithm:
    //    let cek = alg.generate_key()?;
    //
    // 3. Encrypt payload with CEK:
    //    let (encrypted_content, iv) = alg.encrypt(&cek, payload)?;
    //
    // 4. Encrypt CEK to recipient public key (RSAES-OAEP or similar):
    //    let encrypted_key = pub_key.encrypt_key(&cek)?;
    //
    // 5. Build KeyTransRecipientInfo:
    //    let ktri = KeyTransRecipientInfo {
    //        version: 0,
    //        rid: IssuerAndSerialNumber::from(&cert),
    //        key_encryption_algorithm: rsaes_oaep(),
    //        encrypted_key,
    //    };
    //
    // 6. Build EnvelopedData:
    //    let env_data = EnvelopedData {
    //        version: 0,
    //        recipient_infos: vec![ktri.into()],
    //        encrypted_content_info: EncryptedContentInfo {
    //            content_type: id_data(),
    //            content_encryption_algorithm: alg.to_algorithm_identifier(iv),
    //            encrypted_content: Some(encrypted_content),
    //        },
    //    };
    //
    // 7. Wrap in ContentInfo and encode:
    //    let content_info = ContentInfo {
    //        content_type: id_envelopedData(),
    //        content: env_data.to_der()?,
    //    };
    //    Ok(content_info.to_der()?)

    Err(KipukaError::Internal(
        "CMS EnvelopedData construction not yet implemented".into(),
    ))
}

/// Convert a CMS verification result into the standard [`AuthResult`].
///
/// This bridges CMS-based authentication into the same identity model
/// used by mTLS, OTP, and GSSAPI handlers, allowing CMS-authenticated
/// requests to flow through the same authorization logic.
///
/// The `AuthMethod` is set to `Mtls` because the CMS signer certificate
/// is functionally equivalent to a TLS client certificate — it proves
/// possession of the corresponding private key and chains to a trusted CA.
///
/// # Arguments
///
/// * `cms_result` — a successfully verified CMS SignedData result.
///
/// # Errors
///
/// Returns `KipukaError::Auth` if the signer identity cannot be extracted
/// (empty subject DN).
pub fn extract_signer_identity(
    cms_result: &CmsVerificationResult,
) -> Result<AuthResult, KipukaError> {
    if cms_result.signer_subject_dn.is_empty() {
        return Err(KipukaError::Auth(
            "CMS signer certificate has an empty subject DN".into(),
        ));
    }

    Ok(AuthResult {
        identity: cms_result.signer_subject_dn.clone(),
        // CMS signature-based auth is treated as equivalent to mTLS
        // for authorization purposes — the signer proved possession
        // of a private key whose certificate chains to the truststore.
        method: AuthMethod::Mtls,
        client_cert_der: Some(cms_result.signer_cert_der.clone()),
        subject_dn: Some(cms_result.signer_subject_dn.clone()),
        subject_alt_names: Vec::new(),
        extended_key_usage: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_content_encryption_accepts_aes256gcm() {
        let result = validate_content_encryption("aes-256-gcm");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SupportedContentEncryption::Aes256Gcm);
    }

    #[test]
    fn validate_content_encryption_accepts_oid() {
        let result = validate_content_encryption("2.16.840.1.101.3.4.1.46");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SupportedContentEncryption::Aes256Gcm);
    }

    #[test]
    fn validate_content_encryption_rejects_unknown() {
        let result = validate_content_encryption("triple-des-cbc");
        assert!(result.is_err());
    }

    #[test]
    fn validate_content_encryption_case_insensitive() {
        let result = validate_content_encryption("AES-128-GCM");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SupportedContentEncryption::Aes128Gcm);
    }

    #[test]
    fn verify_rejects_empty_input() {
        let result = verify_cms_signed_data(&[], &[vec![0u8; 200]]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn verify_rejects_short_input() {
        let result = verify_cms_signed_data(&[0u8; 50], &[vec![0u8; 200]]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn verify_rejects_empty_truststore() {
        let result = verify_cms_signed_data(&[0u8; 200], &[]);
        assert!(matches!(result, Err(KipukaError::Auth(_))));
    }

    #[test]
    fn build_enveloped_rejects_empty_payload() {
        let result = build_cms_enveloped_data(&[], &[0u8; 200], "aes-256-gcm");
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn build_enveloped_rejects_empty_cert() {
        let result = build_cms_enveloped_data(&[1, 2, 3], &[], "aes-256-gcm");
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn build_enveloped_rejects_bad_algorithm() {
        let result = build_cms_enveloped_data(&[1, 2, 3], &[0u8; 200], "rc4");
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn extract_identity_rejects_empty_dn() {
        let cms = CmsVerificationResult {
            signer_cert_der: vec![0u8; 100],
            signer_subject_dn: String::new(),
            payload: vec![1, 2, 3],
            signature_algorithm: "sha256WithRSAEncryption".into(),
        };
        let auth = extract_signer_identity(&cms);
        assert!(auth.is_err());
    }

    #[test]
    fn extract_identity_produces_valid_auth_result() {
        let cms = CmsVerificationResult {
            signer_cert_der: vec![0u8; 100],
            signer_subject_dn: "CN=client.example.com".into(),
            payload: vec![1, 2, 3],
            signature_algorithm: "sha256WithRSAEncryption".into(),
        };
        let auth = extract_signer_identity(&cms).unwrap();
        assert_eq!(auth.identity, "CN=client.example.com");
        assert_eq!(auth.method, AuthMethod::Mtls);
        assert!(auth.client_cert_der.is_some());
        assert_eq!(auth.subject_dn.as_deref(), Some("CN=client.example.com"));
    }
}
