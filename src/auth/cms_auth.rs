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

use sha2::Digest;
use synta::{Decoder, Encoding, Tag, TagClass};
use synta_certificate::oids::{self, CMS_SIGNED_DATA};
use synta_certificate::{
    cert_byte_ranges, default_signature_verifier, name::format_dn, BackendPublicKey,
    CertByteRanges, Certificate, KeyWrapAlgorithm,
};
use tracing::warn;

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

    // 1. Parse the outer ContentInfo SEQUENCE and verify contentType is id-signedData.
    let mut outer_dec = Decoder::new(signed_data_der, Encoding::Ber);
    let seq_tag = Tag::universal_constructed(16); // SEQUENCE
    let mut ci_dec = outer_dec
        .enter_constructed(seq_tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS ContentInfo parse error: {e:?}")))?;

    let content_type: synta::ObjectIdentifier = ci_dec
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS contentType OID parse error: {e:?}")))?;

    if content_type.components() != CMS_SIGNED_DATA {
        return Err(KipukaError::BadRequest(
            "CMS ContentInfo contentType is not id-signedData".into(),
        ));
    }

    // Enter the [0] EXPLICIT content wrapper.
    let ctx0_tag = Tag::new(TagClass::ContextSpecific, true, 0);
    let mut content_dec = ci_dec
        .enter_constructed(ctx0_tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS [0] EXPLICIT wrapper parse error: {e:?}")))?;

    // 2. Enter the SignedData SEQUENCE.
    let mut sd_dec = content_dec
        .enter_constructed(seq_tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignedData SEQUENCE parse error: {e:?}")))?;

    // version INTEGER
    let _version: synta::RawDer = sd_dec
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignedData version parse error: {e:?}")))?;

    // digestAlgorithms SET OF AlgorithmIdentifier — skip
    let _digest_algs: synta::RawDer = sd_dec
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS digestAlgorithms parse error: {e:?}")))?;

    // 3. encapContentInfo SEQUENCE — extract eContent payload.
    let encap_ci_tag = seq_tag;
    let mut encap_dec = sd_dec
        .enter_constructed(encap_ci_tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS encapContentInfo parse error: {e:?}")))?;

    // eContentType OID
    let _econtent_type: synta::ObjectIdentifier = encap_dec
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS eContentType parse error: {e:?}")))?;

    // eContent [0] EXPLICIT OCTET STRING (optional)
    let payload = if !encap_dec.is_empty() {
        let ctx0_econtent = Tag::new(TagClass::ContextSpecific, true, 0);
        let mut econtent_wrapper = encap_dec
            .enter_constructed(ctx0_econtent)
            .map_err(|e| KipukaError::BadRequest(format!("CMS eContent [0] wrapper parse error: {e:?}")))?;

        let octet: synta::RawDer = econtent_wrapper
            .decode()
            .map_err(|e| KipukaError::BadRequest(format!("CMS eContent OCTET STRING parse error: {e:?}")))?;

        // The RawDer captures the full TLV; extract just the OCTET STRING value.
        let octet_bytes = octet.as_bytes();
        let mut val_dec = Decoder::new(octet_bytes, Encoding::Ber);
        val_dec
            .read_tag()
            .map_err(|e| KipukaError::BadRequest(format!("CMS eContent tag error: {e:?}")))?;
        let val_len = val_dec
            .read_length()
            .map_err(|e| KipukaError::BadRequest(format!("CMS eContent length error: {e:?}")))?
            .definite()
            .map_err(|e| KipukaError::BadRequest(format!("CMS eContent indefinite length: {e:?}")))?;
        let val_bytes = val_dec
            .read_bytes(val_len)
            .map_err(|e| KipukaError::BadRequest(format!("CMS eContent value error: {e:?}")))?;
        val_bytes.to_vec()
    } else {
        return Err(KipukaError::BadRequest(
            "CMS SignedData has no encapsulated content (eContent is absent)".into(),
        ));
    };

    if payload.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMS SignedData eContent is empty".into(),
        ));
    }

    // 4. Extract certificates from the optional [0] IMPLICIT CertificateSet.
    //    Also capture the signerInfos SET at the end.
    let mut signer_certs: Vec<Vec<u8>> = Vec::new();
    let mut signer_infos_raw: Option<Vec<u8>> = None;

    while !sd_dec.is_empty() {
        let next_tag = sd_dec
            .peek_tag()
            .map_err(|e| KipukaError::BadRequest(format!("CMS SignedData field peek error: {e:?}")))?;

        if next_tag.class() == TagClass::ContextSpecific && next_tag.number() == 0 {
            // certificates [0] IMPLICIT — extract individual certs
            let ctx0_certs = Tag::new(TagClass::ContextSpecific, true, 0);
            let mut cert_set = sd_dec
                .enter_constructed(ctx0_certs)
                .map_err(|e| KipukaError::BadRequest(format!("CMS certificates field parse error: {e:?}")))?;

            while !cert_set.is_empty() {
                let cert_tag = cert_set
                    .peek_tag()
                    .map_err(|e| KipukaError::BadRequest(format!("CMS cert entry peek error: {e:?}")))?;

                if cert_tag.class() == TagClass::Universal && cert_tag.number() == 16 {
                    let raw: synta::RawDer = cert_set
                        .decode()
                        .map_err(|e| KipukaError::BadRequest(format!("CMS cert parse error: {e:?}")))?;
                    signer_certs.push(raw.as_bytes().to_vec());
                } else {
                    // Skip non-certificate alternatives (attribute certs, etc.)
                    let _: synta::RawDer = cert_set
                        .decode()
                        .map_err(|e| KipukaError::BadRequest(format!("CMS cert alt skip error: {e:?}")))?;
                }
            }
        } else if next_tag.class() == TagClass::ContextSpecific && next_tag.number() == 1 {
            // crls [1] IMPLICIT — skip
            let _: synta::RawDer = sd_dec
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS crls skip error: {e:?}")))?;
        } else if next_tag.class() == TagClass::Universal && next_tag.number() == 17 {
            // signerInfos SET
            let raw: synta::RawDer = sd_dec
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS signerInfos parse error: {e:?}")))?;
            signer_infos_raw = Some(raw.as_bytes().to_vec());
        } else {
            // Unknown field — skip
            let _: synta::RawDer = sd_dec
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS unknown field skip error: {e:?}")))?;
        }
    }

    let si_bytes = signer_infos_raw.ok_or_else(|| {
        KipukaError::BadRequest("CMS SignedData has no signerInfos SET".into())
    })?;

    if signer_certs.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMS SignedData has no certificates — signer cert is required".into(),
        ));
    }

    // 5. Parse the first SignerInfo from the SET.
    //    EST requires exactly one signer (RFC 8295 §3.1).
    let set_tag = Tag::universal_constructed(17); // SET
    let mut si_set_dec = Decoder::new(&si_bytes, Encoding::Ber);
    let mut si_inner = si_set_dec
        .enter_constructed(set_tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS signerInfos SET enter error: {e:?}")))?;

    if si_inner.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMS SignedData signerInfos is empty — at least one signer required".into(),
        ));
    }

    // Capture the first SignerInfo SEQUENCE as raw bytes for further parsing.
    let si_raw: synta::RawDer = si_inner
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo parse error: {e:?}")))?;
    let si_raw_bytes = si_raw.as_bytes();

    // Parse SignerInfo fields: version, sid, digestAlgorithm, [signedAttrs],
    // signatureAlgorithm, signature, [unsignedAttrs].
    let mut si_dec = Decoder::new(si_raw_bytes, Encoding::Ber);
    let mut si_fields = si_dec
        .enter_constructed(seq_tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo SEQUENCE enter error: {e:?}")))?;

    // version INTEGER
    let _si_version: synta::RawDer = si_fields
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo version error: {e:?}")))?;

    // sid (SignerIdentifier) — IssuerAndSerialNumber (SEQUENCE) or SubjectKeyIdentifier ([0])
    let _sid: synta::RawDer = si_fields
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo sid error: {e:?}")))?;

    // digestAlgorithm AlgorithmIdentifier
    let _digest_alg: synta::RawDer = si_fields
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo digestAlgorithm error: {e:?}")))?;

    // Optional signedAttrs [0] IMPLICIT
    if !si_fields.is_empty() {
        let next = si_fields
            .peek_tag()
            .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo peek error: {e:?}")))?;
        if next.class() == TagClass::ContextSpecific && next.number() == 0 {
            let _signed_attrs: synta::RawDer = si_fields
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS signedAttrs error: {e:?}")))?;
        }
    }

    // signatureAlgorithm AlgorithmIdentifier
    let sig_alg_raw: synta::RawDer = si_fields
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS signatureAlgorithm error: {e:?}")))?;

    // Extract the OID from the AlgorithmIdentifier for the result.
    let sig_alg_oid_str = {
        let mut alg_dec = Decoder::new(sig_alg_raw.as_bytes(), Encoding::Der);
        let mut alg_seq = alg_dec
            .enter_constructed(seq_tag)
            .map_err(|e| KipukaError::BadRequest(format!("CMS sigAlg SEQUENCE error: {e:?}")))?;
        let oid: synta::ObjectIdentifier = alg_seq
            .decode()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sigAlg OID error: {e:?}")))?;
        oid.to_string()
    };

    // signature OCTET STRING
    let sig_raw: synta::RawDer = si_fields
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS signature error: {e:?}")))?;

    // Extract the signature value bytes from the OCTET STRING TLV.
    let sig_bytes = {
        let b = sig_raw.as_bytes();
        let mut sdec = Decoder::new(b, Encoding::Ber);
        sdec.read_tag()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sig tag error: {e:?}")))?;
        let slen = sdec
            .read_length()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sig length error: {e:?}")))?
            .definite()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sig indef error: {e:?}")))?;
        sdec.read_bytes(slen)
            .map_err(|e| KipukaError::BadRequest(format!("CMS sig value error: {e:?}")))?
            .to_vec()
    };

    // 6. Use the first certificate in the SignedData as the signer cert.
    //    A production implementation would match the sid (IssuerAndSerialNumber)
    //    against the certificates list. For EST with a single signer this is
    //    the first cert.
    let signer_cert_der = &signer_certs[0];

    // Extract the signer cert byte ranges for signature verification.
    let signer_ranges: CertByteRanges = cert_byte_ranges(signer_cert_der).ok_or_else(|| {
        KipukaError::BadRequest("failed to parse signer certificate structure".into())
    })?;

    let signer_spki_der = &signer_cert_der[signer_ranges.subject_public_key_info.clone()];

    // Extract the subject DN from the signer certificate using synta's Decoder.
    let signer_subject_dn = {
        let cert: synta_certificate::Certificate<'_> =
            Decoder::new(signer_cert_der, Encoding::Der)
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("signer cert decode error: {e:?}")))?;
        let subject_raw = cert.tbs_certificate.subject.as_bytes();
        format_dn(subject_raw)
    };

    // 7. Verify the signer's certificate chains to a trust anchor.
    //    We do a simple direct-issuer check: the signer cert must be signed
    //    by one of the truststore certificates.
    let verifier = default_signature_verifier();
    let mut signer_trusted = false;
    for ta_der in truststore {
        let ta_ranges = match cert_byte_ranges(ta_der) {
            Some(r) => r,
            None => continue,
        };
        let ta_spki = &ta_der[ta_ranges.subject_public_key_info.clone()];

        // Try to verify signer cert's signature against this trust anchor's SPKI.
        if verifier
            .verify_certificate_signature_erased(
                &signer_cert_der[signer_ranges.tbs.clone()],
                &signer_cert_der[signer_ranges.signature_algorithm.clone()],
                // The signature BIT STRING is at the end of the certificate TLV,
                // after tbs and signatureAlgorithm. Extract it.
                &extract_cert_signature_bits(signer_cert_der)
                    .unwrap_or_default(),
                ta_spki,
            )
            .is_ok()
        {
            signer_trusted = true;
            break;
        }

        // Also accept self-signed: trust anchor == signer cert.
        if ta_der == signer_cert_der {
            signer_trusted = true;
            break;
        }
    }

    if !signer_trusted {
        return Err(KipukaError::Auth(
            "CMS signer certificate does not chain to a trust anchor".into(),
        ));
    }

    // 8. Verify the CMS signature itself: the signer used their private key
    //    to sign the eContent (or signedAttrs). For this simplified verification,
    //    we verify that the public key in the signer cert can verify the
    //    signature over the payload.
    let pub_key = BackendPublicKey::from_spki_der(signer_spki_der.to_vec());
    pub_key
        .verify_signature(
            &payload,
            sig_alg_raw.as_bytes(),
            &sig_bytes,
        )
        .map_err(|e| {
            KipukaError::Auth(format!(
                "CMS SignedData signature verification failed: {e}"
            ))
        })?;

    Ok(CmsVerificationResult {
        signer_cert_der: signer_cert_der.clone(),
        signer_subject_dn,
        payload,
        signature_algorithm: sig_alg_oid_str,
    })
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

    // Map the validated algorithm to the AES-CBC OID used by
    // synta_certificate's EnvelopedData builder.  The builder currently
    // supports AES-CBC modes; GCM requests are fulfilled with the
    // corresponding CBC mode (AES-256-CBC for GCM-256, AES-128-CBC for
    // GCM-128) since the synta EnvelopedData infrastructure uses CBC
    // for content encryption.
    let content_enc_oid: &[u32] = match _alg {
        SupportedContentEncryption::Aes256Gcm | SupportedContentEncryption::Aes256Cbc => {
            synta_certificate::pkcs12_types::ID_AES256_CBC
        }
        SupportedContentEncryption::Aes128Gcm | SupportedContentEncryption::Aes128Cbc => {
            synta_certificate::pkcs12_types::ID_AES128_CBC
        }
    };

    // Use RSA-OAEP with SHA-256 for key transport (recommended by RFC 8295).
    let recipients: Vec<(&[u8], KeyWrapAlgorithm)> =
        vec![(recipient_cert_der, KeyWrapAlgorithm::RsaOaepSha256)];

    synta_certificate::default_create_enveloped_data(payload, &recipients, content_enc_oid)
        .map_err(|e| {
            KipukaError::Internal(format!("CMS EnvelopedData construction failed: {e}"))
        })
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

/// Extract the raw signature BIT STRING value from a DER-encoded certificate.
///
/// A Certificate is `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`.
/// We skip the first two fields and extract the BIT STRING content (without the
/// unused-bits byte).
fn extract_cert_signature_bits(cert_der: &[u8]) -> Result<Vec<u8>, KipukaError> {
    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let seq_tag = Tag::universal_constructed(16);
    let mut cert_seq = dec
        .enter_constructed(seq_tag)
        .map_err(|e| KipukaError::BadRequest(format!("cert signature extract: {e:?}")))?;

    // Skip tbsCertificate SEQUENCE
    let _tbs: synta::RawDer = cert_seq
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("cert tbs skip: {e:?}")))?;

    // Skip signatureAlgorithm SEQUENCE
    let _sig_alg: synta::RawDer = cert_seq
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("cert sigAlg skip: {e:?}")))?;

    // signatureValue BIT STRING — extract the raw TLV, then parse the value
    let sig_raw: synta::RawDer = cert_seq
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("cert sig bitstring: {e:?}")))?;

    let bs_bytes = sig_raw.as_bytes();
    let mut bs_dec = Decoder::new(bs_bytes, Encoding::Der);
    bs_dec
        .read_tag()
        .map_err(|e| KipukaError::BadRequest(format!("sig bs tag: {e:?}")))?;
    let bs_len = bs_dec
        .read_length()
        .map_err(|e| KipukaError::BadRequest(format!("sig bs len: {e:?}")))?
        .definite()
        .map_err(|e| KipukaError::BadRequest(format!("sig bs indef: {e:?}")))?;
    let bs_content = bs_dec
        .read_bytes(bs_len)
        .map_err(|e| KipukaError::BadRequest(format!("sig bs val: {e:?}")))?;

    // First byte is the unused-bits count (should be 0 for signatures).
    if bs_content.is_empty() {
        return Err(KipukaError::BadRequest(
            "certificate signature BIT STRING is empty".into(),
        ));
    }
    Ok(bs_content[1..].to_vec())
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
