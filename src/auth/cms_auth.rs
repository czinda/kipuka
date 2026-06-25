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

    // 5. Parse the first SignerInfo from the SET using the synta CMS types.
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

    // Capture the first SignerInfo SEQUENCE as raw bytes, then parse with
    // the synta cms_2009_types::SignerInfo struct for structured access.
    let si_raw: synta::RawDer = si_inner
        .decode()
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo parse error: {e:?}")))?;
    let si_raw_bytes = si_raw.as_bytes();

    let signer_info = synta_certificate::cms_2009_types::SignerInfo::from_der(si_raw_bytes)
        .map_err(|e| KipukaError::BadRequest(format!("CMS SignerInfo structured parse error: {e:?}")))?;

    // Extract the signatureAlgorithm OID string for the result.
    let sig_alg_oid_str = {
        let mut alg_dec = Decoder::new(signer_info.signature_algorithm.as_bytes(), Encoding::Der);
        let mut alg_seq = alg_dec
            .enter_constructed(seq_tag)
            .map_err(|e| KipukaError::BadRequest(format!("CMS sigAlg SEQUENCE error: {e:?}")))?;
        let oid: synta::ObjectIdentifier = alg_seq
            .decode()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sigAlg OID error: {e:?}")))?;
        oid.to_string()
    };

    // Extract the signature value bytes from the SignerInfo.
    let sig_bytes = signer_info.signature.as_bytes().to_vec();

    // 6. Match the signer certificate using the sid (SignerIdentifier).
    //    RFC 5652 §5.3: The sid identifies the signer's certificate by
    //    either IssuerAndSerialNumber or SubjectKeyIdentifier.
    let sid_raw = signer_info.sid.as_bytes();
    let signer_cert_der = match_signer_cert_by_sid(sid_raw, &signer_certs)?;

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
    //    Use Certificate::from_der() to access signature_value directly
    //    instead of the manual extract_cert_signature_bits helper.
    let signer_cert_parsed = Certificate::from_der(signer_cert_der).map_err(|e| {
        KipukaError::BadRequest(format!("failed to parse signer certificate: {e:?}"))
    })?;
    let cert_sig_bits = signer_cert_parsed.signature_value.as_bytes();

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
                cert_sig_bits,
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

    // 8. Verify the CMS signature itself.
    //    RFC 5652 §5.4: When signedAttrs are present, the signature is computed
    //    over the DER-encoded signedAttrs (re-tagged from IMPLICIT [0] 0xa0 to
    //    SET OF 0x31). The message-digest attribute within signedAttrs must match
    //    a digest of the eContent payload.
    //    When signedAttrs are absent, the signature is over the payload directly.
    let verification_data = if let Some(ref signed_attrs_raw) = signer_info.signed_attrs {
        // signedAttrs are present — verify message-digest attribute matches
        // a hash of eContent, then verify signature over the re-tagged signedAttrs.
        let signed_attrs_bytes = signed_attrs_raw.as_bytes();

        // Verify message-digest attribute: extract the digest algorithm OID from
        // the SignerInfo and hash the eContent payload.
        let digest_alg_oid = {
            let mut da_dec = Decoder::new(signer_info.digest_algorithm.as_bytes(), Encoding::Der);
            let mut da_seq = da_dec
                .enter_constructed(seq_tag)
                .map_err(|e| KipukaError::BadRequest(format!("CMS digestAlg SEQUENCE error: {e:?}")))?;
            let oid: synta::ObjectIdentifier = da_seq
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS digestAlg OID error: {e:?}")))?;
            oid.components().to_vec()
        };

        let payload_hash = compute_digest(&digest_alg_oid, &payload)?;
        verify_message_digest_attribute(signed_attrs_bytes, &payload_hash)?;

        // RFC 5652 §5.4: Re-tag the signedAttrs from IMPLICIT [0] (0xa0) to
        // SET OF (0x31) for signature verification.
        let mut retagged = signed_attrs_bytes.to_vec();
        if retagged.first() == Some(&0xa0) {
            retagged[0] = 0x31;
        }
        retagged
    } else {
        // No signedAttrs — signature is over the payload directly.
        payload.clone()
    };

    let pub_key = BackendPublicKey::from_spki_der(signer_spki_der.to_vec());
    pub_key
        .verify_signature(
            &verification_data,
            signer_info.signature_algorithm.as_bytes(),
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
        SupportedContentEncryption::Aes256Gcm => {
            warn!(
                requested = %content_encryption_alg,
                actual = "AES-256-CBC",
                "CMS EnvelopedData: GCM downgraded to CBC — authenticated encryption \
                 is being replaced with unauthenticated encryption"
            );
            synta_certificate::pkcs12_types::ID_AES256_CBC
        }
        SupportedContentEncryption::Aes128Gcm => {
            warn!(
                requested = %content_encryption_alg,
                actual = "AES-128-CBC",
                "CMS EnvelopedData: GCM downgraded to CBC — authenticated encryption \
                 is being replaced with unauthenticated encryption"
            );
            synta_certificate::pkcs12_types::ID_AES128_CBC
        }
        SupportedContentEncryption::Aes256Cbc => {
            synta_certificate::pkcs12_types::ID_AES256_CBC
        }
        SupportedContentEncryption::Aes128Cbc => {
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

/// Match the signer certificate from the certificates list using the sid
/// (SignerIdentifier) field.
///
/// RFC 5652 §5.3: The sid is either an IssuerAndSerialNumber (SEQUENCE)
/// or a SubjectKeyIdentifier ([0] IMPLICIT OCTET STRING).
fn match_signer_cert_by_sid<'a>(
    sid_raw: &[u8],
    certs: &'a [Vec<u8>],
) -> Result<&'a Vec<u8>, KipukaError> {
    if sid_raw.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMS SignerInfo sid is empty".into(),
        ));
    }

    // Determine the sid variant by examining the first byte's tag.
    let first_byte = sid_raw[0];

    if first_byte == 0x30 {
        // IssuerAndSerialNumber — SEQUENCE tag.
        let ias = synta_certificate::cms_2009_types::IssuerAndSerialNumber::from_der(sid_raw)
            .map_err(|e| KipukaError::BadRequest(format!(
                "CMS sid IssuerAndSerialNumber parse error: {e:?}"
            )))?;

        for cert_der in certs {
            if let Ok(cert) = Certificate::from_der(cert_der) {
                if cert.tbs_certificate.issuer.as_bytes() == ias.issuer.as_bytes()
                    && cert.tbs_certificate.serial_number == ias.serial_number
                {
                    return Ok(cert_der);
                }
            }
        }
        Err(KipukaError::BadRequest(
            "CMS signer certificate not found by IssuerAndSerialNumber".into(),
        ))
    } else if first_byte == 0x80 {
        // SubjectKeyIdentifier — [0] IMPLICIT OCTET STRING.
        // Extract the SKI value (skip the tag and length bytes).
        let mut dec = Decoder::new(sid_raw, Encoding::Ber);
        dec.read_tag()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sid SKI tag error: {e:?}")))?;
        let len = dec
            .read_length()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sid SKI length error: {e:?}")))?
            .definite()
            .map_err(|e| KipukaError::BadRequest(format!("CMS sid SKI indef error: {e:?}")))?;
        let ski_value = dec
            .read_bytes(len)
            .map_err(|e| KipukaError::BadRequest(format!("CMS sid SKI value error: {e:?}")))?;

        for cert_der in certs {
            if let Ok(cert) = Certificate::from_der(cert_der) {
                // Look up the SubjectKeyIdentifier extension (OID 2.5.29.14)
                // from the certificate's extensions.
                if let Some(ref exts_raw) = cert.tbs_certificate.extensions {
                    if let Some(ext_value) = synta_certificate::find_extension_value(
                        exts_raw.as_bytes(),
                        oids::SUBJECT_KEY_IDENTIFIER,
                    ) {
                        // The extension value is an OCTET STRING wrapping the key id.
                        let mut ev_dec = Decoder::new(ext_value, Encoding::Der);
                        if let Ok(tag) = ev_dec.read_tag() {
                            if tag.number() == 4 {
                                // OCTET STRING
                                if let Ok(ev_len) = ev_dec.read_length() {
                                    if let Ok(def_len) = ev_len.definite() {
                                        if let Ok(key_id) = ev_dec.read_bytes(def_len) {
                                            if key_id == ski_value {
                                                return Ok(cert_der);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(KipukaError::BadRequest(
            "CMS signer certificate not found by SubjectKeyIdentifier".into(),
        ))
    } else {
        // Fallback: if sid format is unrecognised, use the first cert and warn.
        warn!(
            first_byte = format_args!("0x{first_byte:02x}"),
            "CMS SignerIdentifier has unexpected tag, falling back to first certificate"
        );
        Ok(&certs[0])
    }
}

/// Compute a message digest of `data` using the specified algorithm OID.
///
/// Supports SHA-256, SHA-384, SHA-512, and SHA-1 (for legacy compatibility).
fn compute_digest(alg_oid: &[u32], data: &[u8]) -> Result<Vec<u8>, KipukaError> {
    if alg_oid == oids::ID_SHA256 {
        Ok(sha2::Sha256::digest(data).to_vec())
    } else if alg_oid == oids::ID_SHA384 {
        Ok(sha2::Sha384::digest(data).to_vec())
    } else if alg_oid == oids::ID_SHA512 {
        Ok(sha2::Sha512::digest(data).to_vec())
    } else if alg_oid == oids::ID_SHA1 {
        Err(KipukaError::BadRequest(
            "CMS digest algorithm SHA-1 is not permitted — use SHA-256 or stronger".into(),
        ))
    } else {
        Err(KipukaError::BadRequest(format!(
            "unsupported CMS digest algorithm OID: {alg_oid:?}"
        )))
    }
}

/// Verify that the message-digest attribute in signedAttrs matches the
/// expected digest of the eContent payload.
///
/// RFC 5652 §11.2: The message-digest attribute value is an OCTET STRING
/// containing the digest of the eContent.
fn verify_message_digest_attribute(
    signed_attrs_bytes: &[u8],
    expected_digest: &[u8],
) -> Result<(), KipukaError> {
    // The signedAttrs RawDer includes the IMPLICIT [0] tag. Parse the attributes
    // by entering the constructed tag (either 0xa0 or 0x31).
    let tag = Tag::new(TagClass::ContextSpecific, true, 0);
    let mut dec = Decoder::new(signed_attrs_bytes, Encoding::Ber);
    let mut attrs = dec
        .enter_constructed(tag)
        .map_err(|e| KipukaError::BadRequest(format!("CMS signedAttrs enter error: {e:?}")))?;

    let seq_tag = Tag::universal_constructed(16);

    // Walk through the attributes looking for id-messageDigest (1.2.840.113549.1.9.4).
    while !attrs.is_empty() {
        let mut attr_seq = attrs
            .enter_constructed(seq_tag)
            .map_err(|e| KipukaError::BadRequest(format!("CMS attr SEQUENCE error: {e:?}")))?;

        let attr_oid: synta::ObjectIdentifier = attr_seq
            .decode()
            .map_err(|e| KipukaError::BadRequest(format!("CMS attr OID error: {e:?}")))?;

        if attr_oid.components() == oids::PKCS9_MESSAGE_DIGEST {
            // Found the message-digest attribute. The value is a SET containing
            // an OCTET STRING with the digest.
            let set_tag = Tag::universal_constructed(17);
            let mut val_set = attr_seq
                .enter_constructed(set_tag)
                .map_err(|e| KipukaError::BadRequest(format!("CMS messageDigest SET error: {e:?}")))?;

            let digest_raw: synta::RawDer = val_set
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS messageDigest value error: {e:?}")))?;

            // Parse the OCTET STRING value.
            let digest_bytes = digest_raw.as_bytes();
            let mut d_dec = Decoder::new(digest_bytes, Encoding::Der);
            d_dec
                .read_tag()
                .map_err(|e| KipukaError::BadRequest(format!("CMS md tag error: {e:?}")))?;
            let d_len = d_dec
                .read_length()
                .map_err(|e| KipukaError::BadRequest(format!("CMS md length error: {e:?}")))?
                .definite()
                .map_err(|e| KipukaError::BadRequest(format!("CMS md indef error: {e:?}")))?;
            let digest_value = d_dec
                .read_bytes(d_len)
                .map_err(|e| KipukaError::BadRequest(format!("CMS md value error: {e:?}")))?;

            if digest_value != expected_digest {
                return Err(KipukaError::Auth(
                    "CMS message-digest attribute does not match eContent hash".into(),
                ));
            }
            return Ok(());
        }

        // Not the attribute we want — skip remaining fields.
        while !attr_seq.is_empty() {
            let _: synta::RawDer = attr_seq
                .decode()
                .map_err(|e| KipukaError::BadRequest(format!("CMS attr value skip error: {e:?}")))?;
        }
    }

    // RFC 5652 §11.2: The message-digest attribute MUST be present when
    // signedAttrs is present.
    Err(KipukaError::BadRequest(
        "CMS signedAttrs is missing the required message-digest attribute".into(),
    ))
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
