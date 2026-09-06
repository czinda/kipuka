//! Authenticated protocol responses using the configured CA signing identity.
use crate::{
    ca::issue::{CaSigningKey, sign_message},
    error::KipukaError,
};
use synta::{
    Decoder, Encoding, ExplicitTag, Integer, ObjectIdentifier, OctetStringRef, RawDer, SetOf, Tag,
    ToDer,
};
use synta_certificate::{
    AlgorithmIdentifier, Certificate, DataHasher,
    cms_2010_types::IssuerAndSerialNumber,
    cms_rfc5652_types::{Attribute, EncapsulatedContentInfo, SignedData, SignerInfo},
};

/// Wrap a CMC PKIResponse in authenticated CMS and include all issued certificates.
pub(crate) fn signed_cmc(
    content: &[u8],
    certificates: &[Vec<u8>],
    ca_der: &[u8],
    key: CaSigningKey<'_>,
    hash: &str,
) -> Result<Vec<u8>, KipukaError> {
    let run = || -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content_oid = ObjectIdentifier::new(&[1, 3, 6, 1, 5, 5, 7, 12, 3])?;
        let digest = synta_certificate::default_data_hasher().hash_data(hash, content)?;
        let ct_values = SetOf::from_vec(vec![content_oid.clone()]).to_der()?;
        let md_values = SetOf::from_vec(vec![OctetStringRef::new(&digest)]).to_der()?;
        let ct = Attribute {
            attr_type: ObjectIdentifier::new(synta_certificate::oids::PKCS9_CONTENT_TYPE)?,
            attr_values: RawDer(&ct_values),
        }
        .to_der()?;
        let md = Attribute {
            attr_type: ObjectIdentifier::new(synta_certificate::oids::PKCS9_MESSAGE_DIGEST)?,
            attr_values: RawDer(&md_values),
        }
        .to_der()?;
        let attrs = SetOf::from_vec(vec![RawDer(&ct), RawDer(&md)]).to_der()?;
        let mut decoder = Decoder::new(&attrs, Encoding::Der);
        let content_attrs = decoder
            .enter_constructed(Tag::universal_constructed(17))?
            .remaining()
            .to_vec();
        let (algorithm, signature) = sign_message(key, hash, &attrs)?;
        let ca = Certificate::from_der(ca_der)?;
        let sid = IssuerAndSerialNumber {
            issuer: synta_certificate::Name::from_der(ca.tbs_certificate.issuer.as_bytes())?,
            serial_number: ca.tbs_certificate.serial_number,
        }
        .to_der()?;
        let digest_algorithm =
            synta_certificate::digest_alg_id(hash).ok_or("unsupported CMS digest")?;
        let signer = SignerInfo {
            version: Integer::from_i64(1),
            sid: RawDer(&sid),
            digest_algorithm: digest_algorithm.clone(),
            signed_attrs: Some(RawDer(&content_attrs)),
            signature_algorithm: AlgorithmIdentifier::from_der(&algorithm)?,
            signature: OctetStringRef::new(&signature),
            unsigned_attrs: None,
        };
        let mut all = certificates.to_vec();
        all.push(ca_der.to_vec());
        all.sort();
        all.dedup();
        let certs = all.concat();
        let data = SignedData {
            version: Integer::from_i64(3),
            digest_algorithms: SetOf::from_vec(vec![digest_algorithm]),
            encap_content_info: EncapsulatedContentInfo {
                e_content_type: content_oid,
                e_content: Some(OctetStringRef::new(content)),
            },
            certificates: Some(RawDer(&certs)),
            crls: None,
            signer_infos: SetOf::from_vec(vec![signer]),
        }
        .to_der()?;
        let explicit = ExplicitTag::context_specific(0, RawDer(&data)).to_der()?;
        Ok(synta_certificate::pkcs7_types::ContentInfo {
            content_type: ObjectIdentifier::new(synta_certificate::oids::CMS_SIGNED_DATA)?,
            content: RawDer(&explicit),
        }
        .to_der()?)
    };
    run().map_err(|e| KipukaError::Ca(format!("CMC response signing failed: {e}")))
}

/// Protect the CMP ProtectedPart (DER SEQUENCE of header and body).
pub(crate) fn protect_cmp(
    raw: &[u8],
    ca_der: &[u8],
    key: CaSigningKey<'_>,
    hash: &str,
) -> Result<Vec<u8>, KipukaError> {
    let run = || -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut msg = synta_certificate::cmp_types::PKIMessage::from_der(raw)?;
        let ca = Certificate::from_der(ca_der)?;
        let algorithm = synta_certificate::signing_algorithm_der(
            &ca.tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm,
            hash,
        )
        .ok_or("unsupported CMP signing algorithm")?;
        msg.header.protection_alg = Some(AlgorithmIdentifier::from_der(&algorithm)?);
        // Keep GeneralName as the actual certificate subject, not its display string.
        msg.header.sender = synta_certificate::GeneralName::DirectoryName(
            synta_certificate::Name::from_der(ca.tbs_certificate.subject.as_bytes())?,
        );
        let mut encoder = synta::Encoder::new(Encoding::Der);
        encoder.start_constructed_no_guard(Tag::universal_constructed(16))?;
        encoder.encode(&msg.header)?;
        encoder.encode(&msg.body)?;
        encoder.end_constructed()?;
        let (actual, signature) = sign_message(key, hash, &encoder.finish()?)?;
        if actual != algorithm {
            return Err("configured signing algorithm does not match CA key".into());
        }
        msg.protection = Some(synta::BitStringRef::new(&signature, 0)?);
        msg.extra_certs = Some(vec![RawDer(ca_der)]);
        Ok(msg.to_der()?)
    };
    run().map_err(|e| KipukaError::Ca(format!("CMP response signing failed: {e}")))
}

pub(crate) struct CmcRequest {
    pub body_part_id: u32,
    pub request_type: u32,
    pub der: Vec<u8>,
}

/// Decode the PKCS#10 TaggedRequest choice. Accept the explicit Synta builder
/// encoding and standards clients' implicit context tag without guessing CSR bytes.
pub(crate) fn cmc_requests(
    data: &synta_certificate::cmc_types::PKIData<'_>,
) -> Result<Vec<CmcRequest>, KipukaError> {
    let parse = || -> Result<Vec<CmcRequest>, Box<dyn std::error::Error>> {
        let mut result = Vec::new();
        for raw in &data.req_sequence {
            let mut decoder = Decoder::new(raw.as_bytes(), Encoding::Der);
            let tag = decoder.peek_tag()?;
            if tag != Tag::context_specific_constructed(0) {
                return Err("local CMC supports PKCS#10 TaggedRequest only".into());
            }
            let inner = decoder.enter_constructed(tag)?;
            let explicit = synta_certificate::cmc_types::TaggedCertificationRequest::from_der(
                inner.remaining(),
            );
            let mut implicit = raw.as_bytes().to_vec();
            implicit[0] = 0x30;
            let entry = explicit.or_else(|_| {
                synta_certificate::cmc_types::TaggedCertificationRequest::from_der(&implicit)
            })?;
            let id = u32::try_from(entry.body_part_id.as_i64()?)?;
            if result.iter().any(|r: &CmcRequest| r.body_part_id == id) {
                return Err("duplicate CMC body part ID".into());
            }
            result.push(CmcRequest {
                body_part_id: id,
                request_type: 0,
                der: entry.certification_request.as_bytes().to_vec(),
            });
        }
        Ok(result)
    };
    parse().map_err(|e| KipukaError::BadRequest(format!("CMC requests: {e}")))
}

pub(crate) fn cmc_transaction(
    response: &[u8],
    transaction: Option<i64>,
) -> Result<Vec<u8>, KipukaError> {
    let Some(transaction) = transaction else {
        return Ok(response.to_vec());
    };
    let bind = || -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let value = Integer::from_i64(transaction).to_der()?;
        let mut response = synta_certificate::cmc_types::PKIResponse::from_der(response)?;
        response
            .control_sequence
            .push(synta_certificate::cmc_types::TaggedAttribute {
                body_part_id: Integer::from_i64(0),
                attr_type: ObjectIdentifier::new(synta_cmc::oids::ID_CMC_TRANSACTION_ID)?,
                attr_values: SetOf::from_vec(vec![RawDer(&value)]),
            });
        Ok(response.to_der()?)
    };
    bind().map_err(|e| KipukaError::Ca(e.to_string()))
}

#[cfg(test)]
mod review_protocol_regressions {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder, extension::BasicConstraints},
    };

    fn identity(name: &str, serial: u32) -> (X509, Vec<u8>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut dn = X509NameBuilder::new().unwrap();
        dn.append_entry_by_text("CN", name).unwrap();
        let dn = dn.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&dn).unwrap();
        cert.set_issuer_name(&dn).unwrap();
        cert.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        (cert.build(), key.private_key_to_pem_pkcs8().unwrap())
    }

    #[test]
    fn cmc_response_contains_issued_certificate_and_openssl_verifies() {
        let (ca, key) = identity("Synthetic CMC signer", 1);
        let (issued, _) = identity("Synthetic issued certificate", 2);
        let ca_der = ca.to_der().unwrap();
        let issued_der = issued.to_der().unwrap();
        let content = synta_cmc::builder::PKIResponseBuilder::new()
            .build()
            .unwrap();
        let response = signed_cmc(
            &content,
            std::slice::from_ref(&issued_der),
            &ca_der,
            CaSigningKey::Pem(&key),
            "sha256",
        )
        .unwrap();
        let local =
            crate::auth::cms_auth::verify_cms_signed_data(&response, std::slice::from_ref(&ca_der))
                .unwrap();
        assert_eq!(local.payload, content);
        assert_eq!(local.signer_cert_der, ca_der);
        let p7 = openssl::pkcs7::Pkcs7::from_der(&response).unwrap();
        let certificates = p7.signed().unwrap().certificates().unwrap();
        assert!(
            certificates
                .iter()
                .any(|c| c.to_der().unwrap() == issued_der)
        );
        assert!(certificates.iter().any(|c| c.to_der().unwrap() == ca_der));
        let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
        store.add_cert(ca).unwrap();
        let mut cms = openssl::cms::CmsContentInfo::from_der(&response).unwrap();
        let mut verified = Vec::new();
        cms.verify(
            None,
            Some(&store.build()),
            None,
            Some(&mut verified),
            openssl::cms::CMSOptions::BINARY,
        )
        .unwrap();
        assert_eq!(verified, content);
    }

    fn protected_part(message: &synta_certificate::cmp_types::PKIMessage<'_>) -> Vec<u8> {
        let mut encoder = synta::Encoder::new(Encoding::Der);
        encoder
            .start_constructed_no_guard(Tag::universal_constructed(16))
            .unwrap();
        encoder.encode(&message.header).unwrap();
        encoder.encode(&message.body).unwrap();
        encoder.end_constructed().unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn cmp_response_protection_covers_header_and_body() {
        use synta_certificate::cmp_types::{PKIBody, PKIHeader, PKIMessage};
        let (ca, key) = identity("Synthetic CMP signer", 3);
        let ca_der = ca.to_der().unwrap();
        let sender = synta_certificate::GeneralNameSpec::rfc822("synthetic@example.test");
        let message = PKIMessage {
            header: PKIHeader {
                pvno: Integer::from_i64(2),
                sender: sender.to_general_name().unwrap(),
                recipient: sender.to_general_name().unwrap(),
                message_time: None,
                protection_alg: None,
                sender_kid: None,
                recip_kid: None,
                transaction_id: Some(OctetStringRef::new(b"synthetic-transaction")),
                sender_nonce: Some(OctetStringRef::new(b"synthetic-nonce")),
                recip_nonce: None,
                free_text: None,
                general_info: None,
            },
            body: PKIBody::Pkiconf(synta::Null),
            protection: None,
            extra_certs: None,
        };
        let protected = protect_cmp(
            &message.to_der().unwrap(),
            &ca_der,
            CaSigningKey::Pem(&key),
            "sha256",
        )
        .unwrap();
        let mut parsed = PKIMessage::from_der(&protected).unwrap();
        assert!(parsed.header.protection_alg.is_some());
        assert_eq!(parsed.extra_certs.as_ref().unwrap()[0].as_bytes(), ca_der);
        assert!(matches!(
            parsed.header.sender,
            synta_certificate::GeneralName::DirectoryName(_)
        ));
        let signature = parsed.protection.as_ref().unwrap().as_bytes();
        let public = ca.public_key().unwrap();
        let verify = |bytes: &[u8]| {
            openssl::sign::Verifier::new(MessageDigest::sha256(), &public)
                .unwrap()
                .verify_oneshot(signature, bytes)
                .unwrap()
        };
        assert!(verify(&protected_part(&parsed)));
        parsed.header.transaction_id = Some(OctetStringRef::new(b"different-transaction"));
        assert!(!verify(&protected_part(&parsed)));
        parsed.header.transaction_id = Some(OctetStringRef::new(b"synthetic-transaction"));
        parsed.body = PKIBody::Genp(RawDer(&[0x30, 0]));
        assert!(!verify(&protected_part(&parsed)));
    }
}
