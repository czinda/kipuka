use super::*;
#[allow(dead_code)]
#[path = "../../tests/common/pki.rs"]
mod pki;

fn response(id: &CertId, cert: &[u8], key: &[u8], stale: bool) -> Vec<u8> {
    let cert = synta_certificate::Certificate::from_der(cert).unwrap();
    let now = chrono::Utc::now();
    let updated = (now - chrono::Duration::minutes(if stale { 120 } else { 1 }))
        .format("%Y%m%d%H%M%SZ")
        .to_string();
    let expires = (now + chrono::Duration::minutes(if stale { -60 } else { 30 }))
        .format("%Y%m%d%H%M%SZ")
        .to_string();
    let produced = now.format("%Y%m%d%H%M%SZ").to_string();
    let alg = sha256_algorithm_identifier_der();
    let tbs = synta_certificate::OCSPResponseBuilder::new()
        .responder_name(cert.tbs_certificate.subject.as_bytes())
        .produced_at(&produced)
        .add_response(synta_certificate::SingleResponseSpec {
            hash_algorithm_der: &alg,
            issuer_name_hash: &id.issuer_name_hash,
            issuer_key_hash: &id.issuer_key_hash,
            serial: &id.serial_number,
            status: 0,
            this_update: &updated,
            next_update: Some(&expires),
        })
        .build_tbs()
        .unwrap();
    let (alg, sig) =
        crate::ca::issue::sign_message(crate::ca::issue::CaSigningKey::Pem(key), "sha256", &tbs)
            .unwrap();
    synta_certificate::OCSPResponseBuilder::assemble(&tbs, &alg, &sig).unwrap()
}

#[test]
fn ocsp_requires_issuer_signature_exact_certid_and_freshness() {
    let (pem, key, ca) = pki::generate_self_signed_ca("CN=OCSP Test CA", 365);
    let (_, _, leaf) = pki::generate_client_cert("device.example.test", &pem, &key, 30);
    let client = OcspClient::new(OcspConfig {
        enabled: true,
        require_nonce: false,
        ..Default::default()
    });
    let id = client.build_cert_id(&leaf, &ca).unwrap();
    let good = response(&id, &ca, &key, false);
    let mut ttl = Duration::ZERO;
    assert_eq!(
        client
            .parse_ocsp_response(&good, &id, &ca, None, &mut ttl)
            .unwrap(),
        OcspStatus::Good
    );
    assert!(ttl > Duration::ZERO && ttl <= Duration::from_secs(1800));
    let mut wrong = id.clone();
    wrong.serial_number = vec![7];
    assert!(
        client
            .parse_ocsp_response(&good, &wrong, &ca, None, &mut ttl)
            .is_err()
    );
    let mut wrong = id.clone();
    wrong.hash_algorithm = "1.3.14.3.2.26".into();
    assert!(
        client
            .parse_ocsp_response(&good, &wrong, &ca, None, &mut ttl)
            .is_err()
    );
    assert!(
        client
            .parse_ocsp_response(&response(&id, &ca, &key, true), &id, &ca, None, &mut ttl)
            .is_err()
    );
    let (_, other_key, other_ca) = pki::generate_self_signed_ca("CN=Other CA", 365);
    assert!(
        client
            .parse_ocsp_response(
                &response(&id, &other_ca, &other_key, false),
                &id,
                &ca,
                None,
                &mut ttl
            )
            .is_err()
    );
    assert!(
        client
            .parse_ocsp_response(&good, &id, &ca, Some(&[1; 32]), &mut ttl)
            .is_err()
    );
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(
        client
            .parse_ocsp_response(&bad, &id, &ca, None, &mut ttl)
            .is_err()
    );
}
