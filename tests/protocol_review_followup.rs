#[allow(dead_code)]
mod common;
use axum::extract::State;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509, X509NameBuilder, extension::KeyUsage},
};
use synta::{Integer, OctetStringRef, RawDer};
use synta_certificate::cmp_types::{PKIBody, PKIHeader, PKIMessage};

// Independent DER framing, deliberately not the server's ProtectedPart encoder.
fn sequence(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    if bytes.len() < 128 {
        out.push(bytes.len() as u8);
    } else if bytes.len() < 256 {
        out.extend([0x81, bytes.len() as u8]);
    } else {
        out.extend([0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
    }
    out.extend(bytes);
    out
}
fn client(server: &common::TestServer, expired: bool, signing: bool) -> (X509, PKey<Private>) {
    let ca = X509::from_der(&server.ca.cert_der).unwrap();
    let ca_key = PKey::private_key_from_pem(&server.ca.key_pem).unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "synthetic-cmp").unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name.build()).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::from_unix(1).unwrap())
        .unwrap();
    let expiry = if expired {
        Asn1Time::from_unix(2).unwrap()
    } else {
        Asn1Time::days_from_now(2).unwrap()
    };
    cert.set_not_after(&expiry).unwrap();
    let mut usage = KeyUsage::new();
    if signing {
        usage.digital_signature();
    } else {
        usage.key_encipherment();
    }
    cert.append_extension(usage.build().unwrap()).unwrap();
    cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
    (cert.build(), key)
}
fn request(cert: &X509, key: &PKey<Private>, revocation: bool, wrapper: bool) -> Vec<u8> {
    let cert_der = cert.to_der().unwrap();
    // RevReqContent with CertTemplate serial 42; empty GenMsgContent otherwise.
    let body = if revocation {
        vec![0x30, 7, 0x30, 5, 0x30, 3, 0x81, 1, 42]
    } else {
        vec![0x30, 0]
    };
    let alg = synta_certificate::AlgorithmIdentifier::from_der(&[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 0x0b, 5, 0,
    ])
    .unwrap();
    let sender = synta_certificate::GeneralNameSpec::rfc822("synthetic@example.test");
    let recipient = synta_certificate::GeneralNameSpec::rfc822("ca@example.test");
    let mut msg = PKIMessage {
        header: PKIHeader {
            pvno: Integer::from_i64(2),
            sender: sender.to_general_name().unwrap(),
            recipient: recipient.to_general_name().unwrap(),
            message_time: None,
            protection_alg: Some(alg),
            sender_kid: None,
            recip_kid: None,
            transaction_id: Some(OctetStringRef::new(b"synthetic-transaction")),
            sender_nonce: Some(OctetStringRef::new(b"synthetic-nonce")),
            recip_nonce: None,
            free_text: None,
            general_info: None,
        },
        body: if revocation {
            PKIBody::Rr(RawDer(&body))
        } else {
            PKIBody::Genm(RawDer(&body))
        },
        protection: None,
        extra_certs: Some(vec![RawDer(&cert_der)]),
    };
    let joined = [msg.header.to_der().unwrap(), msg.body.to_der().unwrap()].concat();
    let bytes = if wrapper { sequence(&joined) } else { joined };
    let signature = openssl::sign::Signer::new(MessageDigest::sha256(), key)
        .unwrap()
        .sign_oneshot_to_vec(&bytes)
        .unwrap();
    msg.protection = Some(synta::BitStringRef::new(&signature, 0).unwrap());
    msg.to_der().unwrap()
}
async fn server() -> (common::TestServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = toml::from_str(&format!(
        r#"
[database]
url="sqlite::memory:"
[ca]
key_file="{}"
cert_file="/dev/null"
[cmp]
enabled=true
allow_rr=true
[[cmp.mac_secrets]]
reference="synthetic@example.test"
secret_hex="73796e7468657469632d736563726574"
[ocsp]
enabled=false
[cms_est]
enabled=true
[est]
disconnected=true
"#,
        dir.path().join("ca.pem").display()
    ))
    .unwrap();
    let server = common::TestServer::start_with_config(config).await;
    std::fs::write(dir.path().join("ca.pem"), &server.ca.key_pem).unwrap();
    (server, dir)
}
#[tokio::test]
async fn cmp_independent_protected_part_lifecycle_and_self_revocation() {
    let (server, _dir) = server().await;
    let (cert, key) = client(&server, false, true);
    let call =
        |body: Vec<u8>| kipuka::routes::cmp::post_cmp(State(server.state.clone()), body.into());
    assert!(
        call(request(&cert, &key, false, true)).await.is_ok(),
        "standard ProtectedPart must authenticate"
    );
    assert!(
        call(request(&cert, &key, false, false)).await.is_err(),
        "legacy unwrapped encoding must fail"
    );
    let (expired, expired_key) = client(&server, true, true);
    assert!(
        call(request(&expired, &expired_key, false, true))
            .await
            .unwrap_err()
            .to_string()
            .contains("validity")
    );
    let (wrong_usage, wrong_key) = client(&server, false, false);
    assert!(
        call(request(&wrong_usage, &wrong_key, false, true))
            .await
            .unwrap_err()
            .to_string()
            .contains("key usage")
    );
    let cert_der = cert.to_der().unwrap();
    let parsed = synta_certificate::Certificate::from_der(&cert_der).unwrap();
    let subject = synta_certificate::format_dn(parsed.tbs_certificate.subject.as_bytes());
    sqlx::query("INSERT INTO certificates (serial,subject_dn,issuer_dn,not_before,not_after,der_encoded,ca_id,profile,status) VALUES ('2a',?,'synthetic','2020-01-01','2030-01-01',?,'default','default','active')").bind(subject).bind(cert.to_der().unwrap()).execute(&server.state.db).await.unwrap();
    assert!(
        call(request(&cert, &key, true, true)).await.is_ok(),
        "self revocation must query subject_dn"
    );
    let status: (String,) = sqlx::query_as("SELECT status FROM certificates WHERE serial='2a'")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(status.0, "revoked");
    assert!(
        call(request(&cert, &key, false, true))
            .await
            .unwrap_err()
            .to_string()
            .contains("revoked")
    );
}
#[tokio::test]
async fn cms_disconnected_rejects_without_issuing() {
    let (server, _dir) = server().await;
    let label = kipuka::routes::LabelExtractor::resolve(&server.state, None).unwrap();
    let result = kipuka::routes::cms_est::post_cms_simpleenroll(
        label,
        State(server.state.clone()),
        vec![1; 100].into(),
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("disconnected"));
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn cmp_mac_cannot_revoke_certificates() {
    let (server, _dir) = server().await;
    let (cert, key) = client(&server, false, true);
    sqlx::query("INSERT INTO certificates (serial,subject_dn,issuer_dn,not_before,not_after,der_encoded,ca_id,profile,status) VALUES ('2a','different-owner','synthetic','2020-01-01','2030-01-01',?,'default','default','active')")
        .bind(cert.to_der().unwrap()).execute(&server.state.db).await.unwrap();
    let raw = request(&cert, &key, true, true);
    let mut msg = PKIMessage::from_der(&raw).unwrap();
    let sha = synta_certificate::AlgorithmIdentifier::from_der(&[
        0x30, 0x0b, 0x06, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1,
    ])
    .unwrap();
    let hmac = synta_certificate::AlgorithmIdentifier::from_der(&[
        0x30, 0x0a, 0x06, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 9,
    ])
    .unwrap();
    let pbm = synta_certificate::cmp_types::PBMParameter {
        salt: OctetStringRef::new(b"synthetic-salt"),
        owf: sha,
        iteration_count: Integer::from_i64(1),
        mac: hmac,
    }
    .to_der()
    .unwrap();
    let oid = vec![0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 7, 0x42, 0x0d];
    let alg_der = sequence(&[oid, pbm].concat());
    msg.header.protection_alg =
        Some(synta_certificate::AlgorithmIdentifier::from_der(&alg_der).unwrap());
    msg.extra_certs = None;
    let derived = openssl::sha::sha256(b"synthetic-secretsynthetic-salt");
    let key = PKey::hmac(&derived).unwrap();
    let input = sequence(&[msg.header.to_der().unwrap(), msg.body.to_der().unwrap()].concat());
    let signature = openssl::sign::Signer::new(MessageDigest::sha256(), &key)
        .unwrap()
        .sign_oneshot_to_vec(&input)
        .unwrap();
    msg.protection = Some(synta::BitStringRef::new(&signature, 0).unwrap());
    let error =
        kipuka::routes::cmp::post_cmp(State(server.state.clone()), msg.to_der().unwrap().into())
            .await
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("revocation requires certificate signature"),
        "{error}"
    );
    let status: (String,) = sqlx::query_as("SELECT status FROM certificates WHERE serial='2a'")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(
        status.0, "active",
        "MAC must not mutate the target certificate"
    );
}
