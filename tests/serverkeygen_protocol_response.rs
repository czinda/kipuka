#[allow(dead_code)]
mod common;
use base64::Engine;
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    pkey::PKey,
    x509::X509,
};

fn verify_multipart(
    body: &[u8],
    placeholder: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Vec<u8> {
    let mime = std::str::from_utf8(body).unwrap();
    let boundary = mime
        .lines()
        .find(|line| line.starts_with("--"))
        .unwrap()
        .trim();
    assert!(boundary.starts_with("--"));
    let mut cert = None;
    let mut key = None;
    for part in mime.split(boundary) {
        if let Some((headers, body)) = part.split_once("\r\n\r\n") {
            let der = base64::engine::general_purpose::STANDARD
                .decode(
                    body.chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>(),
                )
                .unwrap();
            if headers.contains("application/pkcs8") {
                key = Some(PKey::private_key_from_der(&der).unwrap());
            }
            if headers.contains("application/pkcs7-mime") {
                let p7 = openssl::pkcs7::Pkcs7::from_der(&der).unwrap();
                cert = Some(p7.signed().unwrap().certificates().unwrap()[0].to_owned());
            }
        }
    }
    let key = key.expect("private key MIME part");
    let cert = cert.expect("certificate MIME part");
    assert!(
        cert.subject_alt_names()
            .unwrap()
            .iter()
            .any(|name| name.dnsname() == Some("san-keygen.example.test")),
        "serverkeygen must preserve CSR SAN requests"
    );
    let public = cert.public_key().unwrap();
    assert!(key.public_eq(&public));
    assert!(
        !key.public_eq(placeholder),
        "serverkeygen must replace the template key"
    );
    cert.to_der().unwrap()
}

#[tokio::test]
async fn normal_and_cms_keygen_deliver_fresh_matching_keys_and_persist() {
    let directory = tempfile::tempdir().unwrap();
    let key_file = directory.path().join("synthetic-ca.pem");
    let mut config: kipuka::config::Config = toml::from_str(
        r#"
        [database]
        url="sqlite::memory:"
        run_migrations=true
        [ca]
        key_file="/dev/null"
        cert_file="/dev/null"
        [est]
        serverkeygen=true
        [cms_est]
        enabled=true
        [ocsp]
        enabled=false
    "#,
    )
    .unwrap();
    config.cas[0].key_file = key_file.to_string_lossy().into_owned();
    let server = common::TestServer::start_with_config(config).await;
    std::fs::write(&key_file, &server.ca.key_pem).unwrap();
    let template_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut request = openssl::x509::X509Req::builder().unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "synthetic-keygen.example.test")
        .unwrap();
    request.set_subject_name(&name.build()).unwrap();
    request.set_pubkey(&template_key).unwrap();
    let san = openssl::x509::extension::SubjectAlternativeName::new()
        .dns("san-keygen.example.test")
        .build(&request.x509v3_context(None))
        .unwrap();
    let mut extensions = openssl::stack::Stack::new().unwrap();
    extensions.push(san).unwrap();
    request.add_extensions(&extensions).unwrap();
    request
        .sign(&template_key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let csr = request.build().to_der().unwrap();
    let placeholder = openssl::x509::X509Req::from_der(&csr)
        .unwrap()
        .public_key()
        .unwrap();
    let mut identity = kipuka::auth::AuthResult::anonymous();
    identity.identity = "synthetic-keygen".into();
    identity.method = kipuka::auth::AuthMethod::Mtls;
    let response = kipuka::routes::serverkeygen::post_serverkeygen(
        kipuka::auth::EstAuth(identity),
        kipuka::routes::LabelExtractor::resolve(&server.state, None).unwrap(),
        axum::extract::State(server.state.clone()),
        base64::engine::general_purpose::STANDARD
            .encode(&csr)
            .into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("multipart/mixed; boundary=")
    );
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let first = verify_multipart(&body, &placeholder);

    let (client_pem, client_key, _) = common::pki::generate_client_cert(
        "synthetic-cms-client",
        &server.ca.cert_pem,
        &server.ca.key_pem,
        1,
    );
    let client_cert = X509::from_pem(&client_pem).unwrap();
    let client_key = PKey::private_key_from_pem(&client_key).unwrap();
    let signed = CmsContentInfo::sign(
        Some(&client_cert),
        Some(&client_key),
        None,
        Some(&csr),
        CMSOptions::BINARY,
    )
    .unwrap()
    .to_der()
    .unwrap();
    let response = kipuka::routes::cms_est::post_cms_serverkeygen(
        kipuka::routes::LabelExtractor::resolve(&server.state, None).unwrap(),
        axum::extract::State(server.state.clone()),
        signed.into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let content = synta_certificate::pkcs7_types::ContentInfo::from_der(&body).unwrap();
    assert_eq!(
        content.content_type.components(),
        &[1, 2, 840, 113549, 1, 9, 16, 1, 23],
        "GCM must use CMS AuthEnvelopedData"
    );
    let mut altered = body.to_vec();
    *altered.last_mut().unwrap() ^= 1;
    assert!(
        CmsContentInfo::from_der(&altered)
            .unwrap()
            .decrypt(&client_key, &client_cert)
            .is_err(),
        "altered GCM authentication tag must reject plaintext"
    );
    let decrypted = CmsContentInfo::from_der(&body)
        .unwrap()
        .decrypt(&client_key, &client_cert)
        .unwrap();
    let second = verify_multipart(&decrypted, &placeholder);
    assert_ne!(first, second);
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT der_encoded FROM certificates")
        .fetch_all(&server.state.db)
        .await
        .unwrap();
    assert!(stored.contains(&first));
    assert!(stored.contains(&second));
}
