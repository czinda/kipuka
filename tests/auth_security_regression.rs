//! Regressions for the reviewed authentication and issuance boundaries.
#[allow(dead_code)]
mod common;
use axum::http::StatusCode;
use base64::Engine;

#[tokio::test]
async fn review_disabled_admin_is_not_mounted() {
    let mut config = common::test_config();
    config.admin.as_mut().unwrap().enabled = false;
    config.admin.as_mut().unwrap().listen_addr = Some("127.0.0.1:1".into());
    let server = common::TestServer::start_with_config(config).await;
    let response = reqwest::Client::new()
        .get(format!("{}/admin/cas", server.base_url()))
        .bearer_auth("test-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn review_mtls_only_label_rejects_otp() {
    let mut config = common::test_config();
    config
        .est
        .labels
        .push(toml::from_str("name='secure'\nauth_methods=['mtls']\ndisconnected=true\n").unwrap());
    let server = common::TestServer::start_with_config(config).await;
    let client = reqwest::Client::new();
    let result = client
        .post(format!("{}/admin/otp/generate", server.base_url()))
        .bearer_auth("test-admin-token")
        .json(&serde_json::json!({"entity_id":"device-a.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::CREATED);
    let token: serde_json::Value = result.json().await.unwrap();
    let (csr, _) = common::generate_test_csr("CN=device-a.example.com", "rsa:2048");
    let response = client
        .post(format!(
            "{}/.well-known/est/secure/simpleenroll",
            server.base_url()
        ))
        .basic_auth(
            "device-a.example.com",
            Some(token["token"].as_str().unwrap()),
        )
        .header("content-type", "application/pkcs10")
        .body(base64::engine::general_purpose::STANDARD.encode(csr))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let detail = response.text().await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{detail}");
}

#[test]
fn review_reenroll_name_check_rejects_changed_subject_attributes() {
    let auth = kipuka::auth::AuthResult {
        identity: "device-a.example.com".into(),
        method: kipuka::auth::AuthMethod::Mtls,
        client_cert_der: None,
        subject_dn: Some("CN=device-a.example.com,O=TenantA".into()),
        subject_alt_names: vec!["device-a.example.com".into()],
        extended_key_usage: vec![],
    };
    assert!(
        kipuka::auth::mtls::validate_pop_linking(
            &auth,
            "CN=device-a.example.com,O=PrivilegedTenant"
        )
        .is_err()
    );
}

#[test]
fn review_shared_issuer_rejects_corrupted_csr_signature() {
    let ca = common::TestCa::new();
    let (mut csr, _) = common::generate_test_csr("CN=device-a.example.com", "rsa:2048");
    let n = csr.len();
    csr[n - 1] ^= 1;
    let key = ca.key_pem.as_slice();
    let result = kipuka::ca::issue::issue_certificate(
        &csr,
        &Default::default(),
        &ca.cert_der,
        kipuka::ca::issue::CaSigningKey::Pem(key),
        "sha256",
        None,
        None,
    );
    assert!(
        result.is_err(),
        "shared issuer accepted corrupted CSR: {result:?}"
    );
}
