//! CoAP EST enrollment-authorization enforcement (NIAP CA PP FDP_ACF.1).
//!
//! Regression coverage for the transport-parity gap where EST-coaps issued
//! certificates without applying the per-label access-control policy that the
//! HTTP `/simpleenroll` path enforces.  The fix routes CoAP requests through
//! the same [`LabelExtractor`] resolution and `authorize_csr_der` check.
//!
//! The authorization decision runs *before* any signing key is resolved, so a
//! denied request never touches CA key material (which the in-memory test
//! server does not have) — these tests assert purely on the CoAP outcome code.
//!
//! [`LabelExtractor`]: kipuka::routes::LabelExtractor

#[allow(dead_code)]
mod common;

use common::TestServer;
use kipuka::config::Config;
use kipuka::routes::coap::CoapEstHandler;
use kipuka_coap::EstHandler;
use kipuka_coap::server::EstOperation;

/// Config with one label `secure` that binds the CSR CN to the authenticated
/// identity (FDP_ACF.1), plus the default (policy-free) endpoint.
fn config_with_secure_label() -> Config {
    let toml_str = r#"
[server]
listen_addr = "127.0.0.1:0"

[database]
url = "sqlite::memory:"
run_migrations = true

[ca]
key_file = "/dev/null"
cert_file = "/dev/null"
validity_days = 90

[est]
simpleenroll = true
simplereenroll = true

[[est.label]]
name = "secure"
require_cn_match = true

[otp]
enabled = true

[admin]
enabled = true
auth_method = "mtls"
admin_ca_file = "/dev/null"
bearer_token = "test-admin-token"

[audit]
enabled = true
"#;
    toml::from_str(toml_str).expect("failed to parse CoAP authz test config")
}

/// A labeled enroll whose CSR CN cannot match the (absent) authenticated
/// identity is denied with 4.03 Forbidden — the policy is enforced over CoAP,
/// not silently bypassed.
#[tokio::test]
async fn coap_simpleenroll_denied_by_label_policy() {
    let server = TestServer::start_with_config(config_with_secure_label()).await;
    let handler = CoapEstHandler::new(server.state.clone());

    // No client certificate → empty identity; `require_cn_match` cannot be
    // satisfied by any non-empty CSR Common Name.
    let (csr_der, _key) = common::generate_test_csr("CN=device-a.example.com", "rsa:2048");

    let err = handler
        .handle(
            EstOperation::SimpleEnroll,
            Some("secure"),
            &csr_der,
            None,
            None,
        )
        .expect_err("labeled policy must deny a mismatched CSR");

    assert!(
        matches!(err, kipuka_coap::CoapError::Forbidden(_)),
        "expected 4.03 Forbidden from FDP_ACF.1 denial, got {err:?}"
    );
}

/// An unknown label is a routing/addressing failure (4.04 Not Found), kept
/// distinct from an authorization denial (4.03 Forbidden).
#[tokio::test]
async fn coap_simpleenroll_unknown_label_is_not_found() {
    let server = TestServer::start_with_config(config_with_secure_label()).await;
    let handler = CoapEstHandler::new(server.state.clone());

    let (csr_der, _key) = common::generate_test_csr("CN=device-a.example.com", "rsa:2048");

    let err = handler
        .handle(
            EstOperation::SimpleEnroll,
            Some("does-not-exist"),
            &csr_der,
            None,
            None,
        )
        .expect_err("unknown label must not resolve to an issuer");

    assert!(
        matches!(err, kipuka_coap::CoapError::ResourceNotFound(_)),
        "expected 4.04 Not Found for an unknown label, got {err:?}"
    );
}

/// Real bridge callback work runs on the transport's blocking worker, allowing
/// asynchronous database admission/persistence without a nested-runtime panic.
#[tokio::test]
async fn coap_blocking_bridge_persists_issued_certificate_and_audit() {
    let directory = tempfile::tempdir().unwrap();
    let key_file = directory.path().join("synthetic-ca-key.pem");
    let mut config = config_with_secure_label();
    config.cas[0].key_file = key_file.to_string_lossy().into_owned();
    config.ocsp.enabled = false;
    let server = TestServer::start_with_config(config).await;
    std::fs::write(&key_file, &server.ca.key_pem).unwrap();
    let client_cert = kipuka_coap::dtls::ClientCertInfo::from_der(&server.ca.cert_der).unwrap();
    let (csr, _) = common::generate_test_csr("CN=synthetic-device.example.test", "rsa:2048");
    let handler = CoapEstHandler::new(server.state.clone());
    let response = tokio::task::spawn_blocking(move || {
        handler.handle(
            EstOperation::SimpleEnroll,
            None,
            &csr,
            Some(285),
            Some(&client_cert),
        )
    })
    .await
    .expect("blocking callback must not panic")
    .expect("enrollment should succeed");
    let pkcs7 = openssl::pkcs7::Pkcs7::from_der(&response.payload).unwrap();
    let issued = pkcs7.signed().unwrap().certificates().unwrap()[0]
        .to_der()
        .unwrap();
    let persisted: Vec<u8> =
        sqlx::query_scalar("SELECT der_encoded FROM certificates WHERE ca_id = 'default'")
            .fetch_one(&server.state.db)
            .await
            .unwrap();
    assert_eq!(persisted, issued);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE '%ca_id=default%'",
    )
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert!(
        count >= 1,
        "issuance must persist an audit record before returning"
    );
}
