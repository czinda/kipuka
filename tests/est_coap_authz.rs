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
