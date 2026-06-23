//! Negative tests for EST endpoint error handling.
//!
//! Verifies that the server correctly rejects malformed, unauthorized,
//! and unsupported requests with appropriate HTTP status codes.

mod common;

use common::{TestClient, TestServer, generate_test_csr};

// ── Authentication errors ───────────────────────────────────────────────────

/// POST /simpleenroll with no authentication returns 401.
#[tokio::test]
async fn simpleenroll_no_auth_returns_401() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _) = generate_test_csr("no-auth-device.test", "rsa:2048");
    let resp = client.est_post_csr("simpleenroll", &csr_der, None).await;

    assert_eq!(
        resp.status(),
        401,
        "POST /simpleenroll without authentication must return 401"
    );

    // RFC 7030 S4.2.3: 401 must include WWW-Authenticate
    let www_auth = resp.headers().get("www-authenticate");
    assert!(
        www_auth.is_some(),
        "401 response must include WWW-Authenticate header"
    );
}

/// POST /simpleenroll with an expired OTP returns 401.
#[tokio::test]
async fn simpleenroll_expired_otp_returns_401() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _) = generate_test_csr("expired-otp-device.test", "rsa:2048");

    // Use a fabricated OTP that does not exist in the store (simulates expired)
    let resp = client
        .est_post_csr(
            "simpleenroll",
            &csr_der,
            Some(("", "expired-fake-token-value")),
        )
        .await;

    assert_eq!(
        resp.status(),
        401,
        "POST /simpleenroll with expired/invalid OTP must return 401"
    );
}

// ── Request format errors ───────────────────────────────────────────────────

/// POST /simpleenroll with garbage CSR data returns 400.
#[tokio::test]
async fn simpleenroll_invalid_csr_returns_400() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    // Generate an OTP if possible, otherwise use a fake one
    let otp_resp = client
        .admin_post(
            "otp/generate",
            &serde_json::json!({"subject": "CN=invalid-csr-device.test"}),
        )
        .await;

    let auth = if otp_resp.status().is_success() {
        let body: serde_json::Value = otp_resp.json().await.unwrap();
        body["otp"].as_str().map(String::from)
    } else {
        None
    };

    // Send garbage data that is not a valid PKCS#10 CSR
    let garbage = b"this is not a valid CSR at all";
    let resp = client
        .est_post_csr("simpleenroll", garbage, auth.as_deref().map(|o| ("", o)))
        .await;

    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 401,
        "POST /simpleenroll with invalid CSR must return 400 (or 401 if auth fails first), got: {status}"
    );
}

/// POST /simpleenroll with wrong Content-Type returns 415.
#[tokio::test]
async fn simpleenroll_wrong_content_type_returns_415() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .est_post_raw("simpleenroll", "application/json", b"{}".to_vec())
        .await;

    assert_eq!(
        resp.status(),
        415,
        "POST /simpleenroll with wrong Content-Type must return 415"
    );
}

/// POST /simplereenroll with wrong Content-Type returns 415.
#[tokio::test]
async fn simplereenroll_wrong_content_type_returns_415() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .est_post_raw("simplereenroll", "text/plain", b"not a csr".to_vec())
        .await;

    assert_eq!(
        resp.status(),
        415,
        "POST /simplereenroll with wrong Content-Type must return 415"
    );
}

/// POST /fullcmc with wrong Content-Type returns 415.
#[tokio::test]
async fn fullcmc_wrong_content_type_returns_415() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .est_post_raw("fullcmc", "application/pkcs10", b"irrelevant".to_vec())
        .await;

    assert_eq!(
        resp.status(),
        415,
        "POST /fullcmc with pkcs10 (not pkcs7-mime) Content-Type must return 415"
    );
}

/// POST /serverkeygen with wrong Content-Type returns 415.
#[tokio::test]
async fn serverkeygen_wrong_content_type_returns_415() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .est_post_raw(
            "serverkeygen",
            "application/octet-stream",
            b"binary garbage".to_vec(),
        )
        .await;

    assert_eq!(
        resp.status(),
        415,
        "POST /serverkeygen with wrong Content-Type must return 415"
    );
}

// ── Label errors ────────────────────────────────────────────────────────────

/// GET /cacerts with an unknown label returns 404.
#[tokio::test]
async fn cacerts_unknown_label_returns_404() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.est_get("nonexistent-label/cacerts").await;
    assert_eq!(resp.status(), 404, "Unknown EST label must return 404");
}

/// POST /simpleenroll on an unknown label returns 404.
#[tokio::test]
async fn simpleenroll_unknown_label_returns_404() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _) = generate_test_csr("label-test.test", "rsa:2048");

    let resp = client
        .est_post_csr(
            "no-such-label/simpleenroll",
            &csr_der,
            Some(("", "fake-otp")),
        )
        .await;

    assert_eq!(
        resp.status(),
        404,
        "simpleenroll on unknown label must return 404"
    );
}

// ── Method errors ───────────────────────────────────────────────────────────

/// GET /simpleenroll (wrong HTTP method) returns 405 or similar.
#[tokio::test]
async fn simpleenroll_get_not_allowed() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.est_get("simpleenroll").await;

    let status = resp.status().as_u16();
    assert!(
        status == 405 || status == 404,
        "GET /simpleenroll (wrong method) should return 405 or 404, got: {status}"
    );
}

/// POST /cacerts (wrong HTTP method) returns 405 or similar.
#[tokio::test]
async fn cacerts_post_not_allowed() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .est_post_raw("cacerts", "application/pkcs10", b"".to_vec())
        .await;

    let status = resp.status().as_u16();
    assert!(
        status == 405 || status == 404,
        "POST /cacerts (wrong method) should return 405 or 404, got: {status}"
    );
}

// ── Simplereenroll without mTLS ─────────────────────────────────────────────

/// POST /simplereenroll without client certificate returns 401.
#[tokio::test]
async fn simplereenroll_no_client_cert_returns_401() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _) = generate_test_csr("reenroll-no-cert.test", "rsa:2048");
    let resp = client.est_post_csr("simplereenroll", &csr_der, None).await;

    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "simplereenroll without client cert must return 401 or 403, got: {status}"
    );
}

// ── Empty body errors ───────────────────────────────────────────────────────

/// POST /simpleenroll with empty body returns 400.
#[tokio::test]
async fn simpleenroll_empty_body_returns_400() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .est_post_raw("simpleenroll", "application/pkcs10", vec![])
        .await;

    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 401,
        "POST /simpleenroll with empty body should return 400 (or 401), got: {status}"
    );
}
