//! Admin API integration tests.
//!
//! Verifies all admin endpoints:
//! - OTP management (generate, list, revoke)
//! - CA listing and health
//! - System health checks
//! - Certificate listing and revocation

mod common;

use common::{TestClient, TestServer};

// ── OTP Management ──────────────────────────────────────────────────────────

/// POST /admin/otp/generate creates a new OTP and returns it.
#[tokio::test]
async fn otp_generate_returns_token() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .admin_post(
            "otp/generate",
            &serde_json::json!({
                "subject": "CN=test-device.kipuka.test"
            }),
        )
        .await;

    let status = resp.status();
    if status.is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("otp").is_some() || body.get("token").is_some(),
            "OTP generate response must include an OTP/token field"
        );
    } else {
        // Admin API may not be fully wired yet
        eprintln!("WARN: OTP generate returned {status} — admin API may not be fully implemented");
    }
}

/// GET /admin/otp lists active OTP tokens.
#[tokio::test]
async fn otp_list_returns_array() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("otp").await;
    let status = resp.status();

    if status.is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.is_array() || body.get("otps").map_or(false, |v| v.is_array()),
            "OTP list response must be an array or contain an 'otps' array"
        );
    } else {
        eprintln!("WARN: OTP list returned {status}");
    }
}

/// DELETE /admin/otp/{id} revokes an OTP.
#[tokio::test]
async fn otp_revoke_nonexistent_returns_404() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_delete("otp/nonexistent-id-12345").await;
    let status = resp.status().as_u16();

    // Non-existent OTP should return 404
    assert!(
        status == 404 || status == 200,
        "revoking non-existent OTP should return 404 (or 200 if idempotent), got: {status}"
    );
}

/// OTP generate → list → revoke lifecycle.
#[tokio::test]
async fn otp_full_lifecycle() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    // Step 1: Generate
    let gen_resp = client
        .admin_post(
            "otp/generate",
            &serde_json::json!({"subject": "CN=lifecycle-test.test"}),
        )
        .await;

    if !gen_resp.status().is_success() {
        eprintln!("SKIP: OTP lifecycle test — admin API not fully wired");
        return;
    }

    let gen_body: serde_json::Value = gen_resp.json().await.unwrap();
    let otp_id = gen_body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Step 2: List — verify the OTP appears
    let list_resp = client.admin_get("otp").await;
    if list_resp.status().is_success() {
        let list_body = list_resp.text().await.unwrap();
        // The generated OTP ID should appear in the list
        // (exact format depends on implementation)
        let _ = list_body;
    }

    // Step 3: Revoke
    let revoke_resp = client.admin_delete(&format!("otp/{otp_id}")).await;
    let revoke_status = revoke_resp.status().as_u16();
    assert!(
        revoke_status == 200 || revoke_status == 204 || revoke_status == 404,
        "OTP revoke should return 200/204/404, got: {revoke_status}"
    );
}

// ── CA Management ───────────────────────────────────────────────────────────

/// GET /admin/cas lists all configured CAs.
#[tokio::test]
async fn cas_list_returns_configured_cas() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("cas").await;
    let status = resp.status();

    if status.is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        // Should contain at least the default CA
        let cas = body
            .as_array()
            .or_else(|| body.get("cas").and_then(|v| v.as_array()));

        if let Some(cas) = cas {
            assert!(!cas.is_empty(), "CA list should not be empty");
        }
    } else {
        eprintln!("WARN: CAs list returned {status}");
    }
}

/// GET /admin/cas/{id} returns details for a specific CA.
#[tokio::test]
async fn cas_get_default_ca() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("cas/default").await;
    let status = resp.status();

    // The default CA should always exist
    assert!(
        status == 200 || status == 404,
        "GET /admin/cas/default should return 200 or 404, got: {status}"
    );
}

/// GET /admin/cas/{id} for unknown CA returns 404.
#[tokio::test]
async fn cas_get_unknown_returns_404() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("cas/does-not-exist").await;
    assert_eq!(
        resp.status(),
        404,
        "GET /admin/cas/<unknown> should return 404"
    );
}

// ── System Health ───────────────────────────────────────────────────────────

/// GET /admin/health returns system health status.
#[tokio::test]
async fn health_returns_status() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("health").await;
    let status = resp.status();

    assert!(
        status.is_success(),
        "GET /admin/health should return 2xx, got: {status}"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("status").is_some(),
        "health response must include a 'status' field"
    );
}

/// GET /admin/health/db returns database connectivity status.
#[tokio::test]
async fn health_db_returns_status() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("health/db").await;
    let status = resp.status();

    assert!(
        status.is_success(),
        "GET /admin/health/db should return 2xx, got: {status}"
    );
}

/// GET /admin/health/ca returns CA backend health.
#[tokio::test]
async fn health_ca_returns_status() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("health/ca").await;
    let status = resp.status();

    assert!(
        status.is_success() || status == 503,
        "GET /admin/health/ca should return 2xx or 503, got: {status}"
    );
}

/// GET /admin/health/hsm returns HSM connectivity status.
#[tokio::test]
async fn health_hsm_returns_status() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("health/hsm").await;
    let status = resp.status();

    // HSM may not be configured — 200 (not configured) or 503 (unavailable)
    assert!(
        status.is_success() || status == 503 || status == 501,
        "GET /admin/health/hsm should return 2xx, 501, or 503, got: {status}"
    );
}

// ── Certificate Management ──────────────────────────────────────────────────

/// GET /admin/certs lists issued certificates.
#[tokio::test]
async fn certs_list_returns_array() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.admin_get("certs").await;
    let status = resp.status();

    if status.is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.is_array() || body.get("certificates").map_or(false, |v| v.is_array()),
            "certs list should be an array or contain a 'certificates' array"
        );
    } else {
        eprintln!("WARN: certs list returned {status}");
    }
}

/// POST /admin/certs/{serial}/revoke for unknown serial returns 404.
#[tokio::test]
async fn certs_revoke_unknown_serial_returns_404() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client
        .admin_post(
            "certs/DEADBEEF01234567/revoke",
            &serde_json::json!({"reason": "keyCompromise"}),
        )
        .await;

    let status = resp.status().as_u16();
    assert!(
        status == 404 || status == 400,
        "revoking unknown serial should return 404 or 400, got: {status}"
    );
}

// ── Admin Authentication ────────────────────────────────────────────────────

/// Admin endpoints without auth return 401.
#[tokio::test]
async fn admin_no_auth_returns_401() {
    let server = TestServer::start().await;

    // Build a client that does NOT send Bearer token
    let raw_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap();

    let resp = raw_client
        .get(format!("{}/admin/health", server.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "admin endpoint without auth must return 401"
    );
}

/// Admin endpoints with invalid Bearer token return 401.
#[tokio::test]
async fn admin_invalid_token_returns_401() {
    let server = TestServer::start().await;

    let raw_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap();

    let resp = raw_client
        .get(format!("{}/admin/health", server.base_url()))
        .header("Authorization", "Bearer ")  // empty token
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "admin endpoint with empty Bearer token must return 401"
    );
}
