//! Bounded lockout admission must not give invented usernames global influence.
#[allow(dead_code)]
mod common;
use axum::http::StatusCode;

#[tokio::test]
async fn invented_entities_do_not_consume_lockouts_but_provisioned_entities_do() {
    let mut config = common::test_config();
    config.auth_lockout.max_failures = 2;
    let server = common::TestServer::start_with_config(config).await;
    let client = reqwest::Client::new();
    let url = format!("{}/.well-known/est/simpleenroll", server.base_url());
    for _ in 0..4 {
        let response = client
            .post(&url)
            .basic_auth("invented.example.test", Some("invalid"))
            .header("content-type", "application/pkcs10")
            .body("invalid")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = client
        .post(format!("{}/admin/otp/generate", server.base_url()))
        .bearer_auth("test-admin-token")
        .json(&serde_json::json!({"entity_id": "provisioned.example.test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let token: serde_json::Value = response.json().await.unwrap();
    for expected in [StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS] {
        let response = client
            .post(&url)
            .basic_auth("provisioned.example.test", Some("invalid"))
            .header("content-type", "application/pkcs10")
            .body("invalid")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let response = client
        .post(&url)
        .basic_auth(
            "provisioned.example.test",
            Some(token["token"].as_str().unwrap()),
        )
        .header("content-type", "application/pkcs10")
        .body("invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}
