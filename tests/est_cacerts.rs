//! Integration tests for GET /.well-known/est/cacerts
//!
//! Verifies that the /cacerts endpoint:
//! - Returns 200 with the correct content type
//! - Returns a valid PKCS#7 degenerate (certs-only) structure
//! - Contains the configured CA certificate
//! - Is accessible without authentication
//! - Supports EST labels

// TODO: Uncomment and implement once the server scaffolding is in place.
// These tests require a running test server with a test CA.

#[cfg(test)]
mod tests {
    // use kipuka_est;
    // use reqwest;
    // use std::net::SocketAddr;

    /// Helper: start a test server with an ephemeral port and return the base URL.
    ///
    /// The test server uses:
    /// - An in-memory SQLite database
    /// - A self-signed test CA certificate
    /// - TLS disabled (plain HTTP for test simplicity) or with a test cert
    async fn _start_test_server() -> String {
        // TODO: Build test config, start axum server on 127.0.0.1:0,
        // return the bound address as a URL string.
        todo!("Implement test server startup")
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn cacerts_returns_200_with_pkcs7_content_type() {
        // let base_url = start_test_server().await;
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .get(format!("{base_url}/.well-known/est/cacerts"))
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 200);
        //
        // let content_type = resp.headers().get("content-type").unwrap().to_str().unwrap();
        // assert!(
        //     content_type.contains("application/pkcs7-mime"),
        //     "Expected application/pkcs7-mime, got: {content_type}"
        // );
        // assert!(
        //     content_type.contains("smime-type=certs-only"),
        //     "Expected smime-type=certs-only in content type, got: {content_type}"
        // );
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn cacerts_returns_valid_pkcs7_response() {
        // let base_url = start_test_server().await;
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .get(format!("{base_url}/.well-known/est/cacerts"))
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 200);
        //
        // let body = resp.text().await.unwrap();
        //
        // // Body should be base64-encoded
        // let der = base64::engine::general_purpose::STANDARD
        //     .decode(body.trim())
        //     .expect("Response body should be valid base64");
        //
        // // DER should start with a SEQUENCE tag (0x30)
        // assert_eq!(der[0], 0x30, "PKCS#7 DER should start with SEQUENCE tag");
        //
        // // Parse as PKCS#7 ContentInfo using Synta and verify it contains certs
        // // TODO: Use synta to parse and verify the PKCS#7 structure
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn cacerts_accessible_without_authentication() {
        // The /cacerts endpoint MUST be accessible without any authentication
        // per RFC 7030 Section 4.1.
        //
        // let base_url = start_test_server().await;
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .no_proxy()  // No client cert, no auth headers
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .get(format!("{base_url}/.well-known/est/cacerts"))
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 200, "cacerts must not require authentication");
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn cacerts_with_label_returns_label_specific_ca() {
        // EST labels allow different CA certificates for different profiles.
        // GET /.well-known/est/<label>/cacerts should return the label's CA.
        //
        // let base_url = start_test_server().await;
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .get(format!("{base_url}/.well-known/est/server-tls/cacerts"))
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 200);
        // // TODO: Verify the returned cert matches the label's CA, not the default CA
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn cacerts_unknown_label_returns_404() {
        // An unknown label should return 404, not fall back to the default CA.
        //
        // let base_url = start_test_server().await;
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .get(format!("{base_url}/.well-known/est/nonexistent-label/cacerts"))
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 404);
    }
}
