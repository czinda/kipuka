//! Integration tests for POST /.well-known/est/simpleenroll
//!
//! Verifies that the /simpleenroll endpoint:
//! - Accepts a valid CSR with OTP authentication and issues a certificate
//! - Returns the correct content type (application/pkcs7-mime)
//! - Rejects requests without authentication
//! - Rejects invalid CSRs
//! - Rejects expired or already-used OTP tokens
//! - Respects label-specific certificate profile constraints

#[cfg(test)]
mod tests {
    // use kipuka_est;
    // use kipuka_otp;
    // use reqwest;
    // use base64::Engine;

    /// Helper: generate a test CSR with the given subject CN.
    ///
    /// Returns (csr_pem, private_key_pem) as base64-encoded strings.
    fn _generate_test_csr(_cn: &str) -> (String, String) {
        // TODO: Use synta or openssl to generate a CSR.
        // The CSR should be base64-encoded (not base64url) per EST spec.
        todo!("Generate test CSR")
    }

    /// Helper: provision an OTP token in the test database and return the plaintext.
    async fn _provision_otp(_entity_id: &str) -> String {
        // TODO: Create an OTP token via the OTP module, return plaintext.
        todo!("Provision test OTP")
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn simpleenroll_with_valid_otp_issues_certificate() {
        // let base_url = start_test_server().await;
        // let (csr_b64, _key) = generate_test_csr("test-device.example.com");
        // let otp = provision_otp("test-device").await;
        //
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // // EST uses HTTP Basic auth for OTP. Username is ignored per RFC 7030.
        // let resp = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .basic_auth("", Some(&otp))
        //     .header("Content-Type", "application/pkcs10")
        //     .body(csr_b64)
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 200);
        //
        // let content_type = resp.headers().get("content-type").unwrap().to_str().unwrap();
        // assert!(content_type.contains("application/pkcs7-mime"));
        //
        // let body = resp.text().await.unwrap();
        // let der = base64::engine::general_purpose::STANDARD
        //     .decode(body.trim())
        //     .expect("Response should be valid base64");
        // assert!(!der.is_empty(), "Certificate DER should not be empty");
        //
        // // TODO: Parse the PKCS#7 response and extract the certificate.
        // // Verify the subject matches the CSR.
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn simpleenroll_without_auth_returns_401() {
        // let base_url = start_test_server().await;
        // let (csr_b64, _key) = generate_test_csr("unauth-device.example.com");
        //
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .header("Content-Type", "application/pkcs10")
        //     .body(csr_b64)
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 401, "Request without auth must be rejected");
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn simpleenroll_with_invalid_csr_returns_400() {
        // let base_url = start_test_server().await;
        // let otp = provision_otp("bad-csr-device").await;
        //
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // // Send garbage instead of a valid CSR
        // let resp = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .basic_auth("", Some(&otp))
        //     .header("Content-Type", "application/pkcs10")
        //     .body("dGhpcyBpcyBub3QgYSB2YWxpZCBDU1I=")  // "this is not a valid CSR" in base64
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 400, "Invalid CSR must be rejected");
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn simpleenroll_with_expired_otp_returns_401() {
        // let base_url = start_test_server().await;
        // let (csr_b64, _key) = generate_test_csr("expired-otp-device.example.com");
        //
        // // TODO: Provision an OTP with an already-passed expiration time.
        // let _expired_otp = "expired-token-value";
        //
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .basic_auth("", Some("expired-token-value"))
        //     .header("Content-Type", "application/pkcs10")
        //     .body(csr_b64)
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 401, "Expired OTP must be rejected");
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn simpleenroll_otp_single_use_rejects_reuse() {
        // let base_url = start_test_server().await;
        // let (csr_b64, _key) = generate_test_csr("reuse-test.example.com");
        // let otp = provision_otp("reuse-test").await;
        //
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // // First enrollment should succeed
        // let resp1 = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .basic_auth("", Some(&otp))
        //     .header("Content-Type", "application/pkcs10")
        //     .body(csr_b64.clone())
        //     .send()
        //     .await
        //     .unwrap();
        // assert_eq!(resp1.status(), 200, "First use should succeed");
        //
        // // Second enrollment with same OTP should fail
        // let resp2 = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .basic_auth("", Some(&otp))
        //     .header("Content-Type", "application/pkcs10")
        //     .body(csr_b64)
        //     .send()
        //     .await
        //     .unwrap();
        // assert_eq!(resp2.status(), 401, "Reused OTP must be rejected");
    }

    #[ignore = "stub: requires full server wiring"]
    #[tokio::test]
    async fn simpleenroll_wrong_content_type_returns_415() {
        // let base_url = start_test_server().await;
        // let otp = provision_otp("wrong-ct-device").await;
        //
        // let client = reqwest::Client::builder()
        //     .danger_accept_invalid_certs(true)
        //     .build()
        //     .unwrap();
        //
        // let resp = client
        //     .post(format!("{base_url}/.well-known/est/simpleenroll"))
        //     .basic_auth("", Some(&otp))
        //     .header("Content-Type", "application/json")
        //     .body("{}")
        //     .send()
        //     .await
        //     .unwrap();
        //
        // assert_eq!(resp.status(), 415, "Wrong content type must be rejected");
    }
}
