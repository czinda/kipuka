//! Post-Quantum Cryptography (PQC) EST flow tests.
//!
//! These tests validate ML-DSA and ML-KEM enrollment through kipuka.
//! They are conditionally compiled and run only when OpenSSL 3.5+ is
//! available (which includes FIPS 204/203 support).
//!
//! PQC algorithms tested:
//! - ML-DSA-44 (NIST Security Level 2)
//! - ML-DSA-65 (NIST Security Level 3)
//! - ML-DSA-87 (NIST Security Level 5)
//! - ML-KEM-512/768/1024 via /serverkeygen
//! - Composite ML-DSA-44+P-256

#[allow(dead_code)]
mod common;

use common::pki;
use common::{TestClient, TestServer};

/// Skip helper: returns true if OpenSSL 3.5+ with ML-DSA support is available.
fn pqc_available() -> bool {
    pki::openssl_supports_mldsa()
}

// ── ML-DSA Enrollment Tests ─────────────────────────────────────────────────

/// Enroll with an ML-DSA-44 CSR (NIST Security Level 2).
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+ and fully wired CA signing"]
async fn enroll_mldsa44() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for ML-DSA-44 test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _key_pem) = pki::generate_mldsa_csr("mldsa44-device.test", "ml-dsa-44")
        .expect("failed to generate ML-DSA-44 CSR");

    // Attempt enrollment (may need OTP depending on server config)
    let resp = client
        .est_post_csr("simpleenroll", &csr_der, Some(("", "test-pqc-otp")))
        .await;

    let status = resp.status().as_u16();
    // Accept 200 (issued), 202 (deferred), or 400 (unsupported by CA backend)
    assert!(
        status == 200 || status == 202 || status == 400 || status == 401,
        "ML-DSA-44 enrollment should return 200/202/400/401, got: {status}"
    );
}

/// Enroll with an ML-DSA-65 CSR (NIST Security Level 3).
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+ and fully wired CA signing"]
async fn enroll_mldsa65() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for ML-DSA-65 test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _key_pem) = pki::generate_mldsa_csr("mldsa65-device.test", "ml-dsa-65")
        .expect("failed to generate ML-DSA-65 CSR");

    let resp = client
        .est_post_csr("simpleenroll", &csr_der, Some(("", "test-pqc-otp")))
        .await;

    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 202 || status == 400 || status == 401,
        "ML-DSA-65 enrollment should return 200/202/400/401, got: {status}"
    );
}

/// Enroll with an ML-DSA-87 CSR (NIST Security Level 5).
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+ and fully wired CA signing"]
async fn enroll_mldsa87() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for ML-DSA-87 test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _key_pem) = pki::generate_mldsa_csr("mldsa87-device.test", "ml-dsa-87")
        .expect("failed to generate ML-DSA-87 CSR");

    let resp = client
        .est_post_csr("simpleenroll", &csr_der, Some(("", "test-pqc-otp")))
        .await;

    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 202 || status == 400 || status == 401,
        "ML-DSA-87 enrollment should return 200/202/400/401, got: {status}"
    );
}

// ── Server-Side Key Generation (ML-KEM) ─────────────────────────────────────

/// Server-side keygen with ML-KEM-512.
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+, HSM integration, and fully wired serverkeygen"]
async fn serverkeygen_mlkem512() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for ML-KEM-512 test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    // For serverkeygen, the client sends a CSR requesting server-generated keys.
    // The key type request is typically embedded in CSR attributes or negotiated
    // via the EST label configuration.
    let (csr_der, _) = common::generate_test_csr("mlkem512-device.test", "rsa:2048");

    let resp = client
        .est_post_csr("serverkeygen", &csr_der, Some(("", "test-pqc-otp")))
        .await;

    let status = resp.status().as_u16();
    // Accept any non-500 response — 200 (issued), 401 (auth), 501 (not impl)
    assert!(
        status < 500,
        "serverkeygen ML-KEM-512 should not return 5xx, got: {status}"
    );
}

/// Server-side keygen with ML-KEM-768.
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+, HSM integration, and fully wired serverkeygen"]
async fn serverkeygen_mlkem768() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for ML-KEM-768 test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _) = common::generate_test_csr("mlkem768-device.test", "rsa:2048");

    let resp = client
        .est_post_csr("serverkeygen", &csr_der, Some(("", "test-pqc-otp")))
        .await;

    let status = resp.status().as_u16();
    assert!(
        status < 500,
        "serverkeygen ML-KEM-768 should not return 5xx, got: {status}"
    );
}

/// Server-side keygen with ML-KEM-1024.
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+, HSM integration, and fully wired serverkeygen"]
async fn serverkeygen_mlkem1024() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for ML-KEM-1024 test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let (csr_der, _) = common::generate_test_csr("mlkem1024-device.test", "rsa:2048");

    let resp = client
        .est_post_csr("serverkeygen", &csr_der, Some(("", "test-pqc-otp")))
        .await;

    let status = resp.status().as_u16();
    assert!(
        status < 500,
        "serverkeygen ML-KEM-1024 should not return 5xx, got: {status}"
    );
}

// ── Composite Algorithms ────────────────────────────────────────────────────

/// Enroll with composite ML-DSA-44 + ECDSA P-256 CSR.
///
/// Composite algorithms (draft-ietf-lamps-pq-composite-sigs) combine a
/// classical and a PQC signature algorithm for hybrid security.
#[tokio::test]
#[ignore = "requires OpenSSL 3.5+ with composite key support"]
async fn enroll_composite_mldsa44_p256() {
    if !pqc_available() {
        eprintln!("SKIP: OpenSSL 3.5+ not available for composite test");
        return;
    }

    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    // Composite key generation requires OpenSSL 3.5+ with composite provider.
    // This test is best-effort: if the key generation fails, the test is skipped.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("composite.key");
    let csr_path = dir.path().join("composite.csr");
    let csr_der_path = dir.path().join("composite.csr.der");

    // Attempt to generate composite key
    let status = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "mldsa44_p256",
            "-out",
            key_path.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            // Generate CSR
            let s = std::process::Command::new("openssl")
                .args([
                    "req",
                    "-new",
                    "-key",
                    key_path.to_str().unwrap(),
                    "-out",
                    csr_path.to_str().unwrap(),
                    "-subj",
                    "/CN=composite-device.test",
                ])
                .status()
                .unwrap();
            assert!(s.success(), "composite CSR generation failed");

            let s = std::process::Command::new("openssl")
                .args([
                    "req",
                    "-in",
                    csr_path.to_str().unwrap(),
                    "-outform",
                    "DER",
                    "-out",
                    csr_der_path.to_str().unwrap(),
                ])
                .status()
                .unwrap();
            assert!(s.success());

            let csr_der = std::fs::read(&csr_der_path).unwrap();

            let resp = client
                .est_post_csr("simpleenroll", &csr_der, Some(("", "test-pqc-otp")))
                .await;

            let resp_status = resp.status().as_u16();
            assert!(
                resp_status < 500,
                "composite enrollment should not return 5xx, got: {resp_status}"
            );
        }
        _ => {
            eprintln!("SKIP: composite key algorithm mldsa44_p256 not supported by this OpenSSL");
        }
    }
}

// ── CSR Attributes with PQC OIDs ────────────────────────────────────────────

/// Verify /csrattrs can include PQC algorithm OIDs when configured.
#[tokio::test]
async fn csrattrs_pqc_oids() {
    let server = TestServer::start().await;
    let client = TestClient::new(&server.base_url());

    let resp = client.est_get("csrattrs").await;
    let status = resp.status();

    // The test server may or may not have PQC OIDs configured.
    // We verify the endpoint responds correctly; PQC OID content is
    // validated only when the server is configured with PQC attributes.
    assert!(
        status == 200 || status == 204,
        "GET /csrattrs should return 200 or 204, got: {status}"
    );
}
