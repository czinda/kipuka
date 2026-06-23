//! CoAP/DTLS EST transport tests (RFC 9483).
//!
//! These tests validate EST-over-CoAP functionality:
//! - CoAP GET /cacerts
//! - CoAP POST /sen (simpleenroll)
//! - Block-wise transfer for large PQC certificates
//! - DTLS session reuse
//!
//! All tests are `#[ignore]` because they require:
//! 1. CoAP support compiled in (`[coap]` config section)
//! 2. A DTLS transport layer (not just HTTP)
//! 3. A CoAP client library for Rust
//!
//! These tests serve as specification contracts — they define the expected
//! behavior and will be enabled once the CoAP transport is implemented.

mod common;

use common::TestServer;

// ── CoAP GET /est/crts (cacerts equivalent) ─────────────────────────────────

/// CoAP GET /.well-known/est/crts returns the CA certificate chain.
///
/// RFC 9483 S4.1: The CoAP path for cacerts is `/est/crts` (abbreviated).
/// The response uses CBOR content format with application/pkix-cert.
#[tokio::test]
#[ignore = "requires CoAP transport implementation"]
async fn coap_get_cacerts() {
    let _server = TestServer::start().await;

    // CoAP client would send:
    //   GET coaps://127.0.0.1:{port}/est/crts
    //   Accept: application/pkix-cert
    //
    // Expected response:
    //   2.05 Content
    //   Content-Format: application/pkix-cert
    //   Body: DER-encoded certificate(s)
    //
    // NOTE: CoAP uses abbreviated paths per RFC 9483 S2.1:
    //   /est/crts    → /cacerts
    //   /est/sen     → /simpleenroll
    //   /est/sren    → /simplereenroll
    //   /est/att     → /csrattrs
    //   /est/skg     → /serverkeygen
    //   /est/fmc     → /fullcmc

    todo!("Implement CoAP cacerts test once CoAP transport is ready");
}

// ── CoAP POST /est/sen (simpleenroll equivalent) ────────────────────────────

/// CoAP POST /est/sen enrolls a certificate via CoAP transport.
///
/// RFC 9483 S4.2: simpleenroll over CoAP uses POST with a PKCS#10 payload.
/// DTLS provides the transport-layer security (instead of TLS).
#[tokio::test]
#[ignore = "requires CoAP transport implementation"]
async fn coap_post_simpleenroll() {
    let _server = TestServer::start().await;

    // CoAP client would send:
    //   POST coaps://127.0.0.1:{port}/est/sen
    //   Content-Format: application/pkcs10
    //   Body: DER-encoded PKCS#10 CSR
    //
    // Expected response:
    //   2.04 Changed (success) or 4.01 Unauthorized
    //   Content-Format: application/pkix-cert
    //   Body: DER-encoded certificate

    todo!("Implement CoAP simpleenroll test once CoAP transport is ready");
}

// ── Block-wise transfer ─────────────────────────────────────────────────────

/// Large PQC certificates use CoAP block-wise transfer (RFC 7959).
///
/// ML-DSA signatures are 2.5-4.6 KB, which exceeds typical CoAP MTU
/// (~1280 bytes for 6LoWPAN).  Block-wise transfer splits the payload
/// across multiple CoAP messages.
#[tokio::test]
#[ignore = "requires CoAP transport with block-wise transfer"]
async fn coap_blockwise_transfer_large_pqc_cert() {
    let _server = TestServer::start().await;

    // For PQC certificates (ML-DSA-87 signatures are ~4.6 KB),
    // the CoAP response must be split into multiple Block2 options.
    //
    // Test flow:
    // 1. Client sends POST /est/sen with ML-DSA CSR
    // 2. Server responds with Block2(num=0, more=1, size=1024)
    // 3. Client requests Block2(num=1, more=0, size=1024)
    // 4. ... until all blocks received
    // 5. Client reassembles the complete certificate DER
    //
    // Verify:
    // - All blocks are received without gaps
    // - Reassembled DER is a valid X.509 certificate
    // - Certificate has the expected ML-DSA signature algorithm

    todo!("Implement block-wise transfer test for PQC certificates");
}

// ── DTLS session reuse ──────────────────────────────────────────────────────

/// DTLS session reuse for multiple CoAP requests.
///
/// DTLS handshake is expensive (4-6 round trips).  For enrollment
/// workflows that issue multiple requests (cacerts → enroll → csrattrs),
/// the DTLS session should be reused across requests.
#[tokio::test]
#[ignore = "requires DTLS transport implementation"]
async fn coap_dtls_session_reuse() {
    let _server = TestServer::start().await;

    // Test flow:
    // 1. Establish DTLS session (handshake)
    // 2. CoAP GET /est/crts (cacerts)
    // 3. CoAP POST /est/sen (simpleenroll) — same DTLS session
    // 4. CoAP GET /est/att (csrattrs) — same DTLS session
    //
    // Verify:
    // - Only 1 DTLS handshake occurred (not 3)
    // - Session ID or connection ID is consistent across requests
    // - Server-side session state is maintained

    todo!("Implement DTLS session reuse test");
}

// ── CoAP response codes ─────────────────────────────────────────────────────

/// CoAP error responses use correct CoAP status codes.
///
/// RFC 9483 maps HTTP status codes to CoAP response codes:
/// - 401 → 4.01 Unauthorized
/// - 400 → 4.00 Bad Request
/// - 404 → 4.04 Not Found
/// - 415 → 4.15 Unsupported Content-Format
/// - 503 → 5.03 Service Unavailable
#[tokio::test]
#[ignore = "requires CoAP transport implementation"]
async fn coap_error_response_codes() {
    let _server = TestServer::start().await;

    // Test unauthorized enrollment:
    //   POST /est/sen without DTLS client certificate
    //   Expected: 4.01 Unauthorized
    //
    // Test bad request:
    //   POST /est/sen with invalid CSR
    //   Expected: 4.00 Bad Request
    //
    // Test unknown path:
    //   GET /est/nonexistent
    //   Expected: 4.04 Not Found

    todo!("Implement CoAP error code mapping tests");
}
