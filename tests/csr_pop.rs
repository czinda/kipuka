//! CSR proof-of-possession (PoP) enforcement tests — GitLab #9 / GitHub #5.
//!
//! RFC 7030 §4.2 requires an EST server to verify the CSR self-signature before
//! issuing, proving the requester possesses the private key for the public key
//! in the CSR. Enforcement lives in the central issuance chokepoint
//! `ca::issue::issue_certificate`, so *every* direct-signing enrollment path
//! (simpleenroll, simplereenroll, CMS-EST, CoAP, STAR, CMP, software
//! serverkeygen) inherits it.
//!
//! These tests exercise the gate directly against a real (test) CA — no HTTP
//! server wiring required — so they run in the default `cargo test` set.

#[allow(dead_code)]
mod common;

use common::{TestCa, generate_test_csr};
use kipuka::ca::issue::{CaSigningKey, EnrollmentProfile, IssuanceError, issue_certificate};

/// A CSR whose self-signature is valid must be issued.
#[test]
fn valid_csr_pop_is_accepted() {
    let ca = TestCa::new();
    let (csr_der, _key_der) = generate_test_csr("pop-valid.example.com", "rsa:2048");

    let profile = EnrollmentProfile::default();
    let result = issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        CaSigningKey::Pem(&ca.key_pem),
        "sha256",
        None,
        None,
    );

    assert!(
        result.is_ok(),
        "a validly self-signed CSR should be issued, got: {:?}",
        result.err()
    );
}

/// A CSR whose self-signature has been tampered with must be rejected with
/// `InvalidCsr` — the CA must never sign a request the client cannot prove
/// possession of.
#[test]
fn tampered_csr_pop_is_rejected() {
    let ca = TestCa::new();
    let (mut csr_der, _key_der) = generate_test_csr("pop-tampered.example.com", "rsa:2048");

    // Flip the final byte of the DER. That byte lies inside the trailing
    // `signature` BIT STRING, so the CSR still parses (length is unchanged) but
    // the self-signature no longer verifies against the CSR's own public key.
    let last = csr_der.len() - 1;
    csr_der[last] ^= 0xFF;

    let profile = EnrollmentProfile::default();
    let result = issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        CaSigningKey::Pem(&ca.key_pem),
        "sha256",
        None,
        None,
    );

    match result {
        Err(IssuanceError::InvalidCsr(msg)) => {
            assert!(
                msg.contains("proof-of-possession"),
                "expected a proof-of-possession failure, got: {msg}"
            );
        }
        other => panic!("expected InvalidCsr for a tampered CSR signature, got: {other:?}"),
    }
}

/// The same tamper check over an ECDSA P-256 key, to confirm PoP enforcement is
/// not RSA-specific.
#[test]
fn tampered_ecdsa_csr_pop_is_rejected() {
    let ca = TestCa::new();
    let (mut csr_der, _key_der) = generate_test_csr("pop-ecdsa.example.com", "ec:P-256");

    let last = csr_der.len() - 1;
    csr_der[last] ^= 0xFF;

    let profile = EnrollmentProfile::default();
    let result = issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        CaSigningKey::Pem(&ca.key_pem),
        "sha256",
        None,
        None,
    );

    assert!(
        matches!(result, Err(IssuanceError::InvalidCsr(_))),
        "expected InvalidCsr for a tampered ECDSA CSR, got: {result:?}"
    );
}
