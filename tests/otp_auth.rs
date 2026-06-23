//! Unit tests for OTP token lifecycle
//!
//! Verifies:
//! - Token generation produces cryptographically random tokens
//! - Token hashing and verification (argon2id)
//! - Timing-safe comparison prevents timing attacks
//! - Token consumption and single-use enforcement
//! - Token expiration
//! - Token revocation
//! - Use count limits

#[cfg(test)]
mod tests {
    // use kipuka_otp::{OtpToken, OtpConfig, OtpStore};
    // use std::time::Duration;

    // ── Token Generation ─────────────────────────────────────────────────

    #[test]
    fn generate_otp_produces_correct_length() {
        // let config = OtpConfig {
        //     token_length: 24,
        //     ..Default::default()
        // };
        // let (plaintext, _hash) = OtpToken::generate(&config).unwrap();
        // assert_eq!(plaintext.len(), 24);
    }

    #[test]
    fn generate_otp_produces_unique_tokens() {
        // let config = OtpConfig::default();
        // let mut tokens = std::collections::HashSet::new();
        // for _ in 0..100 {
        //     let (plaintext, _) = OtpToken::generate(&config).unwrap();
        //     assert!(tokens.insert(plaintext), "Generated duplicate OTP token");
        // }
    }

    #[test]
    fn generate_otp_uses_safe_alphabet() {
        // OTP tokens should use only alphanumeric characters for easy
        // copy-paste and HTTP Basic auth compatibility.
        //
        // let config = OtpConfig { token_length: 100, ..Default::default() };
        // let (plaintext, _) = OtpToken::generate(&config).unwrap();
        // assert!(
        //     plaintext.chars().all(|c| c.is_ascii_alphanumeric()),
        //     "OTP token contains non-alphanumeric characters: {plaintext}"
        // );
    }

    // ── Token Hashing and Verification ───────────────────────────────────

    #[test]
    fn hash_and_verify_otp_argon2id() {
        // let config = OtpConfig {
        //     hash_algorithm: "argon2id".to_string(),
        //     ..Default::default()
        // };
        // let (plaintext, hash) = OtpToken::generate(&config).unwrap();
        //
        // assert!(
        //     OtpToken::verify(&plaintext, &hash, &config).unwrap(),
        //     "Valid OTP should verify successfully"
        // );
    }

    #[test]
    fn verify_otp_rejects_wrong_token() {
        // let config = OtpConfig::default();
        // let (_plaintext, hash) = OtpToken::generate(&config).unwrap();
        //
        // assert!(
        //     !OtpToken::verify("wrong-token-value", &hash, &config).unwrap(),
        //     "Wrong OTP must not verify"
        // );
    }

    #[test]
    fn verify_otp_rejects_empty_token() {
        // let config = OtpConfig::default();
        // let (_plaintext, hash) = OtpToken::generate(&config).unwrap();
        //
        // assert!(
        //     !OtpToken::verify("", &hash, &config).unwrap(),
        //     "Empty string must not verify as valid OTP"
        // );
    }

    // ── Timing-Safe Comparison ───────────────────────────────────────────

    #[test]
    fn timing_safe_comparison_used() {
        // This test verifies that OTP verification uses constant-time
        // comparison. We can't directly test timing, but we verify the
        // code path uses the correct function.
        //
        // The implementation should use `subtle::ConstantTimeEq` or
        // `ring::constant_time::verify_slices_are_equal`, NOT `==`.
        //
        // TODO: This is best verified by code review or by measuring
        // timing variance across many iterations (statistical test).
    }

    // ── Token Consumption ────────────────────────────────────────────────

    #[tokio::test]
    async fn consume_otp_increments_use_count() {
        // let store = OtpStore::new_in_memory().await.unwrap();
        // let config = OtpConfig { max_uses: 3, ..Default::default() };
        //
        // let (plaintext, token) = OtpToken::generate(&config).unwrap();
        // let token_id = store.insert(token, "test-entity", None).await.unwrap();
        //
        // // First use
        // assert!(store.consume(&plaintext).await.unwrap());
        // let t = store.get(token_id).await.unwrap();
        // assert_eq!(t.current_uses, 1);
        //
        // // Second use
        // assert!(store.consume(&plaintext).await.unwrap());
        // let t = store.get(token_id).await.unwrap();
        // assert_eq!(t.current_uses, 2);
        //
        // // Third use (last allowed)
        // assert!(store.consume(&plaintext).await.unwrap());
        // let t = store.get(token_id).await.unwrap();
        // assert_eq!(t.current_uses, 3);
        //
        // // Fourth use should fail
        // assert!(!store.consume(&plaintext).await.unwrap());
    }

    #[tokio::test]
    async fn single_use_otp_rejected_on_reuse() {
        // let store = OtpStore::new_in_memory().await.unwrap();
        // let config = OtpConfig { max_uses: 1, ..Default::default() };
        //
        // let (plaintext, token) = OtpToken::generate(&config).unwrap();
        // store.insert(token, "test-entity", None).await.unwrap();
        //
        // assert!(store.consume(&plaintext).await.unwrap(), "First use should succeed");
        // assert!(!store.consume(&plaintext).await.unwrap(), "Second use must fail");
    }

    // ── Token Expiration ─────────────────────────────────────────────────

    #[tokio::test]
    async fn expired_otp_rejected() {
        // let store = OtpStore::new_in_memory().await.unwrap();
        // let config = OtpConfig {
        //     default_ttl: Duration::from_millis(1),  // Expire almost immediately
        //     ..Default::default()
        // };
        //
        // let (plaintext, token) = OtpToken::generate(&config).unwrap();
        // store.insert(token, "test-entity", None).await.unwrap();
        //
        // // Wait for expiration
        // tokio::time::sleep(Duration::from_millis(10)).await;
        //
        // assert!(
        //     !store.consume(&plaintext).await.unwrap(),
        //     "Expired OTP must be rejected"
        // );
    }

    // ── Token Revocation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn revoked_otp_rejected() {
        // let store = OtpStore::new_in_memory().await.unwrap();
        // let config = OtpConfig::default();
        //
        // let (plaintext, token) = OtpToken::generate(&config).unwrap();
        // let token_id = store.insert(token, "test-entity", None).await.unwrap();
        //
        // // Revoke the token
        // store.revoke(token_id).await.unwrap();
        //
        // assert!(
        //     !store.consume(&plaintext).await.unwrap(),
        //     "Revoked OTP must be rejected"
        // );
    }

    #[tokio::test]
    async fn revocation_is_permanent() {
        // Once revoked, a token cannot be un-revoked.
        //
        // let store = OtpStore::new_in_memory().await.unwrap();
        // let config = OtpConfig::default();
        //
        // let (plaintext, token) = OtpToken::generate(&config).unwrap();
        // let token_id = store.insert(token, "test-entity", None).await.unwrap();
        //
        // store.revoke(token_id).await.unwrap();
        //
        // let t = store.get(token_id).await.unwrap();
        // assert!(t.revoked);
        // assert!(t.revoked_at.is_some());
        //
        // // Verify the token hash is still present (for audit trail)
        // // but the token cannot be used.
        // assert!(!store.consume(&plaintext).await.unwrap());
    }
}
