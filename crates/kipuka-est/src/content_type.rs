//! RFC 7030 MIME content types for EST operations.
//!
//! Defines the standard Content-Type values used in EST HTTP requests and responses.
//! Media type registrations follow:
//! - RFC 5967 (application/pkcs10)
//! - RFC 5958 (application/pkcs8)
//! - RFC 2311 / RFC 8551 (application/pkcs7-mime)

/// PKCS#7 certificates-only message (DER-encoded, base64-wrapped).
///
/// Used for `/cacerts` responses and enrollment certificate responses.
/// RFC 7030 §4.1.3, §4.2.3.
pub const PKCS7_MIME: &str = "application/pkcs7-mime";

/// PKCS#7 with smimeType=certs-only parameter.
pub const PKCS7_CERTS_ONLY: &str = "application/pkcs7-mime; smimeType=certs-only";

/// PKCS#10 certificate signing request (DER-encoded, base64-wrapped).
///
/// Registered by RFC 5967 ("The application/pkcs10 Media Type"). This is the
/// mandatory Content-Type for CSR submission in EST `/simpleenroll` and
/// `/simplereenroll` request bodies (RFC 7030 §4.2.1).
///
/// The DER-encoded CSR is base64-wrapped for HTTP transport per RFC 7030 §4.
/// Optional parameters defined by RFC 5967 §2:
/// - `charset` (not used; DER is binary)
/// - `smime-type` (see [`APPLICATION_PKCS10_SMIME`])
pub const PKCS10: &str = "application/pkcs10";

/// PKCS#10 CSR with S/MIME type parameter per RFC 5967 §2.
///
/// Used when wrapping a CSR inside an S/MIME message (e.g., for CMC requests).
/// The `smime-type=certs-only` variant indicates the content is a bare CSR
/// suitable for S/MIME processing pipelines.
pub const APPLICATION_PKCS10_SMIME: &str = "application/pkcs10; smime-type=certs-only";

/// PKCS#8 private key (DER-encoded, base64-wrapped).
///
/// Used for `/serverkeygen` response part 2 containing the ML-KEM private key.
/// RFC 7030 §4.4.2, format per RFC 5958 (OneAsymmetricKey / PrivateKeyInfo).
pub const PKCS8: &str = "application/pkcs8";

/// CSR attributes structure (DER-encoded, base64-wrapped).
///
/// Used for `/csrattrs` responses.
/// RFC 7030 §4.5.2.
pub const CSRATTRS: &str = "application/csrattrs";

/// CMC request/response (DER-encoded, base64-wrapped).
///
/// Used for `/fullcmc` request and response bodies.
/// RFC 5272, RFC 7030 §4.3.
pub const CMC_REQUEST: &str = "application/pkcs7-mime; smimeType=CMC-Request";
pub const CMC_RESPONSE: &str = "application/pkcs7-mime; smimeType=CMC-Response";

/// Multipart MIME container for `/serverkeygen` responses.
///
/// Contains two parts:
/// 1. `application/pkcs7-mime` - Certificate signed by ML-DSA or composite CA
/// 2. `application/pkcs8` - ML-KEM private key for client
///
/// RFC 7030 §4.4.2.
pub const MULTIPART_MIXED: &str = "multipart/mixed";

/// Default boundary string for multipart/mixed responses.
pub const DEFAULT_BOUNDARY: &str = "----=_EST_ServerKeyGen_Boundary";

/// Constructs a multipart/mixed Content-Type header with custom boundary.
pub fn multipart_content_type(boundary: &str) -> String {
    format!("multipart/mixed; boundary={}", boundary)
}

/// Validates a Content-Type header value against an expected EST media type.
///
/// Per RFC 5967 §2 and RFC 7030 §4, Content-Type headers may include optional
/// parameters (charset, smime-type, boundary). This function matches the base
/// media type case-insensitively and tolerates optional parameters.
///
/// # Examples
///
/// ```
/// # use kipuka_est::content_type::validate_content_type;
/// assert!(validate_content_type("application/pkcs10", "application/pkcs10"));
/// assert!(validate_content_type("application/pkcs10; charset=utf-8", "application/pkcs10"));
/// assert!(validate_content_type("Application/PKCS10", "application/pkcs10"));
/// assert!(!validate_content_type("text/plain", "application/pkcs10"));
/// ```
pub fn validate_content_type(header_value: &str, expected_base: &str) -> bool {
    let base = header_value
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    base.eq_ignore_ascii_case(expected_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_types() {
        assert_eq!(PKCS7_MIME, "application/pkcs7-mime");
        assert_eq!(PKCS10, "application/pkcs10");
        assert_eq!(PKCS8, "application/pkcs8");
        assert_eq!(CSRATTRS, "application/csrattrs");
        assert_eq!(MULTIPART_MIXED, "multipart/mixed");
    }

    #[test]
    fn test_pkcs10_smime_variant() {
        assert!(APPLICATION_PKCS10_SMIME.starts_with("application/pkcs10"));
        assert!(APPLICATION_PKCS10_SMIME.contains("smime-type"));
    }

    #[test]
    fn test_multipart_content_type() {
        let ct = multipart_content_type("my-boundary");
        assert_eq!(ct, "multipart/mixed; boundary=my-boundary");
    }

    #[test]
    fn test_cmc_types() {
        assert!(CMC_REQUEST.contains("CMC-Request"));
        assert!(CMC_RESPONSE.contains("CMC-Response"));
    }

    #[test]
    fn test_validate_content_type_exact() {
        assert!(validate_content_type("application/pkcs10", PKCS10));
        assert!(validate_content_type("application/pkcs8", PKCS8));
    }

    #[test]
    fn test_validate_content_type_with_params() {
        assert!(validate_content_type(
            "application/pkcs10; charset=utf-8",
            PKCS10
        ));
        assert!(validate_content_type(
            "application/pkcs10; smime-type=certs-only",
            PKCS10
        ));
    }

    #[test]
    fn test_validate_content_type_case_insensitive() {
        assert!(validate_content_type("Application/PKCS10", PKCS10));
        assert!(validate_content_type("APPLICATION/PKCS8", PKCS8));
    }

    #[test]
    fn test_validate_content_type_mismatch() {
        assert!(!validate_content_type("text/plain", PKCS10));
        assert!(!validate_content_type("application/pkcs7-mime", PKCS10));
    }
}
