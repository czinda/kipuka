//! RFC 7030 MIME content types for EST operations.
//!
//! Defines the standard Content-Type values used in EST HTTP requests and responses.

/// PKCS#7 certificates-only message (DER-encoded, base64-wrapped).
///
/// Used for `/cacerts` responses and enrollment certificate responses.
/// RFC 7030 §4.1.3, §4.2.3.
pub const PKCS7_MIME: &str = "application/pkcs7-mime";

/// PKCS#7 with smimeType=certs-only parameter.
pub const PKCS7_CERTS_ONLY: &str = "application/pkcs7-mime; smimeType=certs-only";

/// PKCS#10 certificate signing request (DER-encoded, base64-wrapped).
///
/// Used for `/simpleenroll` and `/simplereenroll` request bodies.
/// RFC 7030 §4.2.1.
pub const PKCS10: &str = "application/pkcs10";

/// PKCS#8 private key (DER-encoded, base64-wrapped).
///
/// Used for `/serverkeygen` response part 2 containing the ML-KEM private key.
/// RFC 7030 §4.4.2.
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
    fn test_multipart_content_type() {
        let ct = multipart_content_type("my-boundary");
        assert_eq!(ct, "multipart/mixed; boundary=my-boundary");
    }

    #[test]
    fn test_cmc_types() {
        assert!(CMC_REQUEST.contains("CMC-Request"));
        assert!(CMC_RESPONSE.contains("CMC-Response"));
    }
}
