//! CoAP content-format IDs for EST media types.
//!
//! RFC 9483 §5.4 defines Content-Format option values that map EST HTTP
//! Content-Type headers to compact integer IDs for CoAP transport.
//! These IDs are registered in the IANA "CoAP Content-Formats" registry
//! per RFC 9483 §10.1.
//!
//! CoAP uses a single integer in the Content-Format option (option 12)
//! instead of a textual MIME type string, saving bytes on constrained links.

/// `application/pkcs7-mime; smime-type=server-generated` (RFC 9483 §10.1, TBD280).
///
/// Used for server-generated key responses where the server produces the
/// key pair and returns the private key to the client.
pub const APPLICATION_PKCS7_MIME_SERVER_GEN_TYPE: u16 = 280;

/// `application/pkcs7-mime; smime-type=certs-only` (RFC 9483 §10.1, TBD281).
///
/// Used for CA certificate chain responses (`/cacerts`, `/crts`) and
/// enrollment certificate responses.
pub const APPLICATION_PKCS7_MIME_CERTS_ONLY: u16 = 281;

/// `application/pkcs7-mime; smime-type=CMC-Request` (RFC 9483 §10.1, TBD282).
///
/// Used for Full CMC enrollment requests per RFC 5272.
pub const APPLICATION_PKCS7_MIME_CMC_REQUEST: u16 = 282;

/// `application/pkcs7-mime; smime-type=CMC-Response` (RFC 9483 §10.1, TBD283).
///
/// Used for Full CMC enrollment responses per RFC 5272.
pub const APPLICATION_PKCS7_MIME_CMC_RESPONSE: u16 = 283;

/// `application/pkcs7-mime` (RFC 9483 §10.1, TBD284).
///
/// Generic PKCS#7 MIME type without smime-type parameter.
pub const APPLICATION_PKCS7_MIME: u16 = 284;

/// `application/pkcs10` (RFC 9483 §10.1, TBD285).
///
/// PKCS#10 certificate signing request, used in `/sen` and `/sren`
/// request bodies. DER-encoded (not base64-wrapped, unlike HTTP EST).
pub const APPLICATION_PKCS10: u16 = 285;

/// `application/pkcs8` (RFC 9483 §10.1, TBD286).
///
/// PKCS#8 private key, used in `/skg` (server key generation) responses
/// to deliver the generated private key to the client.
pub const APPLICATION_PKCS8: u16 = 286;

/// `application/csrattrs` (RFC 9483 §10.1, TBD287).
///
/// CSR attributes structure, used in `/att` responses to hint which
/// attributes the client should include in its CSR.
pub const APPLICATION_CSRATTRS: u16 = 287;

/// `multipart/core` (RFC 8710).
///
/// Used to combine multiple CoAP content items in a single payload,
/// e.g., certificate + private key in a server key generation response.
pub const MULTIPART_CORE: u16 = 62;

/// Maps a CoAP Content-Format ID to its HTTP Content-Type equivalent.
///
/// Returns `None` for unrecognized format IDs. This mapping is used when
/// bridging between EST-coaps (CoAP) and EST (HTTP) backends.
///
/// # RFC Reference
///
/// RFC 9483 §5.4, Table 2: Content-Format ID to media type mapping.
pub fn to_http_content_type(format_id: u16) -> Option<&'static str> {
    match format_id {
        APPLICATION_PKCS7_MIME_SERVER_GEN_TYPE => {
            Some("application/pkcs7-mime; smime-type=server-generated")
        }
        APPLICATION_PKCS7_MIME_CERTS_ONLY => {
            Some("application/pkcs7-mime; smime-type=certs-only")
        }
        APPLICATION_PKCS7_MIME_CMC_REQUEST => {
            Some("application/pkcs7-mime; smime-type=CMC-Request")
        }
        APPLICATION_PKCS7_MIME_CMC_RESPONSE => {
            Some("application/pkcs7-mime; smime-type=CMC-Response")
        }
        APPLICATION_PKCS7_MIME => Some("application/pkcs7-mime"),
        APPLICATION_PKCS10 => Some("application/pkcs10"),
        APPLICATION_PKCS8 => Some("application/pkcs8"),
        APPLICATION_CSRATTRS => Some("application/csrattrs"),
        MULTIPART_CORE => Some("multipart/core"),
        _ => None,
    }
}

/// Maps an HTTP Content-Type string to its CoAP Content-Format ID.
///
/// Matches the base media type case-insensitively and recognizes
/// smime-type parameters for PKCS#7 variants. Returns `None` for
/// unrecognized MIME types.
///
/// # RFC Reference
///
/// RFC 9483 §5.4, Table 2: media type to Content-Format ID mapping.
pub fn from_http_content_type(mime: &str) -> Option<u16> {
    let lower = mime.to_ascii_lowercase();
    let lower = lower.trim();

    // Check for smime-type parameter variants first (more specific matches).
    if lower.starts_with("application/pkcs7-mime") {
        if lower.contains("server-generated") {
            return Some(APPLICATION_PKCS7_MIME_SERVER_GEN_TYPE);
        }
        if lower.contains("certs-only") {
            return Some(APPLICATION_PKCS7_MIME_CERTS_ONLY);
        }
        if lower.contains("cmc-request") {
            return Some(APPLICATION_PKCS7_MIME_CMC_REQUEST);
        }
        if lower.contains("cmc-response") {
            return Some(APPLICATION_PKCS7_MIME_CMC_RESPONSE);
        }
        return Some(APPLICATION_PKCS7_MIME);
    }

    // Extract the base media type (before any parameters).
    let base = lower.split(';').next().unwrap_or("").trim();

    match base {
        "application/pkcs10" => Some(APPLICATION_PKCS10),
        "application/pkcs8" => Some(APPLICATION_PKCS8),
        "application/csrattrs" => Some(APPLICATION_CSRATTRS),
        "multipart/core" => Some(MULTIPART_CORE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_format_constants() {
        assert_eq!(APPLICATION_PKCS7_MIME_SERVER_GEN_TYPE, 280);
        assert_eq!(APPLICATION_PKCS7_MIME_CERTS_ONLY, 281);
        assert_eq!(APPLICATION_PKCS7_MIME_CMC_REQUEST, 282);
        assert_eq!(APPLICATION_PKCS7_MIME_CMC_RESPONSE, 283);
        assert_eq!(APPLICATION_PKCS7_MIME, 284);
        assert_eq!(APPLICATION_PKCS10, 285);
        assert_eq!(APPLICATION_PKCS8, 286);
        assert_eq!(APPLICATION_CSRATTRS, 287);
        assert_eq!(MULTIPART_CORE, 62);
    }

    #[test]
    fn test_to_http_content_type() {
        assert_eq!(
            to_http_content_type(APPLICATION_PKCS10),
            Some("application/pkcs10")
        );
        assert_eq!(
            to_http_content_type(APPLICATION_PKCS8),
            Some("application/pkcs8")
        );
        assert_eq!(
            to_http_content_type(APPLICATION_PKCS7_MIME_CERTS_ONLY),
            Some("application/pkcs7-mime; smime-type=certs-only")
        );
        assert_eq!(
            to_http_content_type(APPLICATION_CSRATTRS),
            Some("application/csrattrs")
        );
        assert_eq!(
            to_http_content_type(MULTIPART_CORE),
            Some("multipart/core")
        );
        assert_eq!(to_http_content_type(9999), None);
    }

    #[test]
    fn test_from_http_content_type_exact() {
        assert_eq!(
            from_http_content_type("application/pkcs10"),
            Some(APPLICATION_PKCS10)
        );
        assert_eq!(
            from_http_content_type("application/pkcs8"),
            Some(APPLICATION_PKCS8)
        );
        assert_eq!(
            from_http_content_type("application/csrattrs"),
            Some(APPLICATION_CSRATTRS)
        );
    }

    #[test]
    fn test_from_http_content_type_case_insensitive() {
        assert_eq!(
            from_http_content_type("Application/PKCS10"),
            Some(APPLICATION_PKCS10)
        );
        assert_eq!(
            from_http_content_type("APPLICATION/PKCS8"),
            Some(APPLICATION_PKCS8)
        );
    }

    #[test]
    fn test_from_http_content_type_pkcs7_variants() {
        assert_eq!(
            from_http_content_type("application/pkcs7-mime; smime-type=certs-only"),
            Some(APPLICATION_PKCS7_MIME_CERTS_ONLY)
        );
        assert_eq!(
            from_http_content_type("application/pkcs7-mime; smimeType=CMC-Request"),
            Some(APPLICATION_PKCS7_MIME_CMC_REQUEST)
        );
        assert_eq!(
            from_http_content_type("application/pkcs7-mime; smimeType=CMC-Response"),
            Some(APPLICATION_PKCS7_MIME_CMC_RESPONSE)
        );
        assert_eq!(
            from_http_content_type("application/pkcs7-mime; smime-type=server-generated"),
            Some(APPLICATION_PKCS7_MIME_SERVER_GEN_TYPE)
        );
        assert_eq!(
            from_http_content_type("application/pkcs7-mime"),
            Some(APPLICATION_PKCS7_MIME)
        );
    }

    #[test]
    fn test_from_http_content_type_unknown() {
        assert_eq!(from_http_content_type("text/plain"), None);
        assert_eq!(from_http_content_type("application/json"), None);
    }

    #[test]
    fn test_roundtrip_all_formats() {
        let ids = [
            APPLICATION_PKCS7_MIME_SERVER_GEN_TYPE,
            APPLICATION_PKCS7_MIME_CERTS_ONLY,
            APPLICATION_PKCS7_MIME_CMC_REQUEST,
            APPLICATION_PKCS7_MIME_CMC_RESPONSE,
            APPLICATION_PKCS7_MIME,
            APPLICATION_PKCS10,
            APPLICATION_PKCS8,
            APPLICATION_CSRATTRS,
            MULTIPART_CORE,
        ];

        for id in ids {
            let mime = to_http_content_type(id).expect("known format should have MIME type");
            let back = from_http_content_type(mime).expect("known MIME type should have format ID");
            assert_eq!(back, id, "roundtrip failed for format ID {id}: {mime}");
        }
    }
}
