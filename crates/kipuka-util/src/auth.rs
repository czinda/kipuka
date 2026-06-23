//! HTTP authentication header parsing.
//!
//! Extracts credentials from `Authorization` headers for EST enrollment
//! authentication. Supports:
//! - HTTP Basic (RFC 7617) -- username:password for OTP validation
//! - Bearer token (RFC 6750) -- OAuth2 / JWT tokens
//! - Negotiate (RFC 4559) -- GSSAPI/Kerberos SPNEGO tokens
//! - Client certificate -- extracted from TLS connection info

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use thiserror::Error;
use tracing::debug;

/// Errors during authentication header parsing.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The `Authorization` header is missing.
    #[error("missing Authorization header")]
    Missing,

    /// The header value is not valid UTF-8 or is malformed.
    #[error("malformed Authorization header: {0}")]
    Malformed(String),

    /// The authentication scheme is not supported.
    #[error("unsupported authentication scheme: {0}")]
    UnsupportedScheme(String),

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Parsed credential from an HTTP `Authorization` header.
#[derive(Debug, Clone)]
pub enum AuthCredential {
    /// HTTP Basic: username and password (password may be an OTP).
    Basic { username: String, password: String },

    /// Bearer token (opaque string; interpretation is caller's responsibility).
    Bearer { token: String },

    /// Negotiate (GSSAPI/SPNEGO): raw token bytes from base64-decoded header.
    Negotiate { token_bytes: Vec<u8> },

    /// Client certificate distinguished name extracted from TLS peer info.
    ClientCert { subject_dn: String },
}

/// Parse an `Authorization` header value into a structured credential.
pub fn parse_authorization(header_value: &str) -> Result<AuthCredential, AuthError> {
    let header_value = header_value.trim();
    if header_value.is_empty() {
        return Err(AuthError::Missing);
    }

    // Split on first space: "Scheme <credentials>"
    let (scheme, payload) = header_value
        .split_once(' ')
        .ok_or_else(|| AuthError::Malformed("expected 'Scheme <credentials>'".into()))?;

    let payload = payload.trim();
    if payload.is_empty() {
        return Err(AuthError::Malformed(
            "empty credentials after scheme".into(),
        ));
    }

    match scheme.to_ascii_lowercase().as_str() {
        "basic" => parse_basic(payload),
        "bearer" => parse_bearer(payload),
        "negotiate" => parse_negotiate(payload),
        other => Err(AuthError::UnsupportedScheme(other.to_owned())),
    }
}

/// Parse HTTP Basic authentication (RFC 7617 Section 2).
///
/// The `Authorization: Basic` header carries base64-encoded credentials
/// in the form `user-id:password`.  Per RFC 7617:
///
/// - **Section 2**: the first colon separates the user-id from the password.
///   The user-id MUST NOT contain a colon; the password may.
/// - **Section 2.1**: credentials SHOULD be encoded as UTF-8 when the
///   `charset="UTF-8"` parameter is present in the WWW-Authenticate
///   challenge.  We always decode as UTF-8 and reject non-UTF-8.
/// - **Security**: null bytes (0x00) in credentials are rejected to prevent
///   injection attacks against backends that treat null as a terminator.
fn parse_basic(payload: &str) -> Result<AuthCredential, AuthError> {
    let decoded = STANDARD.decode(payload)?;

    // RFC 7617 §2.1: reject null bytes in the decoded credentials.
    // Null bytes can cause truncation in C-based backends (LDAP, PAM)
    // and should never appear in legitimate credentials.
    if decoded.contains(&0x00) {
        return Err(AuthError::Malformed(
            "Basic credentials contain null byte (rejected for security)".into(),
        ));
    }

    // RFC 7617 §2.1: decode as UTF-8.
    let text = String::from_utf8(decoded)
        .map_err(|e| AuthError::Malformed(format!("non-UTF-8 Basic credentials: {e}")))?;

    // RFC 7617 §2: the user-id and password are separated by the first colon.
    let (username, password) = text.split_once(':').ok_or_else(|| {
        AuthError::Malformed("Basic credentials missing ':' separator (RFC 7617 §2)".into())
    })?;

    // RFC 7617 §2: the user-id MUST NOT be empty.
    if username.is_empty() {
        return Err(AuthError::Malformed(
            "Basic auth user-id is empty (RFC 7617 §2)".into(),
        ));
    }

    debug!(username = %username, "parsed Basic auth credential (RFC 7617)");

    Ok(AuthCredential::Basic {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

/// Parse Bearer token (RFC 6750).
fn parse_bearer(payload: &str) -> Result<AuthCredential, AuthError> {
    debug!("parsed Bearer token credential");
    Ok(AuthCredential::Bearer {
        token: payload.to_owned(),
    })
}

/// Parse Negotiate (GSSAPI/SPNEGO) token (RFC 4559).
fn parse_negotiate(payload: &str) -> Result<AuthCredential, AuthError> {
    let token_bytes = STANDARD.decode(payload)?;
    debug!(token_len = token_bytes.len(), "parsed Negotiate credential");
    Ok(AuthCredential::Negotiate { token_bytes })
}

/// Extract the subject DN from a client certificate.
///
/// Convenience function for building an [`AuthCredential::ClientCert`]
/// from TLS peer certificate information.
pub fn client_cert_credential(subject_dn: &str) -> AuthCredential {
    debug!(subject_dn = %subject_dn, "client certificate credential");
    AuthCredential::ClientCert {
        subject_dn: subject_dn.to_owned(),
    }
}

// ── RFC 7617 WWW-Authenticate challenge ─────────────────────────────────────

/// Default `WWW-Authenticate` header value for HTTP Basic authentication.
///
/// RFC 7617 Section 2.2: the challenge includes:
/// - `realm` — the protection space identifier.
/// - `charset="UTF-8"` — indicates the server accepts UTF-8 encoded
///   credentials per RFC 7617 Section 2.1.
///
/// EST servers use this to prompt clients for OTP credentials when
/// mTLS is not available.
pub const WWW_AUTHENTICATE_BASIC: &str = "Basic realm=\"kipuka-est\", charset=\"UTF-8\"";

/// Builder for `WWW-Authenticate: Basic` challenge headers.
///
/// RFC 7617 Section 2.2: the Basic challenge contains a `realm` parameter
/// identifying the protection space, and an optional `charset` parameter
/// indicating the server's preferred encoding for credentials.
///
/// # Example
///
/// ```ignore
/// let challenge = BasicChallenge::new("my-realm");
/// assert_eq!(challenge.to_header_value(), "Basic realm=\"my-realm\", charset=\"UTF-8\"");
/// ```
#[derive(Debug, Clone)]
pub struct BasicChallenge {
    /// The realm string identifying the protection space.
    ///
    /// RFC 7617 Section 2.2: the realm value is a case-sensitive string
    /// defined by the origin server.  Clients use it to determine which
    /// stored credentials to send.
    pub realm: String,

    /// The charset parameter.
    ///
    /// RFC 7617 Section 2.1: when present and set to "UTF-8", it indicates
    /// the server supports UTF-8 encoded credentials.  This is the only
    /// value defined by the RFC.
    pub charset: String,
}

impl BasicChallenge {
    /// Create a new Basic challenge with the given realm.
    ///
    /// The `charset` defaults to `"UTF-8"` per RFC 7617 Section 2.1.
    pub fn new(realm: &str) -> Self {
        Self {
            realm: realm.to_owned(),
            charset: "UTF-8".to_owned(),
        }
    }

    /// Format the challenge as a `WWW-Authenticate` header value.
    ///
    /// RFC 7617 Section 2.2:
    /// ```text
    /// WWW-Authenticate: Basic realm="<realm>", charset="UTF-8"
    /// ```
    pub fn to_header_value(&self) -> String {
        format!(
            "Basic realm=\"{}\", charset=\"{}\"",
            self.realm, self.charset
        )
    }
}

impl Default for BasicChallenge {
    fn default() -> Self {
        Self::new("kipuka-est")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_auth() {
        // "user:pass" base64-encoded
        let cred = parse_authorization("Basic dXNlcjpwYXNz").unwrap();
        match cred {
            AuthCredential::Basic { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    fn parse_bearer_auth() {
        let cred = parse_authorization("Bearer eyJhbGciOiJSUzI1NiJ9.test").unwrap();
        match cred {
            AuthCredential::Bearer { token } => {
                assert_eq!(token, "eyJhbGciOiJSUzI1NiJ9.test");
            }
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn parse_negotiate_auth() {
        let cred = parse_authorization("Negotiate YWJjZA==").unwrap();
        match cred {
            AuthCredential::Negotiate { token_bytes } => {
                assert_eq!(token_bytes, b"abcd");
            }
            _ => panic!("expected Negotiate"),
        }
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(matches!(
            parse_authorization("Digest abc123"),
            Err(AuthError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn rejects_missing_header() {
        assert!(matches!(parse_authorization(""), Err(AuthError::Missing)));
    }

    // ── RFC 7617 compliance tests ───────────────────────────────────────

    #[test]
    fn basic_auth_valid_utf8() {
        // "ユーザー:パスワード" (Japanese user:password) base64-encoded
        let encoded = STANDARD.encode("ユーザー:パスワード");
        let header = format!("Basic {encoded}");
        let cred = parse_authorization(&header).unwrap();
        match cred {
            AuthCredential::Basic { username, password } => {
                assert_eq!(username, "ユーザー");
                assert_eq!(password, "パスワード");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    fn basic_auth_colon_in_password() {
        // RFC 7617 §2: password may contain colons.
        // "user:pass:with:colons" base64-encoded
        let encoded = STANDARD.encode("user:pass:with:colons");
        let header = format!("Basic {encoded}");
        let cred = parse_authorization(&header).unwrap();
        match cred {
            AuthCredential::Basic { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass:with:colons");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    fn basic_auth_missing_colon() {
        // RFC 7617 §2: credentials without a colon separator are malformed.
        let encoded = STANDARD.encode("no-colon-here");
        let header = format!("Basic {encoded}");
        let result = parse_authorization(&header);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("':'"),
            "error should mention missing colon: {err}"
        );
    }

    #[test]
    fn basic_auth_empty_username() {
        // RFC 7617 §2: user-id MUST NOT be empty.
        let encoded = STANDARD.encode(":password");
        let header = format!("Basic {encoded}");
        let result = parse_authorization(&header);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "error should mention empty user-id: {err}"
        );
    }

    #[test]
    fn basic_auth_null_byte_rejected() {
        // Security: null bytes in credentials are rejected.
        let creds_with_null = b"user\x00:password";
        let encoded = STANDARD.encode(creds_with_null);
        let header = format!("Basic {encoded}");
        let result = parse_authorization(&header);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("null byte"),
            "error should mention null byte: {err}"
        );
    }

    // ── BasicChallenge / WWW-Authenticate tests ─────────────────────────

    #[test]
    fn basic_challenge_default() {
        let challenge = BasicChallenge::default();
        assert_eq!(challenge.realm, "kipuka-est");
        assert_eq!(challenge.charset, "UTF-8");
        assert_eq!(
            challenge.to_header_value(),
            "Basic realm=\"kipuka-est\", charset=\"UTF-8\""
        );
    }

    #[test]
    fn basic_challenge_custom_realm() {
        let challenge = BasicChallenge::new("my-custom-realm");
        assert_eq!(
            challenge.to_header_value(),
            "Basic realm=\"my-custom-realm\", charset=\"UTF-8\""
        );
    }

    #[test]
    fn www_authenticate_constant() {
        assert_eq!(
            WWW_AUTHENTICATE_BASIC,
            "Basic realm=\"kipuka-est\", charset=\"UTF-8\""
        );
    }
}
