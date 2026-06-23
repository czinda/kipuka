//! HTTP authentication header parsing.
//!
//! Extracts credentials from `Authorization` headers for EST enrollment
//! authentication. Supports:
//! - HTTP Basic (RFC 7617) -- username:password for OTP validation
//! - Bearer token (RFC 6750) -- OAuth2 / JWT tokens
//! - Negotiate (RFC 4559) -- GSSAPI/Kerberos SPNEGO tokens
//! - Client certificate -- extracted from TLS connection info

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
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
        return Err(AuthError::Malformed("empty credentials after scheme".into()));
    }

    match scheme.to_ascii_lowercase().as_str() {
        "basic" => parse_basic(payload),
        "bearer" => parse_bearer(payload),
        "negotiate" => parse_negotiate(payload),
        other => Err(AuthError::UnsupportedScheme(other.to_owned())),
    }
}

/// Parse HTTP Basic authentication (RFC 7617).
fn parse_basic(payload: &str) -> Result<AuthCredential, AuthError> {
    let decoded = STANDARD.decode(payload)?;
    let text = String::from_utf8(decoded)
        .map_err(|e| AuthError::Malformed(format!("non-UTF-8 Basic credentials: {e}")))?;

    let (username, password) = text
        .split_once(':')
        .ok_or_else(|| AuthError::Malformed("Basic credentials missing ':'".into()))?;

    debug!(username = %username, "parsed Basic auth credential");

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
    debug!(
        token_len = token_bytes.len(),
        "parsed Negotiate credential"
    );
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
        assert!(matches!(
            parse_authorization(""),
            Err(AuthError::Missing)
        ));
    }
}
