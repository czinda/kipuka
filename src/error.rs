//! Unified error type for Kipuka EST server.
//!
//! `KipukaError` covers all failure modes from configuration through
//! certificate issuance.  The [`IntoResponse`] impl produces HTTP responses
//! appropriate for EST clients:
//!
//! - Client errors return `4xx` with a `text/plain` body describing the problem.
//! - Server errors return `500` or `503`; internal details are logged but not
//!   exposed to the client.
//! - EST-specific error semantics follow RFC 7030 §4.2.3 (CMC response for
//!   enrollment failures) and §3.2.4 (HTTP error codes).

use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

/// Unified error type for the Kipuka EST server.
///
/// Each variant maps to a specific failure domain.  The [`IntoResponse`]
/// implementation translates these into HTTP responses suitable for EST
/// clients per RFC 7030 §4.2.3.
#[derive(Debug, thiserror::Error)]
pub enum KipukaError {
    // ── Startup / configuration ──────────────────────────────────────────────
    /// Configuration file parse or validation error.
    #[error("configuration error: {0}")]
    Config(String),

    /// TLS setup failure (certificate loading, cipher negotiation, etc.).
    #[error("TLS error: {0}")]
    Tls(String),

    /// Database connection or query failure.
    #[error("database error: {0}")]
    Db(String),

    /// HSM / PKCS#11 session error.
    #[error("HSM error: {0}")]
    Hsm(String),

    // ── Request-level errors ─────────────────────────────────────────────────
    /// Authentication or authorization failure.
    ///
    /// RFC 7030 §3.2.3: EST server MUST respond with 401 when the client
    /// fails HTTP-based or certificate-based authentication.
    #[error("authentication error: {0}")]
    Auth(String),

    /// EST protocol-level error (bad CSR, unsupported operation, etc.).
    ///
    /// RFC 7030 §4.2.3: the server MAY return a CMC response body with
    /// a Full PKI Response indicating the failure reason.
    #[error("EST error: {0}")]
    Est(String),

    /// CA signing or certificate issuance error.
    #[error("CA error: {0}")]
    Ca(String),

    /// Audit subsystem failure.
    ///
    /// NIAP CA PP FAU_STG.4: when the audit trail is full and the overflow
    /// policy is `halt`, EST operations MUST be rejected.
    #[error("audit error: {0}")]
    Audit(String),

    /// I/O error (file system, socket, etc.).
    #[error("I/O error: {0}")]
    Io(String),

    // ── HTTP-level errors ────────────────────────────────────────────────────
    /// Resource not found (unknown EST label, unknown CA, etc.).
    #[error("not found")]
    NotFound,

    /// HTTP method not allowed on this endpoint.
    #[error("method not allowed")]
    MethodNotAllowed,

    /// Request payload exceeds configured `max_body_size`.
    #[error("payload too large")]
    PayloadTooLarge,

    /// Content-Type is not `application/pkcs10` or another expected EST type.
    ///
    /// RFC 7030 §4.2: EST endpoints expect specific MIME types.
    #[error("unsupported media type")]
    UnsupportedMediaType,

    /// Bad request: malformed CSR, missing fields, etc.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Service temporarily unavailable (HSM offline, DB unreachable, etc.).
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Catch-all internal server error.
    #[error("internal server error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for KipukaError {
    fn from(e: sqlx::Error) -> Self {
        KipukaError::Db(e.to_string())
    }
}

impl From<std::io::Error> for KipukaError {
    fn from(e: std::io::Error) -> Self {
        KipukaError::Io(e.to_string())
    }
}

impl KipukaError {
    /// Map the error variant to an HTTP status code.
    ///
    /// EST error responses follow RFC 7030 §4.2.3 and the general HTTP
    /// status code semantics from RFC 7231.
    fn http_status(&self) -> StatusCode {
        match self {
            // Client errors
            KipukaError::Auth(_) => StatusCode::UNAUTHORIZED,
            KipukaError::Est(_) => StatusCode::BAD_REQUEST,
            KipukaError::BadRequest(_) => StatusCode::BAD_REQUEST,
            KipukaError::NotFound => StatusCode::NOT_FOUND,
            KipukaError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            KipukaError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            KipukaError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            KipukaError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,

            // Server errors — never expose internal details to EST clients
            KipukaError::Config(_)
            | KipukaError::Tls(_)
            | KipukaError::Db(_)
            | KipukaError::Hsm(_)
            | KipukaError::Ca(_)
            | KipukaError::Audit(_)
            | KipukaError::Io(_)
            | KipukaError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Return a client-safe error detail string.
    ///
    /// Server-side errors return a generic message; client errors return
    /// the specific detail to aid debugging.
    fn client_detail(&self) -> String {
        let status = self.http_status();
        if status.is_server_error() {
            "internal server error".to_string()
        } else {
            self.to_string()
        }
    }
}

impl IntoResponse for KipukaError {
    fn into_response(self) -> Response {
        let status = self.http_status();

        // Log server errors at error level; client errors at debug level.
        if status.is_server_error() {
            tracing::error!(error = %self, status = status.as_u16(), "server error");
        } else {
            tracing::debug!(error = %self, status = status.as_u16(), "client error");
        }

        let detail = self.client_detail();

        // EST error responses use text/plain per RFC 7030 §4.2.3.
        // For enrollment failures, a CMC Full PKI Response (application/pkcs7-mime)
        // could be returned instead — that will be implemented when the EST
        // enrollment handlers are built.
        let mut resp = (status, detail).into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );

        // RFC 7030 §4.2.3: 401 responses MUST include WWW-Authenticate.
        // RFC 7617 §2.2: the challenge includes charset="UTF-8" to indicate
        // the server accepts UTF-8 encoded credentials.
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static(kipuka_util::WWW_AUTHENTICATE_BASIC),
            );
        }

        // RFC 7030 §4.2.3: 503 responses SHOULD include Retry-After.
        if status == StatusCode::SERVICE_UNAVAILABLE
            && let Ok(hv) = HeaderValue::from_str("120") {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }

        resp
    }
}

/// Convenience alias used throughout the server.
pub type Result<T> = std::result::Result<T, KipukaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_error_returns_401() {
        let err = KipukaError::Auth("bad certificate".into());
        assert_eq!(err.http_status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn est_error_returns_400() {
        let err = KipukaError::Est("malformed CSR".into());
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn db_error_returns_500() {
        let err = KipukaError::Db("connection refused".into());
        assert_eq!(err.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn server_error_hides_detail() {
        let err = KipukaError::Internal("secret details".into());
        assert_eq!(err.client_detail(), "internal server error");
    }

    #[test]
    fn client_error_exposes_detail() {
        let err = KipukaError::BadRequest("missing CN".into());
        assert_eq!(err.client_detail(), "bad request: missing CN");
    }

    #[test]
    fn from_sqlx_error() {
        let sqlx_err = sqlx::Error::RowNotFound;
        let err = KipukaError::from(sqlx_err);
        assert!(matches!(err, KipukaError::Db(_)));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = KipukaError::from(io_err);
        assert!(matches!(err, KipukaError::Io(_)));
    }

    #[test]
    fn into_response_unauthorized_has_www_authenticate() {
        let resp = KipukaError::Auth("bad cert".into()).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get("www-authenticate").is_some());
    }

    #[test]
    fn into_response_service_unavailable_has_retry_after() {
        let resp = KipukaError::ServiceUnavailable("HSM offline".into()).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get("retry-after").is_some());
    }

    #[test]
    fn into_response_content_type_is_text_plain() {
        let resp = KipukaError::NotFound.into_response();
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
    }
}
