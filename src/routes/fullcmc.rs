//! `POST /.well-known/est/fullcmc` — Full CMC Request.
//!
//! RFC 7030 §4.3: EST clients submit a Full CMC request (PKCS#7 SignedData
//! containing a CMC PKIData) for complex enrollment scenarios that require
//! RA intermediation.
//!
//! The signer of the CMC request MUST hold the id-kp-cmcRA EKU
//! (OID 1.3.6.1.5.5.7.3.28) per RHELBU-3536 R15.
//!
//! The server proxies the CMC request to the CA backend and returns
//! the CMC response.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::auth::{AuthMethod, EstAuth};
use crate::error::KipukaError;
use crate::routes::est::{content_types, decode_est_base64, encode_est_base64};
use crate::routes::LabelExtractor;
use crate::state::AppState;

/// CMC error codes mapped to HTTP status codes (RHELBU-3536 R17).
///
/// RFC 5272 §15.2 defines CMC failure codes.  These are mapped to
/// HTTP status codes for the EST response.
#[derive(Debug, Clone, Copy)]
pub enum CmcErrorCode {
    /// badAlg (0) — unrecognized or unsupported algorithm.
    BadAlgorithm,
    /// badMessageCheck (1) — integrity check failed.
    BadMessageCheck,
    /// badRequest (2) — transaction not permitted or supported.
    BadRequest,
    /// badTime (3) — message time field not sufficiently close to system time.
    BadTime,
    /// badCertId (4) — no certificate found matching provided criteria.
    BadCertId,
    /// badDataFormat (5) — data not formatted as expected.
    BadDataFormat,
    /// wrongAuthority (6) — wrong authority specified in request.
    WrongAuthority,
    /// incorrectData (7) — included data is incorrect.
    IncorrectData,
    /// missingTimeStamp (8) — required timestamp missing.
    MissingTimestamp,
    /// badPOP (9) — proof-of-possession failed.
    BadPop,
}

impl CmcErrorCode {
    /// Map a CMC error code to an HTTP status code.
    pub fn to_http_status(self) -> StatusCode {
        match self {
            CmcErrorCode::BadAlgorithm => StatusCode::BAD_REQUEST,
            CmcErrorCode::BadMessageCheck => StatusCode::BAD_REQUEST,
            CmcErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            CmcErrorCode::BadTime => StatusCode::BAD_REQUEST,
            CmcErrorCode::BadCertId => StatusCode::NOT_FOUND,
            CmcErrorCode::BadDataFormat => StatusCode::BAD_REQUEST,
            CmcErrorCode::WrongAuthority => StatusCode::FORBIDDEN,
            CmcErrorCode::IncorrectData => StatusCode::BAD_REQUEST,
            CmcErrorCode::MissingTimestamp => StatusCode::BAD_REQUEST,
            CmcErrorCode::BadPop => StatusCode::FORBIDDEN,
        }
    }
}

/// `POST /.well-known/est/fullcmc`
///
/// Accepts a CMC request (PKCS#7 SignedData) and returns a CMC response.
///
/// # Authentication
///
/// Requires mTLS with a certificate carrying the id-kp-cmcRA EKU
/// (OID 1.3.6.1.5.5.7.3.28, RHELBU-3536 R15).
///
/// # Request
///
/// | Header         | Value                                        |
/// |----------------|----------------------------------------------|
/// | Content-Type   | `application/pkcs7-mime; smime-type=CMC-request` |
/// | Body           | Base64-encoded DER PKCS#7 SignedData (CMC PKIData) |
///
/// # Response
///
/// | Header         | Value                                        |
/// |----------------|----------------------------------------------|
/// | Status         | `200 OK`                                     |
/// | Content-Type   | `application/pkcs7-mime; smime-type=CMC-response` |
///
/// # Errors
///
/// - `400 Bad Request` — malformed CMC request
/// - `401 Unauthorized` — authentication failed
/// - `403 Forbidden` — signer lacks id-kp-cmcRA EKU
/// - `500 Internal Server Error` — CA backend error
pub async fn post_fullcmc(
    auth: EstAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    let ca_id = label.ca_id();
    let identity = &auth.0.identity;

    // Check that fullcmc is enabled in the configuration.
    if !state.config.est.fullcmc {
        return Err(KipukaError::Est("Full CMC is not enabled".into()));
    }

    // Full CMC requires mTLS authentication.
    if auth.0.method != AuthMethod::Mtls {
        return Err(KipukaError::Auth(
            "Full CMC requires mTLS client certificate authentication".into(),
        ));
    }

    // RHELBU-3536 R15: Validate that the signer certificate carries the
    // id-kp-cmcRA Extended Key Usage.
    if !auth.0.has_cmc_ra_eku() {
        tracing::warn!(
            identity = %identity,
            "fullcmc rejected: signer lacks id-kp-cmcRA EKU"
        );
        return Err(KipukaError::Auth(
            "CMC signer certificate must have id-kp-cmcRA EKU (1.3.6.1.5.5.7.3.28)".into(),
        ));
    }

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        identity = %identity,
        "fullcmc request"
    );

    // Decode the base64-encoded CMC request.
    let cmc_request_der = decode_est_base64(&body)
        .map_err(|e| KipukaError::BadRequest(format!("CMC request decoding failed: {e}")))?;

    if cmc_request_der.is_empty() {
        return Err(KipukaError::BadRequest("empty CMC request".into()));
    }

    // Validate the CMC request structure.
    //
    // TODO: Parse the PKCS#7 SignedData and extract the CMC PKIData.
    //
    // 1. Verify the outer SignedData signature
    // 2. Extract the CMC PKIData from the encapsulated content
    // 3. Validate the CMC control attributes
    // 4. Extract the certification requests from the reqSequence

    // Look up the CA backend.
    let _ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Proxy the CMC request to the CA backend.
    //
    // TODO: Implement CMC request forwarding.
    // let cmc_response_der = kipuka_est::cmc::process_request(ca, &cmc_request_der).await?;
    let cmc_response_der: Vec<u8> = Vec::new(); // Placeholder

    if cmc_response_der.is_empty() {
        return Err(KipukaError::Ca("CMC processing not yet implemented".into()));
    }

    // Encode the CMC response.
    let body = encode_est_base64(&cmc_response_der);

    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_types::CMC_RESPONSE),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
    );

    state
        .record_audit_event(
            "fullcmc_success",
            &format!("ca_id={ca_id}, identity={identity}"),
        )
        .await;

    Ok(resp)
}
