//! Full CMC (Certificate Management over CMS) operations.
//!
//! Provides passthrough submission of CMC requests to Dogtag's CMC Full
//! enrollment endpoint. This supports kipuka's `/fullcmc` EST endpoint
//! (RFC 7030 S4.3) by proxying CMC messages directly to the CA.

use tracing::debug;

use crate::client::DogtagClient;
use crate::{DogtagError, DogtagResult};

/// CMC-specific client operations.
///
/// Thin wrapper indicating CMC-related functionality. The actual HTTP
/// client is shared via [`DogtagClient`].
pub struct CmcClient;

impl DogtagClient {
    /// Submit a Full CMC request to Dogtag.
    ///
    /// Sends `POST /ca/ee/ca/profileSubmitCMCFull` with the raw CMC
    /// request bytes (DER-encoded CMS/PKCS#7). Returns the CMC response
    /// bytes for direct relay to the EST client.
    ///
    /// This is a pure passthrough: kipuka's `/fullcmc` endpoint receives
    /// a CMC request from the EST client and forwards it to Dogtag without
    /// interpretation. The response is similarly relayed back.
    ///
    /// # Content Types
    ///
    /// - Request: `application/pkcs7-mime` (CMC request, DER)
    /// - Response: `application/pkcs7-mime` (CMC response, DER)
    pub async fn submit_cmc_request(&self, cmc_der: &[u8]) -> DogtagResult<Vec<u8>> {
        debug!(
            size = cmc_der.len(),
            "Submitting Full CMC request to Dogtag"
        );

        let resp = self
            .post_bytes(
                "/ca/ee/ca/profileSubmitCMCFull",
                cmc_der.to_vec(),
                "application/pkcs7-mime",
            )
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DogtagError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| DogtagError::ParseError(format!("Failed to read CMC response: {e}")))
    }
}
