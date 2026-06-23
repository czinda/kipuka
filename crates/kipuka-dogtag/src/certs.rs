//! Certificate retrieval, listing, and revocation via Dogtag CA REST API.
//!
//! Provides operations against the `/ca/rest/certs` and `/ca/rest/agent/certs`
//! endpoints for certificate lifecycle management.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::client::DogtagClient;
use crate::{DogtagError, DogtagResult};

/// Information about an issued certificate.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CertInfo {
    /// Certificate serial number (hex string).
    pub id: String,
    /// Subject DN of the certificate.
    #[serde(default)]
    pub subject_d_n: Option<String>,
    /// Issuer DN.
    #[serde(default)]
    pub issuer_d_n: Option<String>,
    /// Certificate status (e.g., "VALID", "REVOKED", "EXPIRED").
    #[serde(default)]
    pub status: Option<String>,
    /// Not-before date (ISO 8601).
    #[serde(default)]
    pub not_valid_before: Option<String>,
    /// Not-after date (ISO 8601).
    #[serde(default)]
    pub not_valid_after: Option<String>,
    /// Base64-encoded certificate (if requested via full retrieval).
    #[serde(default)]
    pub encoded: Option<String>,
}

/// Filter parameters for certificate listing.
#[derive(Debug, Default, Serialize)]
pub struct CertFilter {
    /// Filter by subject DN substring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Filter by certificate status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Maximum number of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Starting index for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
}

/// Revocation reason codes per RFC 5280 S5.3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationReason {
    /// The private key has been compromised.
    KeyCompromise,
    /// The CA's private key has been compromised.
    CaCompromise,
    /// The certificate holder's affiliation has changed.
    AffiliationChanged,
    /// The certificate has been superseded by a new one.
    Superseded,
    /// The certificate is no longer needed.
    CessationOfOperation,
    /// The certificate is temporarily on hold.
    CertificateHold,
    /// Remove a certificate from hold.
    RemoveFromCrl,
    /// The certificate holder's privileges have been withdrawn.
    PrivilegeWithdrawn,
    /// The attribute authority has been compromised.
    AaCompromise,
    /// Unspecified reason.
    Unspecified,
}

impl RevocationReason {
    /// Return the CRL reason code integer value per RFC 5280.
    fn as_code(self) -> u32 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

/// Revocation request body.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RevokeRequest {
    reason: u32,
}

/// Response from certificate listing.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CertListResponse {
    #[serde(default)]
    entries: Vec<CertInfo>,
}

impl DogtagClient {
    /// Retrieve a single certificate by serial number.
    ///
    /// Sends `GET /ca/rest/certs/{serial}`. The serial number should be
    /// the hex-encoded certificate serial (e.g., "0x1" or "1").
    pub async fn get_certificate(&self, serial: &str) -> DogtagResult<CertInfo> {
        debug!(serial, "Fetching certificate");
        let resp = self.get(&format!("/ca/rest/certs/{serial}")).await?;
        Self::json_response(resp).await
    }

    /// Revoke a certificate by serial number.
    ///
    /// Sends `POST /ca/rest/agent/certs/{serial}/revoke` with the specified
    /// revocation reason. Requires agent-level authentication (mTLS with
    /// an agent certificate).
    ///
    /// The revocation reason code follows RFC 5280 S5.3.1.
    pub async fn revoke_certificate(
        &self,
        serial: &str,
        reason: RevocationReason,
    ) -> DogtagResult<()> {
        debug!(serial, reason = ?reason, "Revoking certificate");

        let body = RevokeRequest {
            reason: reason.as_code(),
        };

        let resp = self
            .post_json(&format!("/ca/rest/agent/certs/{serial}/revoke"), &body)
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(DogtagError::ApiError { status, body });
        }

        Ok(())
    }

    /// List certificates matching the given filter.
    ///
    /// Sends `GET /ca/rest/certs` with query parameters derived from the
    /// [`CertFilter`]. Supports pagination via `start` and `size` fields.
    pub async fn list_certificates(&self, filter: CertFilter) -> DogtagResult<Vec<CertInfo>> {
        debug!(?filter, "Listing certificates");

        // Build query string manually since GET doesn't use post_json.
        let mut query_parts = Vec::new();
        if let Some(ref subject) = filter.subject {
            query_parts.push(format!("subject={subject}"));
        }
        if let Some(ref status) = filter.status {
            query_parts.push(format!("status={status}"));
        }
        if let Some(size) = filter.size {
            query_parts.push(format!("size={size}"));
        }
        if let Some(start) = filter.start {
            query_parts.push(format!("start={start}"));
        }

        let path = if query_parts.is_empty() {
            "/ca/rest/certs".to_owned()
        } else {
            format!("/ca/rest/certs?{}", query_parts.join("&"))
        };

        let resp = self.get(&path).await?;
        let list: CertListResponse = Self::json_response(resp).await?;
        Ok(list.entries)
    }
}
