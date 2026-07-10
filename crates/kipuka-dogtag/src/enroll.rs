//! Certificate enrollment via Dogtag CA REST API.
//!
//! Implements profile-based certificate enrollment using PKCS#10 CSRs.
//! Supports both synchronous enrollment (certificate returned immediately)
//! and asynchronous enrollment (request ID returned for later polling),
//! corresponding to EST's standard and Disconnected modes respectively.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::client::DogtagClient;
use crate::{DogtagError, DogtagResult};

/// Result of a certificate enrollment request.
#[derive(Debug, Clone)]
pub struct EnrollResult {
    /// Dogtag certificate request ID.
    pub request_id: String,
    /// Current status of the enrollment request.
    pub status: EnrollStatus,
    /// DER-encoded certificate, if issued synchronously.
    pub certificate_der: Option<Vec<u8>>,
}

/// Status of a certificate enrollment request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollStatus {
    /// Request completed, certificate issued.
    Complete,
    /// Request is pending agent approval.
    Pending,
    /// Request was rejected.
    Rejected,
    /// Request was canceled.
    Canceled,
}

/// Enrollment request body sent to Dogtag CA.
///
/// Maps to the JSON payload for `POST /ca/rest/certrequests`.
#[derive(Serialize)]
struct EnrollmentRequest {
    #[serde(rename = "ProfileID")]
    profile_id: String,
    #[serde(rename = "Renewal")]
    renewal: bool,
    #[serde(rename = "Input")]
    input: Vec<ProfileInput>,
}

#[derive(Serialize)]
struct ProfileInput {
    #[serde(rename = "ClassID")]
    class_id: String,
    #[serde(rename = "Attribute")]
    attributes: Vec<ProfileAttribute>,
}

#[derive(Serialize)]
struct ProfileAttribute {
    name: String,
    #[serde(rename = "Value")]
    value: String,
}

/// Response from Dogtag certificate enrollment.
#[derive(Deserialize)]
struct EnrollmentResponse {
    #[serde(default)]
    entries: Vec<EnrollmentEntry>,
}

#[derive(Deserialize)]
struct EnrollmentEntry {
    #[serde(rename = "requestId")]
    request_id: Option<String>,
    #[serde(rename = "requestStatus")]
    request_status: Option<String>,
    #[serde(default, rename = "certId")]
    cert_id: Option<String>,
}

/// Certificate data response.
#[derive(Deserialize)]
struct CertDataResponse {
    #[serde(default, alias = "Encoded")]
    encoded: Option<String>,
}

impl DogtagClient {
    /// Enroll a certificate using a PKCS#10 CSR and enrollment profile.
    ///
    /// Sends `POST /ca/rest/certrequests` with the CSR embedded in the
    /// specified enrollment profile. The profile controls certificate
    /// extensions, key usage, validity period, and approval workflow.
    ///
    /// # Arguments
    ///
    /// * `csr_pem` - PEM-encoded PKCS#10 certificate signing request.
    /// * `profile_id` - Dogtag enrollment profile ID (e.g., "caServerCert").
    ///
    /// # Returns
    ///
    /// An [`EnrollResult`] containing the request ID, status, and the
    /// DER-encoded certificate if the profile uses auto-approval.
    /// If the profile requires agent approval, the status will be
    /// [`EnrollStatus::Pending`] and the certificate will be `None`.
    pub async fn enroll_certificate(
        &self,
        csr_pem: &str,
        profile_id: &str,
    ) -> DogtagResult<EnrollResult> {
        debug!(profile = profile_id, "Submitting enrollment request");

        // Login to establish a session — SessionAuthentication profiles
        // (e.g. acmeServerCert) require a valid JSESSIONID cookie.
        let login_resp = self.post_json("/ca/rest/account/login", &serde_json::json!({})).await;
        match &login_resp {
            Ok(r) if r.status().is_success() => {
                tracing::info!("Dogtag session login succeeded");
            }
            Ok(r) => {
                tracing::warn!(status = r.status().as_u16(), "Dogtag session login returned non-200 (continuing)");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Dogtag session login failed (continuing without session)");
            }
        }

        let request = EnrollmentRequest {
            profile_id: profile_id.to_owned(),
            renewal: false,
            input: vec![
                ProfileInput {
                    class_id: "certReqInputImpl".to_owned(),
                    attributes: vec![
                        ProfileAttribute {
                            name: "cert_request_type".to_owned(),
                            value: "pkcs10".to_owned(),
                        },
                        ProfileAttribute {
                            name: "cert_request".to_owned(),
                            value: csr_pem.to_owned(),
                        },
                    ],
                },
                ProfileInput {
                    class_id: "submitterInfoInputImpl".to_owned(),
                    attributes: vec![
                        ProfileAttribute {
                            name: "requestor_name".to_owned(),
                            value: "kipuka EST Server".to_owned(),
                        },
                        ProfileAttribute {
                            name: "requestor_email".to_owned(),
                            value: String::new(),
                        },
                        ProfileAttribute {
                            name: "requestor_phone".to_owned(),
                            value: String::new(),
                        },
                    ],
                },
            ],
        };

        let resp = self.post_json("/ca/rest/certrequests", &request).await?;
        let enrollment: EnrollmentResponse = Self::json_response(resp).await?;

        let entry = enrollment
            .entries
            .into_iter()
            .next()
            .ok_or_else(|| DogtagError::ParseError("Empty enrollment response".into()))?;

        let request_id = entry
            .request_id
            .ok_or_else(|| DogtagError::ParseError("Missing request_id in response".into()))?;

        let status = match entry.request_status.as_deref() {
            Some("complete") => EnrollStatus::Complete,
            Some("pending") => EnrollStatus::Pending,
            Some("rejected") => EnrollStatus::Rejected,
            Some("canceled") => EnrollStatus::Canceled,
            Some(other) => {
                return Err(DogtagError::ParseError(format!(
                    "Unknown request status: {other}"
                )));
            }
            None => {
                return Err(DogtagError::ParseError(
                    "Missing request_status in response".into(),
                ));
            }
        };

        // Auto-approve pending requests: two-step Dogtag REST flow.
        // Step 1: GET the review response (populates requestId in the body)
        // Step 2: POST the review response back to the approve endpoint
        // Sending an empty body causes NullPointerException in Dogtag's
        // RequestProcessor because CertReviewResponse.getRequestId() is null.
        let (status, certificate_der) = if status == EnrollStatus::Pending {
            tracing::info!(request_id = %request_id, "auto-approving pending enrollment");

            // Step 1: GET the review form (must include Accept: application/json
            // or Dogtag returns XML which fails JSON parsing)
            let review_url = format!("/ca/rest/agent/certrequests/{request_id}");
            let review_resp = self.get(&review_url).await;

            let approve_resp = match review_resp {
                Ok(resp) => {
                    let resp_status = resp.status();
                    if !resp_status.is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        tracing::error!(
                            status = resp_status.as_u16(),
                            body_preview = %&body[..body.len().min(200)],
                            "GET review form failed"
                        );
                        self.post_json(
                            &format!("/ca/rest/agent/certrequests/{request_id}/approve"),
                            &serde_json::json!({}),
                        )
                        .await
                    } else {
                        let review_body: serde_json::Value = match Self::json_response(resp).await {
                            Ok(body) => {
                                tracing::info!("review form retrieved, posting approval");
                                body
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "review form not valid JSON (missing Accept header?)");
                                serde_json::json!({})
                            }
                        };
                        self.post_json(
                            &format!("/ca/rest/agent/certrequests/{request_id}/approve"),
                            &review_body,
                        )
                        .await
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to GET review form");
                    self.post_json(
                        &format!("/ca/rest/agent/certrequests/{request_id}/approve"),
                        &serde_json::json!({}),
                    )
                    .await
                }
            };

            match approve_resp {
                Ok(resp) => {
                    let resp_status = resp.status();
                    if !resp_status.is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        tracing::error!(
                            status = resp_status.as_u16(),
                            body_preview = %&body[..body.len().min(300)],
                            "approve POST returned error"
                        );
                        (EnrollStatus::Pending, None)
                    } else {
                        let approved: EnrollmentEntry = Self::json_response(resp).await?;
                        let new_status = match approved.request_status.as_deref() {
                            Some("complete") => {
                                tracing::info!(request_id = %request_id, "auto-approve succeeded");
                                EnrollStatus::Complete
                            }
                            Some("pending") => {
                                tracing::warn!(request_id = %request_id, "still pending after approve");
                                EnrollStatus::Pending
                            }
                            other => {
                                tracing::warn!(request_id = %request_id, status = ?other, "unexpected status after approval");
                                EnrollStatus::Pending
                            }
                        };
                        let cert = if new_status == EnrollStatus::Complete {
                            if let Some(cert_id) = &approved.cert_id {
                                Some(self.fetch_cert_der(cert_id).await?)
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        (new_status, cert)
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "auto-approve POST failed");
                    (EnrollStatus::Pending, None)
                }
            }
        } else if status == EnrollStatus::Complete {
            let cert = if let Some(cert_id) = &entry.cert_id {
                Some(self.fetch_cert_der(cert_id).await?)
            } else {
                None
            };
            (status, cert)
        } else {
            (status, None)
        };

        Ok(EnrollResult {
            request_id,
            status,
            certificate_der,
        })
    }

    /// Poll the status of an enrollment request.
    ///
    /// Sends `GET /ca/rest/certrequests/{request_id}` to check whether
    /// a pending enrollment has been approved or rejected. Used for
    /// EST Disconnected mode (RFC 7030 S4.4.2) where the CA requires
    /// out-of-band approval before issuing the certificate.
    pub async fn get_enrollment_status(&self, request_id: &str) -> DogtagResult<EnrollResult> {
        debug!(request_id, "Checking enrollment status");

        let resp = self
            .get(&format!("/ca/rest/certrequests/{request_id}"))
            .await?;
        let entry: EnrollmentEntry = Self::json_response(resp).await?;

        let status = match entry.request_status.as_deref() {
            Some("complete") => EnrollStatus::Complete,
            Some("pending") => EnrollStatus::Pending,
            Some("rejected") => EnrollStatus::Rejected,
            Some("canceled") => EnrollStatus::Canceled,
            other => {
                return Err(DogtagError::ParseError(format!(
                    "Unknown request status: {other:?}"
                )));
            }
        };

        let certificate_der = if status == EnrollStatus::Complete {
            if let Some(cert_id) = &entry.cert_id {
                Some(self.fetch_cert_der(cert_id).await?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(EnrollResult {
            request_id: request_id.to_owned(),
            status,
            certificate_der,
        })
    }

    /// Fetch DER-encoded certificate by serial/cert ID.
    async fn fetch_cert_der(&self, cert_id: &str) -> DogtagResult<Vec<u8>> {
        let resp = self.get(&format!("/ca/rest/certs/{cert_id}")).await?;
        let cert_data: CertDataResponse = Self::json_response(resp).await?;

        let encoded = cert_data
            .encoded
            .ok_or_else(|| DogtagError::ParseError("Missing certificate data".into()))?;

        // Strip PEM headers if present, then decode base64.
        let b64: String = encoded
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();

        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| DogtagError::ParseError(format!("Invalid base64 in certificate: {e}")))
    }
}
