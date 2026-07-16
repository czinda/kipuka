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

/// Result of a server-side key generation request.
#[derive(Debug, Clone)]
pub struct ServerKeygenResult {
    pub request_id: String,
    pub certificate_der: Option<Vec<u8>>,
    pub pkcs12_b64: Option<String>,
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
        self.enroll_certificate_with_type(csr_pem, profile_id, "pkcs10").await
    }

    /// Enroll a certificate with an explicit request type (`pkcs10` or `crmf`).
    pub async fn enroll_certificate_with_type(
        &self,
        request_data: &str,
        profile_id: &str,
        request_type: &str,
    ) -> DogtagResult<EnrollResult> {
        debug!(profile = profile_id, request_type, "Submitting enrollment request");

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
                            value: request_type.to_owned(),
                        },
                        ProfileAttribute {
                            name: "cert_request".to_owned(),
                            value: request_data.to_owned(),
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
                            body_preview = %crate::truncate_str(&body, 200),
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
                            body_preview = %crate::truncate_str(&body, 300),
                            "approve POST returned error"
                        );
                        (EnrollStatus::Pending, None)
                    } else {
                        // Approve may return JSON (CertReviewResponse) or HTML.
                        // If JSON parsing fails, fall back to polling the request.
                        let approved: serde_json::Value = match resp.json().await {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(error = %e, "approve response not JSON, polling request status");
                                let poll = self.get_enrollment_status(&request_id).await?;
                                let status = poll.status;
                                let cert = poll.certificate_der;
                                return Ok(EnrollResult { request_id: request_id.to_owned(), status, certificate_der: cert });
                            }
                        };
                        let status_str = approved.get("requestStatus")
                            .or_else(|| approved.get("RequestStatus"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let cert_id = approved.get("certId")
                            .or_else(|| approved.get("CertId"))
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        tracing::info!(request_id = %request_id, status = %status_str, "approve result");

                        let new_status = match status_str {
                            "complete" => EnrollStatus::Complete,
                            "pending" => EnrollStatus::Pending,
                            other => {
                                tracing::warn!(request_id = %request_id, status = %other, "unexpected status after approval");
                                EnrollStatus::Pending
                            }
                        };
                        let cert = if new_status == EnrollStatus::Complete {
                            if let Some(ref cid) = cert_id {
                                Some(self.fetch_cert_der(cid).await?)
                            } else {
                                // Try to find cert ID in the response
                                let alt_id = approved.get("certificateId")
                                    .or_else(|| approved.get("CertificateID"))
                                    .and_then(|v| v.as_str());
                                if let Some(aid) = alt_id {
                                    Some(self.fetch_cert_der(aid).await?)
                                } else {
                                    tracing::warn!("approve succeeded but no cert ID found in response");
                                    None
                                }
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

    /// Server-side key generation via Dogtag's `caServerKeygen_UserCert` profile.
    ///
    /// Dogtag CA + KRA generate the key pair internally. The CA archives
    /// the private key via the KRA (using ML-KEM if the transport cert is
    /// ML-KEM-1024) and returns the cert + PKCS#12.
    pub async fn server_keygen(
        &self,
        subject_uid: &str,
        subject_cn: &str,
        p12_password: &str,
        key_type: &str,
        key_size: u32,
    ) -> DogtagResult<ServerKeygenResult> {
        debug!(subject_cn, key_type, key_size, "Server-side key generation");

        // Login for session
        let _ = self.post_json("/ca/rest/account/login", &serde_json::json!({})).await;

        let request = EnrollmentRequest {
            profile_id: "caServerKeygen_UserCert".to_owned(),
            renewal: false,
            input: vec![
                ProfileInput {
                    class_id: "serverKeygenInputImpl".to_owned(),
                    attributes: vec![
                        ProfileAttribute {
                            name: "serverSideKeygenP12Passwd".to_owned(),
                            value: p12_password.to_owned(),
                        },
                        ProfileAttribute {
                            name: "keyType".to_owned(),
                            value: key_type.to_owned(),
                        },
                        ProfileAttribute {
                            name: "keySize".to_owned(),
                            value: key_size.to_string(),
                        },
                    ],
                },
                ProfileInput {
                    class_id: "subjectNameInputImpl".to_owned(),
                    attributes: vec![
                        ProfileAttribute {
                            name: "sn_uid".to_owned(),
                            value: subject_uid.to_owned(),
                        },
                        ProfileAttribute {
                            name: "sn_cn".to_owned(),
                            value: subject_cn.to_owned(),
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
        let resp_body: serde_json::Value = Self::json_response(resp).await?;

        // The server-keygen response includes the PKCS#12 in the output
        let entries = resp_body.get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| DogtagError::ParseError("No entries in server-keygen response".into()))?;

        let entry = entries.first()
            .ok_or_else(|| DogtagError::ParseError("Empty entries in server-keygen response".into()))?;

        let status = entry.get("requestStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if status != "complete" {
            let error_msg = entry.get("errorMessage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(DogtagError::EnrollmentRejected {
                reason: format!("status={status}: {error_msg}"),
            });
        }

        // Extract cert ID and fetch the certificate
        let cert_id_str = entry.get("certId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .or_else(|| {
                entry.get("certURL")
                    .and_then(|u| u.as_str())
                    .and_then(|u| u.rsplit('/').next())
                    .map(|s| s.to_owned())
            })
            .unwrap_or_default();
        let cert_id = cert_id_str.as_str();

        let certificate_der = if !cert_id.is_empty() {
            Some(self.fetch_cert_der(cert_id).await?)
        } else {
            None
        };

        // Extract PKCS#12 data from the output
        let p12_b64 = entry.get("pkcs12")
            .or_else(|| resp_body.get("pkcs12"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());

        let request_id = entry.get("requestID")
            .or_else(|| entry.get("requestId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        Ok(ServerKeygenResult {
            request_id,
            certificate_der,
            pkcs12_b64: p12_b64,
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
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(DogtagError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        // Try JSON first (normal path).
        if let Ok(cert_data) = serde_json::from_str::<CertDataResponse>(&body) {
            if let Some(ref encoded) = cert_data.encoded {
                return Self::decode_pem_to_der(encoded);
            }
        }

        // Fallback: raw PEM certificate in the response body.
        if body.contains("-----BEGIN CERTIFICATE-----") {
            tracing::debug!("response is raw PEM, extracting directly");
            return Self::decode_pem_to_der(&body);
        }

        // Fallback: XML response with <Encoded> or <encoded> tag.
        if let Some(pem) = Self::extract_cert_from_xml(&body) {
            tracing::debug!("extracted certificate from XML response");
            return Self::decode_pem_to_der(&pem);
        }

        Err(DogtagError::ParseError(format!(
            "cannot extract certificate from response; body: {}",
            crate::truncate_str(&body, 500)
        )))
    }

    fn decode_pem_to_der(pem: &str) -> DogtagResult<Vec<u8>> {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| DogtagError::ParseError(format!("invalid base64 in certificate: {e}")))
    }

    fn extract_cert_from_xml(xml: &str) -> Option<String> {
        for (open, close) in [("<Encoded>", "</Encoded>"), ("<encoded>", "</encoded>")] {
            if let Some(start) = xml.find(open) {
                let start = start + open.len();
                if let Some(end) = xml[start..].find(close) {
                    return Some(xml[start..start + end].to_owned());
                }
            }
        }
        None
    }
}
