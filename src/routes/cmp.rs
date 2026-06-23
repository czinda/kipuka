//! CMP v3 endpoint (RFC 9810).
//!
//! Certificate Management Protocol version 3 provides a comprehensive
//! certificate lifecycle management protocol.  Unlike EST which uses
//! HTTP semantics, CMP uses its own ASN.1 message format (PKIMessage)
//! transported over HTTP.
//!
//! RFC 9810 §3: CMP messages are encoded as DER and transported via
//! HTTP POST to `/.well-known/cmp`.
//!
//! # Supported message types
//!
//! | Type | Body       | Description                    |
//! |------|------------|--------------------------------|
//! | ir   | CertReqMessages | Initialization request    |
//! | cr   | CertReqMessages | Certification request     |
//! | kur  | CertReqMessages | Key update request        |
//! | rr   | RevReqContent   | Revocation request        |
//! | genm | GenMsgContent   | General message           |
//!
//! # Protection
//!
//! CMP messages are protected by either:
//! - **Signature-based** — the sender signs with their certificate
//! - **MAC-based** — using a shared secret (for initial enrollment)

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::error::KipukaError;
use crate::state::AppState;

/// Content-Type for CMP messages (RFC 9810 §6.2).
const CONTENT_TYPE_CMP: &str = "application/pkixcmp";

/// CMP message type, identified by the implicit tag on the PKIBody
/// choice within PKIMessage (RFC 9810 §5.3).
///
/// Each variant corresponds to a specific CMP operation.  Request
/// types have matching response types (e.g., `Ir` → `Ip`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpMessageType {
    /// Initialization request (tag 0) — new certificate enrollment
    /// with no prior credential.
    Ir,
    /// Initialization response (tag 1).
    Ip,
    /// Certification request (tag 2) — standard enrollment with an
    /// existing credential.
    Cr,
    /// Certification response (tag 3).
    Cp,
    /// Key update request (tag 7) — re-enrollment / key rollover.
    Kur,
    /// Key update response (tag 8).
    Kup,
    /// Revocation request (tag 11).
    Rr,
    /// Revocation response (tag 12).
    Rp,
    /// General message (tag 21) — CA information, supported algorithms.
    GenM,
    /// General response (tag 22).
    GenP,
    /// Error message (tag 23).
    Error,
    /// Certificate confirmation (tag 24).
    CertConf,
    /// PKI confirmation (tag 25).
    PkiConf,
}

impl CmpMessageType {
    /// Map an ASN.1 implicit tag value to the corresponding message type.
    ///
    /// RFC 9810 §5.3 defines the PKIBody CHOICE tags:
    ///
    /// ```text
    /// ir       [0]  CertReqMessages
    /// ip       [1]  CertRepMessage
    /// cr       [2]  CertReqMessages
    /// cp       [3]  CertRepMessage
    /// ...
    /// kur      [7]  CertReqMessages
    /// kup      [8]  CertRepMessage
    /// ...
    /// rr       [11] RevReqContent
    /// rp       [12] RevRepContent
    /// ...
    /// genm     [21] GenMsgContent
    /// genp     [22] GenRepContent
    /// error    [23] ErrorMsgContent
    /// certConf [24] CertConfirmContent
    /// pkiConf  [25] PKIConfirmContent
    /// ```
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Ir),
            1 => Some(Self::Ip),
            2 => Some(Self::Cr),
            3 => Some(Self::Cp),
            7 => Some(Self::Kur),
            8 => Some(Self::Kup),
            11 => Some(Self::Rr),
            12 => Some(Self::Rp),
            21 => Some(Self::GenM),
            22 => Some(Self::GenP),
            23 => Some(Self::Error),
            24 => Some(Self::CertConf),
            25 => Some(Self::PkiConf),
            _ => None,
        }
    }

    /// Returns `true` if this message type is a client request.
    pub fn is_request(&self) -> bool {
        matches!(
            self,
            Self::Ir | Self::Cr | Self::Kur | Self::Rr | Self::GenM | Self::CertConf
        )
    }

    /// Return the expected response type for a given request type.
    ///
    /// Returns `None` for response types or types that do not expect
    /// a specific response (e.g., `CertConf` expects `PkiConf`, but
    /// error messages do not expect a response).
    pub fn expected_response(&self) -> Option<Self> {
        match self {
            Self::Ir => Some(Self::Ip),
            Self::Cr => Some(Self::Cp),
            Self::Kur => Some(Self::Kup),
            Self::Rr => Some(Self::Rp),
            Self::GenM => Some(Self::GenP),
            Self::CertConf => Some(Self::PkiConf),
            _ => None,
        }
    }
}

impl std::fmt::Display for CmpMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Ir => "ir",
            Self::Ip => "ip",
            Self::Cr => "cr",
            Self::Cp => "cp",
            Self::Kur => "kur",
            Self::Kup => "kup",
            Self::Rr => "rr",
            Self::Rp => "rp",
            Self::GenM => "genm",
            Self::GenP => "genp",
            Self::Error => "error",
            Self::CertConf => "certConf",
            Self::PkiConf => "pkiConf",
        };
        f.write_str(name)
    }
}

/// CMP message protection mechanism.
///
/// RFC 9810 §5.1.3: PKIMessage `protection` is computed over the
/// `header` and `body` fields.  Two modes are defined:
///
/// - **Signature-based**: the sender signs with a certificate-bound key.
/// - **MAC-based**: a shared secret protects the message; used for
///   initial enrollment when no certificate exists yet.
#[derive(Debug, Clone)]
pub enum CmpProtectionType {
    /// Signature-based protection (RFC 9810 §5.1.3.3).
    ///
    /// The sender's certificate is included in the `extraCerts` field
    /// of the PKIMessage.
    Signature {
        /// Signature algorithm OID or name.
        algorithm: String,
        /// DER-encoded signer certificate.
        cert_der: Vec<u8>,
    },
    /// MAC-based protection (RFC 9810 §5.1.3.1).
    ///
    /// Uses a shared secret (reference number + passphrase) to compute
    /// a MAC over the message.  Typically used for initial enrollment
    /// (`ir`) before the client has a certificate.
    Mac {
        /// MAC algorithm name (e.g., `"hmac-sha256"`).
        algorithm: String,
    },
}

/// Parsed CMP request message.
///
/// Represents the essential fields extracted from a PKIMessage DER
/// encoding for dispatch and processing.
#[derive(Debug, Clone)]
pub struct CmpRequest {
    /// The request message type (ir, cr, kur, rr, genm, certConf).
    pub message_type: CmpMessageType,

    /// Transaction identifier (RFC 9810 §5.1.1).
    ///
    /// Used to correlate request-response pairs.  The server copies
    /// this value into the response.
    pub transaction_id: Vec<u8>,

    /// Sender nonce (RFC 9810 §5.1.1).
    ///
    /// Provides replay protection.  The server returns this as
    /// `recipNonce` in the response.
    pub sender_nonce: Vec<u8>,

    /// Sender general name (RFC 9810 §5.1.1).
    ///
    /// For signature-protected messages: the certificate subject DN.
    /// For MAC-protected messages: the reference number.
    pub sender: String,

    /// Protection mechanism and credentials.
    pub protection: CmpProtectionType,

    /// DER-encoded PKIBody content for the specific message type.
    pub body_der: Vec<u8>,
}

/// CMP response message under construction.
///
/// The handler builds this struct and passes it to [`build_cmp_response`]
/// to produce the DER-encoded PKIMessage for the HTTP response.
#[derive(Debug, Clone)]
pub struct CmpResponse {
    /// The response message type (ip, cp, kup, rp, genp, pkiConf, error).
    pub message_type: CmpMessageType,

    /// Transaction identifier copied from the request.
    pub transaction_id: Vec<u8>,

    /// Recipient nonce — copied from the request's sender nonce.
    pub recip_nonce: Vec<u8>,

    /// Sender nonce — freshly generated by the server.
    pub sender_nonce: Vec<u8>,

    /// Server sender name (CA subject DN).
    pub sender: String,

    /// DER-encoded response body content.
    pub body_der: Vec<u8>,
}

/// Parse a DER-encoded CMP PKIMessage into a [`CmpRequest`].
///
/// RFC 9810 §5: PKIMessage is an ASN.1 SEQUENCE:
///
/// ```text
/// PKIMessage ::= SEQUENCE {
///     header     PKIHeader,
///     body       PKIBody,
///     protection [0] PKIProtection OPTIONAL,
///     extraCerts [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL
/// }
/// ```
///
/// This function performs minimal structural validation and extracts
/// the fields needed for request dispatch.
///
/// # Errors
///
/// - `KipukaError::BadRequest` — malformed DER, unknown message type,
///   missing required header fields.
/// - `KipukaError::Internal` — full ASN.1 parsing not yet implemented.
pub fn parse_cmp_message(der: &[u8]) -> Result<CmpRequest, KipukaError> {
    if der.is_empty() {
        return Err(KipukaError::BadRequest("empty CMP message".into()));
    }

    // A minimal PKIMessage (header + body) is at least ~50 bytes.
    if der.len() < 50 {
        return Err(KipukaError::BadRequest(
            "CMP message is too short to be a valid PKIMessage".into(),
        ));
    }

    // Verify outer SEQUENCE tag (0x30).
    if der[0] != 0x30 {
        return Err(KipukaError::BadRequest(
            "CMP message does not start with a SEQUENCE tag".into(),
        ));
    }

    // Extract the PKIBody tag to determine message type.
    //
    // The PKIBody is a CHOICE type with implicit context-class tags.
    // After the PKIHeader SEQUENCE, the body appears as a
    // context-tagged element: [tag] IMPLICIT.
    //
    // For a stub implementation, we attempt to find the body tag by
    // scanning past the header SEQUENCE.  A full implementation would
    // use a proper ASN.1 DER parser.

    // TODO: Implement full ASN.1 PKIMessage parsing.
    //
    // Implementation plan using `der` + `x509-cert` crates:
    //
    // 1. Parse outer SEQUENCE:
    //    let pki_msg = PkiMessage::from_der(der)?;
    //
    // 2. Extract header fields:
    //    let header = &pki_msg.header;
    //    let transaction_id = header.transaction_id.as_bytes().to_vec();
    //    let sender_nonce = header.sender_nonce.as_bytes().to_vec();
    //    let sender = header.sender.to_string();
    //
    // 3. Determine body type from the CHOICE tag:
    //    let (tag, body_der) = pki_msg.body.tag_and_content();
    //    let message_type = CmpMessageType::from_tag(tag)?;
    //
    // 4. Extract protection:
    //    let protection = match pki_msg.protection {
    //        Some(sig) => CmpProtectionType::Signature { ... },
    //        None => return Err("unprotected message"),
    //    };
    //
    // 5. Return CmpRequest { message_type, transaction_id, ... }

    Err(KipukaError::Internal(
        "CMP PKIMessage parsing not yet implemented".into(),
    ))
}

/// Build a DER-encoded CMP PKIMessage response.
///
/// Constructs a PKIMessage with:
/// - `header`: sender, recipient, transactionID, senderNonce, recipNonce
/// - `body`: the response content tagged with the response type
/// - `protection`: signature computed with the CA signing key
/// - `extraCerts`: CA certificate chain for validation
///
/// # Errors
///
/// - `KipukaError::BadRequest` — empty transaction ID or body.
/// - `KipukaError::Internal` — ASN.1 encoding not yet implemented.
pub fn build_cmp_response(
    req: &CmpRequest,
    response_type: CmpMessageType,
    body: &[u8],
) -> Result<Vec<u8>, KipukaError> {
    if req.transaction_id.is_empty() {
        return Err(KipukaError::BadRequest(
            "cannot build CMP response: empty transaction ID".into(),
        ));
    }

    if body.is_empty() {
        return Err(KipukaError::BadRequest(
            "cannot build CMP response: empty body".into(),
        ));
    }

    // Verify the response type is appropriate for the request.
    if let Some(expected) = req.message_type.expected_response() {
        if expected != response_type {
            tracing::warn!(
                request_type = %req.message_type,
                response_type = %response_type,
                expected = %expected,
                "CMP response type mismatch"
            );
        }
    }

    // TODO: Implement CMP PKIMessage response construction.
    //
    // Implementation plan:
    //
    // 1. Build PKIHeader:
    //    let header = PkiHeader {
    //        pvno: Pvno::Cmp2021,
    //        sender: GeneralName::directoryName(ca_subject_dn),
    //        recipient: GeneralName::from_str(&req.sender),
    //        message_time: Some(GeneralizedTime::now()),
    //        protection_alg: Some(sha256_with_rsa()),
    //        transaction_id: OctetString::new(req.transaction_id.clone()),
    //        sender_nonce: OctetString::new(random_nonce()),
    //        recip_nonce: Some(OctetString::new(req.sender_nonce.clone())),
    //    };
    //
    // 2. Build PKIBody with the response tag:
    //    let pki_body = PkiBody::new(response_type.tag(), body);
    //
    // 3. Compute protection (signature over header + body):
    //    let to_protect = concat_der(&header, &pki_body);
    //    let signature = ca_key.sign(&to_protect)?;
    //    let protection = BitString::new(signature);
    //
    // 4. Assemble PKIMessage:
    //    let pki_msg = PkiMessage { header, body: pki_body, protection, extra_certs };
    //
    // 5. Encode:
    //    Ok(pki_msg.to_der()?)

    Err(KipukaError::Internal(
        "CMP PKIMessage response construction not yet implemented".into(),
    ))
}

/// `POST /.well-known/cmp` — process a CMP PKIMessage.
///
/// RFC 9810 §6.2: CMP messages are transported over HTTP using
/// `Content-Type: application/pkixcmp`.  The request and response
/// bodies are DER-encoded PKIMessage values.
///
/// # Processing
///
/// 1. Validate Content-Type is `application/pkixcmp`.
/// 2. Parse the PKIMessage to extract message type and protection.
/// 3. Verify message protection (signature or MAC).
/// 4. Dispatch based on message type:
///    - `ir` / `cr` → enrollment (certificate issuance)
///    - `kur` → key update (re-enrollment)
///    - `rr` → revocation
///    - `genm` → general message (CA info, algorithms)
///    - `certConf` → certificate confirmation
/// 5. Build and return the response PKIMessage.
///
/// # Errors
///
/// - `400 Bad Request` — malformed PKIMessage, unsupported type
/// - `403 Forbidden` — MAC verification failure, untrusted signer
/// - `415 Unsupported Media Type` — wrong Content-Type
/// - `500 Internal Server Error` — CA backend failure
pub async fn post_cmp(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, KipukaError> {
    // Check that CMP is enabled.
    let cmp_config = match state.config.cmp {
        Some(ref cfg) if cfg.enabled => cfg,
        _ => return Err(KipukaError::Est("CMP is not enabled".into())),
    };

    tracing::info!("CMP request received ({} bytes)", body.len());

    if body.is_empty() {
        return Err(KipukaError::BadRequest("empty CMP message".into()));
    }

    // Parse the PKIMessage.
    let cmp_req = parse_cmp_message(&body)?;

    tracing::info!(
        message_type = %cmp_req.message_type,
        sender = %cmp_req.sender,
        transaction_id_len = cmp_req.transaction_id.len(),
        "CMP message parsed"
    );

    // Reject non-request message types.
    if !cmp_req.message_type.is_request() {
        return Err(KipukaError::BadRequest(format!(
            "unexpected CMP message type '{}' — only request types are accepted",
            cmp_req.message_type,
        )));
    }

    // Verify message protection.
    match &cmp_req.protection {
        CmpProtectionType::Signature { algorithm, cert_der } => {
            tracing::debug!(
                algorithm = %algorithm,
                cert_len = cert_der.len(),
                "verifying signature-based CMP protection"
            );

            // TODO: Verify the signature over (header || body) using
            // the signer's public key from cert_der, then validate
            // the signer's certificate chain against the CA truststore.
            //
            // let signer_cert = x509::Certificate::from_der(cert_der)?;
            // let to_verify = concat_header_body(&cmp_req);
            // signer_cert.verify_signature(algorithm, &to_verify, &protection_bits)?;
            // x509::verify_chain(&signer_cert, &[], &truststore)?;
        }
        CmpProtectionType::Mac { algorithm } => {
            if !cmp_config.allow_mac_protection {
                return Err(KipukaError::Auth(
                    "MAC-based CMP protection is not allowed by policy".into(),
                ));
            }

            tracing::debug!(
                algorithm = %algorithm,
                "verifying MAC-based CMP protection"
            );

            // TODO: Look up the shared secret by reference number
            // (from the sender field), compute the MAC over
            // (header || body), and compare with the protection value.
            //
            // let secret = otp_store.lookup_cmp_secret(&cmp_req.sender)?;
            // let expected_mac = compute_mac(algorithm, &secret, &to_protect)?;
            // if expected_mac != protection_bits {
            //     return Err(KipukaError::Auth("MAC verification failed"));
            // }
        }
    }

    // Determine the expected response type.
    let response_type = cmp_req.message_type.expected_response().ok_or_else(|| {
        KipukaError::BadRequest(format!(
            "CMP message type '{}' has no defined response",
            cmp_req.message_type,
        ))
    })?;

    // Dispatch based on message type.
    let response_body_der = match cmp_req.message_type {
        CmpMessageType::Ir => {
            if !cmp_config.allow_ir {
                return Err(KipukaError::Est(
                    "CMP initialization requests (ir) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing initialization request (ir)");

            // TODO: Parse CertReqMessages from body_der, extract the
            // certificate template, issue the certificate, and build
            // a CertRepMessage response.
            //
            // let cert_req = CertReqMessages::from_der(&cmp_req.body_der)?;
            // let cert_der = kipuka_est::issue::sign_cmp_request(ca, &cert_req).await?;
            // let cert_rep = CertRepMessage::success(cert_der);
            // cert_rep.to_der()?
            Vec::new()
        }
        CmpMessageType::Cr => {
            if !cmp_config.allow_cr {
                return Err(KipukaError::Est(
                    "CMP certification requests (cr) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing certification request (cr)");

            // TODO: Same as ir but the sender has an existing certificate.
            Vec::new()
        }
        CmpMessageType::Kur => {
            if !cmp_config.allow_kur {
                return Err(KipukaError::Est(
                    "CMP key update requests (kur) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing key update request (kur)");

            // TODO: Verify the old certificate is valid and not revoked,
            // issue a new certificate with the updated key.
            Vec::new()
        }
        CmpMessageType::Rr => {
            if !cmp_config.allow_rr {
                return Err(KipukaError::Est(
                    "CMP revocation requests (rr) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing revocation request (rr)");

            // TODO: Parse RevReqContent, look up the certificate by
            // serial number, revoke it, build RevRepContent response.
            Vec::new()
        }
        CmpMessageType::GenM => {
            tracing::info!("CMP: processing general message (genm)");

            // TODO: Parse GenMsgContent InfoTypeAndValue sequence.
            // Return CA certificates, supported algorithms, etc.
            Vec::new()
        }
        CmpMessageType::CertConf => {
            tracing::info!("CMP: processing certificate confirmation (certConf)");

            // TODO: Verify the certificate hash in the confirmation
            // matches the issued certificate.  Return PKIConfirm (empty).
            Vec::new()
        }
        _ => {
            return Err(KipukaError::BadRequest(format!(
                "unsupported CMP message type: {}",
                cmp_req.message_type,
            )));
        }
    };

    if response_body_der.is_empty() {
        return Err(KipukaError::Ca(
            "CMP processing not yet implemented".into(),
        ));
    }

    // Build the response PKIMessage.
    let response_der = build_cmp_response(&cmp_req, response_type, &response_body_der)?;

    state
        .record_audit_event(
            "cmp_success",
            &format!(
                "type={}, sender={}",
                cmp_req.message_type, cmp_req.sender
            ),
        )
        .await;

    // RFC 9810 §6.2: Response Content-Type is application/pkixcmp.
    let mut resp = (StatusCode::OK, response_der).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_CMP),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_tag_maps_request_types() {
        assert_eq!(CmpMessageType::from_tag(0), Some(CmpMessageType::Ir));
        assert_eq!(CmpMessageType::from_tag(2), Some(CmpMessageType::Cr));
        assert_eq!(CmpMessageType::from_tag(7), Some(CmpMessageType::Kur));
        assert_eq!(CmpMessageType::from_tag(11), Some(CmpMessageType::Rr));
        assert_eq!(CmpMessageType::from_tag(21), Some(CmpMessageType::GenM));
    }

    #[test]
    fn from_tag_maps_response_types() {
        assert_eq!(CmpMessageType::from_tag(1), Some(CmpMessageType::Ip));
        assert_eq!(CmpMessageType::from_tag(3), Some(CmpMessageType::Cp));
        assert_eq!(CmpMessageType::from_tag(8), Some(CmpMessageType::Kup));
        assert_eq!(CmpMessageType::from_tag(12), Some(CmpMessageType::Rp));
        assert_eq!(CmpMessageType::from_tag(22), Some(CmpMessageType::GenP));
    }

    #[test]
    fn from_tag_maps_special_types() {
        assert_eq!(CmpMessageType::from_tag(23), Some(CmpMessageType::Error));
        assert_eq!(CmpMessageType::from_tag(24), Some(CmpMessageType::CertConf));
        assert_eq!(CmpMessageType::from_tag(25), Some(CmpMessageType::PkiConf));
    }

    #[test]
    fn from_tag_rejects_unknown() {
        assert_eq!(CmpMessageType::from_tag(4), None);
        assert_eq!(CmpMessageType::from_tag(10), None);
        assert_eq!(CmpMessageType::from_tag(50), None);
        assert_eq!(CmpMessageType::from_tag(255), None);
    }

    #[test]
    fn is_request_identifies_requests() {
        assert!(CmpMessageType::Ir.is_request());
        assert!(CmpMessageType::Cr.is_request());
        assert!(CmpMessageType::Kur.is_request());
        assert!(CmpMessageType::Rr.is_request());
        assert!(CmpMessageType::GenM.is_request());
        assert!(CmpMessageType::CertConf.is_request());
    }

    #[test]
    fn is_request_rejects_responses() {
        assert!(!CmpMessageType::Ip.is_request());
        assert!(!CmpMessageType::Cp.is_request());
        assert!(!CmpMessageType::Kup.is_request());
        assert!(!CmpMessageType::Rp.is_request());
        assert!(!CmpMessageType::GenP.is_request());
        assert!(!CmpMessageType::Error.is_request());
        assert!(!CmpMessageType::PkiConf.is_request());
    }

    #[test]
    fn expected_response_maps_correctly() {
        assert_eq!(CmpMessageType::Ir.expected_response(), Some(CmpMessageType::Ip));
        assert_eq!(CmpMessageType::Cr.expected_response(), Some(CmpMessageType::Cp));
        assert_eq!(CmpMessageType::Kur.expected_response(), Some(CmpMessageType::Kup));
        assert_eq!(CmpMessageType::Rr.expected_response(), Some(CmpMessageType::Rp));
        assert_eq!(CmpMessageType::GenM.expected_response(), Some(CmpMessageType::GenP));
        assert_eq!(
            CmpMessageType::CertConf.expected_response(),
            Some(CmpMessageType::PkiConf)
        );
    }

    #[test]
    fn expected_response_none_for_responses() {
        assert_eq!(CmpMessageType::Ip.expected_response(), None);
        assert_eq!(CmpMessageType::Error.expected_response(), None);
        assert_eq!(CmpMessageType::PkiConf.expected_response(), None);
    }

    #[test]
    fn display_formats_correctly() {
        assert_eq!(format!("{}", CmpMessageType::Ir), "ir");
        assert_eq!(format!("{}", CmpMessageType::Kur), "kur");
        assert_eq!(format!("{}", CmpMessageType::CertConf), "certConf");
    }

    #[test]
    fn parse_rejects_empty_message() {
        let result = parse_cmp_message(&[]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn parse_rejects_short_message() {
        let result = parse_cmp_message(&[0x30, 0x03, 0x01, 0x01, 0x00]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn parse_rejects_non_sequence() {
        // Tag 0x02 = INTEGER, not SEQUENCE.
        let result = parse_cmp_message(&[0x02; 100]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn build_response_rejects_empty_transaction_id() {
        let req = CmpRequest {
            message_type: CmpMessageType::Ir,
            transaction_id: Vec::new(),
            sender_nonce: vec![1, 2, 3],
            sender: "CN=test".into(),
            protection: CmpProtectionType::Mac {
                algorithm: "hmac-sha256".into(),
            },
            body_der: vec![0u8; 50],
        };
        let result = build_cmp_response(&req, CmpMessageType::Ip, &[1, 2, 3]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    #[test]
    fn build_response_rejects_empty_body() {
        let req = CmpRequest {
            message_type: CmpMessageType::Cr,
            transaction_id: vec![1, 2, 3, 4],
            sender_nonce: vec![5, 6, 7],
            sender: "CN=test".into(),
            protection: CmpProtectionType::Signature {
                algorithm: "sha256WithRSAEncryption".into(),
                cert_der: vec![0u8; 200],
            },
            body_der: vec![0u8; 50],
        };
        let result = build_cmp_response(&req, CmpMessageType::Cp, &[]);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }
}
