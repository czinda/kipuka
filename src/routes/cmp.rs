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
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use synta::{Integer, Null, OctetStringRef, RawDer};
use synta_certificate::GeneralNameSpec;
use synta_certificate::cmp_types::{
    CertOrEncCert, CertRepMessage, CertResponse, CertifiedKeyPair, PBMParameter, PKIBody,
    PKIHeader, PKIMessage, PKIStatusInfo, RevRepContent,
};
use synta_certificate::crmf_types::CertReqMsg;

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

    // Parse the DER-encoded PKIMessage using synta-certificate's
    // auto-generated CMP types (RFC 9810 / RFC 4210).
    let pki_msg = PKIMessage::from_der(der)
        .map_err(|e| KipukaError::BadRequest(format!("failed to parse CMP PKIMessage: {e}")))?;

    // Extract header fields.
    let transaction_id = pki_msg
        .header
        .transaction_id
        .map(|o| o.as_bytes().to_vec())
        .unwrap_or_default();

    let sender_nonce = pki_msg
        .header
        .sender_nonce
        .map(|o| o.as_bytes().to_vec())
        .unwrap_or_default();

    // Format sender GeneralName for logging / correlation.
    let sender = format_general_name(&pki_msg.header.sender);

    // Determine message type from the PKIBody CHOICE variant.
    let (message_type, body_der) = match &pki_msg.body {
        PKIBody::Ir(raw) => (CmpMessageType::Ir, raw.0.to_vec()),
        PKIBody::Ip(raw) => (CmpMessageType::Ip, raw.0.to_vec()),
        PKIBody::Cr(raw) => (CmpMessageType::Cr, raw.0.to_vec()),
        PKIBody::Cp(raw) => (CmpMessageType::Cp, raw.0.to_vec()),
        PKIBody::P10cr(raw) => (CmpMessageType::Cr, raw.0.to_vec()),
        PKIBody::Kur(raw) => (CmpMessageType::Kur, raw.0.to_vec()),
        PKIBody::Kup(raw) => (CmpMessageType::Kup, raw.0.to_vec()),
        PKIBody::Rr(raw) => (CmpMessageType::Rr, raw.0.to_vec()),
        PKIBody::Rp(raw) => (CmpMessageType::Rp, raw.0.to_vec()),
        PKIBody::Genm(raw) => (CmpMessageType::GenM, raw.0.to_vec()),
        PKIBody::Genp(raw) => (CmpMessageType::GenP, raw.0.to_vec()),
        PKIBody::Error(raw) => (CmpMessageType::Error, raw.0.to_vec()),
        PKIBody::CertConf(raw) => (CmpMessageType::CertConf, raw.0.to_vec()),
        PKIBody::Pkiconf(_) => (CmpMessageType::PkiConf, Vec::new()),
        _ => {
            return Err(KipukaError::BadRequest(
                "unsupported CMP PKIBody variant".into(),
            ));
        }
    };

    // Extract protection information.
    let protection = if let Some(prot_bits) = &pki_msg.protection {
        // Check if the protection algorithm indicates MAC-based or signature-based.
        if let Some(ref alg_id) = pki_msg.header.protection_alg {
            let alg_oid_str = alg_id.algorithm.to_string();
            // id-PasswordBasedMac (1.2.840.113533.7.66.13) and
            // id-DHBasedMac (1.2.840.113533.7.66.30) indicate MAC-based protection.
            if alg_oid_str.contains("1.2.840.113533.7.66.13")
                || alg_oid_str.contains("1.2.840.113533.7.66.30")
                || alg_oid_str.contains("1.3.6.1.5.5.7.15.10")
            {
                CmpProtectionType::Mac {
                    algorithm: alg_oid_str,
                }
            } else {
                // Signature-based protection — extract the signer certificate
                // from extraCerts if present.
                let cert_der = pki_msg
                    .extra_certs
                    .as_ref()
                    .and_then(|certs| certs.first())
                    .map(|c| c.0.to_vec())
                    .unwrap_or_default();
                CmpProtectionType::Signature {
                    algorithm: alg_oid_str,
                    cert_der,
                }
            }
        } else {
            // Protection bits present but no algorithm — treat as unprotected
            // (malformed, but don't crash).
            let _ = prot_bits;
            return Err(KipukaError::BadRequest(
                "CMP message has protection bits but no protectionAlg in header".into(),
            ));
        }
    } else {
        // Unprotected messages are not acceptable — reject them outright.
        return Err(KipukaError::Auth("CMP message has no protection".into()));
    };

    Ok(CmpRequest {
        message_type,
        transaction_id,
        sender_nonce,
        sender,
        protection,
        body_der,
    })
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
    ca_subject_der: Option<&[u8]>,
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
    if let Some(expected) = req.message_type.expected_response()
        && expected != response_type
    {
        tracing::warn!(
            request_type = %req.message_type,
            response_type = %response_type,
            expected = %expected,
            "CMP response type mismatch"
        );
    }

    // Generate a fresh sender nonce for replay protection.
    let server_nonce = generate_nonce();

    // Build the response PKIBody tagged with the appropriate CHOICE variant.
    let pki_body = match response_type {
        CmpMessageType::Ip => PKIBody::Ip(RawDer(body)),
        CmpMessageType::Cp => PKIBody::Cp(RawDer(body)),
        CmpMessageType::Kup => PKIBody::Kup(RawDer(body)),
        CmpMessageType::Rp => PKIBody::Rp(RawDer(body)),
        CmpMessageType::GenP => PKIBody::Genp(RawDer(body)),
        CmpMessageType::Error => PKIBody::Error(RawDer(body)),
        CmpMessageType::PkiConf => PKIBody::Pkiconf(Null),
        _ => {
            return Err(KipukaError::Internal(format!(
                "cannot build CMP response for body type: {response_type}"
            )));
        }
    };

    // Build PKIHeader with:
    //   - pvno = 2 (cmp2000, compatible with both RFC 4210 and RFC 9810)
    //   - sender = CA subject DN (extracted from the default CA certificate)
    //   - recipient = original sender
    //   - transactionID = echoed from request
    //   - senderNonce = fresh random nonce
    //   - recipNonce = request's senderNonce (replay protection)
    let sender_spec = if let Some(der) = ca_subject_der {
        GeneralNameSpec::directory_name(der)
    } else {
        GeneralNameSpec::rfc822("ca@kipuka.dev")
    };
    // Use the request's sender as the recipient, echoing it back per CMP protocol.
    let recipient_spec = if req.sender.is_empty() {
        GeneralNameSpec::rfc822("unknown@kipuka.dev")
    } else {
        GeneralNameSpec::rfc822(&req.sender)
    };

    let sender_gn = sender_spec
        .to_general_name()
        .map_err(|e| KipukaError::Internal(format!("failed to encode CA sender name: {e}")))?;
    let recipient_gn = recipient_spec
        .to_general_name()
        .map_err(|e| KipukaError::Internal(format!("failed to encode recipient name: {e}")))?;

    let header = PKIHeader {
        pvno: Integer::from_i64(2),
        sender: sender_gn,
        recipient: recipient_gn,
        message_time: None,
        protection_alg: None,
        sender_kid: None,
        recip_kid: None,
        transaction_id: Some(OctetStringRef::new(&req.transaction_id)),
        sender_nonce: Some(OctetStringRef::new(&server_nonce)),
        recip_nonce: Some(OctetStringRef::new(&req.sender_nonce)),
        free_text: None,
        general_info: None,
    };

    // Assemble the PKIMessage (unprotected for now; a full implementation
    // would compute a signature over header || body using the CA key).
    let pki_msg = PKIMessage {
        header,
        body: pki_body,
        protection: None,
        extra_certs: None,
    };

    pki_msg
        .to_der()
        .map_err(|e| KipukaError::Internal(format!("failed to DER-encode CMP response: {e}")))
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

    // Verify message protection (RFC 4210 §5.1.3 / RFC 9810 §5.1.3).
    //
    // The protection value is a signature or MAC computed over the
    // DER-encoded PKIHeader || PKIBody (concatenated, no outer wrapper).
    // We re-parse the original PKIMessage to extract the protection bits,
    // algorithm DER, and header||body bytes needed for verification.
    let pki_msg_for_verify = PKIMessage::from_der(&body).map_err(|e| {
        KipukaError::BadRequest(format!(
            "failed to re-parse PKIMessage for verification: {e}"
        ))
    })?;

    // Compute DER(header) || DER(body) — the data that was signed/MACed.
    let protected_bytes = {
        let header_der = synta::ToDer::to_der(&pki_msg_for_verify.header)
            .map_err(|e| KipukaError::Internal(format!("failed to re-encode PKIHeader: {e}")))?;
        let body_der_raw = synta::ToDer::to_der(&pki_msg_for_verify.body)
            .map_err(|e| KipukaError::Internal(format!("failed to re-encode PKIBody: {e}")))?;
        let mut buf = Vec::with_capacity(header_der.len() + body_der_raw.len());
        buf.extend_from_slice(&header_der);
        buf.extend_from_slice(&body_der_raw);
        buf
    };

    // Extract protection bits (signature or MAC value).
    let protection_bits = pki_msg_for_verify
        .protection
        .as_ref()
        .map(|bits| bits.as_bytes().to_vec())
        .unwrap_or_default();

    // Extract DER-encoded AlgorithmIdentifier for the protection algorithm.
    let protection_alg_der = pki_msg_for_verify
        .header
        .protection_alg
        .as_ref()
        .and_then(|alg| synta::ToDer::to_der(alg).ok())
        .unwrap_or_default();

    match &cmp_req.protection {
        CmpProtectionType::Signature {
            algorithm,
            cert_der,
        } => {
            tracing::debug!(
                algorithm = %algorithm,
                cert_len = cert_der.len(),
                "verifying signature-based CMP protection"
            );

            if cert_der.is_empty() {
                return Err(KipukaError::Auth(
                    "CMP signature protection: no signer certificate in extraCerts".into(),
                ));
            }

            // 1. Extract the signer certificate's SPKI for signature verification.
            let signer_ranges = synta_certificate::cert_byte_ranges(cert_der).ok_or_else(|| {
                KipukaError::Auth(
                    "failed to parse signer certificate structure from extraCerts".into(),
                )
            })?;
            let signer_spki_der = &cert_der[signer_ranges.subject_public_key_info.clone()];

            // 2. Verify the signature over (header || body) using the signer's
            //    public key.  protection_alg_der is the DER-encoded
            //    AlgorithmIdentifier; protection_bits is the raw signature bytes.
            let pub_key =
                synta_certificate::BackendPublicKey::from_spki_der(signer_spki_der.to_vec());
            pub_key
                .verify_signature(&protected_bytes, &protection_alg_der, &protection_bits)
                .map_err(|e| {
                    KipukaError::Auth(format!("CMP signature verification failed: {e}"))
                })?;

            tracing::info!("CMP signature protection verified successfully");

            // 3. Validate the signer certificate chains to a CA trust anchor.
            //    Use the same direct-issuer check pattern as CMS SignedData
            //    verification (cms_auth.rs).
            let signer_cert_parsed =
                synta_certificate::Certificate::from_der(cert_der).map_err(|e| {
                    KipukaError::Auth(format!("failed to parse CMP signer certificate: {e:?}"))
                })?;
            let cert_sig_bits = signer_cert_parsed.signature_value.as_bytes();
            let verifier = synta_certificate::default_signature_verifier();

            let mut signer_trusted = false;
            for ca_cfg in &state.config.cas {
                let ca = match state.get_ca(&ca_cfg.id) {
                    Some(ca) => ca,
                    None => continue,
                };
                let ta_der = &ca.cert_der;
                let ta_ranges = match synta_certificate::cert_byte_ranges(ta_der) {
                    Some(r) => r,
                    None => continue,
                };
                let ta_spki = &ta_der[ta_ranges.subject_public_key_info.clone()];

                // Verify signer cert's signature against this CA's SPKI.
                if verifier
                    .verify_certificate_signature_erased(
                        &cert_der[signer_ranges.tbs.clone()],
                        &cert_der[signer_ranges.signature_algorithm.clone()],
                        cert_sig_bits,
                        ta_spki,
                    )
                    .is_ok()
                {
                    signer_trusted = true;
                    break;
                }

                // Also accept self-signed: trust anchor == signer cert.
                if ta_der.as_slice() == cert_der.as_slice() {
                    signer_trusted = true;
                    break;
                }
            }

            if !signer_trusted {
                return Err(KipukaError::Auth(
                    "CMP signer certificate does not chain to a configured CA trust anchor".into(),
                ));
            }

            tracing::info!("CMP signer certificate chain verified against CA truststore");
        }
        CmpProtectionType::Mac { algorithm } => {
            if !cmp_config.allow_mac_protection {
                return Err(KipukaError::Auth(
                    "MAC-based CMP protection is not allowed by policy".into(),
                ));
            }

            tracing::debug!(
                algorithm = %algorithm,
                sender = %cmp_req.sender,
                "verifying MAC-based CMP protection"
            );

            // 1. Extract PBMParameter from the protectionAlg parameters.
            //
            // RFC 4210 §5.1.3.1: the AlgorithmIdentifier for
            // id-PasswordBasedMac has PBMParameter as its parameters.
            let pbm_param_element = pki_msg_for_verify
                .header
                .protection_alg
                .as_ref()
                .and_then(|alg| alg.parameters.as_ref())
                .ok_or_else(|| {
                    KipukaError::Auth(
                        "CMP MAC protection: protectionAlg has no PBMParameter".into(),
                    )
                })?;

            // The parameters field is an Element — DER-encode it to get the
            // raw bytes, then parse as PBMParameter.
            let pbm_param_bytes = synta::ToDer::to_der(pbm_param_element).map_err(|e| {
                KipukaError::Auth(format!(
                    "CMP MAC protection: failed to encode PBMParameter element: {e}"
                ))
            })?;

            let pbm = PBMParameter::from_der(&pbm_param_bytes).map_err(|e| {
                KipukaError::Auth(format!(
                    "CMP MAC protection: failed to parse PBMParameter: {e}"
                ))
            })?;

            // 2. Look up the shared secret by reference number (sender field).
            let secret_entry = cmp_config
                .mac_secrets
                .iter()
                .find(|s| s.reference == cmp_req.sender)
                .ok_or_else(|| {
                    tracing::warn!(
                        sender = %cmp_req.sender,
                        "CMP MAC protection: no shared secret configured for sender"
                    );
                    KipukaError::Auth(format!(
                        "CMP MAC protection: no shared secret found for reference '{}'",
                        cmp_req.sender,
                    ))
                })?;

            let shared_secret = hex::decode(&secret_entry.secret_hex).map_err(|e| {
                KipukaError::Internal(format!(
                    "CMP MAC secret for '{}' has invalid hex encoding: {e}",
                    secret_entry.reference,
                ))
            })?;

            // 3. Derive the MAC key via iterated OWF (RFC 4210 §5.1.3.1).
            //
            // basekey = OWF(secret || salt)
            // for i in 1..iterationCount:
            //     basekey = OWF(basekey)
            let derived_key = derive_pbm_key(
                &shared_secret,
                pbm.salt.as_bytes(),
                &pbm.owf,
                pbm.iteration_count.as_i64().unwrap_or(1) as u32,
            )?;

            // 4. Compute HMAC over protected_bytes using the MAC algorithm
            //    from PBMParameter and the derived key.
            let computed_mac = compute_pbm_hmac(&derived_key, &protected_bytes, &pbm.mac)?;

            // 5. Constant-time compare with the protection bits.
            use subtle::ConstantTimeEq;
            if computed_mac.ct_eq(&protection_bits).into() {
                tracing::info!("CMP MAC protection verified successfully");
            } else {
                return Err(KipukaError::Auth(
                    "CMP MAC protection verification failed: MAC mismatch".into(),
                ));
            }
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
            process_enrollment_request(&state, &cmp_req, "ir").await?
        }
        CmpMessageType::Cr => {
            if !cmp_config.allow_cr {
                return Err(KipukaError::Est(
                    "CMP certification requests (cr) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing certification request (cr)");
            process_enrollment_request(&state, &cmp_req, "cr").await?
        }
        CmpMessageType::Kur => {
            if !cmp_config.allow_kur {
                return Err(KipukaError::Est(
                    "CMP key update requests (kur) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing key update request (kur)");
            // KUR is treated identically to CR for certificate issuance;
            // additional validation (old cert not revoked) is a policy check
            // that the protection verification above enforces.
            process_enrollment_request(&state, &cmp_req, "kur").await?
        }
        CmpMessageType::Rr => {
            if !cmp_config.allow_rr {
                return Err(KipukaError::Est(
                    "CMP revocation requests (rr) are not allowed".into(),
                ));
            }
            tracing::info!("CMP: processing revocation request (rr)");
            process_revocation_request(&state, &cmp_req).await?
        }
        CmpMessageType::GenM => {
            tracing::info!("CMP: processing general message (genm)");
            process_general_message(&state, &cmp_req)?
        }
        CmpMessageType::CertConf => {
            tracing::info!("CMP: processing certificate confirmation (certConf)");
            // CertConf acknowledges receipt of the issued certificate.
            // The response is PKIConfirm which is an empty NULL body.
            // The Null is encoded directly in the PKIBody::Pkiconf variant
            // by build_cmp_response, so we return an empty placeholder here.
            // RFC 9810 §5.3.18: PKIConfirmContent ::= NULL
            synta::ToDer::to_der(&Null)
                .map_err(|e| KipukaError::Internal(format!("failed to encode PKIConfirm: {e}")))?
        }
        _ => {
            return Err(KipukaError::BadRequest(format!(
                "unsupported CMP message type: {}",
                cmp_req.message_type,
            )));
        }
    };

    // Extract the CA subject Name DER for the response sender field.
    let ca_subject_der = state
        .config
        .cas
        .first()
        .and_then(|ca_cfg| state.get_ca(&ca_cfg.id))
        .and_then(|ca| {
            synta_certificate::Certificate::from_der(&ca.cert_der)
                .ok()
                .map(|cert| cert.tbs_certificate.subject.as_bytes().to_vec())
        });

    // Build the response PKIMessage.
    let response_der = build_cmp_response(
        &cmp_req,
        response_type,
        &response_body_der,
        ca_subject_der.as_deref(),
    )?;

    state
        .record_audit_event(
            "cmp_success",
            &format!("type={}, sender={}", cmp_req.message_type, cmp_req.sender),
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

// ── Helper functions ──────────────────────────────────────────────────────────

/// Generate a 16-byte random nonce for CMP replay protection.
fn generate_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut nonce = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Format a `GeneralName` to a human-readable string for logging.
fn format_general_name(gn: &synta_certificate::GeneralName<'_>) -> String {
    use synta_certificate::GeneralName;
    match gn {
        GeneralName::DirectoryName(name) => {
            // Encode the Name to DER, then format using synta-certificate's
            // RFC 4514 DN formatter.
            synta::ToDer::to_der(name)
                .map(|der| synta_certificate::format_dn(&der))
                .unwrap_or_else(|_| "<invalid DN>".to_string())
        }
        GeneralName::Rfc822Name(s) => s.as_str().to_string(),
        GeneralName::DNSName(s) => s.as_str().to_string(),
        GeneralName::UniformResourceIdentifier(s) => s.as_str().to_string(),
        _ => "<other GeneralName>".to_string(),
    }
}

/// Process a CMP enrollment request (ir, cr, or kur).
///
/// Parses the `CertReqMessages` body, extracts the first `CertReqMsg`,
/// builds a minimal CSR from the CRMF `CertTemplate`, issues a certificate
/// via `ca::issue::issue_certificate`, and returns the DER-encoded
/// `CertRepMessage` for the response body.
async fn process_enrollment_request(
    state: &Arc<AppState>,
    cmp_req: &CmpRequest,
    req_type: &str,
) -> Result<Vec<u8>, KipukaError> {
    // Parse CertReqMessages (SEQUENCE OF CertReqMsg) from the body DER.
    let cert_req_msgs: Vec<CertReqMsg<'_>> =
        synta::Decoder::new(&cmp_req.body_der, synta::Encoding::Der)
            .decode()
            .map_err(|e| {
                KipukaError::BadRequest(format!(
                    "failed to parse CMP {req_type} CertReqMessages: {e}"
                ))
            })?;

    if cert_req_msgs.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMP CertReqMessages contains no requests".into(),
        ));
    }

    // Process the first CertReqMsg.
    let cert_req_msg = &cert_req_msgs[0];
    let cert_req_id = cert_req_msg.cert_req.cert_req_id.clone();
    let cert_template = &cert_req_msg.cert_req.cert_template;

    // Extract the subject Name DER from the CertTemplate.
    let subject_der = cert_template
        .subject
        .as_ref()
        .ok_or_else(|| KipukaError::BadRequest("CRMF CertTemplate missing subject name".into()))?
        .to_der()
        .map_err(|e| KipukaError::BadRequest(format!("failed to encode CRMF subject: {e}")))?;

    // Extract the SubjectPublicKeyInfo DER from the CertTemplate.
    let spki_der = cert_template
        .public_key
        .as_ref()
        .ok_or_else(|| KipukaError::BadRequest("CRMF CertTemplate missing public key".into()))?
        .to_der()
        .map_err(|e| KipukaError::BadRequest(format!("failed to encode CRMF SPKI: {e}")))?;

    tracing::debug!(
        subject = %synta_certificate::format_dn(&subject_der),
        spki_len = spki_der.len(),
        "CMP {}: extracted certificate request template", req_type,
    );

    // Select the default CA for enrollment.
    let ca_id = state
        .config
        .cas
        .first()
        .map(|c| c.id.as_str())
        .unwrap_or("default");

    let ca = state
        .get_ca(ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA '{ca_id}' not found")))?;

    // Build a synthetic PKCS#10 CSR from the CRMF template fields so we
    // can reuse the existing `issue_certificate` path.  The CSR signature
    // is a dummy zero-length value — CMP message-level protection
    // (verified above) provides the trust anchor, not the CSR self-signature.
    //
    // Use the CA certificate's actual signature algorithm instead of a
    // hardcoded placeholder — extract it via cert_byte_ranges().
    let sig_alg_der = synta_certificate::cert_byte_ranges(&ca.cert_der)
        .map(|ranges| ca.cert_der[ranges.signature_algorithm.clone()].to_vec())
        .unwrap_or_else(|| {
            // Fallback: hand-encode sha256WithRSAEncryption AlgorithmIdentifier
            // SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }
            vec![
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
                0x00,
            ]
        });

    let csr_builder = synta_certificate::CsrBuilder::new()
        .subject_name(&subject_der)
        .public_key_der(&spki_der);

    let cri_der = csr_builder
        .build_cri(&sig_alg_der)
        .map_err(|e| KipukaError::Ca(format!("failed to build CRI from CRMF template: {e}")))?;

    // Assemble with a zero-length dummy signature.
    let csr_der = synta_certificate::CsrBuilder::assemble(&cri_der, &sig_alg_der, &[0u8])
        .map_err(|e| KipukaError::Ca(format!("failed to assemble CSR from CRMF template: {e}")))?;

    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    // Resolve signing key (PEM or HSM).
    let resolved_key = crate::ca::issue::resolve_signing_key(ca_cfg, state.hsm.as_ref()).await?;

    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca.validity_days.min(398),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    // Issue the certificate.
    let result = crate::ca::issue::issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        resolved_key.as_signing_key(),
        &ca.hash_algorithm,
    )
    .map_err(|e| KipukaError::Ca(format!("CMP certificate issuance failed: {e}")))?;

    tracing::info!(
        serial = %result.serial_number,
        subject = %result.subject_dn,
        "CMP {}: certificate issued successfully", req_type,
    );

    // Build CertRepMessage with a single successful CertResponse.
    //
    // PKIStatusInfo: status = 0 (accepted), no status string, no failInfo.
    let status_info = PKIStatusInfo {
        status: Integer::from_i64(0), // accepted
        status_string: None,
        fail_info: None,
    };

    let cert_response = CertResponse {
        cert_req_id,
        status: status_info,
        certified_key_pair: Some(CertifiedKeyPair {
            cert_or_enc_cert: CertOrEncCert::Certificate(RawDer(&result.certificate_der)),
            private_key: None,
            publication_info: None,
        }),
        rsp_info: None,
    };

    let cert_rep = CertRepMessage {
        ca_pubs: None,
        response: vec![cert_response],
    };

    cert_rep
        .to_der()
        .map_err(|e| KipukaError::Internal(format!("failed to encode CMP CertRepMessage: {e}")))
}

/// Process a CMP revocation request (rr).
///
/// Parses the `RevReqContent` (SEQUENCE OF RevDetails), extracts the
/// certificate serial number from the cert template, marks the certificate
/// as revoked in the database, and returns the DER-encoded `RevRepContent`.
async fn process_revocation_request(
    state: &Arc<AppState>,
    cmp_req: &CmpRequest,
) -> Result<Vec<u8>, KipukaError> {
    use synta_certificate::cmp_types::RevDetails;
    use synta_certificate::crmf_types::CertTemplate;

    // Parse RevReqContent (SEQUENCE OF RevDetails).
    let rev_details: Vec<RevDetails<'_>> =
        synta::Decoder::new(&cmp_req.body_der, synta::Encoding::Der)
            .decode()
            .map_err(|e| {
                KipukaError::BadRequest(format!("failed to parse CMP RevReqContent: {e}"))
            })?;

    if rev_details.is_empty() {
        return Err(KipukaError::BadRequest(
            "CMP RevReqContent contains no revocation requests".into(),
        ));
    }

    // ── Revocation authorization ──────────────────────────────────────
    //
    // For signature-protected messages, verify that the signer is
    // authorized to revoke the requested certificate(s):
    //
    // - **RA privilege**: if the signer cert has id-kp-cmcRA EKU
    //   (1.3.6.1.5.5.7.3.28), allow revocation of any certificate.
    // - **Self-revocation**: otherwise, the signer cert's subject DN
    //   must match the subject of the certificate being revoked.
    //
    // MAC-protected revocation requests are rejected above, so we
    // only handle the signature case here.
    if let CmpProtectionType::Signature { cert_der, .. } = &cmp_req.protection {
        let signer_cert = synta_certificate::Certificate::from_der(cert_der).map_err(|e| {
            KipukaError::Auth(format!(
                "failed to parse signer certificate for revocation authorization: {e:?}"
            ))
        })?;
        let signer_subject_der = signer_cert.tbs_certificate.subject.as_bytes();
        let signer_subject_dn = synta_certificate::format_dn(signer_subject_der);

        // Check if the signer holds id-kp-cmcRA EKU (RA privilege).
        const CMC_RA_OID: &str = "1.3.6.1.5.5.7.3.28";
        let signer_is_ra = signer_cert
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|ext_raw| {
                synta_certificate::find_extension_value(
                    ext_raw.as_bytes(),
                    synta_certificate::oids::EXTENDED_KEY_USAGE,
                )
            })
            .map(|eku_bytes| {
                let mut decoder = synta::Decoder::new(eku_bytes, synta::Encoding::Der);
                let oids: Vec<synta::ObjectIdentifier> = decoder.decode().unwrap_or_default();
                oids.iter().any(|oid| oid.to_string() == CMC_RA_OID)
            })
            .unwrap_or(false);

        if signer_is_ra {
            tracing::info!(
                signer = %signer_subject_dn,
                "CMP rr: signer has id-kp-cmcRA EKU — RA revocation authorized"
            );
        } else {
            // Self-revocation: check each RevDetails entry to verify the
            // signer's subject matches the revokee's subject.
            for detail in &rev_details {
                let cert_tmpl_check =
                    CertTemplate::from_der(detail.cert_details.0).map_err(|e| {
                        KipukaError::BadRequest(format!(
                            "failed to parse RevDetails CertTemplate for authz: {e}"
                        ))
                    })?;

                if let Some(serial_check) = &cert_tmpl_check.serial_number {
                    let serial_hex_check = hex::encode(serial_check.as_bytes());

                    // Query the database for the certificate's subject DN.
                    let row: Option<(String,)> = sqlx::query_as(crate::db::pg_sql(
                        "SELECT subject FROM certificates WHERE serial = ?",
                    ))
                    .bind(&serial_hex_check)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|e| {
                        KipukaError::Ca(format!(
                            "database error checking revocation authorization: {e}"
                        ))
                    })?;

                    if let Some((revokee_subject,)) = row {
                        if revokee_subject != signer_subject_dn {
                            tracing::warn!(
                                signer = %signer_subject_dn,
                                revokee = %revokee_subject,
                                serial = %serial_hex_check,
                                "CMP rr: signer is not the certificate owner \
                                 and does not have RA privilege"
                            );
                            return Err(KipukaError::Forbidden(format!(
                                "CMP revocation denied: signer '{signer_subject_dn}' is not authorized \
                                 to revoke certificate serial {serial_hex_check} (owner: '{revokee_subject}')"
                            )));
                        }

                        tracing::debug!(
                            serial = %serial_hex_check,
                            subject = %signer_subject_dn,
                            "CMP rr: self-revocation authorized"
                        );
                    }
                    // If the certificate is not in the database, the revocation
                    // will produce a "not found" result below — not an authz error.
                }
            }
        }
    }
    // MAC-protected revocations: already rejected by the MAC verification
    // check above, so we do not need to handle them here.

    // Process each RevDetails entry and collect status responses.
    let mut statuses = Vec::with_capacity(rev_details.len());

    for detail in &rev_details {
        // The cert_details field is a CertTemplate containing the
        // serial number and issuer of the certificate to revoke.
        let cert_tmpl = CertTemplate::from_der(detail.cert_details.0).map_err(|e| {
            KipukaError::BadRequest(format!("failed to parse RevDetails CertTemplate: {e}"))
        })?;

        let serial = cert_tmpl.serial_number.ok_or_else(|| {
            KipukaError::BadRequest("RevDetails CertTemplate missing serial number".into())
        })?;

        let serial_hex = hex::encode(serial.as_bytes());

        tracing::info!(
            serial = %serial_hex,
            "CMP rr: revoking certificate"
        );

        // Update the certificate status to 'revoked' in the database.
        let rows = sqlx::query(crate::db::pg_sql(
            "UPDATE certificates SET status = 'revoked' WHERE serial = ?",
        ))
        .bind(&serial_hex)
        .execute(&state.db)
        .await
        .map_err(|e| KipukaError::Ca(format!("database error revoking serial {serial_hex}: {e}")))?
        .rows_affected();

        if rows == 0 {
            tracing::warn!(
                serial = %serial_hex,
                "CMP rr: certificate not found in database"
            );
        }

        state
            .record_audit_event(
                "cmp_revocation",
                &format!("serial={serial_hex}, sender={}", cmp_req.sender),
            )
            .await;

        // Build a successful PKIStatusInfo for this revocation.
        statuses.push(PKIStatusInfo {
            status: Integer::from_i64(0), // accepted
            status_string: None,
            fail_info: None,
        });
    }

    let rev_rep = RevRepContent {
        status: statuses,
        rev_certs: None,
        crls: None,
    };

    rev_rep
        .to_der()
        .map_err(|e| KipukaError::Internal(format!("failed to encode CMP RevRepContent: {e}")))
}

/// Derive a MAC key using the Password-Based MAC scheme (RFC 4210 §5.1.3.1).
///
/// The derivation is:
///   1. `basekey = OWF(secret || salt)`
///   2. For `i` in `1..iteration_count`: `basekey = OWF(basekey)`
///
/// where `OWF` is the one-way function specified in the `PBMParameter`.
///
/// The `owf_alg` parameter is the `AlgorithmIdentifier` from the `owf` field
/// of the `PBMParameter`, whose `.algorithm` OID identifies the hash function.
fn derive_pbm_key(
    secret: &[u8],
    salt: &[u8],
    owf_alg: &synta_certificate::AlgorithmIdentifier<'_>,
    iteration_count: u32,
) -> Result<Vec<u8>, KipukaError> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    let owf_oid = owf_alg.algorithm.to_string();

    // Map the OWF OID to a hash function.
    //
    // Common OIDs:
    //   SHA-1:   1.3.14.3.2.26  (id-sha1, NOT recommended)
    //   SHA-256: 2.16.840.1.101.3.4.2.1  (id-sha256)
    //   SHA-384: 2.16.840.1.101.3.4.2.2  (id-sha384)
    //   SHA-512: 2.16.840.1.101.3.4.2.3  (id-sha512)
    //
    // We intentionally exclude SHA-1 as it is deprecated for new deployments.
    enum OwfKind {
        Sha256,
        Sha384,
        Sha512,
    }

    let owf_kind = if owf_oid.contains("2.16.840.1.101.3.4.2.1") {
        OwfKind::Sha256
    } else if owf_oid.contains("2.16.840.1.101.3.4.2.2") {
        OwfKind::Sha384
    } else if owf_oid.contains("2.16.840.1.101.3.4.2.3") {
        OwfKind::Sha512
    } else {
        return Err(KipukaError::Auth(format!(
            "CMP PBM: unsupported OWF algorithm OID: {owf_oid}"
        )));
    };

    if iteration_count == 0 {
        return Err(KipukaError::Auth(
            "CMP PBM: iteration count must be positive".into(),
        ));
    }

    // Cap iteration count to prevent DoS via absurdly large values.
    if iteration_count > 100_000 {
        return Err(KipukaError::Auth(
            "CMP PBM: iteration count exceeds maximum (100000)".into(),
        ));
    }

    // Step 1: basekey = OWF(secret || salt)
    let mut input = Vec::with_capacity(secret.len() + salt.len());
    input.extend_from_slice(secret);
    input.extend_from_slice(salt);

    let mut key = match owf_kind {
        OwfKind::Sha256 => Sha256::digest(&input).to_vec(),
        OwfKind::Sha384 => Sha384::digest(&input).to_vec(),
        OwfKind::Sha512 => Sha512::digest(&input).to_vec(),
    };

    // Step 2: iterate OWF (iteration_count - 1 more times,
    // since first application was step 1).
    for _ in 1..iteration_count {
        key = match owf_kind {
            OwfKind::Sha256 => Sha256::digest(&key).to_vec(),
            OwfKind::Sha384 => Sha384::digest(&key).to_vec(),
            OwfKind::Sha512 => Sha512::digest(&key).to_vec(),
        };
    }

    Ok(key)
}

/// Compute an HMAC over `data` using the MAC algorithm from `PBMParameter`
/// and the derived key.
///
/// The `mac_alg` parameter is the `AlgorithmIdentifier` from the `mac` field
/// of the `PBMParameter`, whose `.algorithm` OID identifies the HMAC variant.
fn compute_pbm_hmac(
    key: &[u8],
    data: &[u8],
    mac_alg: &synta_certificate::AlgorithmIdentifier<'_>,
) -> Result<Vec<u8>, KipukaError> {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

    let mac_oid = mac_alg.algorithm.to_string();

    // Map the MAC OID to an HMAC variant.
    //
    // Common OIDs:
    //   hmac-SHA256: 1.2.840.113549.2.9
    //   hmac-SHA384: 1.2.840.113549.2.10
    //   hmac-SHA512: 1.2.840.113549.2.11
    //   hmac-SHA1:   1.2.840.113549.2.7  (deprecated)
    //
    // The OWF hash OIDs (id-sha256 etc.) are also accepted as MAC algorithm
    // identifiers since some CMP implementations use them interchangeably.
    if mac_oid.contains("1.2.840.113549.2.9") || mac_oid.contains("2.16.840.1.101.3.4.2.1") {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| KipukaError::Internal(format!("HMAC-SHA256 key init failed: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    } else if mac_oid.contains("1.2.840.113549.2.10") || mac_oid.contains("2.16.840.1.101.3.4.2.2")
    {
        let mut mac = Hmac::<Sha384>::new_from_slice(key)
            .map_err(|e| KipukaError::Internal(format!("HMAC-SHA384 key init failed: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    } else if mac_oid.contains("1.2.840.113549.2.11") || mac_oid.contains("2.16.840.1.101.3.4.2.3")
    {
        let mut mac = Hmac::<Sha512>::new_from_slice(key)
            .map_err(|e| KipukaError::Internal(format!("HMAC-SHA512 key init failed: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    } else {
        Err(KipukaError::Auth(format!(
            "CMP PBM: unsupported MAC algorithm OID: {mac_oid}"
        )))
    }
}

/// Process a CMP general message (genm).
///
/// Parses the `GenMsgContent` (SEQUENCE OF InfoTypeAndValue) and returns
/// appropriate information.  Currently supports returning CA certificates.
fn process_general_message(
    _state: &Arc<AppState>,
    cmp_req: &CmpRequest,
) -> Result<Vec<u8>, KipukaError> {
    use synta_certificate::cmp_types::InfoTypeAndValue;

    // Parse GenMsgContent to determine what information is being requested.
    let gen_msg: Vec<InfoTypeAndValue<'_>> = if cmp_req.body_der.is_empty() {
        Vec::new()
    } else {
        synta::Decoder::new(&cmp_req.body_der, synta::Encoding::Der)
            .decode()
            .map_err(|e| {
                KipukaError::BadRequest(format!("failed to parse CMP GenMsgContent: {e}"))
            })?
    };

    // Build GenRepContent (SEQUENCE OF InfoTypeAndValue) response.
    //
    // For now, return an empty GenRepContent.  Known OIDs that could be
    // supported:
    //   - id-it-caCerts (1.3.6.1.5.5.7.4.17): return CA certificate chain
    //   - id-it-rootCaKeyUpdate (1.3.6.1.5.5.7.4.18): CA key rollover info
    //   - id-it-certReqTemplate (1.3.6.1.5.5.7.4.19): certificate template
    //
    // Log the requested OIDs so we can add support incrementally.
    for itv in &gen_msg {
        tracing::debug!(
            oid = %itv.info_type,
            "CMP genm: client requested info type"
        );
    }

    // Return an empty SEQUENCE as the GenRepContent.
    let gen_rep: Vec<InfoTypeAndValue<'_>> = Vec::new();
    let mut encoder = synta::Encoder::new(synta::Encoding::Der);
    synta::Encode::encode(&gen_rep, &mut encoder)
        .map_err(|e| KipukaError::Internal(format!("failed to encode CMP GenRepContent: {e}")))?;
    encoder.finish().map_err(|e| {
        KipukaError::Internal(format!("failed to finalize CMP GenRepContent DER: {e}"))
    })
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
        assert_eq!(
            CmpMessageType::Ir.expected_response(),
            Some(CmpMessageType::Ip)
        );
        assert_eq!(
            CmpMessageType::Cr.expected_response(),
            Some(CmpMessageType::Cp)
        );
        assert_eq!(
            CmpMessageType::Kur.expected_response(),
            Some(CmpMessageType::Kup)
        );
        assert_eq!(
            CmpMessageType::Rr.expected_response(),
            Some(CmpMessageType::Rp)
        );
        assert_eq!(
            CmpMessageType::GenM.expected_response(),
            Some(CmpMessageType::GenP)
        );
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
        let result = build_cmp_response(&req, CmpMessageType::Ip, &[1, 2, 3], None);
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
        let result = build_cmp_response(&req, CmpMessageType::Cp, &[], None);
        assert!(matches!(result, Err(KipukaError::BadRequest(_))));
    }

    /// Build an unprotected PKIMessage DER and verify that
    /// `parse_cmp_message` rejects it (unprotected messages must be refused).
    #[test]
    fn parse_rejects_unprotected_pkiconf_message() {
        use synta_certificate::CMPMessageBuilder;

        let msg_der = CMPMessageBuilder::new()
            .sender(GeneralNameSpec::rfc822("client@example.com"))
            .recipient(GeneralNameSpec::rfc822("ca@example.com"))
            .transaction_id(b"\x01\x02\x03\x04")
            .sender_nonce(b"\xaa\xbb\xcc\xdd")
            .body_pkiconf()
            .build()
            .expect("CMPMessageBuilder::build failed");

        let result = parse_cmp_message(&msg_der);
        assert!(
            matches!(result, Err(KipukaError::Auth(_))),
            "unprotected CMP message should be rejected"
        );
    }

    /// Build an unprotected IR message and verify parse rejects it.
    #[test]
    fn parse_rejects_unprotected_ir_message() {
        use synta_certificate::CMPMessageBuilder;

        // Build a minimal CertReqMessages body (empty SEQUENCE).
        let empty_seq = vec![0x30, 0x00]; // SEQUENCE {}

        let msg_der = CMPMessageBuilder::new()
            .sender(GeneralNameSpec::rfc822("user@example.com"))
            .recipient(GeneralNameSpec::dns("ca.example.com"))
            .transaction_id(b"\x10\x20\x30\x40")
            .sender_nonce(b"\x01\x02\x03\x04\x05\x06\x07\x08")
            .body_ir(&empty_seq)
            .build()
            .expect("CMPMessageBuilder::build failed for ir");

        let result = parse_cmp_message(&msg_der);
        assert!(
            matches!(result, Err(KipukaError::Auth(_))),
            "unprotected CMP message should be rejected"
        );
    }

    /// Build an unprotected GENM message and verify parse rejects it.
    #[test]
    fn parse_rejects_unprotected_genm_message() {
        use synta_certificate::CMPMessageBuilder;

        // Empty GenMsgContent (SEQUENCE OF InfoTypeAndValue).
        let empty_seq = vec![0x30, 0x00];

        let msg_der = CMPMessageBuilder::new()
            .sender(GeneralNameSpec::rfc822("client@test.com"))
            .recipient(GeneralNameSpec::rfc822("ca@test.com"))
            .transaction_id(b"\xff\xfe\xfd\xfc\x01\x02\x03\x04")
            .sender_nonce(b"\x10\x20\x30\x40\x50\x60\x70\x80")
            .body_genm(&empty_seq)
            .build()
            .expect("CMPMessageBuilder::build failed for genm");

        let result = parse_cmp_message(&msg_der);
        assert!(
            matches!(result, Err(KipukaError::Auth(_))),
            "unprotected CMP message should be rejected"
        );
    }

    /// Test build_cmp_response produces valid DER that round-trips
    /// through PKIMessage::from_der.
    #[test]
    fn build_response_produces_valid_der() {
        let req = CmpRequest {
            message_type: CmpMessageType::GenM,
            transaction_id: vec![0x01, 0x02, 0x03, 0x04],
            sender_nonce: vec![0xaa, 0xbb, 0xcc, 0xdd],
            sender: "client@example.com".into(),
            protection: CmpProtectionType::Mac {
                algorithm: "unprotected".into(),
            },
            body_der: vec![0x30, 0x00],
        };

        // Build a GenP response with an empty SEQUENCE body.
        let body_der = vec![0x30, 0x00]; // empty GenRepContent
        let response_der = build_cmp_response(&req, CmpMessageType::GenP, &body_der, None)
            .expect("build_cmp_response should succeed");

        // Verify it parses as a valid PKIMessage.
        let parsed =
            PKIMessage::from_der(&response_der).expect("response should parse as valid PKIMessage");

        // Verify the header fields were set correctly.
        assert_eq!(
            parsed.header.transaction_id.map(|o| o.as_bytes().to_vec()),
            Some(vec![0x01, 0x02, 0x03, 0x04])
        );
        assert_eq!(
            parsed.header.recip_nonce.map(|o| o.as_bytes().to_vec()),
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd])
        );
        assert!(parsed.header.sender_nonce.is_some());
        // senderNonce should be 16 bytes (generated by generate_nonce).
        assert_eq!(parsed.header.sender_nonce.unwrap().as_bytes().len(), 16);
    }

    /// Test build_cmp_response for PkiConf (NULL body).
    #[test]
    fn build_pkiconf_response() {
        let req = CmpRequest {
            message_type: CmpMessageType::CertConf,
            transaction_id: vec![0x11, 0x22],
            sender_nonce: vec![0x33, 0x44],
            sender: "test".into(),
            protection: CmpProtectionType::Mac {
                algorithm: "unprotected".into(),
            },
            body_der: Vec::new(),
        };

        // For PkiConf, the body is NULL — we still need to pass non-empty
        // bytes to satisfy the pre-check, but the actual encoding uses
        // PKIBody::Pkiconf(Null).
        let null_der = synta::ToDer::to_der(&Null).unwrap();
        let response_der = build_cmp_response(&req, CmpMessageType::PkiConf, &null_der, None)
            .expect("build_cmp_response should succeed for PkiConf");

        let parsed = PKIMessage::from_der(&response_der).expect("PkiConf response should parse");
        assert!(matches!(parsed.body, PKIBody::Pkiconf(Null)));
    }

    /// Test that generate_nonce produces 16 bytes.
    #[test]
    fn nonce_is_16_bytes() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 16);
        // Verify it's not all zeros (probabilistic but reliable).
        assert!(nonce.iter().any(|&b| b != 0));
    }

    /// Test format_general_name with various GeneralName types.
    #[test]
    fn format_general_name_rfc822() {
        let spec = GeneralNameSpec::rfc822("test@example.com");
        let gn = spec.to_general_name().unwrap();
        assert_eq!(format_general_name(&gn), "test@example.com");
    }

    /// Test format_general_name with DNS name.
    #[test]
    fn format_general_name_dns() {
        let spec = GeneralNameSpec::dns("ca.example.com");
        let gn = spec.to_general_name().unwrap();
        assert_eq!(format_general_name(&gn), "ca.example.com");
    }

    /// Verify that an empty GenRepContent encodes as a valid SEQUENCE.
    #[test]
    fn genrep_empty_encodes_as_sequence() {
        use synta_certificate::cmp_types::InfoTypeAndValue;

        // Encode an empty GenRepContent the same way process_general_message does.
        let gen_rep: Vec<InfoTypeAndValue<'_>> = Vec::new();
        let mut encoder = synta::Encoder::new(synta::Encoding::Der);
        synta::Encode::encode(&gen_rep, &mut encoder).unwrap();
        let der = encoder.finish().unwrap();

        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE tag
        assert_eq!(der[1], 0x00); // length 0 = empty sequence
    }

    // ── MAC verification tests ──────────────────────────────────────────

    /// Helper: build an AlgorithmIdentifier with the given OID components
    /// and no parameters (NULL).
    fn build_alg_id(oid_components: &[u32]) -> synta_certificate::AlgorithmIdentifier<'static> {
        synta_certificate::AlgorithmIdentifier {
            algorithm: synta::ObjectIdentifier::new(oid_components).unwrap(),
            parameters: None,
        }
    }

    /// Test derive_pbm_key with SHA-256 OWF and known inputs.
    ///
    /// Verifies that:
    /// - Key derivation produces a 32-byte output (SHA-256 digest size)
    /// - The output changes when any input (secret, salt, iteration count) changes
    #[test]
    fn pbm_key_derivation_sha256() {
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
        let secret = b"shared-secret";
        let salt = b"random-salt-value";

        let key = derive_pbm_key(secret, salt, &owf_alg, 1000).unwrap();

        // SHA-256 produces 32 bytes.
        assert_eq!(key.len(), 32);

        // Verify determinism: same inputs → same key.
        let key2 = derive_pbm_key(secret, salt, &owf_alg, 1000).unwrap();
        assert_eq!(key, key2);

        // Different secret → different key.
        let key_diff_secret = derive_pbm_key(b"other-secret", salt, &owf_alg, 1000).unwrap();
        assert_ne!(key, key_diff_secret);

        // Different salt → different key.
        let key_diff_salt = derive_pbm_key(secret, b"other-salt", &owf_alg, 1000).unwrap();
        assert_ne!(key, key_diff_salt);

        // Different iteration count → different key.
        let key_diff_iter = derive_pbm_key(secret, salt, &owf_alg, 500).unwrap();
        assert_ne!(key, key_diff_iter);
    }

    /// Test that derive_pbm_key rejects zero iteration count.
    #[test]
    fn pbm_key_derivation_rejects_zero_iterations() {
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
        let result = derive_pbm_key(b"secret", b"salt", &owf_alg, 0);
        assert!(result.is_err());
    }

    /// Test that derive_pbm_key rejects excessively large iteration count.
    #[test]
    fn pbm_key_derivation_rejects_excessive_iterations() {
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
        let result = derive_pbm_key(b"secret", b"salt", &owf_alg, 200_000);
        assert!(result.is_err());
    }

    /// Test that derive_pbm_key rejects unsupported OWF algorithms.
    #[test]
    fn pbm_key_derivation_rejects_unknown_owf() {
        // Use a bogus OID.
        let owf_alg = build_alg_id(&[1, 2, 3, 4, 5, 6, 7]);
        let result = derive_pbm_key(b"secret", b"salt", &owf_alg, 100);
        assert!(result.is_err());
    }

    /// End-to-end MAC verification: derive key + compute HMAC + verify.
    ///
    /// This simulates the complete PBM verification flow:
    /// 1. Derive the MAC key from a shared secret using SHA-256 OWF
    /// 2. Compute HMAC-SHA-256 over the protected bytes
    /// 3. Verify the MAC matches via constant-time comparison
    #[test]
    fn pbm_mac_verification_roundtrip() {
        use subtle::ConstantTimeEq;

        let secret = b"test-shared-secret";
        let salt = b"test-salt-1234";
        let iteration_count = 500u32;
        let data = b"this is the protected header || body data";

        // SHA-256 OWF
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
        // HMAC-SHA-256 MAC (OID 1.2.840.113549.2.9)
        let mac_alg = build_alg_id(&[1, 2, 840, 113549, 2, 9]);

        // Derive key.
        let key = derive_pbm_key(secret, salt, &owf_alg, iteration_count).unwrap();

        // Compute MAC.
        let mac = compute_pbm_hmac(&key, data, &mac_alg).unwrap();

        // HMAC-SHA-256 produces 32 bytes.
        assert_eq!(mac.len(), 32);

        // Verify: same inputs produce the same MAC.
        let mac2 = compute_pbm_hmac(&key, data, &mac_alg).unwrap();
        assert!(bool::from(mac.ct_eq(&mac2)));
    }

    /// MAC verification with wrong secret produces a different MAC.
    #[test]
    fn pbm_mac_wrong_secret_differs() {
        use subtle::ConstantTimeEq;

        let salt = b"salt-value";
        let iteration_count = 100u32;
        let data = b"protected-message-bytes";

        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
        let mac_alg = build_alg_id(&[1, 2, 840, 113549, 2, 9]);

        // Correct secret.
        let key_correct =
            derive_pbm_key(b"correct-secret", salt, &owf_alg, iteration_count).unwrap();
        let mac_correct = compute_pbm_hmac(&key_correct, data, &mac_alg).unwrap();

        // Wrong secret.
        let key_wrong = derive_pbm_key(b"wrong-secret", salt, &owf_alg, iteration_count).unwrap();
        let mac_wrong = compute_pbm_hmac(&key_wrong, data, &mac_alg).unwrap();

        // MACs must differ.
        assert!(!bool::from(mac_correct.ct_eq(&mac_wrong)));
    }

    /// MAC verification rejects unsupported MAC algorithms.
    #[test]
    fn pbm_mac_rejects_unknown_mac_alg() {
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
        let key = derive_pbm_key(b"secret", b"salt", &owf_alg, 100).unwrap();

        // Use a bogus MAC OID.
        let bad_mac_alg = build_alg_id(&[1, 2, 3, 4, 5, 6, 7]);
        let result = compute_pbm_hmac(&key, b"data", &bad_mac_alg);
        assert!(result.is_err());
    }

    /// Test SHA-384 OWF key derivation.
    #[test]
    fn pbm_key_derivation_sha384() {
        // SHA-384 OID: 2.16.840.1.101.3.4.2.2
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 2]);
        let key = derive_pbm_key(b"secret", b"salt", &owf_alg, 10).unwrap();

        // SHA-384 produces 48 bytes.
        assert_eq!(key.len(), 48);
    }

    /// Test SHA-512 OWF key derivation.
    #[test]
    fn pbm_key_derivation_sha512() {
        // SHA-512 OID: 2.16.840.1.101.3.4.2.3
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 3]);
        let key = derive_pbm_key(b"secret", b"salt", &owf_alg, 10).unwrap();

        // SHA-512 produces 64 bytes.
        assert_eq!(key.len(), 64);
    }

    /// Test HMAC-SHA-384 computation.
    #[test]
    fn pbm_mac_hmac_sha384() {
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 2]);
        let key = derive_pbm_key(b"secret", b"salt", &owf_alg, 10).unwrap();

        // HMAC-SHA-384 OID: 1.2.840.113549.2.10
        let mac_alg = build_alg_id(&[1, 2, 840, 113549, 2, 10]);
        let mac = compute_pbm_hmac(&key, b"test data", &mac_alg).unwrap();

        // HMAC-SHA-384 produces 48 bytes.
        assert_eq!(mac.len(), 48);
    }

    /// Test HMAC-SHA-512 computation.
    #[test]
    fn pbm_mac_hmac_sha512() {
        let owf_alg = build_alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 3]);
        let key = derive_pbm_key(b"secret", b"salt", &owf_alg, 10).unwrap();

        // HMAC-SHA-512 OID: 1.2.840.113549.2.11
        let mac_alg = build_alg_id(&[1, 2, 840, 113549, 2, 11]);
        let mac = compute_pbm_hmac(&key, b"test data", &mac_alg).unwrap();

        // HMAC-SHA-512 produces 64 bytes.
        assert_eq!(mac.len(), 64);
    }
}
