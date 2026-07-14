//! GSSAPI/Kerberos authentication for EST endpoints.
//!
//! Implements the `Authorization: Negotiate` (SPNEGO) authentication
//! mechanism, following the same pattern as Akamu's GSSAPI support.
//!
//! When the `gssapi` feature is enabled, Kerberos tickets are
//! cryptographically verified via the system's GSS-API library
//! (`libgssapi` crate wrapping `libgssapi_krb5.so`).  Without the
//! feature, only structural parsing of the SPNEGO token is available
//! (extracting the service name from the cleartext ticket fields).
//!
//! Channel binding to the TLS session (tls-server-end-point, RFC 5929)
//! is supported to prevent credential forwarding attacks.

use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use tracing::{debug, warn};

use super::{AuthMethod, AuthResult};
use crate::state::AppState;

/// Request extension carrying the GSSAPI mutual-auth output token.
///
/// When `gss_accept_sec_context` produces an output token (i.e., the
/// client requested mutual authentication), this extension is inserted
/// into the request so handlers can include it in the response.
///
/// The inner [`HeaderValue`] is pre-formatted as `"Negotiate <base64>"`.
#[derive(Clone)]
pub struct NegotiateOutToken(pub HeaderValue);

/// TLS channel binding data (tls-server-end-point, RFC 5929).
///
/// Injected into request extensions by the TLS accept loop.  Used to
/// bind the GSSAPI context to the TLS session, preventing relay attacks.
#[derive(Clone)]
pub struct TlsChannelBinding(pub Vec<u8>);

/// Attempt to extract and validate GSSAPI/SPNEGO credentials.
///
/// Returns:
/// - `Some(Ok(AuthResult))` — GSSAPI authentication succeeded
/// - `Some(Err(Response))` — Negotiate header present but invalid (401/403)
/// - `None` — no Negotiate header present (try next auth method)
pub async fn try_extract_gssapi(
    parts: &mut Parts,
    app: &Arc<AppState>,
) -> Option<Result<AuthResult, Response>> {
    let auth_header = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;

    // Only handle Negotiate tokens; Basic is handled by the OTP module.
    let token_b64 = auth_header.strip_prefix("Negotiate ")?;

    // Check that GSSAPI is configured.
    let gss_cred = match app.gss_cred.as_ref() {
        Some(cred) => Arc::clone(cred),
        None => {
            debug!("Negotiate header present but GSSAPI not configured");
            return Some(Err((
                StatusCode::UNAUTHORIZED,
                "GSSAPI is not configured on this server",
            )
                .into_response()));
        }
    };

    // Safety gate: reject structural-only parsing when crypto verification
    // is required (the default) AND the `gssapi` feature is not compiled in.
    // When the `gssapi` feature IS enabled, we use the real GSS-API library
    // to verify tickets cryptographically, so no gate is needed.
    #[cfg(not(feature = "gssapi"))]
    if app.gssapi_require_crypto {
        warn!(
            "GSSAPI authentication rejected: `require_crypto_verification` is true (the default) \
             but the `gssapi` feature is not compiled in.  Structural parsing of Kerberos tokens \
             cannot verify client identity.  Either compile with `--features gssapi` or set \
             `require_crypto_verification = false` in [admin.gssapi] for development/logging."
        );
        return Some(Err((
            StatusCode::FORBIDDEN,
            "GSSAPI authentication requires the `gssapi` feature; \
             structural-only parsing is disabled by default",
        )
            .into_response()));
    }

    // Decode the base64 SPNEGO token.
    let token_bytes = match base64::engine::general_purpose::STANDARD.decode(token_b64) {
        Ok(t) => t,
        Err(_) => {
            return Some(Err((
                StatusCode::BAD_REQUEST,
                "malformed Negotiate token encoding",
            )
                .into_response()));
        }
    };

    // Reject oversized tokens (128 KiB limit, matching Akamu).
    const MAX_TOKEN_BYTES: usize = 128 * 1024;
    if token_bytes.len() > MAX_TOKEN_BYTES {
        return Some(Err((
            StatusCode::BAD_REQUEST,
            "Negotiate token exceeds size limit",
        )
            .into_response()));
    }

    // Extract TLS channel binding data for tls-server-end-point binding.
    let channel_binding: Option<Vec<u8>> = parts
        .extensions
        .get::<TlsChannelBinding>()
        .map(|b| b.0.clone());

    // Use spawn_blocking for the synchronous GSSAPI FFI call so we do not
    // block a tokio worker thread.
    let binding_owned = channel_binding;
    let token_owned = token_bytes;
    let require_crypto = app.gssapi_require_crypto;
    let result = tokio::task::spawn_blocking(move || {
        negotiate_accept(
            gss_cred.as_ref(),
            &token_owned,
            binding_owned.as_deref(),
            require_crypto,
        )
    })
    .await;

    let negotiate_result = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "GSSAPI spawn_blocking panicked");
            return Some(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()));
        }
    };

    match negotiate_result {
        Ok(NegotiateSuccess {
            principal,
            out_token,
        }) => {
            debug!(principal = %principal, "GSSAPI authentication succeeded");

            // Store the output token (if any) for mutual authentication.
            if !out_token.is_empty() {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&out_token);
                if let Ok(hv) = HeaderValue::from_str(&format!("Negotiate {b64}")) {
                    parts.extensions.insert(NegotiateOutToken(hv));
                }
            }

            Some(Ok(AuthResult {
                identity: principal,
                method: AuthMethod::Gssapi,
                client_cert_der: None,
                subject_dn: None,
                subject_alt_names: Vec::new(),
                extended_key_usage: Vec::new(),
            }))
        }
        Err(NegotiateError::Continue(out_token)) => {
            // Multi-leg SPNEGO: return 401 with continuation token.
            let b64 = base64::engine::general_purpose::STANDARD.encode(&out_token);
            let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
            if let Ok(hv) = HeaderValue::from_str(&format!("Negotiate {b64}")) {
                resp.headers_mut().insert("WWW-Authenticate", hv);
            }
            Some(Err(resp))
        }
        Err(NegotiateError::Failed(msg)) => {
            warn!(error = %msg, "GSSAPI authentication failed");
            Some(Err(
                (StatusCode::FORBIDDEN, "GSSAPI authentication failed").into_response()
            ))
        }
    }
}

/// Build a 401 response with a `WWW-Authenticate: Negotiate` challenge.
///
/// Used when GSSAPI is configured but the client has not sent a Negotiate
/// token.  Prompts the client to initiate a SPNEGO exchange.
pub fn negotiate_challenge() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut()
        .insert("WWW-Authenticate", HeaderValue::from_static("Negotiate"));
    resp
}

// ── Internal types ───────────────────────────────────────────────────────────

struct NegotiateSuccess {
    principal: String,
    out_token: Vec<u8>,
}

#[allow(dead_code)]
enum NegotiateError {
    /// Multi-leg exchange: needs another round-trip with this output token.
    Continue(Vec<u8>),
    /// Authentication failed with the given reason.
    Failed(String),
}

/// Synchronous SPNEGO token validation.
///
/// This function wraps the GSS-API context establishment and is designed
/// to run inside `spawn_blocking`.
///
/// When the `gssapi` feature is enabled and `require_crypto` is `true`,
/// the token is verified cryptographically via `gss_accept_sec_context`
/// (libgssapi FFI), producing a verified client principal and an optional
/// mutual-authentication output token.
///
/// When `require_crypto` is `false` (or the `gssapi` feature is not
/// compiled in), the function falls back to structural parsing via
/// `synta_krb5` — extracting the service name (sname) from the cleartext
/// portion of the Kerberos ticket.  This cannot authenticate the client.
///
/// ## Token structure (RFC 4178 / RFC 4121)
///
/// The incoming token is an SPNEGO `NegotiationToken` (APPLICATION 0
/// envelope):
///
/// ```text
/// 60 <len> 06 09 <SPNEGO OID> <NegTokenInit DER>
/// ```
///
/// The `NegTokenInit.mechToken` contains a Kerberos 5 GSS initial context
/// token:
///
/// ```text
/// 60 <len> 06 09 <KRB5 OID> 01 00 <AP-REQ DER>
/// ```
fn negotiate_accept(
    cred: &dyn std::any::Any,
    token: &[u8],
    channel_binding: Option<&[u8]>,
    require_crypto: bool,
) -> Result<NegotiateSuccess, NegotiateError> {
    // ── Cryptographic verification via libgssapi ─────────────────────────
    #[cfg(feature = "gssapi")]
    if require_crypto {
        return verify_gssapi_token(cred, token, channel_binding);
    }

    // ── Structural-only fallback (development / logging mode) ────────────
    let _ = require_crypto; // suppress unused-variable warning without gssapi feature
    negotiate_accept_structural(cred, token, channel_binding)
}

/// Cryptographic GSSAPI verification via `gss_accept_sec_context`.
///
/// The `cred` parameter is expected to be a `libgssapi::credential::Cred`
/// stored inside `Arc<dyn Any>`.  We clone it (reference-counted handle)
/// for each context establishment.
///
/// Returns the authenticated client principal and an optional output token
/// for mutual authentication.
#[cfg(feature = "gssapi")]
fn verify_gssapi_token(
    cred: &dyn std::any::Any,
    token: &[u8],
    channel_binding: Option<&[u8]>,
) -> Result<NegotiateSuccess, NegotiateError> {
    use libgssapi::context::{SecurityContext, ServerCtx};
    use libgssapi::credential::Cred;

    // Downcast to the actual Cred type stored at startup.
    let gss_cred = cred.downcast_ref::<Cred>().ok_or_else(|| {
        NegotiateError::Failed(
            "internal error: GSS credential has wrong type (expected libgssapi::Cred)".into(),
        )
    })?;

    // Clone the credential (reference-counted GSS handle) for this context.
    let cred_clone = gss_cred.clone();

    let mut ctx = ServerCtx::new(Some(cred_clone));

    // Process the client's token.  `step()` returns `Some(tok)` when a
    // response token must be sent back (mutual auth), or `None` when the
    // context is fully established from the server's perspective.
    let out_buf = ctx
        .step(token, channel_binding)
        .map_err(|e| NegotiateError::Failed(format!("gss_accept_sec_context failed: {e}")))?;

    if ctx.is_complete() {
        // Context established — extract the authenticated client principal.
        let client_name = ctx.source_name().map_err(|e| {
            NegotiateError::Failed(format!("failed to retrieve client principal: {e}"))
        })?;

        let principal = client_name.to_string();
        let out_token = out_buf.map(|b| b.to_vec()).unwrap_or_default();

        debug!(
            principal = %principal,
            has_output_token = !out_token.is_empty(),
            "GSSAPI cryptographic verification succeeded"
        );

        Ok(NegotiateSuccess {
            principal,
            out_token,
        })
    } else {
        // Multi-leg negotiation: return the continuation token.
        let out_token = out_buf.map(|b| b.to_vec()).unwrap_or_default();

        if out_token.is_empty() {
            return Err(NegotiateError::Failed(
                "GSS context incomplete but no output token produced".into(),
            ));
        }

        Err(NegotiateError::Continue(out_token))
    }
}

/// Structural-only SPNEGO parsing (no cryptographic verification).
///
/// Extracts the service principal name (sname) from the cleartext portion
/// of the Kerberos ticket.  The client principal is inside the encrypted
/// ticket data and cannot be retrieved without a keytab.
///
/// **Security warning:** The returned identity is prefixed with
/// `krb5-sname:` to indicate it is NOT a verified client identity.
fn negotiate_accept_structural(
    _cred: &dyn std::any::Any,
    token: &[u8],
    channel_binding: Option<&[u8]>,
) -> Result<NegotiateSuccess, NegotiateError> {
    use synta_krb5::gss;

    warn!(
        "GSSAPI structural parsing only: Kerberos tickets are NOT cryptographically verified. \
         The extracted identity is the service name (sname) from the cleartext portion of the \
         ticket, not the authenticated client principal.  The client principal is inside the \
         encrypted ticket data and requires the `gssapi` feature with a valid keytab to decrypt."
    );

    let _ = channel_binding;

    // Step 1: Try parsing as a raw Kerberos GSS token (APPLICATION 0
    // with KRB5 OID).  Some clients send this directly rather than
    // wrapping in SPNEGO.
    if let Some(principal) = try_extract_principal_from_gss_token(token) {
        debug!(principal = %principal, "extracted principal from raw KRB5 GSS token");
        return Ok(NegotiateSuccess {
            principal,
            out_token: Vec::new(),
        });
    }

    // Step 2: Parse as SPNEGO (APPLICATION 0 with SPNEGO OID).
    // The outer APPLICATION 0 envelope wraps a NegTokenInit whose
    // mechToken field contains the Kerberos GSS token.
    if let Some((oid, _tok_type, inner)) = gss::parse_initial_context_token(token) {
        // Check for SPNEGO OID: 1.3.6.1.5.5.2
        const SPNEGO_OID_BYTES: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        if oid == SPNEGO_OID_BYTES {
            // The inner bytes are the NegotiationToken (a CHOICE type).
            // NegTokenInit is [0] IMPLICIT SEQUENCE, mechToken is [2] OCTET STRING.
            if let Some(mech_token) = extract_spnego_mech_token(inner)
                && let Some(principal) = try_extract_principal_from_gss_token(&mech_token)
            {
                debug!(
                    principal = %principal,
                    "extracted principal from SPNEGO mechToken"
                );
                return Ok(NegotiateSuccess {
                    principal,
                    out_token: Vec::new(),
                });
            }
        }

        // Check for raw KRB5 OID — client may have sent KRB5 token directly
        // in the APPLICATION 0 envelope.
        if oid == gss::KRB5_OID_BYTES {
            // inner is the AP-REQ payload after the 2-byte token type
            if let Some(principal) = try_extract_principal_from_ap_req(inner) {
                debug!(
                    principal = %principal,
                    "extracted principal from KRB5 APPLICATION 0 token"
                );
                return Ok(NegotiateSuccess {
                    principal,
                    out_token: Vec::new(),
                });
            }
        }
    }

    // Step 3: Last-resort attempt — try direct AP-REQ DER decode
    // (some broken clients send bare AP-REQ without the GSS envelope).
    if let Some(principal) = try_extract_principal_from_ap_req(token) {
        debug!(
            principal = %principal,
            "extracted principal from bare AP-REQ (non-standard)"
        );
        return Ok(NegotiateSuccess {
            principal,
            out_token: Vec::new(),
        });
    }

    Err(NegotiateError::Failed(
        "failed to parse SPNEGO/Kerberos token: unable to extract client principal".to_string(),
    ))
}

/// Try to parse a GSS APPLICATION 0 Kerberos token and extract the principal.
fn try_extract_principal_from_gss_token(token: &[u8]) -> Option<String> {
    use synta_krb5::gss;

    let (oid, tok_type, payload) = gss::parse_initial_context_token(token)?;

    // Must be Kerberos 5 OID and AP-REQ token type.
    if oid != gss::KRB5_OID_BYTES || tok_type != gss::TOK_AP_REQ {
        return None;
    }

    try_extract_principal_from_ap_req(payload)
}

/// Try to parse an AP-REQ DER blob and extract the service principal name
/// (sname) from the ticket's cleartext fields.
///
/// **Important:** The returned identity is the *service* principal (sname)
/// from the unencrypted portion of the ticket, NOT the authenticated client
/// principal.  The client principal is inside the encrypted ticket data and
/// requires libgssapi with a valid keytab to decrypt.
///
/// The returned string is prefixed with `krb5-sname:` to make it clear to
/// callers that this is not a verified client identity.  For example:
/// `krb5-sname:HTTP/host.example.com@EXAMPLE.COM`.
///
/// For full client identity extraction, the ticket must be decrypted with
/// the server's keytab — that requires the system GSS-API library.
fn try_extract_principal_from_ap_req(ap_req_der: &[u8]) -> Option<String> {
    use synta::{Decoder, Encoding};
    use synta_krb5::kerberos_v5::ApReq;
    use synta_krb5::principal::PrincipalNameExt;

    let ap_req: ApReq = Decoder::new(ap_req_der, Encoding::Der).decode().ok()?;

    // Extract the service principal from the ticket (cleartext sname field).
    let ticket = &ap_req.ticket;
    let realm = &ticket.realm;
    let sname = &ticket.sname;

    // Prefix with "krb5-sname:" to indicate this is the service name from
    // structural parsing, not a cryptographically verified client identity.
    Some(format!("krb5-sname:{}", sname.display(Some(realm))))
}

/// Extract the mechToken from an SPNEGO NegTokenInit.
///
/// SPNEGO NegTokenInit (RFC 4178 §4.2.1):
/// ```text
/// NegTokenInit ::= SEQUENCE {
///     mechTypes       [0] MechTypeList,
///     reqFlags        [1] ContextFlags OPTIONAL,
///     mechToken       [2] OCTET STRING OPTIONAL,
///     mechListMIC     [3] OCTET STRING OPTIONAL,
/// }
/// ```
///
/// The `inner` bytes are the IMPLICIT [0] tagged NegTokenInit SEQUENCE
/// (the NegotiationToken CHOICE tag has already been consumed by the
/// caller).
fn extract_spnego_mech_token(inner: &[u8]) -> Option<Vec<u8>> {
    // NegotiationToken is a CHOICE:
    //   negTokenInit [0] NegTokenInit
    //   negTokenResp [1] NegTokenResp
    //
    // We expect [0] (context tag 0, constructed).
    if inner.is_empty() {
        return None;
    }

    let tag = inner[0];
    // Context tag [0] constructed = 0xa0
    if tag != 0xa0 {
        return None;
    }

    // Read length of the [0] wrapper
    let (wrapper_len, len_bytes) = read_der_length(inner, 1)?;
    let seq_start = 1 + len_bytes;
    let seq_end = seq_start + wrapper_len;
    if seq_end > inner.len() {
        return None;
    }
    let seq_bytes = &inner[seq_start..seq_end];

    // The NegTokenInit SEQUENCE tag
    if seq_bytes.is_empty() || seq_bytes[0] != 0x30 {
        return None;
    }
    let (seq_len, seq_len_bytes) = read_der_length(seq_bytes, 1)?;
    let fields_start = 1 + seq_len_bytes;
    let fields_end = fields_start + seq_len;
    if fields_end > seq_bytes.len() {
        return None;
    }
    let mut pos = fields_start;

    // Walk through the context-tagged fields looking for [2] mechToken.
    while pos < fields_end {
        if pos >= seq_bytes.len() {
            break;
        }
        let field_tag = seq_bytes[pos];
        let (field_len, field_len_bytes) = read_der_length(seq_bytes, pos + 1)?;
        let field_value_start = pos + 1 + field_len_bytes;
        let field_value_end = field_value_start + field_len;

        if field_value_end > seq_bytes.len() {
            break;
        }

        // Context tag [2] = 0xa2 (constructed)
        if field_tag == 0xa2 {
            // The value is an OCTET STRING wrapping the mechToken
            let octet_bytes = &seq_bytes[field_value_start..field_value_end];
            // Strip the OCTET STRING tag (0x04) and length
            if !octet_bytes.is_empty() && octet_bytes[0] == 0x04 {
                let (oct_len, oct_len_bytes) = read_der_length(octet_bytes, 1)?;
                let value_start = 1 + oct_len_bytes;
                let value_end = value_start + oct_len;
                if value_end <= octet_bytes.len() {
                    return Some(octet_bytes[value_start..value_end].to_vec());
                }
            }
            return None;
        }

        pos = field_value_end;
    }

    None
}

/// Read a DER/BER definite-length starting at `bytes[offset]`.
/// Returns `(value_length, bytes_consumed)` or `None`.
fn read_der_length(bytes: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(offset)?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || offset + 1 + n > bytes.len() {
            return None;
        }
        let mut val = 0usize;
        for i in 0..n {
            val = (val << 8) | bytes[offset + 1 + i] as usize;
        }
        Some((val, 1 + n))
    }
}
