//! GSSAPI/Kerberos authentication for EST endpoints.
//!
//! Implements the `Authorization: Negotiate` (SPNEGO) authentication
//! mechanism, following the same pattern as Akamu's GSSAPI support.
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
    let result = tokio::task::spawn_blocking(move || {
        negotiate_accept(&gss_cred, &token_owned, binding_owned.as_deref())
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
/// This function wraps the GSSAPI FFI calls and is designed to run inside
/// `spawn_blocking`.  In the current implementation it delegates to
/// `kipuka_util::gssapi` (placeholder); in production it would call
/// `gss_accept_sec_context` via the `libgssapi` or `akamu_gssapi` crate.
fn negotiate_accept(
    _cred: &dyn std::any::Any,
    token: &[u8],
    channel_binding: Option<&[u8]>,
) -> Result<NegotiateSuccess, NegotiateError> {
    // TODO: Replace with actual GSSAPI implementation.
    //
    // The real implementation should:
    // 1. Call gss_accept_sec_context with the server credential and input token
    // 2. If the context is complete, extract the client principal name
    // 3. Verify GSS_C_REPLAY_FLAG is set (replay detection)
    // 4. If channel_binding is provided, verify it matches the TLS session
    // 5. Return the principal and any output token for mutual auth

    let _ = token;
    let _ = channel_binding;

    Err(NegotiateError::Failed(
        "GSSAPI not yet implemented".to_string(),
    ))
}
