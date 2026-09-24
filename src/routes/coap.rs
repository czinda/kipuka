//! EST-over-CoAP bridge (RFC 9483).
//!
//! This module implements the [`kipuka_coap::EstHandler`] trait, bridging
//! parsed CoAP EST requests to the shared EST enrollment logic.  It lives
//! in the main crate (not in `kipuka-coap`) so that it can access
//! [`AppState`], CA signing functions, and the database.
//!
//! The handler is synchronous (matching the `EstHandler` trait contract),
//! using [`crate::ca::issue::resolve_signing_key_sync`] for key material
//! and [`crate::ca::issue::issue_certificate`] for certificate issuance.

use std::sync::Arc;

use kipuka_coap::CoapError;
use kipuka_coap::dtls::ClientCertInfo;
use kipuka_coap::server::{AuditInfo, EstOperation, EstResponse};

use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::state::AppState;

/// EST handler implementation that bridges CoAP requests to shared
/// enrollment logic.
///
/// Constructed with a reference to the application state and passed
/// to [`CoapDtlsServer::run()`](kipuka_coap::CoapDtlsServer::run)
/// at startup.
pub struct CoapEstHandler {
    state: Arc<AppState>,
}

impl CoapEstHandler {
    /// Create a new CoAP EST handler wrapping the application state.
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl kipuka_coap::EstHandler for CoapEstHandler {
    fn handle(
        &self,
        operation: EstOperation,
        label: Option<&str>,
        payload: &[u8],
        _content_format: Option<u16>,
        client_cert: Option<&ClientCertInfo>,
    ) -> Result<EstResponse, CoapError> {
        // Reject unknown names before authentication without selecting a CA twice.
        if let Some(name) = label.filter(|name| !name.is_empty())
            && !self
                .state
                .config
                .est
                .labels
                .iter()
                .any(|entry| entry.name == name)
        {
            return Err(CoapError::ResourceNotFound(format!(
                "unknown EST label: {name}"
            )));
        }
        if matches!(
            operation,
            EstOperation::SimpleEnroll | EstOperation::SimpleReenroll | EstOperation::ServerKeygen
        ) {
            let cert = client_cert.ok_or_else(|| {
                CoapError::Forbidden("authenticated DTLS client certificate required".into())
            })?;
            let label_config = self
                .state
                .config
                .est
                .labels
                .iter()
                .find(|c| Some(c.name.as_str()) == label);
            if label_config.is_some_and(|c| {
                !c.auth_methods.is_empty()
                    && !c.auth_methods.contains(&crate::config::EstAuthMethod::Mtls)
                    && !c
                        .auth_methods
                        .contains(&crate::config::EstAuthMethod::Certificate)
            }) {
                return Err(CoapError::Forbidden("mTLS not permitted for label".into()));
            }
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| CoapError::Internal("CoAP runtime unavailable".into()))?;
            runtime.block_on(async {
                crate::auth::mtls::check_revocation(&cert.der_bytes, &self.state)
                    .await
                    .map_err(CoapError::Forbidden)?;
                self.state
                    .admit_enrollment(&cert.subject_dn, "coap")
                    .await
                    .map_err(|e| CoapError::Internal(e.to_string()))
            })?;
        }
        let result = match operation {
            EstOperation::CaCerts => handle_cacerts(label, &self.state),
            EstOperation::SimpleEnroll => {
                handle_simpleenroll(payload, label, client_cert, &self.state)
            }
            EstOperation::SimpleReenroll => {
                handle_simplereenroll(payload, label, client_cert, &self.state)
            }
            EstOperation::CsrAttrs => handle_csrattrs(label, &self.state),
            EstOperation::ServerKeygen => Err(CoapError::Internal(
                "server key generation not yet implemented for CoAP transport".into(),
            )),
        };

        // NIAP FAU_GEN.1: persist an audit event for every CoAP EST operation,
        // on success and on authorization denial alike.  The `kipuka-coap`
        // transport layer has no `AppState` access, so audit persistence must
        // happen here — the one dispatch point that holds it.  Previously CoAP
        // events were only logged by the server loop and never written to the
        // `audit_events` table, leaving the entire transport un-audited.
        let actor = client_cert
            .map(|c| c.subject_dn.clone())
            .unwrap_or_default();
        match &result {
            Ok(resp) => {
                if let Some(audit) = resp.audit_event.as_ref() {
                    self.spawn_audit(audit.event_type.clone(), actor, audit.detail.clone());
                }
            }
            Err(err) => {
                if let Some((event_type, detail)) = coap_denial_audit(operation, err) {
                    self.spawn_audit(event_type, actor, detail);
                }
            }
        }

        result
    }
}

impl CoapEstHandler {
    /// Persist a CoAP EST audit event (NIAP FAU_GEN.1) from the synchronous
    /// [`kipuka_coap::EstHandler`] context.
    ///
    /// `record_audit_event*` is async but the trait method is synchronous, so
    /// the write is spawned onto the current Tokio runtime (the CoAP server
    /// loop that invoked us).  When an authenticated DTLS identity is present it
    /// is recorded as the actor, so the FAU_SAR.1 review filter is populated.
    fn spawn_audit(&self, event_type: String, actor: String, detail: String) {
        let state = Arc::clone(&self.state);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if actor.is_empty() {
                        state.record_audit_event(&event_type, &detail).await;
                    } else {
                        state
                            .record_audit_event_with_actor(&event_type, &actor, &detail)
                            .await;
                    }
                });
            }
            Err(_) => {
                tracing::warn!(
                    %event_type,
                    "no Tokio runtime available; CoAP audit event dropped"
                );
            }
        }
    }
}

/// Map a failed CoAP EST operation to its audit event, when the failure is a
/// security-relevant enrollment rejection (FDP_ACF.1 / RFC 7030 §4.2 →
/// FAU_GEN.1).
///
/// Two failure classes produce an `*_denied` audit event, matching the HTTP
/// taxonomy:
/// - `Forbidden` — an authorization denial (the requester is not permitted to
///   enroll the requested identity).
/// - `InvalidMessage` — a rejected client CSR (empty payload, or a bad
///   proof-of-possession / undersized key / disallowed algorithm classified by
///   [`IssuanceError::is_client_error`](crate::ca::issue::IssuanceError::is_client_error)).
///
/// Purely operational faults (`Internal`, DTLS, block-transfer) are surfaced to
/// the client and logged but are not enrollment decisions, so they are not
/// audited here.
fn coap_denial_audit(operation: EstOperation, err: &CoapError) -> Option<(String, String)> {
    let event_type = match operation {
        EstOperation::SimpleEnroll => "coap_simpleenroll_denied",
        EstOperation::SimpleReenroll => "coap_simplereenroll_denied",
        _ => return None,
    };
    match err {
        CoapError::Forbidden(msg) | CoapError::InvalidMessage(msg) => {
            Some((event_type.to_string(), msg.clone()))
        }
        _ => None,
    }
}

/// Resolve an EST label into its enrollment configuration for the CoAP
/// transport, mapping resolution failures onto CoAP error codes.
///
/// Shares [`LabelExtractor::resolve`] with the HTTP/CMS-EST extractor so that
/// the per-label CA selection and FDP_ACF.1 access-control policy are
/// identical across transports.
fn resolve_label(state: &Arc<AppState>, label: Option<&str>) -> Result<LabelExtractor, CoapError> {
    LabelExtractor::resolve(state, label).map_err(|e| match e {
        // An unknown label is a client addressing error → 4.04 Not Found.
        KipukaError::NotFound => {
            CoapError::ResourceNotFound(format!("unknown EST label: {label:?}"))
        }
        // A misconfigured label (dangling CA reference) is a server fault.
        other => CoapError::Internal(format!("label resolution failed: {other}")),
    })
}

/// Handle GET /cacerts — return the CA certificate chain as PKCS#7 certs-only.
///
/// RFC 9483 §5.1: The response Content-Format is 281
/// (`application/pkcs7-mime; smime-type=certs-only`).
///
/// Unlike the HTTP handler, the CoAP response is raw DER (not base64).
fn handle_cacerts(label: Option<&str>, state: &Arc<AppState>) -> Result<EstResponse, CoapError> {
    // Honour the label's CA selection so `/cacerts` returns the chain that
    // matches the CA a subsequent enrollment on the same label would use.
    let label_ex = resolve_label(state, label)?;
    let ca = state
        .get_ca(label_ex.ca_id())
        .ok_or_else(|| CoapError::Internal(format!("CA not found for id={}", label_ex.ca_id())))?;

    let pkcs7_der =
        crate::routes::cacerts::build_certs_only_pkcs7(std::slice::from_ref(&ca.cert_der))
            .map_err(|e| CoapError::Internal(format!("PKCS#7 build failed: {e}")))?;

    tracing::debug!(ca_id = %ca.id, "CoAP /cacerts served");

    Ok(EstResponse {
        payload: pkcs7_der,
        content_format: kipuka_coap::content_format::APPLICATION_PKCS7_MIME_CERTS_ONLY,
        audit_event: Some(AuditInfo {
            event_type: "coap_cacerts".into(),
            detail: format!("ca_id={}", ca.id),
        }),
    })
}

/// Handle POST /simpleenroll — issue a certificate from a PKCS#10 CSR.
///
/// RFC 9483 §5.3: The request Content-Format is 285 (`application/pkcs10`),
/// carrying the DER-encoded CSR directly (no base64 wrapping).
///
/// Uses the synchronous key resolution path
/// ([`crate::ca::issue::resolve_signing_key_sync`]) since the `EstHandler`
/// trait is synchronous.
fn handle_simpleenroll(
    csr_der: &[u8],
    label: Option<&str>,
    client_cert: Option<&ClientCertInfo>,
    state: &Arc<AppState>,
) -> Result<EstResponse, CoapError> {
    if csr_der.is_empty() {
        return Err(CoapError::InvalidMessage("empty CSR payload".into()));
    }

    // Resolve the label to its CA and per-label access-control policy.  Over
    // CoAP the label is the only carrier of an FDP_ACF.1 policy, so this is
    // where transport parity with HTTP is established.
    let label_ex = resolve_label(state, label)?;
    let ca_id = label_ex.ca_id().to_string();

    // Enrollment authorization (NIAP CA PP FDP_ACF.1).
    //
    // Enforce the same identity-binding and name-allowlist policy the HTTP
    // `/simpleenroll` path applies, keyed off the authenticated DTLS client
    // identity (its subject DN) when one was presented.  A no-op unless the
    // resolved label opts in, so unlabeled/default enrollment is unchanged.
    // Without this check the CoAP transport issued certificates for any names
    // the requester chose to put in the CSR — a silent bypass of the policy
    // enforced on every other transport.
    let identity = client_cert.map(|c| c.subject_dn.as_str()).unwrap_or("");
    if let Err(reason) =
        crate::auth::enroll_authz::authorize_csr_der(csr_der, identity, &label_ex.enroll_policy())
    {
        tracing::warn!(
            ca_id = %ca_id,
            identity = %identity,
            %reason,
            "coap simpleenroll rejected: CSR not authorized for requester"
        );
        return Err(CoapError::Forbidden(format!(
            "enrollment not authorized: {reason}"
        )));
    }

    let ca = state
        .get_ca(&ca_id)
        .ok_or_else(|| CoapError::Internal(format!("CA not found for id={ca_id}")))?;

    // Find the CA config entry.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| CoapError::Internal(format!("CA config not found for id={ca_id}")))?;

    // Resolve the signing key synchronously (filesystem read or HSM lookup).
    let resolved_key = crate::ca::issue::resolve_signing_key_sync(ca_cfg, state.hsm.as_ref())
        .map_err(|e| CoapError::Internal(format!("signing key resolution failed: {e}")))?;

    // Build a default enrollment profile.
    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: ca
            .validity_days
            .min(crate::ca::issue::cab_forum_max_validity_days()),
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    // Issue the certificate using the shared issuance logic.
    let result = crate::ca::issue::issue_certificate(
        csr_der,
        &profile,
        &ca.cert_der,
        resolved_key.as_signing_key(),
        &ca.hash_algorithm,
        ca.ocsp_url.as_deref(),
        ca.crl_url.as_deref(),
    )
    .map_err(|e| {
        // A bad client CSR (e.g. failed proof-of-possession) maps to 4.00 Bad
        // Request — the dispatch renders CoapError::InvalidMessage as
        // CoapCode::BAD_REQUEST — while a server-side fault stays 5.00 Internal.
        // The dispatch's coap_denial_audit records the client-caused rejection.
        let msg = format!("certificate issuance failed: {e}");
        if e.is_client_error() {
            CoapError::InvalidMessage(msg)
        } else {
            CoapError::Internal(msg)
        }
    })?;

    tracing::info!(
        ca_id = %ca_id,
        serial = %result.serial_number,
        subject = %result.subject_dn,
        "CoAP simpleenroll: certificate issued"
    );

    tokio::runtime::Handle::try_current()
        .map_err(|_| CoapError::Internal("CoAP runtime unavailable".into()))?
        .block_on(crate::ca::issue::persist_certificate(
            state,
            &ca_id,
            &profile.name,
            &result,
        ))
        .map_err(|e| CoapError::Internal(e.to_string()))?;

    // Wrap the issued certificate in PKCS#7 certs-only (reuses cacerts builder).
    let pkcs7_der = crate::routes::cacerts::build_certs_only_pkcs7(std::slice::from_ref(
        &result.certificate_der,
    ))
    .map_err(|e| CoapError::Internal(format!("PKCS#7 wrap failed: {e}")))?;

    Ok(EstResponse {
        payload: pkcs7_der,
        content_format: kipuka_coap::content_format::APPLICATION_PKCS7_MIME_CERTS_ONLY,
        audit_event: Some(AuditInfo {
            event_type: "coap_simpleenroll".into(),
            detail: format!(
                "serial={} subject={}",
                result.serial_number, result.subject_dn
            ),
        }),
    })
}

/// Handle POST /simplereenroll — re-enroll using existing DTLS client certificate.
///
/// RFC 9483 §5.3: For re-enrollment, the client authenticates using its
/// existing certificate via DTLS client auth, and submits a new CSR.
fn handle_simplereenroll(
    csr_der: &[u8],
    label: Option<&str>,
    client_cert: Option<&ClientCertInfo>,
    state: &Arc<AppState>,
) -> Result<EstResponse, CoapError> {
    // Re-enrollment requires a client certificate from the DTLS handshake.
    let _cert = client_cert.ok_or_else(|| {
        CoapError::Unauthorized(
            "simplereenroll requires DTLS client certificate authentication".into(),
        )
    })?;

    // The issuance logic is shared with simpleenroll, including the FDP_ACF.1
    // authorization check — the client cert is passed through so the policy is
    // keyed off the authenticated re-enrolling identity.
    let mut resp = handle_simpleenroll(csr_der, label, client_cert, state)?;

    // Override the audit event type to distinguish re-enrollment.
    if let Some(ref mut audit) = resp.audit_event {
        audit.event_type = "coap_simplereenroll".into();
    }

    Ok(resp)
}

/// Handle GET /csrattrs — return CSR attributes the server expects.
///
/// RFC 9483 §5.1: The response Content-Format is 287
/// (`application/csrattrs`).
fn handle_csrattrs(label: Option<&str>, state: &Arc<AppState>) -> Result<EstResponse, CoapError> {
    // Resolve the label so per-label CSR attributes and the RFC 9908 template
    // are honoured, matching the HTTP `/csrattrs` handler (transport parity).
    // An unknown label is a client addressing error → 4.04 Not Found, exactly
    // as for `/cacerts`.  Previously this read the global attribute list
    // directly, silently ignoring per-label overrides.
    let label_ex = resolve_label(state, label)?;

    // Per-label attributes override the global list when non-empty.
    let attributes = if label_ex.csr_attributes.is_empty() {
        &state.config.est.csr_attributes
    } else {
        &label_ex.csr_attributes
    };

    // Per-label template overrides the global template.
    let template = label_ex
        .csr_template
        .as_ref()
        .or(state.config.est.csr_template.as_ref());

    let csrattrs_der =
        crate::routes::csrattrs::encode_csr_attrs_with_template(attributes, template)
            .map_err(|e| CoapError::Internal(format!("CSR attributes encoding failed: {e}")))?;

    let detail = if csrattrs_der.is_empty() {
        "empty attributes".to_string()
    } else {
        format!("{} attributes", attributes.len())
    };

    Ok(EstResponse {
        payload: csrattrs_der,
        content_format: kipuka_coap::content_format::APPLICATION_CSRATTRS,
        audit_event: Some(AuditInfo {
            event_type: "coap_csrattrs".into(),
            detail,
        }),
    })
}
