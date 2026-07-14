//! STAR (Short-Term Automatic Renewal) endpoints (RFC 8739).
//!
//! Extends the EST endpoint set (RFC 7030) with STAR semantics for
//! automatic certificate renewal.  Clients create a STAR order once,
//! then fetch the latest certificate at any time without re-authenticating.
//!
//! # Route structure
//!
//! ```text
//! /.well-known/est/star
//!     POST              Create STAR order (authenticated)
//!
//! /.well-known/est/star/{order_id}
//!     GET               Fetch current certificate (unauthenticated)
//!     DELETE            Cancel STAR order (authenticated)
//!
//! /.well-known/est/star/{order_id}/history
//!     GET               List all certificates in series (unauthenticated)
//! ```

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::auth::EstAuth;
use crate::error::KipukaError;
use crate::routes::LabelExtractor;
use crate::routes::est::{content_types, decode_est_base64, encode_est_base64};
use crate::star::{StarCertificate, StarError};
use crate::state::AppState;

/// Build the STAR sub-router.
///
/// Mounts STAR order management endpoints under `/.well-known/est/star/`.
/// The router is nested into the main application router by
/// [`crate::routes::build_router`].
pub fn star_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(post_star_order))
        .route(
            "/{order_id}",
            get(get_star_certificate).delete(delete_star_order),
        )
        .route("/{order_id}/history", get(get_star_history))
}

/// `POST /.well-known/est/star`
///
/// Create a new STAR order.  The client submits a PKCS#10 CSR (base64-
/// encoded, same as `/simpleenroll`) together with optional STAR-specific
/// headers:
///
/// | Header                  | Type   | Default                          |
/// |-------------------------|--------|----------------------------------|
/// | `Star-Renewal-Interval` | u64 s  | `[star].default_renewal_interval_secs` |
/// | `Star-Lifetime`         | u32 d  | `[star].max_lifetime_days`       |
///
/// On success the server issues the first certificate, stores the order,
/// and returns **201 Created** with a `Star-Order-ID` header.
///
/// # Authentication
///
/// Requires EST authentication (mTLS or OTP).
///
/// # Request
///
/// | Header         | Value                |
/// |----------------|----------------------|
/// | Content-Type   | `application/pkcs10` |
/// | Body           | Base64-encoded DER PKCS#10 CSR |
///
/// # Response
///
/// | Header           | Value                                          |
/// |------------------|------------------------------------------------|
/// | Status           | `201 Created`                                  |
/// | Content-Type     | `application/pkcs7-mime; smime-type=certs-only` |
/// | Star-Order-ID    | UUID of the created order                      |
pub async fn post_star_order(
    auth: EstAuth,
    label: LabelExtractor,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, KipukaError> {
    // Check that STAR is enabled.
    let star_config = state
        .config
        .star
        .as_ref()
        .filter(|c| c.enabled)
        .ok_or(KipukaError::NotFound)?;

    // Obtain the STAR manager.
    let star_manager = state
        .star_manager
        .as_ref()
        .ok_or(KipukaError::ServiceUnavailable(
            "STAR manager not available".into(),
        ))?;

    let ca_id = label.ca_id();
    let identity = &auth.0.identity;

    tracing::info!(
        ca_id = %ca_id,
        label = %label.label,
        identity = %identity,
        method = ?auth.0.method,
        "STAR order request"
    );

    // Parse optional STAR headers, falling back to config defaults.
    let renewal_interval_secs: u64 = headers
        .get("star-renewal-interval")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(star_config.default_renewal_interval_secs);

    let lifetime_days: u32 = headers
        .get("star-lifetime")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(star_config.max_lifetime_days);

    // Clamp to configured bounds.
    let renewal_interval_secs = renewal_interval_secs
        .max(star_config.min_renewal_interval_secs)
        .min(star_config.max_renewal_interval_secs);
    let lifetime_days = lifetime_days.min(star_config.max_lifetime_days);

    // Decode the base64-encoded CSR.
    let csr_der = decode_est_base64(&body)
        .map_err(|e| KipukaError::BadRequest(format!("CSR decoding failed: {e}")))?;

    if csr_der.len() < 60 {
        return Err(KipukaError::BadRequest(
            "CSR is too short to be valid".into(),
        ));
    }

    // Create the STAR order via the manager.
    let order = star_manager
        .create_order(
            identity.clone(),
            String::new(), // key_type — extracted from CSR in production
            "default".to_owned(),
            renewal_interval_secs,
            lifetime_days,
            ca_id.to_owned(),
            csr_der.clone(),
            Some(identity.clone()),
        )
        .map_err(star_error_to_kipuka)?;

    let order_id = order.id.clone();

    // Issue the first certificate using the same pattern as simpleenroll.

    // Look up the CA backend.
    let ca = state.get_ca(ca_id).ok_or(KipukaError::NotFound)?;

    // Look up the CA config to get key material path or PKCS#11 URI.
    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca_id)
        .ok_or_else(|| KipukaError::Ca(format!("CA config not found for id={ca_id}")))?;

    // Resolve key material.
    let resolved_key = crate::ca::issue::resolve_signing_key(ca_cfg, state.hsm.as_ref()).await?;

    // Build an enrollment profile scoped to the STAR renewal interval.
    // STAR certificates are short-lived: validity = renewal_interval.
    let validity_days = (renewal_interval_secs as u32 / 86400).max(1);
    let profile = crate::ca::issue::EnrollmentProfile {
        max_validity_days: validity_days,
        ..crate::ca::issue::EnrollmentProfile::default()
    };

    // Issue the first certificate.
    let result = crate::ca::issue::issue_certificate(
        &csr_der,
        &profile,
        &ca.cert_der,
        resolved_key.as_signing_key(),
        &ca.hash_algorithm,
        ca.ocsp_url.as_deref(),
        ca.crl_url.as_deref(),
    )
    .map_err(|e| KipukaError::Ca(format!("STAR certificate issuance failed: {e}")))?;

    // Store the first certificate in the order.
    let first_cert = StarCertificate {
        certificate_der: result.certificate_der.clone(),
        serial_number: result.serial_number.clone(),
        not_before: result.not_before,
        not_after: result.not_after,
        renewal_number: 0,
        star_order_id: order_id.clone(),
    };
    star_manager
        .store_renewed_certificate(&order_id, first_cert.clone())
        .map_err(star_error_to_kipuka)?;

    // Persist order to database.
    sqlx::query(
        "INSERT INTO star_orders \
         (id, subject_dn, key_type, profile, renewal_interval_secs, \
          lifetime_end, max_renewals, status, requestor_dn, ca_id, csr_der) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
    )
    .bind(&order_id)
    .bind(&order.subject_dn)
    .bind(&order.key_type)
    .bind(&order.profile)
    .bind(renewal_interval_secs as i64)
    .bind(order.lifetime_end.to_rfc3339())
    .bind(order.max_renewals as i64)
    .bind(identity)
    .bind(ca_id)
    .bind(&csr_der)
    .execute(&state.db)
    .await?;

    // Persist the first certificate to the star_certificates table.
    sqlx::query(
        "INSERT INTO star_certificates \
         (star_order_id, serial_number, certificate_der, not_before, not_after, renewal_number) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&order_id)
    .bind(&first_cert.serial_number)
    .bind(&first_cert.certificate_der)
    .bind(first_cert.not_before.to_rfc3339())
    .bind(first_cert.not_after.to_rfc3339())
    .bind(first_cert.renewal_number as i64)
    .execute(&state.db)
    .await?;

    state
        .record_audit_event(
            "star_order_created",
            &format!(
                "order_id={order_id}, ca_id={ca_id}, identity={identity}, serial={}",
                result.serial_number
            ),
        )
        .await;

    // Wrap the issued certificate in PKCS#7 certs-only (RFC 7030 §4.2.3).
    let pkcs7_der = crate::routes::cacerts::build_certs_only_pkcs7(std::slice::from_ref(&result.certificate_der))?;
    let response_body = encode_est_base64(&pkcs7_der);

    let mut resp = (StatusCode::CREATED, response_body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_types::PKCS7_CERTS),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("star-order-id"),
        HeaderValue::from_str(&order_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    Ok(resp)
}

/// `GET /.well-known/est/star/{order_id}`
///
/// Fetch the current (most recent) certificate for a STAR order.
///
/// No authentication required — STAR certificates are designed to be
/// fetched by any party that knows the order ID (RFC 8739 §3.4).
///
/// # Response
///
/// | Status | Meaning                                |
/// |--------|----------------------------------------|
/// | 200    | Current certificate returned            |
/// | 404    | Order not found                        |
/// | 410    | Order cancelled or expired (Gone)      |
pub async fn get_star_certificate(
    Path(order_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, KipukaError> {
    // Check that STAR is enabled.
    let _star_config = state
        .config
        .star
        .as_ref()
        .filter(|c| c.enabled)
        .ok_or(KipukaError::NotFound)?;

    let star_manager = state
        .star_manager
        .as_ref()
        .ok_or(KipukaError::ServiceUnavailable(
            "STAR manager not available".into(),
        ))?;

    // Fetch the current certificate (handles status checks internally).
    match star_manager.get_current_certificate(&order_id) {
        Ok(cert) => {
            // Wrap in PKCS#7 certs-only per RFC 7030 §4.2.3.
            let pkcs7_der = crate::routes::cacerts::build_certs_only_pkcs7(std::slice::from_ref(&cert.certificate_der))?;
            let response_body = encode_est_base64(&pkcs7_der);

            let mut resp = (StatusCode::OK, response_body).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_types::PKCS7_CERTS),
            );
            resp.headers_mut().insert(
                header::HeaderName::from_static("content-transfer-encoding"),
                HeaderValue::from_static(content_types::TRANSFER_ENCODING_BASE64),
            );
            Ok(resp)
        }
        Err(StarError::OrderCancelled(_) | StarError::OrderExpired(_)) => {
            // RFC 8739 §3.4: return 410 Gone for terminated orders.
            Ok(StatusCode::GONE.into_response())
        }
        Err(StarError::OrderNotFound(_)) => Err(KipukaError::NotFound),
        Err(e) => Err(KipukaError::Internal(e.to_string())),
    }
}

/// `DELETE /.well-known/est/star/{order_id}`
///
/// Cancel a STAR order.  Future renewals are suppressed and the order
/// status is set to `cancelled`.  Existing certificates remain valid
/// until their natural expiry.
///
/// # Authentication
///
/// Requires EST authentication (mTLS or OTP).
///
/// # Response
///
/// | Status | Meaning                        |
/// |--------|--------------------------------|
/// | 204    | Order cancelled successfully   |
/// | 404    | Order not found                |
pub async fn delete_star_order(
    auth: EstAuth,
    Path(order_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, KipukaError> {
    // Check that STAR is enabled.
    let _star_config = state
        .config
        .star
        .as_ref()
        .filter(|c| c.enabled)
        .ok_or(KipukaError::NotFound)?;

    let star_manager = state
        .star_manager
        .as_ref()
        .ok_or(KipukaError::ServiceUnavailable(
            "STAR manager not available".into(),
        ))?;

    let identity = &auth.0.identity;

    tracing::info!(
        order_id = %order_id,
        identity = %identity,
        "STAR order cancellation request"
    );

    // Cancel via the STAR manager.
    star_manager
        .cancel_order(&order_id)
        .map_err(star_error_to_kipuka)?;

    // Update database.
    sqlx::query("UPDATE star_orders SET status = 'cancelled', cancelled_at = ? WHERE id = ?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(&order_id)
        .execute(&state.db)
        .await?;

    state
        .record_audit_event(
            "star_order_cancelled",
            &format!("order_id={order_id}, identity={identity}"),
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /.well-known/est/star/{order_id}/history`
///
/// List all certificates issued in the STAR renewal series, ordered by
/// renewal number.  Returns a JSON array suitable for monitoring and
/// auditing STAR certificate rotation.
///
/// # Response
///
/// | Header       | Value              |
/// |--------------|--------------------|
/// | Content-Type | `application/json` |
///
/// ```json
/// [
///   {
///     "serial": "01AB...",
///     "not_before": "2025-06-01T00:00:00Z",
///     "not_after": "2025-06-02T00:00:00Z",
///     "renewal_number": 0
///   }
/// ]
/// ```
pub async fn get_star_history(
    Path(order_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, KipukaError> {
    // Check that STAR is enabled.
    let _star_config = state
        .config
        .star
        .as_ref()
        .filter(|c| c.enabled)
        .ok_or(KipukaError::NotFound)?;

    // Verify the order exists (check in-memory first, fall back to DB).
    let star_manager = state.star_manager.as_ref();
    let in_memory = star_manager.and_then(|m| m.get_order(&order_id)).is_some();

    if !in_memory {
        // Check DB as well — the order may have been cleaned from memory.
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM star_orders WHERE id = ?")
            .bind(&order_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));

        if count.0 == 0 {
            return Err(KipukaError::NotFound);
        }
    }

    // Query all certificates in the series.
    let rows: Vec<StarCertRow> = sqlx::query_as(
        "SELECT serial_number, not_before, not_after, renewal_number \
         FROM star_certificates WHERE star_order_id = ? ORDER BY renewal_number ASC",
    )
    .bind(&order_id)
    .fetch_all(&state.db)
    .await?;

    let entries: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "serial": r.serial_number,
                "not_before": r.not_before,
                "not_after": r.not_after,
                "renewal_number": r.renewal_number,
            })
        })
        .collect();

    let json_body = serde_json::to_string(&entries)
        .map_err(|e| KipukaError::Internal(format!("JSON serialization failed: {e}")))?;

    let mut resp = (StatusCode::OK, json_body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    Ok(resp)
}

/// Row type for STAR certificate history queries.
#[derive(sqlx::FromRow)]
struct StarCertRow {
    serial_number: String,
    not_before: String,
    not_after: String,
    renewal_number: i64,
}

/// Map a [`StarError`] to a [`KipukaError`] for HTTP response generation.
fn star_error_to_kipuka(e: StarError) -> KipukaError {
    match e {
        StarError::OrderNotFound(_) => KipukaError::NotFound,
        StarError::OrderCancelled(id) => {
            KipukaError::BadRequest(format!("STAR order {id} is cancelled"))
        }
        StarError::OrderExpired(id) => {
            KipukaError::BadRequest(format!("STAR order {id} has expired"))
        }
        StarError::MaxRenewalsReached { order_id, max } => KipukaError::BadRequest(format!(
            "STAR order {order_id} reached maximum renewals ({max})"
        )),
        StarError::MaxOrdersReached { limit } => {
            KipukaError::ServiceUnavailable(format!("maximum active STAR orders reached ({limit})"))
        }
        StarError::InvalidInterval {
            requested,
            min,
            max,
        } => KipukaError::BadRequest(format!(
            "renewal interval {requested}s outside allowed range {min}s–{max}s"
        )),
        StarError::IssuanceError(msg) => KipukaError::Ca(msg),
        StarError::DatabaseError(msg) => KipukaError::Db(msg),
    }
}
