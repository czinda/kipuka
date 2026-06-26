//! `GET /.well-known/est/renewal-info/{cert_id}` — Certificate Renewal Info.
//!
//! Implements draft-ietf-lamps-est-renewal-info: an unauthenticated endpoint
//! that returns a JSON object with a suggested renewal window for a
//! certificate identified by its `cert_id`.
//!
//! The `cert_id` is constructed as:
//!
//! ```text
//!   base64url(AKI.keyIdentifier) + "." + base64url(Serial)
//! ```
//!
//! where the base64url encoding uses the URL-safe alphabet without padding
//! (RFC 4648 §5).
//!
//! # Authentication
//!
//! No authentication is required.  The cert_id binds the request to a
//! specific certificate, and the AKI component prevents serial-number
//! enumeration against the wrong issuer.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};

use crate::error::KipukaError;
use crate::state::AppState;

/// `GET /.well-known/est/renewal-info/{cert_id}`
///
/// Returns a JSON object with a suggested renewal window for the
/// identified certificate.
///
/// # Response
///
/// | Header         | Value                |
/// |----------------|----------------------|
/// | Status         | `200 OK`             |
/// | Content-Type   | `application/json`   |
/// | Retry-After    | configurable seconds |
///
/// ```json
/// {
///   "suggestedWindow": {
///     "start": "2026-07-20T00:00:00Z",
///     "end": "2026-07-24T00:00:00Z"
///   }
/// }
/// ```
///
/// # Errors
///
/// - `400 Bad Request` — malformed cert_id
/// - `404 Not Found` — certificate not found or AKI mismatch
pub async fn get_renewal_info(
    Path(cert_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, KipukaError> {
    tracing::debug!(cert_id = %cert_id, "renewal-info request");

    // Step 1: Parse the cert_id — split on "." into AKI and serial parts.
    let (aki_b64, serial_b64) = cert_id.split_once('.').ok_or_else(|| {
        tracing::debug!(cert_id = %cert_id, "cert_id missing '.' separator");
        KipukaError::BadRequest("cert_id must be base64url(AKI) '.' base64url(Serial)".into())
    })?;

    let expected_aki = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(aki_b64)
        .map_err(|e| {
            tracing::debug!(error = %e, "invalid base64url in AKI component");
            KipukaError::BadRequest(format!("invalid base64url in AKI component: {e}"))
        })?;

    let serial_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(serial_b64)
        .map_err(|e| {
            tracing::debug!(error = %e, "invalid base64url in serial component");
            KipukaError::BadRequest(format!("invalid base64url in serial component: {e}"))
        })?;

    // Convert serial bytes to the hex string used in the DB.
    let serial_hex = hex::encode(&serial_bytes);

    tracing::debug!(
        serial_hex = %serial_hex,
        aki_len = expected_aki.len(),
        "parsed cert_id components"
    );

    // Step 2: Query the certificate from the database by serial number.
    let row = sqlx::query_as::<_, CertRenewalRow>(
        crate::db::pg_sql(
            "SELECT serial, not_after, der_encoded \
             FROM certificates WHERE serial = ? AND status = 'active'",
        ),
    )
    .bind(&serial_hex)
    .fetch_optional(&state.db_ro)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, serial = %serial_hex, "certificate query failed");
        KipukaError::Db(format!("certificate query failed: {e}"))
    })?;

    let row = row.ok_or_else(|| {
        tracing::debug!(serial = %serial_hex, "certificate not found or not active");
        KipukaError::NotFound
    })?;

    // Step 3: Extract AKI keyIdentifier from the certificate DER.
    let actual_aki = extract_aki_key_id(&row.der_encoded).ok_or_else(|| {
        tracing::debug!(
            serial = %serial_hex,
            "certificate does not contain an AKI keyIdentifier"
        );
        KipukaError::NotFound
    })?;

    // Step 4: Verify that the AKI matches the one in the cert_id.
    // This prevents serial-number enumeration against a different issuer.
    if actual_aki != expected_aki {
        tracing::debug!(
            serial = %serial_hex,
            "AKI mismatch — cert_id references wrong issuer"
        );
        return Err(KipukaError::NotFound);
    }

    // Step 5: Calculate the renewal window.
    let not_after = parse_not_after(&row.not_after).ok_or_else(|| {
        tracing::error!(
            serial = %serial_hex,
            not_after = %row.not_after,
            "failed to parse not_after timestamp"
        );
        KipukaError::Internal("failed to parse certificate expiry".into())
    })?;

    let window_days = state.config.est.renewal_window_days as i64;
    let window_start = not_after - Duration::days(window_days);
    let window_end = not_after - Duration::days(1);

    let body = serde_json::json!({
        "suggestedWindow": {
            "start": window_start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "end": window_end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }
    });

    tracing::debug!(
        serial = %serial_hex,
        window_start = %window_start,
        window_end = %window_end,
        "renewal-info response"
    );

    // Step 6: Build the HTTP response.
    let retry_after = state.config.est.renewal_retry_after_secs;

    let mut resp = (StatusCode::OK, body.to_string()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(hv) = HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, hv);
    }

    Ok(resp)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Database row for the renewal-info query.
#[derive(sqlx::FromRow)]
struct CertRenewalRow {
    #[allow(dead_code)]
    serial: String,
    not_after: String,
    der_encoded: Vec<u8>,
}

/// Extract the AKI `keyIdentifier` from a DER-encoded certificate.
///
/// The Authority Key Identifier extension (OID 2.5.29.35) is encoded as:
///
/// ```text
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier       [0] KeyIdentifier OPTIONAL,
///     ...
/// }
/// KeyIdentifier ::= OCTET STRING
/// ```
///
/// The extension value from `find_extension_value` is the DER encoding of
/// `AuthorityKeyIdentifier`.  We parse the outer SEQUENCE and extract the
/// `[0]` implicit OCTET STRING.
fn extract_aki_key_id(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = synta_certificate::Certificate::from_der(cert_der).ok()?;
    let ext_raw = cert.tbs_certificate.extensions.as_ref()?;
    let aki_der = synta_certificate::find_extension_value(
        ext_raw.as_bytes(),
        synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
    )?;

    // Parse the AKI SEQUENCE to extract keyIdentifier [0].
    //
    // The DER encoding is:
    //   SEQUENCE {
    //     [0] IMPLICIT OCTET STRING (keyIdentifier)   -- tag 0x80
    //     ...optional fields...
    //   }
    //
    // We walk the raw bytes: skip the SEQUENCE tag+length, then look for
    // a context-specific tag [0] (0x80).
    parse_aki_key_identifier(aki_der)
}

/// Parse the keyIdentifier from the raw DER of an AuthorityKeyIdentifier.
fn parse_aki_key_identifier(aki_der: &[u8]) -> Option<Vec<u8>> {
    // The aki_der should be the content of the OCTET STRING wrapping
    // the extension value, which is a SEQUENCE.
    if aki_der.len() < 2 {
        return None;
    }

    let mut pos = 0;

    // Expect SEQUENCE tag (0x30).
    if aki_der[pos] != 0x30 {
        return None;
    }
    pos += 1;

    // Parse the SEQUENCE length.
    let (seq_len, len_bytes) = parse_der_length(&aki_der[pos..])?;
    pos += len_bytes;

    let seq_end = pos + seq_len;
    if seq_end > aki_der.len() {
        return None;
    }

    // Look for [0] IMPLICIT (tag 0x80) within the SEQUENCE.
    while pos < seq_end {
        if pos >= aki_der.len() {
            break;
        }
        let tag = aki_der[pos];
        pos += 1;

        let (field_len, lb) = parse_der_length(&aki_der[pos..])?;
        pos += lb;

        if tag == 0x80 {
            // Found keyIdentifier [0].
            if pos + field_len > aki_der.len() {
                return None;
            }
            return Some(aki_der[pos..pos + field_len].to_vec());
        }

        // Skip this field.
        pos += field_len;
    }

    None
}

/// Parse a DER length field.  Returns `(length, bytes_consumed)`.
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first < 0x80 {
        // Short form: single byte.
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite length — not valid in DER.
        None
    } else {
        // Long form: first byte gives the number of subsequent length bytes.
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || num_bytes + 1 > data.len() {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = length.checked_shl(8)?.checked_add(data[1 + i] as usize)?;
        }
        Some((length, 1 + num_bytes))
    }
}

/// Parse a `not_after` timestamp string from the database.
///
/// The DB stores timestamps as ISO 8601 strings (e.g.,
/// `"2026-07-25T00:00:00Z"`).  We try multiple common formats.
fn parse_not_after(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC 3339 first (most common in our DB).
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try the format without timezone suffix (assume UTC).
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }
    // Try with fractional seconds.
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc());
    }
    None
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aki_from_well_formed_der() {
        // Minimal AKI SEQUENCE with keyIdentifier [0] = 0xDE 0xAD 0xBE 0xEF.
        //
        // SEQUENCE {
        //   [0] IMPLICIT OCTET STRING (4 bytes: DE AD BE EF)
        // }
        let aki_der: &[u8] = &[
            0x30, 0x06, // SEQUENCE, length 6
            0x80, 0x04, // [0] IMPLICIT, length 4
            0xDE, 0xAD, 0xBE, 0xEF,
        ];

        let key_id = parse_aki_key_identifier(aki_der).unwrap();
        assert_eq!(key_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_aki_missing_key_id_returns_none() {
        // AKI SEQUENCE with only authorityCertIssuer [1] — no keyIdentifier.
        let aki_der: &[u8] = &[
            0x30, 0x04, // SEQUENCE, length 4
            0xA1, 0x02, // [1] CONSTRUCTED, length 2
            0x00, 0x00,
        ];

        assert!(parse_aki_key_identifier(aki_der).is_none());
    }

    #[test]
    fn parse_aki_empty_returns_none() {
        assert!(parse_aki_key_identifier(&[]).is_none());
    }

    #[test]
    fn parse_not_after_rfc3339() {
        let dt = parse_not_after("2026-07-25T00:00:00Z").unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 7);
        assert_eq!(dt.day(), 25);
    }

    #[test]
    fn parse_not_after_no_tz() {
        let dt = parse_not_after("2026-07-25T12:30:00").unwrap();
        assert_eq!(dt.hour(), 12);
    }

    #[test]
    fn parse_not_after_invalid_returns_none() {
        assert!(parse_not_after("not-a-date").is_none());
    }

    #[test]
    fn der_length_short_form() {
        let (len, consumed) = parse_der_length(&[0x04]).unwrap();
        assert_eq!(len, 4);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn der_length_long_form_two_bytes() {
        // 0x82 means 2 subsequent bytes encode the length.
        let (len, consumed) = parse_der_length(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn base64url_roundtrip() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let encoded = URL_SAFE_NO_PAD.encode(&data);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    use chrono::Datelike;
    use chrono::Timelike;
}
