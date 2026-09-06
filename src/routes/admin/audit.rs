//! Audit-trail query endpoint for the admin API.
//!
//! NIAP CA PP FAU_SAR.1 (audit review): authorised administrators — both
//! operators and auditors — may read the audit trail.  This endpoint is
//! **read-only**; it never mutates the trail, so it is available to the
//! [`AdminRole::Auditor`](super::AdminRole::Auditor) role as well as
//! operators.
//!
//! Audit-record *integrity verification* (hash-chain checking) is a separate
//! concern tracked on its own branch; this endpoint only lists stored events.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::AdminAuth;
use crate::state::AppState;

/// Query parameters for audit-trail listing.
#[derive(Deserialize)]
pub struct ListAuditQuery {
    /// Filter by event type (stored `event_type` string, e.g. `auth.failure`).
    pub event_type: Option<String>,

    /// Filter by actor (the identity that triggered the event).
    pub actor: Option<String>,

    /// Maximum number of results to return (capped at 1000).
    #[serde(default = "default_limit")]
    pub limit: u32,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    50
}

/// A single audit event as returned to the client.
#[derive(Serialize, sqlx::FromRow)]
pub struct AuditEventSummary {
    /// Monotonic event identifier.
    pub id: i64,

    /// Event timestamp (RFC 3339).
    pub timestamp: String,

    /// Event type string (e.g. `cert.revoke`, `auth.failure`).
    pub event_type: String,

    /// Identity that triggered the event, if recorded.
    pub actor: Option<String>,

    /// Target of the event (e.g. certificate serial), if recorded.
    pub target: Option<String>,

    /// Free-form JSON detail payload, if recorded.
    pub detail_json: Option<String>,

    /// Source IP address, if recorded.
    pub source_ip: Option<String>,
}

/// `GET /admin/audit` — list audit-trail events (read-only).
///
/// Available to both operators and auditors (FAU_SAR.1).  Supports filtering
/// by `event_type` and `actor`, and offset/limit pagination.  Results are
/// ordered newest-first.
pub async fn list_audit_events(
    admin: AdminAuth,
    Query(query): Query<ListAuditQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Read-only: no `require_operator()` — auditors are permitted here.
    tracing::debug!(
        identity = %admin.identity,
        event_type = ?query.event_type,
        actor = ?query.actor,
        limit = query.limit,
        offset = query.offset,
        "listing audit events"
    );

    let limit = query.limit.min(1000);

    let events = match list_audit_from_db(
        &state.db_ro,
        query.event_type.as_deref(),
        query.actor.as_deref(),
        limit,
        query.offset,
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "failed to list audit events from database");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "database_error",
                    "detail": "failed to query audit trail"
                })),
            )
                .into_response();
        }
    };

    // Record the review itself — reading the audit trail is a security-relevant
    // administrative action (FAU_SAR.1 / accountability).
    state
        .record_audit_event_with_actor(
            "admin_audit_review",
            &admin.identity,
            &format!(
                "count={}, filter_event_type={:?}, filter_actor={:?}",
                events.len(),
                query.event_type,
                query.actor
            ),
        )
        .await;

    (StatusCode::OK, Json(events)).into_response()
}

/// Query the audit trail from the database with optional filters.
async fn list_audit_from_db(
    db: &sqlx::AnyPool,
    event_type: Option<&str>,
    actor: Option<&str>,
    limit: u32,
    offset: u32,
) -> Result<Vec<AuditEventSummary>, String> {
    // Build the WHERE clause dynamically using `?` placeholders (rewritten for
    // PostgreSQL by `pg_sql_dynamic`).
    let mut conditions = Vec::new();
    if event_type.is_some() {
        conditions.push("event_type = ?");
    }
    if actor.is_some() {
        conditions.push("actor = ?");
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = crate::db::pg_sql_dynamic(format!(
        "SELECT id, timestamp, event_type, actor, target, detail_json, source_ip \
         FROM audit_events {where_clause} \
         ORDER BY id DESC \
         LIMIT ? OFFSET ?"
    ));

    let mut q = sqlx::query_as::<_, AuditEventSummary>(&sql);
    if let Some(et) = event_type {
        q = q.bind(et.to_string());
    }
    if let Some(ac) = actor {
        q = q.bind(ac.to_string());
    }
    q = q.bind(limit as i64).bind(offset as i64);

    q.fetch_all(db)
        .await
        .map_err(|e| format!("audit query failed: {e}"))
}
