//! HTTP routing for the Kipuka EST server.
//!
//! Builds the main axum [`Router`] with three route groups:
//!
//! 1. **EST endpoints** under `/.well-known/est/` (RFC 5785 + RFC 7030)
//! 2. **Per-label EST endpoints** under `/.well-known/est/{label}/` (RFC 7030 §3.2.2)
//! 3. **Admin API** under `/admin/` with separate authentication
//!
//! Middleware applied at the router level:
//! - Body size limit (`[server].max_body_size`, default 64 KiB)
//! - Request tracing (tracing spans per request)
//! - Audit logging for enrollment and admin operations

pub mod admin;
pub mod cacerts;
pub mod cmp;
pub mod cms_est;
pub mod csrattrs;
pub mod est;
pub mod fullcmc;
pub mod serverkeygen;
pub mod simpleenroll;
pub mod simplereenroll;

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts, Path};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::error::KipukaError;
use crate::state::AppState;

/// Build the complete Kipuka HTTP router.
///
/// # Route structure
///
/// ```text
/// /.well-known/est/
///     cacerts          GET   (§4.1)
///     simpleenroll     POST  (§4.2)
///     simplereenroll   POST  (§4.2.2)
///     fullcmc          POST  (§4.3)
///     serverkeygen     POST  (§4.4)
///     csrattrs         GET   (§4.5)
///
/// /.well-known/est/{label}/
///     (same endpoints as above, with per-label CA routing)
///
/// /admin/
///     health           GET
///     health/db        GET
///     health/hsm       GET
///     health/ca        GET
///     cas              GET
///     cas/{id}         GET
///     cas/{id}/health  GET
///     otp/generate     POST
///     otp              GET
///     otp/{id}         DELETE
///     certs            GET
///     certs/{serial}   GET
///     certs/{serial}/revoke POST
/// ```
pub fn build_router(state: Arc<AppState>) -> Router {
    let max_body = state.config.server.max_body_size;

    // EST routes for the default label.
    let est_routes = est::est_router();

    // Per-label EST routes: /.well-known/est/{label}/
    let labeled_est_routes = Router::new()
        .nest("/{label}", est::est_router());

    // Admin routes with separate authentication.
    let admin_routes = admin::admin_router();

    Router::new()
        .nest("/.well-known/est", est_routes)
        .nest("/.well-known/est", labeled_est_routes)
        .nest("/admin", admin_routes)
        // CMS-wrapped EST routes (RFC 8295).
        .nest("/.well-known/est/cms", cms_est::cms_est_router())
        // CMP v3 endpoint (RFC 9810).
        .route("/.well-known/cmp", post(cmp::post_cmp))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "http_request",
                        method = %req.method(),
                        path = %req.uri().path(),
                        version = ?req.version(),
                    )
                }),
        )
        .with_state(state)
}

// ── Label extractor ──────────────────────────────────────────────────────────

/// Resolved EST label configuration for the current request.
///
/// Analogous to Akamu's `CaId` extractor — resolves the `{label}` path
/// segment to the corresponding [`EstLabelConfig`] entry, falling back
/// to the default label when no path segment is present.
///
/// # Usage
///
/// ```rust,ignore
/// async fn handler(label: LabelExtractor, ...) -> impl IntoResponse {
///     let ca_id = label.ca_id();
///     // ...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LabelExtractor {
    /// The resolved label name (empty string for the default label).
    pub label: String,
    /// The CA identifier to use for this label.
    pub ca_id: String,
    /// Whether CN matching is required for this label.
    pub require_cn_match: bool,
    /// Per-label CSR attribute OIDs (overrides global when non-empty).
    pub csr_attributes: Vec<String>,
    /// Per-label maximum validity (overrides CA default).
    pub max_validity_days: Option<u32>,
    /// Per-label disconnected mode override.
    pub disconnected: Option<bool>,
}

impl LabelExtractor {
    /// The effective CA identifier for this label.
    pub fn ca_id(&self) -> &str {
        &self.ca_id
    }
}

impl<S> FromRequestParts<S> for LabelExtractor
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = Arc::<AppState>::from_ref(state);

        // Try to extract the {label} path parameter.
        let label_name: Option<String> = Path::<String>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|Path(l)| l);

        let est_config = &app.config.est;

        match label_name {
            Some(ref name) if !name.is_empty() => {
                // Look up the label in the configured labels.
                let label_config = est_config
                    .labels
                    .iter()
                    .find(|l| l.name == *name)
                    .ok_or_else(|| {
                        tracing::debug!(label = %name, "unknown EST label");
                        KipukaError::NotFound.into_response()
                    })?;

                // Resolve the CA ID: label-specific or default.
                let ca_id = label_config
                    .ca_id
                    .clone()
                    .unwrap_or_else(|| (*app.default_ca_id).clone());

                // Verify the CA exists.
                if app.get_ca(&ca_id).is_none() {
                    tracing::error!(
                        label = %name,
                        ca_id = %ca_id,
                        "label references unknown CA"
                    );
                    return Err(KipukaError::Config(format!(
                        "label {name:?} references unknown CA {ca_id:?}"
                    ))
                    .into_response());
                }

                Ok(LabelExtractor {
                    label: name.clone(),
                    ca_id,
                    require_cn_match: label_config.require_cn_match,
                    csr_attributes: label_config.csr_attributes.clone(),
                    max_validity_days: label_config.max_validity_days,
                    disconnected: label_config.disconnected,
                })
            }
            _ => {
                // Default label — use the default CA.
                let ca_id = (*app.default_ca_id).clone();

                Ok(LabelExtractor {
                    label: String::new(),
                    ca_id,
                    require_cn_match: false,
                    csr_attributes: est_config.csr_attributes.clone(),
                    max_validity_days: None,
                    disconnected: None,
                })
            }
        }
    }
}
