//! Shared application state threaded through axum handlers via `Arc<AppState>`.
//!
//! `AppState` is constructed once at startup and cloned (cheaply, via `Arc`)
//! into every axum handler.  It holds the parsed config, database pools,
//! per-CA key material, and optional subsystem state (HSM, OTP, audit).

use std::sync::Arc;
use std::time::Instant;

use indexmap::IndexMap;

use crate::audit::AuditState;
use crate::config::Config;

/// Top-level application state cloned into every axum handler.
#[derive(Clone)]
pub struct AppState {
    /// Parsed and validated configuration.
    pub config: Arc<Config>,

    /// Primary database connection pool (read-write).
    pub db: sqlx::AnyPool,

    /// Read-only database connection pool.
    ///
    /// For SQLite WAL mode, this is a `?mode=ro` pool that never acquires
    /// the write lock, enabling concurrent reads during writes.  For
    /// PostgreSQL/MariaDB, this is a clone of `db` (MVCC handles
    /// concurrency natively).
    pub db_ro: sqlx::AnyPool,

    /// Database backend discriminant (drives `BEGIN IMMEDIATE` for SQLite).
    pub db_kind: crate::db::DbKind,

    /// All CAs keyed by their `id`, in config declaration order.
    pub cas: Arc<IndexMap<String, Arc<CaState>>>,

    /// The CA designated as the default for unlabeled EST requests.
    pub default_ca_id: Arc<String>,

    /// OTP store (present when `[otp]` is enabled).
    pub otp_store: Option<Arc<kipuka_otp::OtpStore>>,

    /// HSM context (present when `[hsm]` is configured).
    pub hsm: Option<Arc<kipuka_hsm::HsmContext>>,

    /// Shared audit state (overflow flag, alarm counter).
    pub audit: Arc<AuditState>,

    /// HA manager for multi-CA failover (present when HA is configured).
    pub ha_manager: Option<Arc<crate::ha::HaManager>>,

    /// Server-side GSSAPI credential for SPNEGO authentication.
    ///
    /// `None` when GSSAPI is not configured.  When present, the auth
    /// layer uses it to validate `Authorization: Negotiate` tokens.
    pub gss_cred: Option<Arc<dyn std::any::Any + Send + Sync>>,

    /// Timestamp when the server process started.
    ///
    /// Used for uptime reporting in health endpoints and session
    /// expiry calculations.
    pub startup_time: Instant,
}

impl AppState {
    /// Return the default CA state.
    ///
    /// # Panics
    ///
    /// Panics if `default_ca_id` is not present in `cas`.  This indicates
    /// a bug in the startup code — `Config::validate()` ensures the
    /// default CA exists.
    pub fn default_ca(&self) -> &Arc<CaState> {
        self.cas
            .get(self.default_ca_id.as_str())
            .expect("default CA always present in cas")
    }

    /// Look up a CA by its identifier.  Returns `None` for unknown IDs.
    pub fn get_ca(&self, ca_id: &str) -> Option<&Arc<CaState>> {
        self.cas.get(ca_id)
    }

    /// Record an audit event, logging (but not propagating) any DB error.
    ///
    /// Convenience wrapper that bundles the DB pool and audit state so
    /// call sites only need to pass the event type and detail.
    pub async fn record_audit_event(&self, event_type: &str, detail: &str) {
        // Map the string event type to the enum; default to AdminAction
        // for unrecognised types so we never silently drop events.
        let audit_type = match event_type {
            "cacerts" => crate::audit::AuditEventType::EnrollRequest,
            "simpleenroll_success" | "simpleenroll_deferred" => {
                crate::audit::AuditEventType::CertIssue
            }
            "simplereenroll_success" => crate::audit::AuditEventType::CertReenroll,
            "fullcmc_success" => crate::audit::AuditEventType::CertIssue,
            "serverkeygen_success" => crate::audit::AuditEventType::CertIssue,
            "otp_generated" => crate::audit::AuditEventType::OtpCreate,
            "otp_revoked" => crate::audit::AuditEventType::OtpRevoke,
            "otp_auth_failure" => crate::audit::AuditEventType::AuthFailure,
            "cert_revoked" => crate::audit::AuditEventType::CertRevoke,
            _ => crate::audit::AuditEventType::AdminAction,
        };

        crate::audit::record(
            &self.db,
            &self.audit,
            crate::audit::AuditEvent::new(audit_type).with_detail(detail),
        )
        .await;
    }
}

/// Per-CA key material and issuance policy.
///
/// One `CaState` is created for each `[[ca]]` config entry at startup.
/// The signing key and certificate chain are loaded once and shared
/// across all concurrent handler tasks via `Arc<CaState>`.
pub struct CaState {
    /// Unique identifier (matches `CaConfig.id`).
    pub id: String,

    /// Key type string from config, e.g., `"ec:P-256"` or `"rsa:2048"`.
    pub key_type: String,

    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,

    /// Full certificate chain (CA cert + intermediates) as DER blobs.
    ///
    /// Used for the `/cacerts` EST endpoint (RFC 7030 §4.1).
    pub cert_chain: Vec<Vec<u8>>,

    /// Hash algorithm string, e.g., `"sha256"`.
    pub hash_algorithm: String,

    /// Default validity period for issued certificates.
    pub validity_days: u32,

    /// Optional CRL distribution point URL.
    pub crl_url: Option<String>,

    /// Optional OCSP responder URL.
    pub ocsp_url: Option<String>,

    /// In-memory CRL cache: DER bytes + expiry instant.
    ///
    /// Populated lazily on the first CRL request; invalidated after
    /// revocation events.
    pub crl_cache: parking_lot::Mutex<Option<(Vec<u8>, std::time::Instant)>>,

    /// CA/B Forum compliance enforcement.
    pub cab_forum_compliant: bool,
}

/// Builder for constructing `AppState` during server startup.
///
/// Each setter returns `&mut Self` for chaining.  Call [`build`](`AppStateBuilder::build`)
/// to produce the final `AppState`.
pub struct AppStateBuilder {
    config: Option<Arc<Config>>,
    db: Option<sqlx::AnyPool>,
    db_ro: Option<sqlx::AnyPool>,
    db_kind: Option<crate::db::DbKind>,
    cas: Option<Arc<IndexMap<String, Arc<CaState>>>>,
    default_ca_id: Option<Arc<String>>,
    otp_store: Option<Arc<kipuka_otp::OtpStore>>,
    hsm: Option<Arc<kipuka_hsm::HsmContext>>,
    audit: Option<Arc<AuditState>>,
    ha_manager: Option<Arc<crate::ha::HaManager>>,
    gss_cred: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl AppStateBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            config: None,
            db: None,
            db_ro: None,
            db_kind: None,
            cas: None,
            default_ca_id: None,
            otp_store: None,
            hsm: None,
            audit: None,
            ha_manager: None,
            gss_cred: None,
        }
    }

    pub fn config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn db(mut self, pool: sqlx::AnyPool) -> Self {
        self.db = Some(pool);
        self
    }

    pub fn db_ro(mut self, pool: sqlx::AnyPool) -> Self {
        self.db_ro = Some(pool);
        self
    }

    pub fn db_kind(mut self, kind: crate::db::DbKind) -> Self {
        self.db_kind = Some(kind);
        self
    }

    pub fn cas(mut self, cas: IndexMap<String, Arc<CaState>>) -> Self {
        self.cas = Some(Arc::new(cas));
        self
    }

    pub fn default_ca_id(mut self, id: String) -> Self {
        self.default_ca_id = Some(Arc::new(id));
        self
    }

    pub fn otp_store(mut self, store: Arc<kipuka_otp::OtpStore>) -> Self {
        self.otp_store = Some(store);
        self
    }

    pub fn hsm(mut self, ctx: Arc<kipuka_hsm::HsmContext>) -> Self {
        self.hsm = Some(ctx);
        self
    }

    pub fn audit(mut self, state: Arc<AuditState>) -> Self {
        self.audit = Some(state);
        self
    }

    pub fn ha_manager(mut self, manager: Arc<crate::ha::HaManager>) -> Self {
        self.ha_manager = Some(manager);
        self
    }

    pub fn gss_cred(mut self, cred: Arc<dyn std::any::Any + Send + Sync>) -> Self {
        self.gss_cred = Some(cred);
        self
    }

    /// Build the final `AppState`.
    ///
    /// # Panics
    ///
    /// Panics if required fields (`config`, `db`, `db_kind`, `cas`,
    /// `default_ca_id`, `audit`) are not set.
    pub fn build(self) -> AppState {
        let db = self.db.expect("db is required");
        let db_ro = self.db_ro.unwrap_or_else(|| db.clone());

        AppState {
            config: self.config.expect("config is required"),
            db,
            db_ro,
            db_kind: self.db_kind.expect("db_kind is required"),
            cas: self.cas.expect("cas is required"),
            default_ca_id: self.default_ca_id.expect("default_ca_id is required"),
            otp_store: self.otp_store,
            hsm: self.hsm,
            audit: self.audit.expect("audit is required"),
            ha_manager: self.ha_manager,
            gss_cred: self.gss_cred,
            startup_time: Instant::now(),
        }
    }
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}
