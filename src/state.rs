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

    /// Resolved secrets (never serialized to disk).
    pub secrets: Arc<crate::config::ResolvedSecrets>,

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

    /// Authentication failure tracker / lockout enforcer (FIA_AFL.1).
    ///
    /// Always present; a `max_failures = 0` policy makes every operation a
    /// no-op so the control can be disabled without a `None` branch at call
    /// sites.
    pub failure_tracker: Arc<crate::auth::failure_tracker::FailureTracker>,

    /// HA manager for multi-CA failover (present when HA is configured).
    pub ha_manager: Option<Arc<crate::ha::HaManager>>,

    /// Server-side GSSAPI credential for SPNEGO authentication.
    ///
    /// `None` when GSSAPI is not configured.  When present, the auth
    /// layer uses it to validate `Authorization: Negotiate` tokens.
    pub gss_cred: Option<Arc<dyn std::any::Any + Send + Sync>>,

    /// Whether GSSAPI requires cryptographic ticket verification.
    ///
    /// When `true` (the default), structural-only parsing of Kerberos
    /// tokens is rejected — libgssapi integration is required.  When
    /// `false`, the server accepts structural parsing and returns a
    /// `krb5-sname:` prefixed identity (the service name from the ticket,
    /// not a verified client identity).
    pub gssapi_require_crypto: bool,

    /// Dogtag PKI client pool (present when `[dogtag]` is configured).
    ///
    /// Routes enrollment, CMC, and key generation requests to Dogtag CA/KRA
    /// backends when configured as an alternative to direct signing.
    pub dogtag: Option<Arc<kipuka_dogtag::DogtagPool>>,

    /// STAR certificate manager (present when `[star]` is enabled).
    ///
    /// Manages active STAR orders and their renewal state (RFC 8739).
    pub star_manager: Option<Arc<crate::star::StarManager>>,

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

    /// Returns the DER-encoded certificate of the default CA.
    ///
    /// Used by the OCSP client (RFC 6960) to build CertID structures for
    /// revocation checking of client certificates (RHELBU-3536 R21).
    /// Returns `None` if no default CA is configured or the cert is empty.
    pub fn default_ca_cert_der(&self) -> Option<Vec<u8>> {
        let ca = self.default_ca();
        if ca.cert_der.is_empty() {
            None
        } else {
            Some(ca.cert_der.clone())
        }
    }

    /// Record an audit event, logging (but not propagating) any DB error.
    ///
    /// Convenience wrapper that bundles the DB pool and audit state so
    /// call sites only need to pass the event type and detail.
    pub async fn record_audit_event(&self, event_type: &str, detail: &str) {
        crate::audit::record(
            &self.db,
            &self.audit,
            crate::audit::AuditEvent::new(Self::audit_type_for(event_type)).with_detail(detail),
        )
        .await;
    }

    /// Record an audit event that carries a responsible actor identity.
    ///
    /// Populates the `actor` column (via [`AuditEvent::with_operator`]) so the
    /// FAU_SAR.1 review endpoint can filter by actor.  Used where the
    /// responsible principal is known — enrollment-authorization denials
    /// (FDP_ACF.1) and audit-trail review — so those events are attributable
    /// rather than leaving `actor` NULL and the filter inert.
    ///
    /// [`AuditEvent::with_operator`]: crate::audit::AuditEvent::with_operator
    pub async fn record_audit_event_with_actor(&self, event_type: &str, actor: &str, detail: &str) {
        crate::audit::record(
            &self.db,
            &self.audit,
            crate::audit::AuditEvent::new(Self::audit_type_for(event_type))
                .with_operator(actor)
                .with_detail(detail),
        )
        .await;
    }

    /// Map a string event type to its [`crate::audit::AuditEventType`].
    ///
    /// Unrecognised types default to
    /// [`AdminAction`](crate::audit::AuditEventType::AdminAction) so an event is
    /// never silently dropped.
    fn audit_type_for(event_type: &str) -> crate::audit::AuditEventType {
        match event_type {
            "cacerts" => crate::audit::AuditEventType::EnrollRequest,
            "simpleenroll_success" | "simpleenroll_deferred" => {
                crate::audit::AuditEventType::CertIssue
            }
            "simplereenroll_success" => crate::audit::AuditEventType::CertReenroll,
            "fullcmc_success" => crate::audit::AuditEventType::CertIssue,
            "serverkeygen_success" => crate::audit::AuditEventType::CertIssue,
            // Enrollment-authorization denials (FDP_ACF.1) across every
            // transport map to the enroll.reject taxonomy so they are
            // filterable as a class and not lumped under the admin.action
            // default.  They are not SecurityViolation: a denial is an access
            // decision, not an alarm condition, and must not trip FAU_ARP.1.
            "simpleenroll_denied"
            | "simplereenroll_denied"
            | "serverkeygen_denied"
            | "cms_simpleenroll_denied"
            | "cms_simplereenroll_denied"
            | "cms_serverkeygen_denied" => crate::audit::AuditEventType::EnrollReject,
            "otp_generated" => crate::audit::AuditEventType::OtpCreate,
            "otp_revoked" => crate::audit::AuditEventType::OtpRevoke,
            "otp_auth_failure" => crate::audit::AuditEventType::AuthFailure,
            // FIA_AFL.1 threshold reached — a security-relevant event that also
            // trips the NIAP alarm counter (FAU_ARP.1) via SecurityViolation.
            "auth_lockout" => crate::audit::AuditEventType::SecurityViolation,
            "cert_revoked" => crate::audit::AuditEventType::CertRevoke,
            "star_order_created" | "star_renewal_success" => {
                crate::audit::AuditEventType::CertIssue
            }
            "star_order_cancelled" | "admin_audit_review" => {
                crate::audit::AuditEventType::AdminAction
            }
            // EST-coaps transport (RFC 9148) — mirror the HTTP taxonomy so the
            // FAU_SAR.1 review endpoint can filter CoAP events by class rather
            // than lumping them under the admin.action default.  Denials map to
            // enroll.reject (an access decision, not a SecurityViolation alarm),
            // matching the HTTP `*_denied` events above.
            "coap_cacerts" | "coap_csrattrs" => crate::audit::AuditEventType::EnrollRequest,
            "coap_simpleenroll" => crate::audit::AuditEventType::CertIssue,
            "coap_simplereenroll" => crate::audit::AuditEventType::CertReenroll,
            "coap_simpleenroll_denied" | "coap_simplereenroll_denied" => {
                crate::audit::AuditEventType::EnrollReject
            }
            _ => crate::audit::AuditEventType::AdminAction,
        }
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
    secrets: Option<Arc<crate::config::ResolvedSecrets>>,
    db: Option<sqlx::AnyPool>,
    db_ro: Option<sqlx::AnyPool>,
    db_kind: Option<crate::db::DbKind>,
    cas: Option<Arc<IndexMap<String, Arc<CaState>>>>,
    default_ca_id: Option<Arc<String>>,
    otp_store: Option<Arc<kipuka_otp::OtpStore>>,
    hsm: Option<Arc<kipuka_hsm::HsmContext>>,
    audit: Option<Arc<AuditState>>,
    failure_tracker: Option<Arc<crate::auth::failure_tracker::FailureTracker>>,
    ha_manager: Option<Arc<crate::ha::HaManager>>,
    gss_cred: Option<Arc<dyn std::any::Any + Send + Sync>>,
    gssapi_require_crypto: bool,
    dogtag: Option<Arc<kipuka_dogtag::DogtagPool>>,
    star_manager: Option<Arc<crate::star::StarManager>>,
}

impl AppStateBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            config: None,
            secrets: None,
            db: None,
            db_ro: None,
            db_kind: None,
            cas: None,
            default_ca_id: None,
            otp_store: None,
            hsm: None,
            audit: None,
            failure_tracker: None,
            ha_manager: None,
            gss_cred: None,
            gssapi_require_crypto: true,
            dogtag: None,
            star_manager: None,
        }
    }

    pub fn config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn secrets(mut self, secrets: Arc<crate::config::ResolvedSecrets>) -> Self {
        self.secrets = Some(secrets);
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

    pub fn failure_tracker(
        mut self,
        tracker: Arc<crate::auth::failure_tracker::FailureTracker>,
    ) -> Self {
        self.failure_tracker = Some(tracker);
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

    pub fn gssapi_require_crypto(mut self, require: bool) -> Self {
        self.gssapi_require_crypto = require;
        self
    }

    pub fn dogtag(mut self, pool: Arc<kipuka_dogtag::DogtagPool>) -> Self {
        self.dogtag = Some(pool);
        self
    }

    pub fn star_manager(mut self, manager: Arc<crate::star::StarManager>) -> Self {
        self.star_manager = Some(manager);
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
        let config = self.config.expect("config is required");

        // Derive the failure tracker from `[auth_lockout]` when not supplied.
        let failure_tracker = self.failure_tracker.unwrap_or_else(|| {
            Arc::new(crate::auth::failure_tracker::FailureTracker::new(
                config.auth_lockout.to_policy(),
            ))
        });

        AppState {
            config,
            secrets: self.secrets.expect("secrets is required"),
            db,
            db_ro,
            db_kind: self.db_kind.expect("db_kind is required"),
            cas: self.cas.expect("cas is required"),
            default_ca_id: self.default_ca_id.expect("default_ca_id is required"),
            otp_store: self.otp_store,
            hsm: self.hsm,
            audit: self.audit.expect("audit is required"),
            failure_tracker,
            ha_manager: self.ha_manager,
            gss_cred: self.gss_cred,
            gssapi_require_crypto: self.gssapi_require_crypto,
            dogtag: self.dogtag,
            star_manager: self.star_manager,
            startup_time: Instant::now(),
        }
    }
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}
