//! Structured audit trail (NIAP CA PP FAU family).
//!
//! All EST and administrative operations that must be logged for Common
//! Criteria evaluation call [`record`].  The function inserts one row into
//! `audit_events`, enforces the overflow policy (FAU_STG.4), and maintains
//! the rolling security-violation counter for the alarm response (FAU_ARP.1).
//!
//! # NIAP CA PP requirements implemented
//!
//! | SFR | Requirement | Implementation |
//! |-----|-------------|----------------|
//! | FAU_GEN.1 | Audit record generation | [`AuditEventType`] taxonomy covers all required events |
//! | FAU_STG.1(1) | Audit trail protection | Append-only at application level |
//! | FAU_STG.4 | Audit storage exhaustion | `OverflowAction::Halt` rejects EST operations |
//! | FAU_ARP.1 | Security alarm | Alarm after N consecutive violations |

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Every auditable operation the server can perform.
///
/// NIAP CA PP FAU_GEN.1: the following categories of events MUST be
/// auditable:
///
/// - Certificate lifecycle (enrollment, re-enrollment, rejection, revocation)
/// - Key management (generation, destruction, HSM operations)
/// - OTP lifecycle (creation, usage, expiration, revocation)
/// - Authentication events (success, failure)
/// - Administrative operations (login, logout, config changes)
/// - CA health status changes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    // ── CA lifecycle ─────────────────────────────────────────────────────
    /// CA started or restarted.
    CaStart,
    /// CA stopped (graceful shutdown).
    CaStop,
    /// CA health status changed (degraded, recovered).
    CaHealthChange,

    // ── Certificate lifecycle ────────────────────────────────────────────
    /// Certificate enrollment request received.
    EnrollRequest,
    /// Certificate issued successfully.
    CertIssue,
    /// Certificate re-enrollment completed.
    CertReenroll,
    /// Enrollment request rejected.
    EnrollReject,
    /// Certificate revoked.
    CertRevoke,
    /// CRL generated.
    CrlGenerate,

    // ── Key management ───────────────────────────────────────────────────
    /// Signing key generated (software or HSM).
    KeyGenerate,
    /// Signing key loaded from file or HSM.
    KeyLoad,
    /// Key destroyed or deactivated.
    KeyDestroy,

    // ── OTP lifecycle (RHELBU-3536 R7) ───────────────────────────────────
    /// OTP created by administrator.
    OtpCreate,
    /// OTP used for enrollment authentication.
    OtpUse,
    /// OTP expired (TTL reached).
    OtpExpire,
    /// OTP revoked by administrator.
    OtpRevoke,

    // ── Authentication ───────────────────────────────────────────────────
    /// Client authentication succeeded (mTLS, OTP, Basic, etc.).
    AuthSuccess,
    /// Client authentication failed.
    AuthFailure,

    // ── Admin operations ─────────────────────────────────────────────────
    /// Admin operator logged in.
    AdminLogin,
    /// Admin operator logged out.
    AdminLogout,
    /// Admin performed a privileged operation.
    AdminAction,

    // ── Security anomalies ───────────────────────────────────────────────
    /// Security violation detected (repeated auth failures, etc.).
    SecurityViolation,
}

impl AuditEventType {
    /// Return the canonical dot-separated string for this event type.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEventType::CaStart => "ca.start",
            AuditEventType::CaStop => "ca.stop",
            AuditEventType::CaHealthChange => "ca.health-change",
            AuditEventType::EnrollRequest => "enroll.request",
            AuditEventType::CertIssue => "cert.issue",
            AuditEventType::CertReenroll => "cert.reenroll",
            AuditEventType::EnrollReject => "enroll.reject",
            AuditEventType::CertRevoke => "cert.revoke",
            AuditEventType::CrlGenerate => "crl.generate",
            AuditEventType::KeyGenerate => "key.generate",
            AuditEventType::KeyLoad => "key.load",
            AuditEventType::KeyDestroy => "key.destroy",
            AuditEventType::OtpCreate => "otp.create",
            AuditEventType::OtpUse => "otp.use",
            AuditEventType::OtpExpire => "otp.expire",
            AuditEventType::OtpRevoke => "otp.revoke",
            AuditEventType::AuthSuccess => "auth.success",
            AuditEventType::AuthFailure => "auth.failure",
            AuditEventType::AdminLogin => "admin.login",
            AuditEventType::AdminLogout => "admin.logout",
            AuditEventType::AdminAction => "admin.action",
            AuditEventType::SecurityViolation => "security.violation",
        }
    }
}

/// A single audit event ready for recording.
pub struct AuditEvent {
    /// The type of auditable event.
    pub event_type: AuditEventType,
    /// CA identifier (when the event is CA-specific).
    pub ca_id: Option<String>,
    /// Subject of the event (e.g., certificate subject DN, operator name).
    pub subject: Option<String>,
    /// Human-readable detail string.
    pub detail: Option<String>,
    /// Client IP address (when applicable).
    pub client_addr: Option<String>,
    /// Operator identity (for admin actions).
    pub operator: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event with the given type.
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            ca_id: None,
            subject: None,
            detail: None,
            client_addr: None,
            operator: None,
        }
    }

    /// Builder: set the CA ID.
    pub fn with_ca_id(mut self, ca_id: impl Into<String>) -> Self {
        self.ca_id = Some(ca_id.into());
        self
    }

    /// Builder: set the subject.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Builder: set the detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Builder: set the client address.
    pub fn with_client_addr(mut self, addr: impl Into<String>) -> Self {
        self.client_addr = Some(addr.into());
        self
    }

    /// Builder: set the operator.
    pub fn with_operator(mut self, operator: impl Into<String>) -> Self {
        self.operator = Some(operator.into());
        self
    }
}

/// Shared audit state (overflow flag, alarm counter).
///
/// Lives in `AppState` and survives the lifetime of the server process.
/// Callers pass the database pool explicitly so the same state can be
/// used from any async context.
pub struct AuditState {
    /// When `true`, EST operations MUST be rejected (FAU_STG.4 halt).
    pub halted: AtomicBool,
    config: crate::config::AuditConfig,
    write_lock: tokio::sync::Mutex<()>,

    /// Rolling count of consecutive security violations.
    /// Reset to 0 after a successful authentication.
    pub violation_count: AtomicU32,
}

impl AuditState {
    /// Create a new audit state with no violations and not halted.
    pub fn new() -> Self {
        Self::with_config(crate::config::AuditConfig::default())
    }

    pub fn with_config(config: crate::config::AuditConfig) -> Self {
        Self {
            config,
            write_lock: tokio::sync::Mutex::new(()),
            halted: AtomicBool::new(false),
            violation_count: AtomicU32::new(0),
        }
    }

    /// Check whether EST operations should be rejected due to audit
    /// storage exhaustion (FAU_STG.4).
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::Relaxed)
    }

    /// Set the halted flag (called when audit storage is full and
    /// overflow policy is `halt`).
    pub fn set_halted(&self, halted: bool) {
        self.halted.store(halted, Ordering::Relaxed);
    }

    /// Increment the security violation counter and return the new count.
    pub fn record_violation(&self) -> u32 {
        self.violation_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reset the violation counter (called after successful authentication).
    pub fn reset_violations(&self) {
        self.violation_count.store(0, Ordering::Relaxed);
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}

/// Record an audit event to the database.
///
/// When the database insert fails, the error is logged but not propagated
/// to avoid failing EST operations due to audit backend issues (unless
/// the overflow policy requires halting).
pub async fn record(pool: &sqlx::AnyPool, state: &AuditState, event: AuditEvent) {
    if let Err(error) = record_checked(pool, state, event).await {
        tracing::error!(%error, "audit event could not be persisted");
    }
}

/// Persist an event before a security-sensitive operation; propagate failure.
pub async fn record_checked(
    pool: &sqlx::AnyPool,
    state: &AuditState,
    event: AuditEvent,
) -> Result<(), crate::error::KipukaError> {
    if !state.config.enabled {
        return Ok(());
    }
    let _guard = state.write_lock.lock().await;
    let result = record_inner(pool, state, event).await;
    if result.is_err() && state.config.overflow_policy == crate::config::OverflowPolicy::Halt {
        state.set_halted(true);
    }
    result
}

async fn record_inner(
    pool: &sqlx::AnyPool,
    state: &AuditState,
    event: AuditEvent,
) -> Result<(), crate::error::KipukaError> {
    use crate::error::KipukaError;
    if state.is_halted() {
        return Err(KipukaError::Db("audit operation admission halted".into()));
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| KipukaError::Db(e.to_string()))?;
    write_event(&mut tx, state, &event).await?;
    tx.commit()
        .await
        .map_err(|e| KipukaError::Db(e.to_string()))?;

    // Track security violations for FAU_ARP.1
    if event.event_type == AuditEventType::SecurityViolation {
        let count = state.record_violation();
        if count >= state.config.alarm_threshold {
            tracing::error!(count, "AUDIT SECURITY ALARM");
            if state.config.alarm_action == "halt" {
                state.set_halted(true);
            } else {
                emit_syslog_alarm(count)
                    .map_err(|e| KipukaError::Db(format!("audit syslog alarm failed: {e}")))?;
            }
        }
        tracing::warn!(
            consecutive_violations = count,
            "security violation recorded"
        );
    } else if event.event_type == AuditEventType::AuthSuccess {
        state.reset_violations();
    }
    Ok(())
}

/// Persist issuance auditing in the same transaction as certificate inventory.
/// The caller must commit before publishing the certificate. Failures roll back
/// both records; the database writer lock also enforces cross-process row bounds.
pub(crate) async fn record_issuance_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    state: &AuditState,
    ca_id: &str,
    detail: String,
) -> Result<(), crate::error::KipukaError> {
    if !state.config.enabled {
        return Ok(());
    }
    let event = AuditEvent::new(AuditEventType::CertIssue)
        .with_ca_id(ca_id)
        .with_detail(detail);
    let result = write_event(tx, state, &event).await;
    if result.is_err() && state.config.overflow_policy == crate::config::OverflowPolicy::Halt {
        state.set_halted(true);
    }
    result
}

/// Commit inventory and issuance audit atomically, latching halt on durability failure.
pub(crate) async fn commit_issuance(
    tx: sqlx::Transaction<'_, sqlx::Any>,
    state: &AuditState,
) -> Result<(), crate::error::KipukaError> {
    if let Err(error) = tx.commit().await {
        if state.config.enabled
            && state.config.overflow_policy == crate::config::OverflowPolicy::Halt
        {
            state.set_halted(true);
        }
        return Err(error.into());
    }
    Ok(())
}

async fn write_event(
    connection: &mut sqlx::AnyConnection,
    state: &AuditState,
    event: &AuditEvent,
) -> Result<(), crate::error::KipukaError> {
    use crate::error::KipukaError;
    if state.is_halted() {
        return Err(KipukaError::Db("audit operation admission halted".into()));
    }
    // A database row lock serializes admission across distinct server processes.
    // Acquire it before COUNT so bounded storage cannot race another writer.
    sqlx::query("UPDATE audit_writer_lock SET revision = revision WHERE id = 1")
        .execute(&mut *connection)
        .await
        .map_err(|e| KipukaError::Db(e.to_string()))?;
    if let Some(limit) = state.config.max_rows {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&mut *connection)
            .await
            .map_err(|e| KipukaError::Db(e.to_string()))?;
        if count >= limit as i64 {
            if state.config.overflow_policy == crate::config::OverflowPolicy::Halt {
                return Err(KipukaError::Db("audit storage row limit reached".into()));
            }
            let ids: Vec<i64> = sqlx::query_scalar(crate::db::pg_sql(
                "SELECT id FROM audit_events ORDER BY id LIMIT ?",
            ))
            .bind(count - limit as i64 + 1)
            .fetch_all(&mut *connection)
            .await
            .map_err(|e| KipukaError::Db(e.to_string()))?;
            for id in ids {
                sqlx::query(crate::db::pg_sql("DELETE FROM audit_events WHERE id = ?"))
                    .bind(id)
                    .execute(&mut *connection)
                    .await
                    .map_err(|e| KipukaError::Db(e.to_string()))?;
            }
        }
    }
    // Pack detail into detail_json with proper JSON escaping (no
    // format!() interpolation that could allow injection via quotes or
    // backslashes in detail/ca_id values).
    let detail_json = match (&event.detail, &event.ca_id) {
        (Some(d), Some(ca)) => Some(serde_json::json!({"detail": d, "ca_id": ca}).to_string()),
        (Some(d), None) => Some(serde_json::json!({"detail": d}).to_string()),
        (None, Some(ca)) => Some(serde_json::json!({"ca_id": ca}).to_string()),
        (None, None) => None,
    };

    let sql = crate::db::pg_sql(
        "INSERT INTO audit_events (event_type, actor, target, detail_json, source_ip, session_id) \
         VALUES (?, ?, ?, ?, ?, ?)",
    );
    let result = sqlx::query(sql)
        .bind(event.event_type.as_str())
        .bind(&event.operator)
        .bind(&event.subject)
        .bind(&detail_json)
        .bind(&event.client_addr)
        .bind(None::<String>)
        .execute(&mut *connection)
        .await;

    result.map_err(|e| KipukaError::Db(format!("audit insert failed: {e}")))?;
    Ok(())
}

/// Send an actual LOG_AUTHPRIV/LOG_ALERT datagram to the system logger.
#[cfg(unix)]
fn emit_syslog_alarm(count: u32) -> std::io::Result<()> {
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(1)))?;
    #[cfg(target_os = "macos")]
    let path = "/var/run/syslog";
    #[cfg(not(target_os = "macos"))]
    let path = "/dev/log";
    socket.connect(path)?;
    socket.send(
        format!("<81>kipuka: audit security alarm: {count} consecutive violations").as_bytes(),
    )?;
    Ok(())
}
#[cfg(not(unix))]
fn emit_syslog_alarm(_: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "syslog requires Unix",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_strings() {
        assert_eq!(AuditEventType::CaStart.as_str(), "ca.start");
        assert_eq!(AuditEventType::CertIssue.as_str(), "cert.issue");
        assert_eq!(AuditEventType::OtpCreate.as_str(), "otp.create");
        assert_eq!(AuditEventType::AuthFailure.as_str(), "auth.failure");
        assert_eq!(AuditEventType::AdminLogin.as_str(), "admin.login");
        assert_eq!(
            AuditEventType::SecurityViolation.as_str(),
            "security.violation"
        );
    }

    #[test]
    fn audit_state_violation_tracking() {
        let state = AuditState::new();
        assert_eq!(state.record_violation(), 1);
        assert_eq!(state.record_violation(), 2);
        state.reset_violations();
        assert_eq!(state.record_violation(), 1);
    }

    #[test]
    fn audit_state_halt_flag() {
        let state = AuditState::new();
        assert!(!state.is_halted());
        state.set_halted(true);
        assert!(state.is_halted());
        state.set_halted(false);
        assert!(!state.is_halted());
    }

    #[test]
    fn audit_event_builder() {
        let event = AuditEvent::new(AuditEventType::CertIssue)
            .with_ca_id("production")
            .with_subject("CN=device.example.com")
            .with_detail("serial=ABC123")
            .with_client_addr("10.0.0.1");

        assert_eq!(event.event_type, AuditEventType::CertIssue);
        assert_eq!(event.ca_id.as_deref(), Some("production"));
        assert_eq!(event.subject.as_deref(), Some("CN=device.example.com"));
        assert_eq!(event.detail.as_deref(), Some("serial=ABC123"));
        assert_eq!(event.client_addr.as_deref(), Some("10.0.0.1"));
        assert!(event.operator.is_none());
    }
}

#[cfg(test)]
mod issuance_commit_tests {
    use super::*;
    #[tokio::test]
    async fn failed_commit_rolls_back_audit_and_latches_halt() {
        let (db, kind) =
            crate::db::init_pool(&crate::config::DbConfig::default(), "sqlite::memory:")
                .await
                .unwrap();
        crate::db::run_migrations(&db, kind).await.unwrap();
        sqlx::query("CREATE TABLE commit_failure (id INTEGER REFERENCES audit_writer_lock(id) DEFERRABLE INITIALLY DEFERRED)").execute(&db).await.unwrap();
        let state = AuditState::with_config(crate::config::AuditConfig {
            overflow_policy: crate::config::OverflowPolicy::Halt,
            ..Default::default()
        });
        let mut tx = db.begin().await.unwrap();
        sqlx::query("INSERT INTO commit_failure VALUES (999)")
            .execute(&mut *tx)
            .await
            .unwrap();
        record_issuance_in_transaction(&mut tx, &state, "synthetic", "commit regression".into())
            .await
            .unwrap();
        assert!(commit_issuance(tx, &state).await.is_err());
        assert!(state.is_halted());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
