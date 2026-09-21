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
//! | FAU_STG.1(1) | Audit trail protection | Append-only + tamper-evident hash chain ([`verify_chain`]) |
//! | FAU_STG.4 | Audit storage exhaustion | `OverflowAction::Halt` rejects EST operations |
//! | FAU_ARP.1 | Security alarm | Alarm after N consecutive violations |

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use sha2::{Digest, Sha256};

use crate::error::KipukaError;

/// HMAC-SHA256, used for the keyed audit hash chain when `signed = true`.
type HmacSha256 = Hmac<Sha256>;

/// ASCII Record Separator (0x1e).  Delimits fields in the canonical hash
/// preimage so that field values cannot be shifted across boundaries to
/// produce a colliding preimage (e.g. `"a" + "bc"` vs `"ab" + "c"`).
const RS: u8 = 0x1e;

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

    /// HMAC key for keyed chain integrity (`signed = true`); `None` selects
    /// the unkeyed SHA-256 chain (NIAP CA PP FAU_STG.1).
    integrity_key: Option<Vec<u8>>,
}

impl AuditState {
    /// Create a new audit state with no violations and not halted.
    pub fn new() -> Self {
        Self::with_config(crate::config::AuditConfig::default())
    }

    /// Build audit state from the `[audit]` config with the unkeyed
    /// (SHA-256) hash chain.  Equivalent to [`from_config`] with no key.
    ///
    /// [`from_config`]: AuditState::from_config
    pub fn with_config(config: crate::config::AuditConfig) -> Self {
        Self::from_config(config, None)
    }

    /// Build audit state from the `[audit]` config plus a resolved integrity
    /// key (present only when `signed = true`).  With a key the hash chain is
    /// HMAC-SHA256 keyed; without one it is plain SHA-256.
    pub fn from_config(
        config: crate::config::AuditConfig,
        integrity_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            config,
            write_lock: tokio::sync::Mutex::new(()),
            halted: AtomicBool::new(false),
            violation_count: AtomicU32::new(0),
            integrity_key,
        }
    }

    /// Compute the chained hash `H(prev || RS || canonical)` in lowercase hex.
    ///
    /// `H` is HMAC-SHA256 keyed by [`integrity_key`](Self::integrity_key) when
    /// one is configured, otherwise plain SHA-256.  The same [`AuditState`]
    /// (key + algorithm) that wrote the rows must be used by [`verify_chain`],
    /// or every recomputed hash mismatches.
    fn chain_hash(&self, prev: Option<&str>, canonical: &[u8]) -> String {
        let prev_bytes = prev.unwrap_or("").as_bytes();
        match &self.integrity_key {
            Some(key) => {
                let mut mac =
                    HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
                mac.update(prev_bytes);
                mac.update(&[RS]);
                mac.update(canonical);
                hex::encode(mac.finalize().into_bytes())
            }
            None => {
                let mut h = Sha256::new();
                h.update(prev_bytes);
                h.update([RS]);
                h.update(canonical);
                hex::encode(h.finalize())
            }
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

/// The single insert point shared by every audit write path
/// ([`record`]/[`record_checked`] and [`record_issuance_in_transaction`]).
///
/// Threading the tamper-evident hash chain (NIAP CA PP FAU_STG.1) through
/// this one function — rather than through each caller — guarantees that the
/// transactional issuance path is chained too: an un-chained row anywhere is a
/// silent hole in the evidence.  The `audit_writer_lock` row is updated first,
/// which takes a write lock held for the whole enclosing transaction; because
/// the chain tail is then read (`SELECT ... ORDER BY id DESC LIMIT 1`) and the
/// new row inserted under that same lock, the read-compute-append sequence is
/// atomic against every other writer, including writers in other server
/// processes.  Reading the tail from the database (not from in-memory state)
/// keeps the chain correct across restarts and replicas.
async fn write_event(
    connection: &mut sqlx::AnyConnection,
    state: &AuditState,
    event: &AuditEvent,
) -> Result<(), crate::error::KipukaError> {
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

    // ── Tamper-evident hash chain (FAU_STG.1) ──────────────────────────────
    // Generate the timestamp in Rust (not via a DB DEFAULT) so the stored
    // value is exactly what the chain commits to.  Read the current tail —
    // still holding the writer lock acquired above — then chain onto it.  The
    // enclosing transaction sees its own prior inserts, so multiple writes in
    // one transaction chain correctly.
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let prev_hash: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT record_hash FROM audit_events ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(|e| KipukaError::Db(format!("loading audit chain tail: {e}")))?
    .flatten();
    let canonical = canonical_bytes(
        &timestamp,
        event.event_type.as_str(),
        event.operator.as_deref(),
        event.subject.as_deref(),
        detail_json.as_deref(),
        event.client_addr.as_deref(),
        None, // session_id is not yet populated
    );
    let record_hash = state.chain_hash(prev_hash.as_deref(), &canonical);

    let sql = crate::db::pg_sql(
        "INSERT INTO audit_events \
         (timestamp, event_type, actor, target, detail_json, source_ip, session_id, prev_hash, record_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    let result = sqlx::query(sql)
        .bind(&timestamp)
        .bind(event.event_type.as_str())
        .bind(&event.operator)
        .bind(&event.subject)
        .bind(&detail_json)
        .bind(&event.client_addr)
        .bind(None::<String>)
        .bind(&prev_hash)
        .bind(&record_hash)
        .execute(&mut *connection)
        .await;

    result.map_err(|e| KipukaError::Db(format!("audit insert failed: {e}")))?;
    Ok(())
}

/// Build the deterministic byte serialization of a record for hashing.
///
/// Field order and separators MUST match between [`write_event`] (insert
/// time) and [`verify_chain`] (verification time), or every hash would
/// mismatch.  Each field is followed by an `RS` byte so that no field value
/// can absorb an adjacent one to forge a colliding preimage.
fn canonical_bytes(
    timestamp: &str,
    event_type: &str,
    actor: Option<&str>,
    target: Option<&str>,
    detail_json: Option<&str>,
    source_ip: Option<&str>,
    session_id: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    for field in [
        timestamp,
        event_type,
        actor.unwrap_or(""),
        target.unwrap_or(""),
        detail_json.unwrap_or(""),
        source_ip.unwrap_or(""),
        session_id.unwrap_or(""),
    ] {
        buf.extend_from_slice(field.as_bytes());
        buf.push(RS);
    }
    buf
}

/// One `audit_events` row, as read back for chain verification.
///
/// The `Option` columns mirror the nullable table schema; the empty-string
/// substitution in [`canonical_bytes`] means a `NULL` and an empty string
/// hash identically, which is intentional — both encode "field absent".
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    timestamp: String,
    event_type: String,
    actor: Option<String>,
    target: Option<String>,
    detail_json: Option<String>,
    source_ip: Option<String>,
    session_id: Option<String>,
    prev_hash: Option<String>,
    record_hash: Option<String>,
}

/// Outcome of a full hash-chain verification pass (NIAP CA PP FAU_STG.1).
///
/// `ok == true` means every row's `record_hash` recomputed correctly and every
/// `prev_hash` linked to its predecessor.  On failure, `broken_at` carries the
/// `id` of the first offending row and `detail` explains which invariant broke.
#[derive(Debug, Clone)]
pub struct ChainVerifyReport {
    /// Number of rows examined.
    pub total: u64,
    /// `true` when the entire chain verified.
    pub ok: bool,
    /// `id` of the first row that failed verification, if any.
    pub broken_at: Option<i64>,
    /// Human-readable description of the first failure, if any.
    pub detail: Option<String>,
}

/// Re-walk the entire audit trail and verify the tamper-evident hash chain.
///
/// Reads every row in `id` order and checks, for each, that (1) its `prev_hash`
/// equals the previous row's stored `record_hash` (linkage — detects deletion
/// and reordering) and (2) its `record_hash` recomputes from its own fields via
/// the configured [`AuditState::chain_hash`] (integrity — detects in-place
/// edits).  The first violation short-circuits and is reported in
/// [`ChainVerifyReport::broken_at`]/`detail`.
///
/// This is the review-time counterpart to the write-time chaining in
/// [`write_event`]; the same [`AuditState`] (key + algorithm) that wrote the
/// rows must be supplied, or unkeyed rows would be checked with an HMAC (or
/// vice versa) and every hash would mismatch.
pub async fn verify_chain(
    pool: &sqlx::AnyPool,
    state: &AuditState,
) -> Result<ChainVerifyReport, KipukaError> {
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT id, timestamp, event_type, actor, target, detail_json, source_ip, \
         session_id, prev_hash, record_hash FROM audit_events ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| KipukaError::Db(format!("reading audit trail for verification: {e}")))?;

    let total = rows.len() as u64;
    let mut expected_prev: Option<String> = None;

    for row in &rows {
        // (1) Linkage: this row must point at the previous row's record_hash.
        if row.prev_hash.as_deref() != expected_prev.as_deref() {
            return Ok(ChainVerifyReport {
                total,
                ok: false,
                broken_at: Some(row.id),
                detail: Some(format!(
                    "prev_hash linkage broken at id={}: stored prev_hash does not match the \
                     preceding record_hash (row deleted, inserted, or reordered)",
                    row.id
                )),
            });
        }

        // (2) Integrity: recompute this row's record_hash from its own fields.
        let canonical = canonical_bytes(
            &row.timestamp,
            &row.event_type,
            row.actor.as_deref(),
            row.target.as_deref(),
            row.detail_json.as_deref(),
            row.source_ip.as_deref(),
            row.session_id.as_deref(),
        );
        let recomputed = state.chain_hash(row.prev_hash.as_deref(), &canonical);
        match &row.record_hash {
            Some(stored) if *stored == recomputed => {}
            _ => {
                return Ok(ChainVerifyReport {
                    total,
                    ok: false,
                    broken_at: Some(row.id),
                    detail: Some(format!(
                        "record_hash mismatch at id={}: row contents were altered after \
                         insertion",
                        row.id
                    )),
                });
            }
        }

        expected_prev = row.record_hash.clone();
    }

    Ok(ChainVerifyReport {
        total,
        ok: true,
        broken_at: None,
        detail: None,
    })
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

#[cfg(test)]
mod chain_tests {
    use super::*;

    /// Spin up an in-memory SQLite DB with the full migration set applied.
    async fn test_db() -> sqlx::AnyPool {
        let (db, kind) =
            crate::db::init_pool(&crate::config::DbConfig::default(), "sqlite::memory:")
                .await
                .unwrap();
        crate::db::run_migrations(&db, kind).await.unwrap();
        db
    }

    /// The hash chain is threaded through every write path — the best-effort
    /// [`record`], the checked [`record_checked`], and the transactional
    /// [`record_issuance_in_transaction`] — so exercising all three and then
    /// verifying proves there is no un-chained hole in the evidence.
    #[tokio::test]
    async fn chain_verifies_across_all_write_paths() {
        let db = test_db().await;
        let state = AuditState::new();

        // Path 1: record() (best-effort, wraps record_checked).
        record(
            &db,
            &state,
            AuditEvent::new(AuditEventType::AdminLogin).with_operator("admin"),
        )
        .await;

        // Path 2: record_checked() (propagates failure).
        record_checked(
            &db,
            &state,
            AuditEvent::new(AuditEventType::EnrollRequest).with_detail("simpleenroll"),
        )
        .await
        .unwrap();

        // Path 3: record_issuance_in_transaction() (+ commit_issuance).
        let mut tx = db.begin().await.unwrap();
        record_issuance_in_transaction(&mut tx, &state, "ca-a", "serial=01".into())
            .await
            .unwrap();
        // Two issuance rows in one transaction exercise intra-tx chaining.
        record_issuance_in_transaction(&mut tx, &state, "ca-a", "serial=02".into())
            .await
            .unwrap();
        commit_issuance(tx, &state).await.unwrap();

        let report = verify_chain(&db, &state).await.unwrap();
        assert_eq!(report.total, 4, "all four events must be present");
        assert!(report.ok, "chain must verify: {:?}", report.detail);
        assert!(report.broken_at.is_none());

        // The first row anchors the chain with a NULL prev_hash.
        let first_prev: Option<String> =
            sqlx::query_scalar("SELECT prev_hash FROM audit_events ORDER BY id ASC LIMIT 1")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(first_prev.is_none(), "chain head has no predecessor");
    }

    /// Editing a row's contents in place must be detected: the stored
    /// `record_hash` no longer recomputes from the altered fields.
    #[tokio::test]
    async fn tampering_with_a_row_breaks_the_chain() {
        let db = test_db().await;
        let state = AuditState::new();

        for i in 0..3 {
            record_checked(
                &db,
                &state,
                AuditEvent::new(AuditEventType::AdminAction).with_detail(format!("op-{i}")),
            )
            .await
            .unwrap();
        }
        assert!(verify_chain(&db, &state).await.unwrap().ok);

        // Forge the detail of the middle row without updating its record_hash.
        let victim: i64 =
            sqlx::query_scalar("SELECT id FROM audit_events ORDER BY id ASC LIMIT 1 OFFSET 1")
                .fetch_one(&db)
                .await
                .unwrap();
        sqlx::query("UPDATE audit_events SET detail_json = ? WHERE id = ?")
            .bind(Some(r#"{"detail":"tampered"}"#.to_string()))
            .bind(victim)
            .execute(&db)
            .await
            .unwrap();

        let report = verify_chain(&db, &state).await.unwrap();
        assert!(!report.ok, "tampering must be detected");
        assert_eq!(report.broken_at, Some(victim));
    }

    /// Deleting a row must be detected via the prev_hash linkage check even
    /// though every surviving row's own record_hash still recomputes.
    #[tokio::test]
    async fn deleting_a_row_breaks_linkage() {
        let db = test_db().await;
        let state = AuditState::new();

        for i in 0..3 {
            record_checked(
                &db,
                &state,
                AuditEvent::new(AuditEventType::AdminAction).with_detail(format!("op-{i}")),
            )
            .await
            .unwrap();
        }

        // Delete the middle row: row 3's prev_hash now dangles.
        let victim: i64 =
            sqlx::query_scalar("SELECT id FROM audit_events ORDER BY id ASC LIMIT 1 OFFSET 1")
                .fetch_one(&db)
                .await
                .unwrap();
        sqlx::query("DELETE FROM audit_events WHERE id = ?")
            .bind(victim)
            .execute(&db)
            .await
            .unwrap();

        let report = verify_chain(&db, &state).await.unwrap();
        assert!(!report.ok, "deletion must break linkage");
    }

    /// With keyed HMAC (`signed = true`), an attacker who can write to the
    /// database but lacks the key cannot forge a valid `record_hash`.  Here we
    /// simulate the forgery attempt by recomputing the chain with the *wrong*
    /// key (an unkeyed verifier) — verification must fail.
    #[tokio::test]
    async fn keyed_hmac_detects_forgery_without_the_key() {
        let db = test_db().await;
        let signed_cfg = crate::config::AuditConfig {
            signed: true,
            ..Default::default()
        };
        let keyed = AuditState::from_config(signed_cfg, Some(b"super-secret-key".to_vec()));

        for i in 0..3 {
            record_checked(
                &db,
                &keyed,
                AuditEvent::new(AuditEventType::CertIssue).with_detail(format!("serial-{i}")),
            )
            .await
            .unwrap();
        }

        // With the correct key, the chain verifies.
        assert!(verify_chain(&db, &keyed).await.unwrap().ok);

        // An attacker forges a row's record_hash using the *unkeyed* SHA-256
        // algorithm (they don't have the HMAC key).  Recompute what they would
        // write for the first row and plant it.
        let first = &sqlx::query_as::<_, AuditRow>(
            "SELECT id, timestamp, event_type, actor, target, detail_json, source_ip, \
             session_id, prev_hash, record_hash FROM audit_events ORDER BY id ASC LIMIT 1",
        )
        .fetch_all(&db)
        .await
        .unwrap()[0];
        let unkeyed = AuditState::new();
        let canonical = canonical_bytes(
            &first.timestamp,
            &first.event_type,
            first.actor.as_deref(),
            first.target.as_deref(),
            Some(r#"{"detail":"forged"}"#),
            first.source_ip.as_deref(),
            first.session_id.as_deref(),
        );
        let forged = unkeyed.chain_hash(first.prev_hash.as_deref(), &canonical);
        sqlx::query("UPDATE audit_events SET detail_json = ?, record_hash = ? WHERE id = ?")
            .bind(Some(r#"{"detail":"forged"}"#.to_string()))
            .bind(Some(forged))
            .bind(first.id)
            .execute(&db)
            .await
            .unwrap();

        // The keyed verifier rejects the forgery: the unkeyed hash is not a
        // valid HMAC under the secret key.
        let report = verify_chain(&db, &keyed).await.unwrap();
        assert!(!report.ok, "keyed HMAC must reject a forgery made without the key");
        assert_eq!(report.broken_at, Some(first.id));
    }
}
