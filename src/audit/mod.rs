//! Structured audit trail (NIAP CA PP FAU family).
//!
//! All EST and administrative operations that must be logged for Common
//! Criteria evaluation call [`record`].  The function inserts one row into
//! `audit_events`, links it into a tamper-evident hash chain (FAU_STG.1),
//! enforces the overflow policy (FAU_STG.4), fails closed when the audit
//! backend is unavailable (FPT_FLS.1), and maintains the rolling
//! security-violation counter for the alarm response (FAU_ARP.1).
//!
//! # NIAP CA PP requirements implemented
//!
//! | SFR | Requirement | Implementation |
//! |-----|-------------|----------------|
//! | FAU_GEN.1 | Audit record generation | [`AuditEventType`] taxonomy covers all required events |
//! | FAU_STG.1(1) | Audit trail protection | Hash chain (`prev_hash`/`record_hash`); optional HMAC keying |
//! | FAU_STG.4 | Audit storage exhaustion | `OverflowPolicy::Halt` + `max_rows` reject EST operations |
//! | FAU_ARP.1 | Security alarm | Alarm after N consecutive violations |
//! | FPT_FLS.1 | Fail secure | `fail_closed` halts issuance when a record cannot be written |
//!
//! ## Hash chain
//!
//! Each row stores `record_hash = H(prev_hash || RS || canonical_bytes)`,
//! where `RS` is the ASCII record-separator (0x1e), `canonical_bytes` is a
//! deterministic serialization of the row's fields, and `H` is HMAC-SHA256
//! keyed by the configured integrity key when `signed = true`, or plain
//! SHA-256 otherwise.  [`verify_chain`] re-walks the table and recomputes
//! every link, so any insert, delete, reorder, or in-place edit of a
//! historical row is detectable.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::config::OverflowPolicy;
use crate::error::KipukaError;

type HmacSha256 = Hmac<Sha256>;

/// ASCII record separator used to delimit fields in the canonical byte
/// serialization, so that no field value can spoof a boundary.
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

/// Runtime-fixed audit behavior derived from `[audit]` config.
struct AuditSettings {
    /// What to do when `max_rows` is exceeded (FAU_STG.4).
    overflow_policy: OverflowPolicy,
    /// Maximum number of audit rows; `None` means unbounded.
    max_rows: Option<u64>,
    /// When `true`, a failed audit write halts issuance (FPT_FLS.1).
    fail_closed: bool,
}

/// Mutable tail of the audit hash chain, guarded by an async mutex so that
/// concurrent handlers serialize the read-compute-insert sequence.
#[derive(Default)]
struct ChainTail {
    /// Whether the tail has been loaded from the database yet.
    initialized: bool,
    /// Hex of the most recent `record_hash`, or `None` at genesis.
    last_hash: Option<String>,
    /// Current row count in `audit_events`.
    row_count: u64,
}

/// Shared audit state (chain tail, overflow flag, alarm counter).
///
/// Lives in `AppState` and survives the lifetime of the server process.
/// Callers pass the database pool explicitly so the same state can be
/// used from any async context.
pub struct AuditState {
    /// When `true`, EST operations MUST be rejected (FAU_STG.4 / FPT_FLS.1).
    pub halted: AtomicBool,

    /// Rolling count of consecutive security violations.
    /// Reset to 0 after a successful authentication.
    pub violation_count: AtomicU32,

    /// Behavior derived from `[audit]` config.
    settings: AuditSettings,

    /// HMAC key for keyed chain integrity (`signed = true`); `None` selects
    /// the unkeyed SHA-256 chain.
    integrity_key: Option<Vec<u8>>,

    /// Serializes hash-chain computation against concurrent inserts.
    chain: Mutex<ChainTail>,
}

impl AuditState {
    /// Create a permissive audit state (no key, no row cap, best-effort
    /// writes).  Used by tests and as a safe default before config wiring.
    pub fn new() -> Self {
        Self {
            halted: AtomicBool::new(false),
            violation_count: AtomicU32::new(0),
            settings: AuditSettings {
                overflow_policy: OverflowPolicy::DropOldest,
                max_rows: None,
                fail_closed: false,
            },
            integrity_key: None,
            chain: Mutex::new(ChainTail::default()),
        }
    }

    /// Build audit state from the `[audit]` config plus a resolved integrity
    /// key (present only when `signed = true`).
    pub fn from_config(cfg: &crate::config::AuditConfig, integrity_key: Option<Vec<u8>>) -> Self {
        Self {
            halted: AtomicBool::new(false),
            violation_count: AtomicU32::new(0),
            settings: AuditSettings {
                overflow_policy: cfg.overflow_policy.clone(),
                max_rows: cfg.max_rows,
                fail_closed: cfg.fail_closed,
            },
            integrity_key,
            chain: Mutex::new(ChainTail::default()),
        }
    }

    /// Check whether EST operations should be rejected due to audit
    /// storage exhaustion or an audit-write failure (FAU_STG.4 / FPT_FLS.1).
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::Relaxed)
    }

    /// Set the halted flag (called when audit storage is full or a write
    /// fails under the fail-closed policy).
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

    /// Compute the chained hash `H(prev || RS || canonical)` in hex.
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

    /// Load the chain tail (last hash + row count) from the database once.
    async fn load_tail(
        &self,
        pool: &sqlx::AnyPool,
        tail: &mut ChainTail,
    ) -> Result<(), KipukaError> {
        let last = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT record_hash FROM audit_events ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KipukaError::Audit(format!("loading audit chain tail: {e}")))?;
        tail.last_hash = last.and_then(|(h,)| h);

        let (count,) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM audit_events")
            .fetch_one(pool)
            .await
            .map_err(|e| KipukaError::Audit(format!("counting audit rows: {e}")))?;
        tail.row_count = count.max(0) as u64;
        tail.initialized = true;
        Ok(())
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the deterministic byte serialization of a record for hashing.
///
/// Field order and separators MUST match between [`record`] (insert time)
/// and [`verify_chain`] (verification time), or every hash would mismatch.
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

/// Record an audit event to the database, chaining it into the
/// tamper-evident hash chain.
///
/// Returns `Err` when the event cannot be durably recorded (halted trail,
/// storage exhausted under `Halt`, or a write failure).  Under the
/// fail-closed policy a write failure also sets the halt flag so that
/// subsequent certificate-issuing operations are rejected until an operator
/// intervenes.  Best-effort callers may discard the result with `let _`.
pub async fn record(
    pool: &sqlx::AnyPool,
    state: &AuditState,
    event: AuditEvent,
) -> Result<(), KipukaError> {
    // FAU_STG.4 / FPT_FLS.1: refuse to proceed once halted.
    if state.is_halted() {
        tracing::warn!(
            event_type = event.event_type.as_str(),
            "audit halted — rejecting event"
        );
        return Err(KipukaError::Audit("audit trail halted".into()));
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

    // Generate the timestamp in Rust (not via a DB DEFAULT) so the stored
    // value is exactly what the hash chain commits to.
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Hold the chain lock across the insert so the read-compute-append
    // sequence is atomic with respect to other audit writers.
    let mut tail = state.chain.lock().await;
    if !tail.initialized {
        state.load_tail(pool, &mut tail).await?;
    }

    // FAU_STG.4: enforce the row cap before appending.
    if let Some(max) = state.settings.max_rows
        && tail.row_count >= max
    {
        match state.settings.overflow_policy {
            OverflowPolicy::Halt => {
                state.set_halted(true);
                tracing::error!(
                    max_rows = max,
                    "audit trail full — halting operations (FAU_STG.4)"
                );
                return Err(KipukaError::Audit("audit trail full".into()));
            }
            OverflowPolicy::DropOldest => {
                // Operator explicitly opted out of tamper-evidence: trim
                // the oldest rows to make room.  This severs the chain at
                // the new head, which verify_chain will report.
                let to_delete = (tail.row_count - max + 1) as i64;
                let del_sql = crate::db::pg_sql(
                    "DELETE FROM audit_events WHERE id IN \
                     (SELECT id FROM audit_events ORDER BY id ASC LIMIT ?)",
                );
                match sqlx::query(del_sql).bind(to_delete).execute(pool).await {
                    Ok(_) => {
                        tail.row_count = tail.row_count.saturating_sub(to_delete as u64);
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to drop oldest audit rows");
                    }
                }
            }
        }
    }

    let canonical = canonical_bytes(
        &timestamp,
        event.event_type.as_str(),
        event.operator.as_deref(),
        event.subject.as_deref(),
        detail_json.as_deref(),
        event.client_addr.as_deref(),
        None, // session_id is not yet populated
    );
    let prev_hash = tail.last_hash.clone();
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
        .execute(pool)
        .await;

    match result {
        Ok(_) => {
            tail.last_hash = Some(record_hash);
            tail.row_count += 1;
        }
        Err(e) => {
            tracing::error!(
                event_type = event.event_type.as_str(),
                error = %e,
                "failed to record audit event"
            );
            if state.settings.fail_closed {
                state.set_halted(true);
                tracing::error!("audit write failed — halting issuance (fail-closed, FPT_FLS.1)");
            }
            return Err(KipukaError::Audit(format!("audit write failed: {e}")));
        }
    }
    // Release the chain lock before the (independent) violation bookkeeping.
    drop(tail);

    // Track security violations for FAU_ARP.1.
    if event.event_type == AuditEventType::SecurityViolation {
        let count = state.record_violation();
        tracing::warn!(
            consecutive_violations = count,
            "security violation recorded"
        );
    } else if event.event_type == AuditEventType::AuthSuccess {
        state.reset_violations();
    }

    Ok(())
}

/// One audit row, used by [`verify_chain`].
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

/// Result of verifying the audit hash chain (FAU_STG.1).
#[derive(Debug)]
pub struct ChainVerifyReport {
    /// Total rows examined.
    pub total: u64,
    /// `true` when every link verified.
    pub ok: bool,
    /// `id` of the first row that failed verification, if any.
    pub broken_at: Option<i64>,
    /// Human-readable reason for the failure.
    pub detail: Option<String>,
}

/// Re-walk `audit_events` in `id` order and recompute every hash link.
///
/// Detects in-place edits (`record_hash` mismatch), deletions/reordering
/// (`prev_hash` linkage mismatch), and — when an integrity key is
/// configured — forged rows written directly to the database.  Must be
/// called with the same `AuditState` (key + algorithm) that wrote the rows.
pub async fn verify_chain(
    pool: &sqlx::AnyPool,
    state: &AuditState,
) -> Result<ChainVerifyReport, KipukaError> {
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT id, timestamp, event_type, actor, target, detail_json, source_ip, \
         session_id, prev_hash, record_hash FROM audit_events ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| KipukaError::Audit(format!("reading audit rows for verification: {e}")))?;

    let mut expected_prev: Option<String> = None;
    let mut total: u64 = 0;

    for row in &rows {
        total += 1;

        if row.prev_hash != expected_prev {
            return Ok(ChainVerifyReport {
                total,
                ok: false,
                broken_at: Some(row.id),
                detail: Some("prev_hash linkage mismatch (deletion or reorder)".into()),
            });
        }

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

        let stored_ok = matches!(&row.record_hash, Some(h) if *h == recomputed);
        if !stored_ok {
            return Ok(ChainVerifyReport {
                total,
                ok: false,
                broken_at: Some(row.id),
                detail: Some("record_hash mismatch (row tampered)".into()),
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> sqlx::AnyPool {
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        crate::db::schema::run_migrations(&pool, crate::db::DbKind::Sqlite)
            .await
            .expect("run migrations");
        pool
    }

    fn ev(i: usize) -> AuditEvent {
        AuditEvent::new(AuditEventType::CertIssue).with_subject(format!("CN=device{i}.example.com"))
    }

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

    #[tokio::test]
    async fn hash_chain_records_and_verifies() {
        let pool = test_pool().await;
        let state = AuditState::new();
        for i in 0..5 {
            record(&pool, &state, ev(i)).await.expect("record");
        }
        let report = verify_chain(&pool, &state).await.expect("verify");
        assert!(report.ok, "chain should verify: {report:?}");
        assert_eq!(report.total, 5);
        assert!(report.broken_at.is_none());
    }

    #[tokio::test]
    async fn tamper_with_row_is_detected() {
        let pool = test_pool().await;
        let state = AuditState::new();
        for i in 0..4 {
            record(&pool, &state, ev(i)).await.expect("record");
        }
        // In-place edit of a historical row's target.
        sqlx::query("UPDATE audit_events SET target = 'CN=attacker' WHERE id = 2")
            .execute(&pool)
            .await
            .expect("tamper");

        let report = verify_chain(&pool, &state).await.expect("verify");
        assert!(!report.ok, "tamper must be detected");
        assert_eq!(report.broken_at, Some(2));
    }

    #[tokio::test]
    async fn deletion_breaks_linkage() {
        let pool = test_pool().await;
        let state = AuditState::new();
        for i in 0..4 {
            record(&pool, &state, ev(i)).await.expect("record");
        }
        // Excise a middle row: the following row's prev_hash no longer links.
        sqlx::query("DELETE FROM audit_events WHERE id = 2")
            .execute(&pool)
            .await
            .expect("delete");

        let report = verify_chain(&pool, &state).await.expect("verify");
        assert!(!report.ok, "deletion must be detected");
        assert_eq!(report.broken_at, Some(3));
    }

    #[tokio::test]
    async fn hmac_keying_rejects_wrong_key() {
        let pool = test_pool().await;
        let cfg = crate::config::AuditConfig {
            signed: true,
            ..Default::default()
        };
        let signer = AuditState::from_config(&cfg, Some(b"correct-integrity-key".to_vec()));
        for i in 0..3 {
            record(&pool, &signer, ev(i)).await.expect("record");
        }
        // Same rows verify under the correct key.
        assert!(verify_chain(&pool, &signer).await.expect("verify").ok);

        // A verifier holding a different key must reject the chain.
        let wrong = AuditState::from_config(&cfg, Some(b"attacker-guessed-key".to_vec()));
        let report = verify_chain(&pool, &wrong).await.expect("verify");
        assert!(!report.ok, "wrong HMAC key must fail verification");
        assert_eq!(report.broken_at, Some(1));
    }

    #[tokio::test]
    async fn max_rows_halt_policy_fails_closed() {
        let pool = test_pool().await;
        let cfg = crate::config::AuditConfig {
            max_rows: Some(2),
            overflow_policy: OverflowPolicy::Halt,
            fail_closed: true,
            ..Default::default()
        };
        let state = AuditState::from_config(&cfg, None);

        record(&pool, &state, ev(0)).await.expect("row 1");
        record(&pool, &state, ev(1)).await.expect("row 2");
        assert!(!state.is_halted());

        // Third insert hits the cap under Halt: rejected + halted.
        let third = record(&pool, &state, ev(2)).await;
        assert!(third.is_err(), "third record must be rejected");
        assert!(state.is_halted(), "trail must halt when full");

        // Once halted, further records are refused.
        assert!(record(&pool, &state, ev(3)).await.is_err());
    }
}
