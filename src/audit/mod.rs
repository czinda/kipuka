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
//! | FAU_STG.4 | Audit storage exhaustion | [`OverflowAction::Halt`] rejects EST operations |
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

    /// Rolling count of consecutive security violations.
    /// Reset to 0 after a successful authentication.
    pub violation_count: AtomicU32,
}

impl AuditState {
    /// Create a new audit state with no violations and not halted.
    pub fn new() -> Self {
        Self {
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
    // FAU_STG.4: check overflow before recording
    if state.is_halted() {
        tracing::warn!(
            event_type = event.event_type.as_str(),
            "audit halted — dropping event"
        );
        return;
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
        .execute(pool)
        .await;

    if let Err(e) = result {
        tracing::error!(
            event_type = event.event_type.as_str(),
            error = %e,
            "failed to record audit event"
        );
    }

    // Track security violations for FAU_ARP.1
    if event.event_type == AuditEventType::SecurityViolation {
        let count = state.record_violation();
        tracing::warn!(
            consecutive_violations = count,
            "security violation recorded"
        );
    } else if event.event_type == AuditEventType::AuthSuccess {
        state.reset_violations();
    }
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
