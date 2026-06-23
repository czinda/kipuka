//! Audit configuration.
//!
//! The `[audit]` section controls the audit trail that satisfies NIAP CA PP
//! FAU family requirements:
//!
//! - **FAU_GEN.1** — the server generates audit records for all security-relevant
//!   events (enrollment, authentication, key operations, admin actions).
//! - **FAU_STG.1** — the audit trail is append-only at the application level.
//! - **FAU_STG.4** — when `overflow_policy = "halt"`, EST operations are rejected
//!   if the audit trail storage is exhausted.
//! - **FAU_ARP.1** — when the alarm threshold is reached, the configured alarm
//!   action is triggered.

use serde::Deserialize;

/// Audit log rotation policy.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum RotationPolicy {
    /// Rotate based on file size.
    Size,
    /// Rotate daily.
    #[default]
    Daily,
    /// Rotate weekly.
    Weekly,
    /// Never rotate (rely on external log management).
    Never,
}

/// What to do when audit storage is exhausted (FAU_STG.4).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum OverflowPolicy {
    /// Drop the oldest audit records to make room.
    #[default]
    DropOldest,
    /// Halt EST operations until audit storage is cleared.
    ///
    /// NIAP CA PP FAU_STG.4: "The TSF shall prevent audited events,
    /// except those taken by the authorised administrator, if the
    /// audit trail is full."
    Halt,
}

/// `[audit]` section — audit trail configuration.
///
/// ```toml
/// [audit]
/// enabled = true
/// log_path = "/var/log/kipuka/audit.log"
/// signed = true
/// rotation_policy = "daily"
/// overflow_policy = "halt"
/// max_rows = 1000000
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Enable audit logging.  Default: `true`.
    #[serde(default = "bool_true")]
    pub enabled: bool,

    /// Path to the audit log file.
    ///
    /// When using database-backed audit (`log_to_db = true`), this path
    /// is used for the file-based backup copy.
    #[serde(default = "default_log_path")]
    pub log_path: String,

    /// Enable cryptographic signing of audit log entries.
    ///
    /// When `true`, each audit entry includes an RFC 3161-style timestamp
    /// signature chain for tamper detection.
    #[serde(default)]
    pub signed: bool,

    /// Log rotation policy.
    #[serde(default)]
    pub rotation_policy: RotationPolicy,

    /// Maximum rotation file size in bytes (when `rotation_policy = "size"`).
    /// Default: 100 MiB.
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Number of rotated log files to retain.
    /// Default: 10.
    #[serde(default = "default_retention_count")]
    pub retention_count: u32,

    /// Store audit events in the database in addition to the log file.
    #[serde(default = "bool_true")]
    pub log_to_db: bool,

    /// Overflow policy when audit storage is full (FAU_STG.4).
    #[serde(default)]
    pub overflow_policy: OverflowPolicy,

    /// Maximum number of audit rows in the database.
    ///
    /// When this limit is reached, the `overflow_policy` determines
    /// whether old rows are dropped or EST operations are halted.
    /// `None` means no limit (rely on disk space monitoring).
    pub max_rows: Option<u64>,

    /// Number of consecutive security violations before the alarm
    /// action fires (FAU_ARP.1).
    ///
    /// Default: 10.
    #[serde(default = "default_alarm_threshold")]
    pub alarm_threshold: u32,

    /// Action taken when the alarm threshold is reached.
    ///
    /// - `"syslog"` — emit a syslog alert.
    /// - `"halt"` — halt EST operations.
    ///
    /// Default: `"syslog"`.
    #[serde(default = "default_alarm_action")]
    pub alarm_action: String,

    /// NIAP CA PP FAU_GEN.1: list of auditable event types.
    ///
    /// When non-empty, only these event types are recorded.
    /// When empty (default), all events are audited.
    #[serde(default)]
    pub auditable_events: Vec<String>,
}

fn bool_true() -> bool {
    true
}

fn default_log_path() -> String {
    "/var/log/kipuka/audit.log".to_string()
}

fn default_max_file_size() -> u64 {
    100 * 1024 * 1024 // 100 MiB
}

fn default_retention_count() -> u32 {
    10
}

fn default_alarm_threshold() -> u32 {
    10
}

fn default_alarm_action() -> String {
    "syslog".to_string()
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_path: default_log_path(),
            signed: false,
            rotation_policy: RotationPolicy::default(),
            max_file_size: default_max_file_size(),
            retention_count: default_retention_count(),
            log_to_db: true,
            overflow_policy: OverflowPolicy::default(),
            max_rows: None,
            alarm_threshold: default_alarm_threshold(),
            alarm_action: default_alarm_action(),
            auditable_events: Vec::new(),
        }
    }
}

impl AuditConfig {
    /// Validate audit configuration constraints.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        match self.alarm_action.as_str() {
            "syslog" | "halt" => {}
            other => {
                return Err(format!(
                    "[audit].alarm_action must be \"syslog\" or \"halt\", got {other:?}"
                ));
            }
        }

        if self.alarm_threshold == 0 {
            return Err("[audit].alarm_threshold must be at least 1".into());
        }

        if self.rotation_policy == RotationPolicy::Size && self.max_file_size == 0 {
            return Err(
                "[audit].max_file_size must be at least 1 when rotation_policy = \"size\"".into(),
            );
        }

        Ok(())
    }
}
