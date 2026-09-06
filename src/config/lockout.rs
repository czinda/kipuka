//! Authentication failure-lockout configuration (NIAP CA PP FIA_AFL.1).
//!
//! The `[auth_lockout]` section tunes the failure counter and lockout applied
//! by [`crate::auth::failure_tracker`].  When absent, defaults apply; when
//! `max_failures = 0`, the control is disabled and authentication behaves as
//! it did before the control existed.
//!
//! ```toml
//! [auth_lockout]
//! max_failures = 5
//! failure_window_secs = 300
//! lockout_duration_secs = 900
//! ```

use serde::Deserialize;

/// `[auth_lockout]` — FIA_AFL.1 authentication failure handling.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockoutConfig {
    /// Consecutive failed authentication attempts (per claimed identity,
    /// within `failure_window_secs`) that trigger a lockout.
    ///
    /// `0` disables the control.  Default: `5`.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,

    /// Sliding window (seconds) over which failures are counted.  A gap longer
    /// than this between failures resets the counter.  Default: `300` (5 min).
    #[serde(default = "default_failure_window_secs")]
    pub failure_window_secs: u64,

    /// How long (seconds) an identity remains locked out once the threshold is
    /// reached.  Default: `900` (15 min).
    #[serde(default = "default_lockout_duration_secs")]
    pub lockout_duration_secs: u64,
}

fn default_max_failures() -> u32 {
    5
}

fn default_failure_window_secs() -> u64 {
    300
}

fn default_lockout_duration_secs() -> u64 {
    900
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            failure_window_secs: default_failure_window_secs(),
            lockout_duration_secs: default_lockout_duration_secs(),
        }
    }
}

impl LockoutConfig {
    /// Validate semantic constraints.
    pub fn validate(&self) -> Result<(), String> {
        // Disabled control: no further constraints.
        if self.max_failures == 0 {
            return Ok(());
        }
        if self.failure_window_secs == 0 {
            return Err(
                "[auth_lockout].failure_window_secs must be at least 1 (or set max_failures = 0 to disable)".into(),
            );
        }
        if self.lockout_duration_secs == 0 {
            return Err(
                "[auth_lockout].lockout_duration_secs must be at least 1 (or set max_failures = 0 to disable)".into(),
            );
        }
        Ok(())
    }

    /// Build the runtime [`crate::auth::failure_tracker::LockoutPolicy`].
    pub fn to_policy(&self) -> crate::auth::failure_tracker::LockoutPolicy {
        crate::auth::failure_tracker::LockoutPolicy {
            max_failures: self.max_failures,
            failure_window: std::time::Duration::from_secs(self.failure_window_secs),
            lockout_duration: std::time::Duration::from_secs(self.lockout_duration_secs),
        }
    }
}
