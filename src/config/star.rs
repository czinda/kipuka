//! STAR certificate configuration (RFC 8739).
//!
//! The `[star]` section enables Short-Term Automatic Renewal certificates.
//! When enabled, clients can request STAR orders that automatically renew
//! short-lived certificates without client interaction.  This is the
//! server-side answer to the CA/B Forum 47-day validity mandate (March 2029).

use serde::Deserialize;

/// `[star]` section — Short-Term Automatic Renewal certificates.
///
/// ```toml
/// [star]
/// enabled = true
/// min_renewal_interval_secs = 3600
/// max_renewal_interval_secs = 604800
/// default_renewal_interval_secs = 86400
/// max_lifetime_days = 365
/// max_active_orders = 10000
/// pre_renewal_factor = 0.5
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StarConfig {
    /// Enable STAR certificate support.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum renewal interval in seconds (floor: 3600 = 1 hour).
    #[serde(default = "default_min_renewal_interval_secs")]
    pub min_renewal_interval_secs: u64,

    /// Maximum renewal interval in seconds (ceiling: 604800 = 7 days).
    #[serde(default = "default_max_renewal_interval_secs")]
    pub max_renewal_interval_secs: u64,

    /// Default renewal interval when the client does not specify one.
    #[serde(default = "default_default_renewal_interval_secs")]
    pub default_renewal_interval_secs: u64,

    /// Maximum total STAR order lifetime in days.
    #[serde(default = "default_max_lifetime_days")]
    pub max_lifetime_days: u32,

    /// Maximum number of active STAR orders (resource exhaustion guard).
    #[serde(default = "default_max_active_orders")]
    pub max_active_orders: usize,

    /// Renew when this fraction of the interval remains (0.1–0.9).
    #[serde(default = "default_pre_renewal_factor")]
    pub pre_renewal_factor: f64,
}

fn default_min_renewal_interval_secs() -> u64 {
    3600
}

fn default_max_renewal_interval_secs() -> u64 {
    604800
}

fn default_default_renewal_interval_secs() -> u64 {
    86400
}

fn default_max_lifetime_days() -> u32 {
    365
}

fn default_max_active_orders() -> usize {
    10000
}

fn default_pre_renewal_factor() -> f64 {
    0.5
}

impl Default for StarConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_renewal_interval_secs: default_min_renewal_interval_secs(),
            max_renewal_interval_secs: default_max_renewal_interval_secs(),
            default_renewal_interval_secs: default_default_renewal_interval_secs(),
            max_lifetime_days: default_max_lifetime_days(),
            max_active_orders: default_max_active_orders(),
            pre_renewal_factor: default_pre_renewal_factor(),
        }
    }
}

impl StarConfig {
    /// Validate STAR configuration constraints.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_renewal_interval_secs < 3600 {
            return Err(format!(
                "[star].min_renewal_interval_secs must be >= 3600 (1 hour), got {}",
                self.min_renewal_interval_secs
            ));
        }

        if self.max_renewal_interval_secs > 604800 {
            return Err(format!(
                "[star].max_renewal_interval_secs must be <= 604800 (7 days), got {}",
                self.max_renewal_interval_secs
            ));
        }

        if self.min_renewal_interval_secs > self.max_renewal_interval_secs {
            return Err(format!(
                "[star].min_renewal_interval_secs ({}) must be <= max_renewal_interval_secs ({})",
                self.min_renewal_interval_secs, self.max_renewal_interval_secs
            ));
        }

        if self.default_renewal_interval_secs < self.min_renewal_interval_secs
            || self.default_renewal_interval_secs > self.max_renewal_interval_secs
        {
            return Err(format!(
                "[star].default_renewal_interval_secs ({}) must be between \
                 min_renewal_interval_secs ({}) and max_renewal_interval_secs ({})",
                self.default_renewal_interval_secs,
                self.min_renewal_interval_secs,
                self.max_renewal_interval_secs
            ));
        }

        if self.max_lifetime_days < 1 {
            return Err("[star].max_lifetime_days must be >= 1".into());
        }

        if self.max_active_orders < 1 {
            return Err("[star].max_active_orders must be >= 1".into());
        }

        if !(0.1..=0.9).contains(&self.pre_renewal_factor) {
            return Err(format!(
                "[star].pre_renewal_factor must be between 0.1 and 0.9, got {}",
                self.pre_renewal_factor
            ));
        }

        Ok(())
    }
}
