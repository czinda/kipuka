//! Explicit opt-in HA routing within each label's authorized CA pool.
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "strategy")]
    pub strategy: crate::ha::FailoverStrategy,
    #[serde(default = "interval")]
    pub probe_interval_secs: u64,
    #[serde(default = "timeout")]
    pub probe_timeout_secs: u64,
    #[serde(default = "threshold")]
    pub failure_threshold: u32,
    #[serde(default = "cooldown")]
    pub cooldown_secs: u64,
    /// Verified HTTPS health endpoints keyed by configured CA identifier.
    #[serde(default)]
    pub endpoints: std::collections::BTreeMap<String, String>,
}
fn strategy() -> crate::ha::FailoverStrategy {
    crate::ha::FailoverStrategy::ActivePassive
}
fn interval() -> u64 {
    30
}
fn timeout() -> u64 {
    5
}
fn threshold() -> u32 {
    3
}
fn cooldown() -> u64 {
    60
}

impl HaConfig {
    pub fn validate(&self, cas: &[super::CaConfig]) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.probe_interval_secs == 0
            || self.probe_timeout_secs == 0
            || self.failure_threshold == 0
            || self.cooldown_secs == 0
        {
            return Err("HA timing and failure threshold values must be positive".into());
        }
        for (id, endpoint) in &self.endpoints {
            if !cas.iter().any(|ca| &ca.id == id) {
                return Err(format!("unknown HA CA: {id}"));
            }
            let url = url::Url::parse(endpoint).map_err(|e| e.to_string())?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("HA endpoints must use HTTPS without URL credentials".into());
            }
        }
        Ok(())
    }
}
