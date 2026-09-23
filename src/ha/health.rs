//! Periodic health probing with state machine transitions.
//!
//! Implements RHELBU-3536 R4: health state machine
//! `Healthy -> Degraded -> Unavailable -> Recovering -> Healthy`
//! with configurable probe intervals and alert generation via audit log.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::pool::{CaId, CaPool};

/// Health state of a single CA backend (RHELBU-3536 R4).
///
/// Transitions follow the state machine:
/// ```text
/// Healthy -> Degraded -> Unavailable -> Recovering -> Healthy
///                ^                          |
///                +---- (probe failure) ------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    /// CA is responding normally within latency thresholds.
    Healthy,
    /// CA is responding but with elevated latency or intermittent errors.
    Degraded,
    /// CA is not responding; circuit breaker is open.
    Unavailable,
    /// CA was unavailable and is being re-probed after cooldown.
    Recovering,
}

impl HealthState {
    /// Whether this state allows routing requests to the CA.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Recovering)
    }
}

/// Configuration for the health checker.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between probe rounds (default: 30 seconds).
    pub probe_interval: Duration,
    /// Timeout for a single probe request.
    pub probe_timeout: Duration,
    /// Number of consecutive successes required to transition from
    /// `Recovering` back to `Healthy`.
    pub recovery_threshold: u32,
    /// Latency threshold (ms) above which a CA is considered degraded.
    pub degraded_latency_ms: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(5),
            recovery_threshold: 2,
            degraded_latency_ms: 2000,
        }
    }
}

/// Per-CA probe metrics tracked between probe rounds.
#[derive(Debug, Clone)]
pub struct ProbeMetrics {
    /// Timestamp of the last completed probe.
    pub last_check: Option<Instant>,
    /// Number of consecutive probe failures.
    pub consecutive_failures: u32,
    /// Number of consecutive probe successes (used during recovery).
    pub consecutive_successes: u32,
    /// Last observed response latency.
    pub last_latency: Option<Duration>,
}

impl ProbeMetrics {
    fn new() -> Self {
        Self {
            last_check: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_latency: None,
        }
    }
}

pub struct LocalProbeContext {
    pub config: Arc<crate::config::Config>,
    pub cas: Arc<indexmap::IndexMap<String, Arc<crate::state::CaState>>>,
    pub hsm: Option<Arc<kipuka_hsm::HsmContext>>,
}

/// One-shot liveness check for a single locally-hosted CA.
///
/// Verifies that the CA's signing key resolves and matches its certificate
/// (or, for an HSM-backed CA, that the PKCS#11 session is live), and that the
/// CA certificate is currently within its validity window.
///
/// This is the exact assertion the background probe makes for a `local:` CA,
/// factored out so callers can run it on demand without a running
/// [`HealthChecker`] — notably the admin health endpoint when the HA
/// subsystem is disabled, so that its healthy-CA count reflects a real check
/// rather than an unconditional assumption.
///
/// Returns `Ok(())` when the CA is live, or `Err` with a human-readable
/// reason otherwise.
pub fn probe_local_ca(
    ca_cfg: &crate::config::CaConfig,
    ca_state: &crate::state::CaState,
    hsm: Option<&Arc<kipuka_hsm::HsmContext>>,
) -> Result<(), String> {
    let key = crate::ca::issue::resolve_signing_key_sync(ca_cfg, hsm).map_err(|e| e.to_string())?;
    let cert = openssl::x509::X509::from_der(&ca_state.cert_der).map_err(|e| e.to_string())?;
    match key {
        crate::ca::issue::ResolvedSigningKey::Pem(pem) => {
            let key = openssl::pkey::PKey::private_key_from_pem(&pem).map_err(|e| e.to_string())?;
            let public_key = cert.public_key().map_err(|e| e.to_string())?;
            if !key.public_eq(&public_key) {
                return Err("CA key does not match its certificate".into());
            }
        }
        crate::ca::issue::ResolvedSigningKey::Hsm { context, .. } => {
            context.health_check().map_err(|e| e.to_string())?
        }
    }
    let now = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    if cert.not_before() > now || cert.not_after() <= now {
        return Err("CA certificate is outside its validity period".into());
    }
    Ok(())
}

/// Runs periodic health probes against each CA backend.
///
/// The checker is cloneable (behind `Arc`) and designed to run in a
/// background tokio task managed by [`super::HaManager`].
#[derive(Clone)]
pub struct HealthChecker {
    pool: Arc<CaPool>,
    config: HealthConfig,
    local: Option<Arc<LocalProbeContext>>,
    /// Per-CA probe metrics, keyed by CaId.
    metrics: Arc<parking_lot::RwLock<std::collections::HashMap<CaId, ProbeMetrics>>>,
}

impl HealthChecker {
    /// Create a new health checker for the given pool.
    pub fn new(pool: Arc<CaPool>, config: HealthConfig) -> Self {
        let mut metrics = std::collections::HashMap::new();
        for conn in pool.connections() {
            metrics.insert(conn.id.clone(), ProbeMetrics::new());
        }

        Self {
            pool,
            config,
            local: None,
            metrics: Arc::new(parking_lot::RwLock::new(metrics)),
        }
    }

    pub fn with_local(mut self, local: Arc<LocalProbeContext>) -> Self {
        self.local = Some(local);
        self
    }

    /// Configured probe interval.
    pub fn interval(&self) -> Duration {
        self.config.probe_interval
    }

    /// Execute one round of probes against all registered CAs.
    pub async fn run_probes(&self) {
        debug!("starting health probe round");

        for conn in self.pool.connections() {
            let start = Instant::now();
            let result = self.probe_ca(&conn.id).await;
            let elapsed = start.elapsed();

            let mut metrics = self.metrics.write();
            let m = metrics
                .entry(conn.id.clone())
                .or_insert_with(ProbeMetrics::new);
            m.last_check = Some(Instant::now());
            m.last_latency = Some(elapsed);

            match result {
                Ok(()) => self.handle_probe_success(&conn.id, elapsed, m),
                Err(e) => self.handle_probe_failure(&conn.id, e, m),
            }
        }
    }

    /// Probe a single CA backend.
    ///
    /// Issues an HTTP GET to the CA's health endpoint to verify it is
    /// responding.  For Dogtag CAs this hits `/ca/admin/ca/getStatus`;
    /// for generic HTTP CAs it performs a simple connectivity check
    /// against the configured endpoint.
    ///
    /// The probe respects the configured timeout ([`HealthConfig::probe_timeout`])
    /// and returns `Err` with a human-readable reason on failure.
    async fn probe_ca(&self, id: &CaId) -> Result<(), String> {
        // If the CA is unavailable, check whether cooldown has elapsed.
        // If cooldown hasn't elapsed yet, don't probe — report as still failed.
        let current_snapshot = self.pool.status_snapshot();
        let is_unavailable = current_snapshot
            .get(id)
            .map(|s| s.health == HealthState::Unavailable)
            .unwrap_or(false);

        if is_unavailable && !self.pool.should_reprobe(id) {
            return Err("circuit breaker open, cooldown not elapsed".to_string());
        }

        if is_unavailable {
            debug!(ca = %id, "cooldown elapsed, attempting re-probe");
        }

        // Find the endpoint URL for this CA.
        let endpoint = self
            .pool
            .connections()
            .iter()
            .find(|c| c.id == *id)
            .map(|c| c.endpoint.clone())
            .ok_or_else(|| format!("CA {id} not found in pool"))?;

        if endpoint.starts_with("local:") {
            let context = self.local.as_ref().ok_or("local probe context missing")?;
            let ca = context.cas.get(&id.0).ok_or("local CA state missing")?;
            let config = context
                .config
                .cas
                .iter()
                .find(|ca| ca.id == id.0)
                .ok_or("local CA configuration missing")?;
            return probe_local_ca(config, ca, context.hsm.as_ref());
        }

        // Build the health check URL.
        // For Dogtag CAs (endpoint contains /ca), use the Dogtag status API.
        // For generic CAs, try a simple GET against the endpoint root.
        let health_url = if endpoint.contains("/ca") {
            // Dogtag CA: use the agent status endpoint
            format!("{}/admin/ca/getStatus", endpoint.trim_end_matches('/'))
        } else {
            // Generic CA: probe the endpoint root
            endpoint.clone()
        };

        debug!(ca = %id, url = %health_url, "probing CA health endpoint");

        let client = reqwest::Client::builder()
            .timeout(self.config.probe_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("HTTP client build failed: {e}"))?;

        let response = client.get(&health_url).send().await.map_err(|e| {
            if e.is_timeout() {
                format!(
                    "health probe timed out after {:?}",
                    self.config.probe_timeout
                )
            } else if e.is_connect() {
                format!("health probe connection refused: {e}")
            } else {
                format!("health probe failed: {e}")
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(format!("CA returned server error: HTTP {status}"));
        }

        // For Dogtag, verify the response indicates the CA subsystem is
        // running.  A 200 OK from /admin/ca/getStatus with a body
        // containing "running" confirms the CA is operational.
        if health_url.contains("getStatus") {
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
                if bytes.len() + chunk.len() > 65536 {
                    return Err("health response exceeds 64 KiB".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            let body = String::from_utf8_lossy(&bytes);
            if !body.to_lowercase().contains("running") {
                return Err(format!(
                    "Dogtag CA reports unhealthy status: {}",
                    body.chars().take(200).collect::<String>()
                ));
            }
        }

        debug!(ca = %id, status = %status, "CA health probe succeeded");
        Ok(())
    }

    /// Handle a successful probe, applying state transitions.
    fn handle_probe_success(&self, id: &CaId, latency: Duration, metrics: &mut ProbeMetrics) {
        metrics.consecutive_failures = 0;
        metrics.consecutive_successes += 1;

        let current_snapshot = self.pool.status_snapshot();
        let current_health = current_snapshot
            .get(id)
            .map(|s| s.health.clone())
            .unwrap_or(HealthState::Healthy);

        let latency_ms = latency.as_millis() as u64;

        let new_state = match current_health {
            HealthState::Unavailable => {
                info!(ca = %id, "CA responding again, entering recovery");
                metrics.consecutive_successes = 1;
                HealthState::Recovering
            }
            HealthState::Recovering => {
                if metrics.consecutive_successes >= self.config.recovery_threshold {
                    info!(ca = %id, "CA recovery confirmed, marking healthy");
                    HealthState::Healthy
                } else {
                    debug!(
                        ca = %id,
                        successes = metrics.consecutive_successes,
                        needed = self.config.recovery_threshold,
                        "CA still recovering"
                    );
                    HealthState::Recovering
                }
            }
            HealthState::Degraded | HealthState::Healthy => {
                if latency_ms > self.config.degraded_latency_ms {
                    debug!(ca = %id, latency_ms, "CA responding slowly, marking degraded");
                    HealthState::Degraded
                } else {
                    HealthState::Healthy
                }
            }
        };

        self.pool.set_health(id, new_state);
        self.pool.record_success(id, latency);
    }

    /// Handle a failed probe, applying state transitions.
    fn handle_probe_failure(&self, id: &CaId, error: String, metrics: &mut ProbeMetrics) {
        metrics.consecutive_failures += 1;
        metrics.consecutive_successes = 0;

        warn!(
            ca = %id,
            failures = metrics.consecutive_failures,
            error = %error,
            "health probe failed"
        );

        self.pool.record_failure(id);
    }

    /// Snapshot of probe metrics for monitoring.
    pub fn metrics_snapshot(&self) -> std::collections::HashMap<CaId, ProbeMetrics> {
        self.metrics.read().clone()
    }
}

#[cfg(test)]
mod probe_local_ca_tests {
    //! Regression tests for the on-demand local-CA liveness check.
    //!
    //! These pin the honest behaviour the admin health endpoint depends on when
    //! the HA subsystem is disabled: a CA is only counted "healthy" if its
    //! signing key actually resolves, matches its certificate, and that
    //! certificate is currently in date. Previously the endpoint assumed every
    //! configured CA was healthy without checking anything.

    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509, X509NameBuilder};
    use std::io::Write;

    fn gen_ec_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec).unwrap()
    }

    /// Self-sign a CA certificate for `key`. `valid_days` sets `notAfter`
    /// relative to now — pass a negative value to build an expired certificate.
    fn self_signed(key: &PKey<Private>, valid_days: i64) -> X509 {
        let mut nb = X509NameBuilder::new().unwrap();
        nb.append_entry_by_text("CN", "probe-test-ca").unwrap();
        let name = nb.build();

        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(key).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        b.set_not_before(&Asn1Time::from_unix(now - 3600).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::from_unix(now + valid_days * 86_400).unwrap())
            .unwrap();

        b.sign(key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn ca_state(cert_der: Vec<u8>) -> crate::state::CaState {
        crate::state::CaState {
            id: "probe-test".into(),
            key_type: "ec:P-256".into(),
            cert_der,
            cert_chain: vec![],
            hash_algorithm: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            crl_cache: parking_lot::Mutex::new(None),
            cab_forum_compliant: false,
        }
    }

    fn ca_config(key_path: &std::path::Path) -> crate::config::CaConfig {
        // Build via TOML so the fixture tracks CaConfig's real defaults; the
        // probe only reads key_file (cert comes from CaState), so cert_file is
        // a throwaway.
        let toml = format!(
            "id = \"probe-test\"\nkey_file = \"{}\"\ncert_file = \"/dev/null\"\n",
            key_path.display()
        );
        toml::from_str(&toml).expect("valid CaConfig toml")
    }

    fn write_key(key: &PKey<Private>) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&key.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn healthy_ca_passes_liveness_check() {
        let key = gen_ec_key();
        let cert = self_signed(&key, 365);
        let key_file = write_key(&key);
        let cfg = ca_config(key_file.path());
        let state = ca_state(cert.to_der().unwrap());

        assert!(
            probe_local_ca(&cfg, &state, None).is_ok(),
            "a CA whose on-disk key matches its in-date certificate must be reported live"
        );
    }

    #[test]
    fn mismatched_key_and_cert_fails_liveness_check() {
        // The certificate is bound to key2's public key, but the config points
        // key_file at key1 — precisely the "healthy" fabrication the old health
        // endpoint could not detect.
        let key1 = gen_ec_key();
        let key2 = gen_ec_key();
        let cert = self_signed(&key2, 365);
        let key_file = write_key(&key1);
        let cfg = ca_config(key_file.path());
        let state = ca_state(cert.to_der().unwrap());

        let err = probe_local_ca(&cfg, &state, None)
            .expect_err("a CA whose key does not match its certificate must fail");
        assert!(err.contains("does not match"), "unexpected reason: {err}");
    }

    #[test]
    fn expired_ca_cert_fails_liveness_check() {
        let key = gen_ec_key();
        let cert = self_signed(&key, -1); // notAfter one day in the past
        let key_file = write_key(&key);
        let cfg = ca_config(key_file.path());
        let state = ca_state(cert.to_der().unwrap());

        let err = probe_local_ca(&cfg, &state, None)
            .expect_err("an expired CA certificate must fail the liveness check");
        assert!(err.contains("validity period"), "unexpected reason: {err}");
    }
}
