//! Server listener configuration.
//!
//! Supports three listener modes:
//!
//! 1. **TCP** — standard `host:port` binding (default).
//! 2. **Unix socket** — path prefixed with `unix:` or starting with `/`.
//! 3. **systemd socket activation** — file descriptor passed via `LISTEN_FDS`.

use serde::Deserialize;

/// `[server]` section — network listener and general server tuning.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address.
    ///
    /// - `"0.0.0.0:8443"` or `"[::]:8443"` for TCP.
    /// - `"unix:/run/kipuka/kipuka.sock"` or `"/run/kipuka/kipuka.sock"` for Unix.
    /// - `"fd:3"` for systemd socket activation (`LISTEN_FDS`).
    ///
    /// The `KIPUKA_LISTEN` environment variable overrides this field.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// TCP listen port (ignored when `listen_addr` is a Unix socket or fd).
    ///
    /// When set, overrides the port portion of `listen_addr`.
    /// Useful for separating the bind address from the port in deployment configs.
    pub listen_port: Option<u16>,

    /// Unix socket path (alternative to embedding it in `listen_addr`).
    ///
    /// When set, the server listens on this Unix domain socket instead of TCP.
    /// Mutually exclusive with `listen_port`.
    pub unix_socket: Option<String>,

    /// Maximum HTTP request body size in bytes.
    ///
    /// EST CSR payloads (PKCS#10) are typically 1–4 KB; Full CMC requests
    /// can be larger.  Default: 65536 (64 KiB).
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Number of tokio worker threads.
    ///
    /// `0` (the default) uses `num_cpus` threads.
    #[serde(default)]
    pub worker_threads: usize,

    /// Graceful shutdown timeout in seconds.
    ///
    /// After receiving SIGTERM/SIGINT, the server waits this long for
    /// in-flight requests to complete before forcing shutdown.
    /// Default: 30 seconds.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_max_body_size() -> usize {
    65536
}

fn default_shutdown_timeout_secs() -> u64 {
    30
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: None,
            unix_socket: None,
            max_body_size: default_max_body_size(),
            worker_threads: 0,
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
        }
    }
}

impl ServerConfig {
    /// Resolve the effective listen target, accounting for overrides.
    ///
    /// Priority: `unix_socket` > env `KIPUKA_LISTEN` > `listen_addr`.
    pub fn effective_listen_addr(&self) -> String {
        if let Some(ref sock) = self.unix_socket {
            return format!("unix:{sock}");
        }
        if let Ok(env_addr) = std::env::var("KIPUKA_LISTEN") {
            return env_addr;
        }
        if let Some(port) = self.listen_port {
            // Replace port in listen_addr
            if let Some(colon) = self.listen_addr.rfind(':') {
                return format!("{}:{port}", &self.listen_addr[..colon]);
            }
        }
        self.listen_addr.clone()
    }

    /// Returns `true` when the effective listen target is a Unix domain socket.
    pub fn is_unix_socket(&self) -> bool {
        let addr = self.effective_listen_addr();
        addr.starts_with("unix:") || addr.starts_with('/')
    }

    /// Returns `true` when the effective listen target uses systemd fd passing.
    pub fn is_systemd_fd(&self) -> bool {
        self.effective_listen_addr().starts_with("fd:")
    }
}
