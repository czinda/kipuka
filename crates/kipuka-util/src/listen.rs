//! Network listeners with TLS, Unix sockets, and systemd activation.
//!
//! Provides a unified [`Listener`] abstraction over:
//! - TCP sockets with optional TLS
//! - Unix domain sockets
//! - Systemd socket activation (`SD_LISTEN_FDS`)
//!
//! All listeners support graceful shutdown via a tokio cancellation token.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Errors during listener setup.
#[derive(Debug, Error)]
pub enum ListenError {
    /// Failed to bind a TCP socket.
    #[error("TCP bind failed on {addr}: {source}")]
    TcpBind {
        addr: String,
        source: std::io::Error,
    },

    /// Failed to bind a Unix domain socket.
    #[error("Unix socket bind failed on {path}: {source}")]
    UnixBind {
        path: String,
        source: std::io::Error,
    },

    /// Systemd socket activation environment is misconfigured.
    #[error("systemd socket activation error: {0}")]
    SystemdActivation(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Listener configuration from the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ListenConfig {
    /// Listen on a TCP address with optional TLS.
    Tcp {
        /// Bind address (e.g., "0.0.0.0:443" or "[::]:8443").
        address: String,
        /// Whether to wrap the connection in TLS.
        tls: bool,
    },
    /// Listen on a Unix domain socket.
    Unix {
        /// Path to the socket file.
        path: PathBuf,
    },
    /// Inherit sockets from systemd socket activation.
    Systemd,
}

/// A bound listener ready to accept connections.
pub enum Listener {
    /// TCP listener (may be wrapped in TLS by the caller).
    Tcp(TcpListener),
    /// Unix domain socket listener.
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl Listener {
    /// Bind a listener from configuration.
    pub async fn bind(config: &ListenConfig) -> Result<Self, ListenError> {
        match config {
            ListenConfig::Tcp { address, tls } => {
                let listener = TcpListener::bind(address)
                    .await
                    .map_err(|e| ListenError::TcpBind {
                        addr: address.clone(),
                        source: e,
                    })?;
                info!(
                    address = %address,
                    tls = %tls,
                    "TCP listener bound"
                );
                Ok(Self::Tcp(listener))
            }
            ListenConfig::Unix { path } => {
                #[cfg(unix)]
                {
                    // Remove stale socket file if it exists.
                    if path.exists() {
                        warn!(path = %path.display(), "removing stale Unix socket");
                        std::fs::remove_file(path).ok();
                    }
                    let listener = tokio::net::UnixListener::bind(path).map_err(|e| {
                        ListenError::UnixBind {
                            path: path.display().to_string(),
                            source: e,
                        }
                    })?;
                    info!(path = %path.display(), "Unix socket listener bound");
                    Ok(Self::Unix(listener))
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(ListenError::Io(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "Unix sockets not supported on this platform",
                    )))
                }
            }
            ListenConfig::Systemd => {
                let listener = activate_systemd_socket()?;
                info!("systemd socket activation listener acquired");
                Ok(Self::Tcp(listener))
            }
        }
    }
}

/// Detect and acquire systemd socket activation file descriptors.
///
/// Checks `SD_LISTEN_FDS` and `LISTEN_PID` environment variables per
/// the systemd socket activation protocol (sd_listen_fds(3)).
fn activate_systemd_socket() -> Result<TcpListener, ListenError> {
    let listen_pid: u32 = std::env::var("LISTEN_PID")
        .map_err(|_| {
            ListenError::SystemdActivation("LISTEN_PID not set; not running under systemd".into())
        })?
        .parse()
        .map_err(|e| ListenError::SystemdActivation(format!("invalid LISTEN_PID: {e}")))?;

    let current_pid = std::process::id();
    if listen_pid != current_pid {
        return Err(ListenError::SystemdActivation(format!(
            "LISTEN_PID {listen_pid} does not match current PID {current_pid}"
        )));
    }

    let listen_fds: u32 = std::env::var("LISTEN_FDS")
        .map_err(|_| ListenError::SystemdActivation("LISTEN_FDS not set".into()))?
        .parse()
        .map_err(|e| ListenError::SystemdActivation(format!("invalid LISTEN_FDS: {e}")))?;

    if listen_fds == 0 {
        return Err(ListenError::SystemdActivation(
            "LISTEN_FDS is 0; no sockets passed".into(),
        ));
    }

    // SD_LISTEN_FDS_START is always 3.
    const SD_LISTEN_FDS_START: i32 = 3;

    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        let std_listener =
            unsafe { std::net::TcpListener::from_raw_fd(SD_LISTEN_FDS_START) };
        std_listener.set_nonblocking(true).map_err(|e| {
            ListenError::SystemdActivation(format!("failed to set nonblocking: {e}"))
        })?;
        TcpListener::from_std(std_listener)
            .map_err(|e| ListenError::SystemdActivation(format!("tokio wrap failed: {e}")))
    }

    #[cfg(not(unix))]
    {
        let _ = SD_LISTEN_FDS_START;
        Err(ListenError::SystemdActivation(
            "systemd socket activation not supported on this platform".into(),
        ))
    }
}

/// Graceful shutdown helper.
///
/// Returns a future that completes when a SIGTERM or SIGINT is received.
/// Use with `tokio::select!` to implement graceful shutdown.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");

        tokio::select! {
            _ = sigterm.recv() => info!("received SIGTERM, initiating graceful shutdown"),
            _ = sigint.recv() => info!("received SIGINT, initiating graceful shutdown"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl+C handler");
        info!("received Ctrl+C, initiating graceful shutdown");
    }
}
