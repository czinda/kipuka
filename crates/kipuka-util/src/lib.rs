//! Shared utilities for TLS, authentication, and network listeners.
//!
//! This crate provides reusable utilities that are shared across the
//! `kipuka` binary and its internal crates:
//! - [`auth`]: HTTP authentication header parsing (Basic, Bearer, Negotiate)
//! - [`listen`]: TCP/Unix/systemd socket listeners with graceful shutdown
//! - [`tls`]: TLS configuration, certificate loading, and NIAP CA PP compliance

pub mod auth;
pub mod listen;
pub mod tls;

pub use auth::{AuthCredential, AuthError};
pub use listen::{ListenConfig, Listener};
pub use tls::{TlsConfig, TlsConfigBuilder};

/// Returns the current Unix timestamp in seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
