//! Database configuration.
//!
//! Kipuka supports three database backends via sqlx:
//!
//! - **SQLite** — default, zero-dependency option for single-node deployments.
//! - **PostgreSQL** — recommended for HA and multi-node setups.
//! - **MariaDB** — alternative for environments where MySQL-compatible
//!   databases are the standard.

use serde::Deserialize;

/// `[database]` section — connection pool configuration.
///
/// ```toml
/// [database]
/// url = "sqlite:///var/lib/kipuka/kipuka.db"
/// max_connections = 10
/// min_connections = 2
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    /// Database connection URL.
    ///
    /// Examples:
    /// - `"sqlite:///var/lib/kipuka/kipuka.db"` — file-backed SQLite
    /// - `"sqlite::memory:"` — in-memory SQLite (testing only)
    /// - `"postgres://user:pass@host/kipuka"` — PostgreSQL
    /// - `"mariadb://user:pass@host/kipuka"` — MariaDB
    ///
    /// Supports `"env:VAR_NAME"` to read the URL from an environment variable.
    pub url: String,

    /// Maximum number of connections in the pool.
    ///
    /// Default: 10 for PostgreSQL/MariaDB, 1 for SQLite (WAL mode
    /// serializes writes regardless of pool size).
    pub max_connections: Option<u32>,

    /// Minimum number of idle connections maintained in the pool.
    ///
    /// Default: none (sqlx default applies).
    pub min_connections: Option<u32>,

    /// Connection acquisition timeout in seconds.
    ///
    /// Default: 30.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Maximum connection lifetime in seconds before recycling.
    ///
    /// Default: 3600 (1 hour).
    #[serde(default = "default_max_lifetime_secs")]
    pub max_lifetime_secs: u64,

    /// Enable SQLite WAL (Write-Ahead Logging) mode.
    ///
    /// WAL provides better concurrent read performance by allowing
    /// readers and writers to proceed simultaneously.  Enabled by
    /// default for SQLite; ignored for other backends.
    #[serde(default = "bool_true")]
    pub sqlite_wal: bool,

    /// Run pending migrations at startup.
    ///
    /// Default: `true`.
    #[serde(default = "bool_true")]
    pub run_migrations: bool,
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_max_lifetime_secs() -> u64 {
    3600
}

fn bool_true() -> bool {
    true
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "sqlite:///var/lib/kipuka/kipuka.db".to_string(),
            max_connections: None,
            min_connections: None,
            connect_timeout_secs: default_connect_timeout_secs(),
            max_lifetime_secs: default_max_lifetime_secs(),
            sqlite_wal: true,
            run_migrations: true,
        }
    }
}

impl DbConfig {
    /// Resolve the database URL, expanding `"env:VAR_NAME"` references.
    pub fn resolve_url(&self) -> std::result::Result<String, String> {
        if let Some(var_name) = self.url.strip_prefix("env:") {
            std::env::var(var_name).map_err(|_| {
                format!("[database].url references env var {var_name:?} which is not set")
            })
        } else {
            Ok(self.url.clone())
        }
    }
}
