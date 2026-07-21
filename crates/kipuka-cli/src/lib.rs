//! EST (RFC 7030) client library for kipuka.
//!
//! Provides [`EstClient`] for programmatic access to EST server operations.
//!
//! ```rust,no_run
//! use kipuka_cli::{EstClient, TlsConfig};
//!
//! # async fn example() -> Result<(), kipuka_cli::CliError> {
//! let tls = TlsConfig {
//!     cacert: Some("ca.pem".into()),
//!     ..Default::default()
//! };
//! let client = EstClient::new("https://est.example.com:8443", &tls)?;
//! let result = client.cacerts(None).await?;
//! print!("{}", result.format_pem()?);
//! # Ok(())
//! # }
//! ```

pub mod cacerts;
pub mod client;
pub mod error;

pub use cacerts::CaCertsResult;
pub use client::{EstClient, TlsConfig};
pub use error::{CliError, CliResult};
