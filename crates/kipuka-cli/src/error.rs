use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("EST server returned HTTP {status}: {body}")]
    Server { status: u16, body: String },

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid EST response: {0}")]
    Protocol(String),

    #[error("{0}")]
    Est(#[from] kipuka_est::EstError),

    #[error("Certificate parsing error: {0}")]
    Cert(String),
}

pub type CliResult<T> = Result<T, CliError>;
