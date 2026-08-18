use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use kipuka_cli::{EstClient, TlsConfig};

/// kipuka-cli — EST (RFC 7030) client
#[derive(Parser)]
#[command(name = "kipuka-cli", version, about)]
struct Cli {
    /// EST server URL (e.g., https://est.example.com:8443)
    #[arg(long)]
    server: String,

    /// CA certificate for TLS server verification (PEM file)
    #[arg(long)]
    cacert: Option<PathBuf>,

    /// Client certificate for mTLS authentication (PEM file)
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Client private key for mTLS authentication (PEM file)
    #[arg(long)]
    key: Option<PathBuf>,

    /// Skip TLS certificate verification (INSECURE)
    #[arg(long)]
    insecure: bool,

    /// Increase verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Retrieve CA certificates from the EST server (RFC 7030 §4.1)
    Cacerts {
        /// CA label for multi-CA servers
        #[arg(long)]
        label: Option<String>,

        /// Output file (default: stdout)
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, default_value = "pem")]
        format: OutputFormat,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Pem,
    Der,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();

    let tls = TlsConfig {
        cacert: cli.cacert,
        client_cert: cli.cert,
        client_key: cli.key,
        insecure: cli.insecure,
    };

    let client = match EstClient::new(&cli.server, &tls) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match cli.command {
        Command::Cacerts {
            label,
            output,
            format,
        } => run_cacerts(&client, label.as_deref(), output, format).await,
    }
}

async fn run_cacerts(
    client: &EstClient,
    label: Option<&str>,
    output: Option<PathBuf>,
    format: OutputFormat,
) -> ExitCode {
    let result = match client.cacerts(label).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let data = match format {
        OutputFormat::Pem => match result.format_pem() {
            Ok(pem) => pem.into_bytes(),
            Err(e) => {
                eprintln!("Error formatting certificates: {e}");
                return ExitCode::FAILURE;
            }
        },
        OutputFormat::Der => result.pkcs7_der().to_vec(),
    };

    if let Some(path) = output {
        if let Err(e) = std::fs::write(&path, &data) {
            eprintln!("Error writing to {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    } else {
        use std::io::Write;
        if let Err(e) = std::io::stdout().lock().write_all(&data) {
            eprintln!("Error writing to stdout: {e}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}
