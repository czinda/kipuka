//! Kipuka EST server binary entry point.
//!
//! Usage: `kipuka [OPTIONS]`
//!
//! Options:
//!   `--config <PATH>`     Configuration file path (default: `config.toml`)
//!   `--check-config`      Validate configuration and exit
//!
//! The server initializes in this order:
//!
//! 1. Parse CLI arguments
//! 2. Load and validate configuration
//! 3. Initialize tracing (structured logging)
//! 4. Connect to the database and run migrations
//! 5. Load CA key material
//! 6. Build application state
//! 7. Configure TLS (if enabled)
//! 8. Start the axum HTTP server
//! 9. Spawn background tasks (CRL refresh, audit rotation)
//! 10. Await graceful shutdown signal

use std::sync::Arc;

use base64::Engine as _;
use clap::Parser;
use indexmap::IndexMap;
use tracing_subscriber::EnvFilter;

use kipuka::audit::AuditState;
use kipuka::config::Config;
use kipuka::state::{AppState, AppStateBuilder, CaState};

/// Kipuka EST (RFC 7030) enrollment server.
#[derive(Parser, Debug)]
#[command(name = "kipuka", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Validate configuration and exit without starting the server.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() {
    // ── Crypto provider (required by rustls before any TLS operations) ──────
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // ── sqlx driver registration (required for AnyPool) ─────────────────────
    sqlx::any::install_default_drivers();

    // ── Logging ──────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();

    // ── Load configuration ───────────────────────────────────────────────────
    tracing::info!(config = %cli.config, "loading configuration");
    let config = Config::from_file(&cli.config)?;

    if cli.check_config {
        tracing::info!("configuration is valid");
        return Ok(());
    }

    let config = Arc::new(config);

    // ── Database ─────────────────────────────────────────────────────────────
    tracing::info!("connecting to database");
    let (db, db_kind) = kipuka::db::init_pool(&config.database)
        .await
        .map_err(|e| e.to_string())?;

    if config.database.run_migrations {
        tracing::info!("running database migrations");
        kipuka::db::run_migrations(&db, db_kind)
            .await
            .map_err(|e| e.to_string())?;
    }

    let db_ro = kipuka::db::init_ro_pool(&config.database, db_kind)
        .await
        .map_err(|e| e.to_string())?;

    // ── CA initialization ────────────────────────────────────────────────────
    tracing::info!("loading CA key material");
    let mut cas = IndexMap::new();
    let mut default_ca_id = String::new();

    for ca_cfg in &config.cas {
        tracing::info!(ca_id = %ca_cfg.id, "initializing CA");

        let cert_pem = std::fs::read_to_string(&ca_cfg.cert_file)
            .map_err(|e| format!("failed to read CA cert {}: {e}", ca_cfg.cert_file))?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut cert_chain_der: Vec<Vec<u8>> = Vec::new();
        let mut rest = cert_pem.as_str();
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let after = &rest[start + 27..];
            if let Some(end) = after.find("-----END CERTIFICATE-----") {
                let encoded: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
                let der = b64.decode(&encoded)
                    .map_err(|e| format!("invalid base64 in CA cert: {e}"))?;
                cert_chain_der.push(der);
                rest = &after[end + 25..];
            } else {
                break;
            }
        }
        if cert_chain_der.is_empty() {
            return Err(format!("no certificates found in {}", ca_cfg.cert_file));
        }
        let cert_der = cert_chain_der[0].clone();

        let ca_state = Arc::new(CaState {
            id: ca_cfg.id.clone(),
            key_type: ca_cfg.key_type.clone(),
            cert_der,
            cert_chain: cert_chain_der,
            hash_algorithm: ca_cfg.hash_algorithm.clone(),
            validity_days: ca_cfg.validity_days,
            crl_url: ca_cfg.crl_url.clone(),
            ocsp_url: ca_cfg.ocsp_url.clone(),
            crl_cache: parking_lot::Mutex::new(None),
            cab_forum_compliant: ca_cfg.cab_forum_compliant,
        });

        if ca_cfg.is_default || config.cas.len() == 1 {
            default_ca_id = ca_cfg.id.clone();
        }

        cas.insert(ca_cfg.id.clone(), ca_state);
    }

    // ── OTP store ────────────────────────────────────────────────────────────
    let otp_store = if config.otp.enabled {
        tracing::info!("initializing OTP store");
        Some(kipuka_otp::OtpStore::placeholder())
    } else {
        None
    };

    // ── HSM context ──────────────────────────────────────────────────────────
    let hsm = config.hsm.as_ref().map(|_hsm_cfg| {
        tracing::info!("initializing HSM context");
        Arc::new(kipuka_hsm::HsmContext::placeholder())
    });

    // ── Audit state ──────────────────────────────────────────────────────────
    let audit = Arc::new(AuditState::new());

    // Record server startup
    kipuka::audit::record(
        &db,
        &audit,
        kipuka::audit::AuditEvent::new(kipuka::audit::AuditEventType::CaStart)
            .with_detail("kipuka EST server starting"),
    )
    .await;

    // ── Build AppState ───────────────────────────────────────────────────────
    let state = AppStateBuilder::new()
        .config(config.clone())
        .db(db.clone())
        .db_ro(db_ro)
        .db_kind(db_kind)
        .cas(cas)
        .default_ca_id(default_ca_id)
        .audit(audit.clone());

    let state = if let Some(otp) = otp_store {
        state.otp_store(otp)
    } else {
        state
    };

    let state = if let Some(h) = hsm {
        state.hsm(h)
    } else {
        state
    };

    let app_state = state.build();

    // ── Router ───────────────────────────────────────────────────────────────
    let app_state_arc = Arc::new(app_state.clone());
    let app = kipuka::routes::build_router(app_state_arc);

    // ── Server startup ───────────────────────────────────────────────────────
    let listen_addr = config.server.effective_listen_addr();
    tracing::info!(listen = %listen_addr, "starting EST server");

    if config.tls.enabled {
        tracing::info!("TLS enabled — building acceptor");
        let acceptor = kipuka::tls::build_tls_acceptor(&config.tls).map_err(|e| e.to_string())?;

        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| format!("cannot bind to {listen_addr}: {e}"))?;

        tracing::info!(listen = %listen_addr, "EST server listening (TLS)");

        // Spawn background tasks
        spawn_background_tasks(app_state.clone());

        // Serve with graceful shutdown
        serve_tls(listener, acceptor, app, config.server.shutdown_timeout_secs).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| format!("cannot bind to {listen_addr}: {e}"))?;

        tracing::info!(listen = %listen_addr, "EST server listening (plain HTTP)");

        // Spawn background tasks
        spawn_background_tasks(app_state.clone());

        // Serve with graceful shutdown
        serve_plain(listener, app, config.server.shutdown_timeout_secs).await?;
    }

    // Record graceful shutdown
    kipuka::audit::record(
        &db,
        &audit,
        kipuka::audit::AuditEvent::new(kipuka::audit::AuditEventType::CaStop)
            .with_detail("kipuka EST server stopped"),
    )
    .await;

    Ok(())
}

/// Serve plain HTTP with graceful shutdown.
async fn serve_plain(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown_timeout_secs: u64,
) -> Result<(), String> {
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_timeout_secs))
        .await
        .map_err(|e| format!("server error: {e}"))
}

/// Serve HTTPS with TLS and graceful shutdown.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    app: axum::Router,
    shutdown_timeout_secs: u64,
) -> Result<(), String> {
    use hyper_util::rt::TokioIo;
    use tower::Service;

    let shutdown = shutdown_signal(shutdown_timeout_secs);
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (tcp_stream, peer_addr) = result
                    .map_err(|e| format!("accept error: {e}"))?;

                let acceptor = acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(
                                peer = %peer_addr,
                                error = %e,
                                "TLS handshake failed"
                            );
                            return;
                        }
                    };

                    // Extract the client certificate before wrapping the stream.
                    let peer_cert_der: Option<Vec<u8>> = tls_stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .map(|c| c.as_ref().to_vec());

                    let io = TokioIo::new(tls_stream);
                    let hyper_svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                        if let Some(ref cert_der) = peer_cert_der {
                            req.extensions_mut().insert(
                                kipuka::auth::mtls::PeerCertificate(cert_der.clone()),
                            );
                        }
                        let mut svc = app.clone();
                        async move {
                            svc.call(req).await
                        }
                    });

                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, hyper_svc)
                    .await
                    {
                        tracing::debug!(peer = %peer_addr, error = %e, "connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, stopping TLS server");
                break;
            }
        }
    }

    Ok(())
}

/// Wait for a shutdown signal (SIGTERM or SIGINT).
async fn shutdown_signal(timeout_secs: u64) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received SIGINT — initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM — initiating graceful shutdown");
        }
    }

    tracing::info!(timeout_secs, "waiting for in-flight requests to complete");
}

/// Spawn background tasks for CRL refresh, audit rotation, and OTP cleanup.
fn spawn_background_tasks(state: AppState) {
    // ── CRL refresh ──────────────────────────────────────────────────────
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                tracing::debug!("CRL refresh tick");
                // TODO: regenerate CRLs for each CA
                let _ = &state;
            }
        });
    }

    // ── Audit log rotation ───────────────────────────────────────────────
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                tracing::debug!("audit rotation tick");
                // TODO: rotate audit logs based on policy
                let _ = &state;
            }
        });
    }

    // ── OTP cleanup ──────────────────────────────────────────────────────
    if state.otp_store.is_some() {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                tracing::debug!("OTP cleanup tick");
                // TODO: expire old OTPs
                let _ = &state;
            }
        });
    }
}
