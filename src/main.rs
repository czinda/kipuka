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

    // ── Resolve secrets ────────────────────────────────────────────────────
    tracing::info!("resolving secrets");
    let resolver = kipuka::config::SecretResolver::new();
    let secrets = resolver
        .resolve_config(&config)
        .map_err(|e| format!("secret resolution failed: {e}"))?;

    if resolver.is_interactive() {
        resolver.persist_to_keyring();
    }

    let secrets = std::sync::Arc::new(secrets);
    let config = Arc::new(config);

    // ── Database ─────────────────────────────────────────────────────────────
    tracing::info!("connecting to database");
    let (db, db_kind) = kipuka::db::init_pool(&config.database, &secrets.db_url)
        .await
        .map_err(|e| e.to_string())?;

    if config.database.run_migrations {
        tracing::info!("running database migrations");
        kipuka::db::run_migrations(&db, db_kind)
            .await
            .map_err(|e| e.to_string())?;
    }

    let db_ro = kipuka::db::init_ro_pool(&config.database, db_kind, &secrets.db_url)
        .await
        .map_err(|e| e.to_string())?;

    // ── CA initialization ────────────────────────────────────────────────────
    tracing::info!("loading CA key material");
    let mut cas = IndexMap::new();
    let mut default_ca_id = String::new();

    for ca_cfg in &config.cas {
        tracing::info!(ca_id = %ca_cfg.id, "initializing CA");

        let cert_file = std::fs::File::open(&ca_cfg.cert_file)
            .map_err(|e| format!("failed to open CA cert {}: {e}", ca_cfg.cert_file))?;
        let mut reader = std::io::BufReader::new(cert_file);
        let cert_chain_der: Vec<Vec<u8>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to parse CA cert {}: {e}", ca_cfg.cert_file))?
            .into_iter()
            .map(|c| c.to_vec())
            .collect();
        if cert_chain_der.is_empty() {
            return Err(format!("no certificates found in {}", ca_cfg.cert_file));
        }
        tracing::info!(
            ca_id = %ca_cfg.id,
            cert_count = cert_chain_der.len(),
            cert_file = %ca_cfg.cert_file,
            "loaded CA certificate chain"
        );
        let cert_der = cert_chain_der[0].clone();

        let ca_state = Arc::new(CaState {
            id: ca_cfg.id.clone(),
            key_type: ca_cfg.key_type.clone(),
            cert_der,
            cert_chain: cert_chain_der,
            hash_algorithm: if ca_cfg.key_type.starts_with("ml-dsa") {
                "none".to_string()
            } else {
                ca_cfg.hash_algorithm.clone()
            },
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
    let hsm = if let Some(hsm_cfg) = config.hsm.as_ref() {
        tracing::info!(
            provider = ?hsm_cfg.provider,
            library = %hsm_cfg.library_path,
            "initializing HSM context"
        );

        let ctx = kipuka_hsm::Pkcs11Context::new(&hsm_cfg.library_path)
            .map_err(|e| format!("PKCS#11 library load failed: {e}"))?;

        // Log library info.
        if let Ok(info) = ctx.library_info() {
            tracing::info!(info = %info, "PKCS#11 library loaded");
        }

        // Find the HSM slot by token label or slot ID.
        let slot = if let Some(ref label) = hsm_cfg.token_label {
            kipuka_hsm::HsmSlot::find_by_label(&ctx, label)
                .map_err(|e| format!("HSM slot lookup by label '{label}' failed: {e}"))?
        } else {
            kipuka_hsm::HsmSlot::find_first_slot(&ctx)
                .map_err(|e| format!("HSM slot enumeration failed: {e}"))?
        };

        if let Ok(info) = slot.token_info() {
            tracing::info!(info = %info, "PKCS#11 token found");
        }

        // Open a read-write session and login.
        let session = slot
            .open_rw_session()
            .map_err(|e| format!("PKCS#11 session open failed: {e}"))?;

        let pin = secrets
            .hsm_pin
            .as_deref()
            .ok_or_else(|| "HSM is configured but no PIN was resolved".to_string())?
            .to_string();

        slot.login(&session, &pin)
            .map_err(|e| format!("PKCS#11 login failed: {e}"))?;

        tracing::info!("PKCS#11 session logged in — HSM ready for signing");

        // Map config provider to HSM crate provider.
        let provider = match hsm_cfg.provider {
            kipuka::config::HsmProvider::Entrust => kipuka_hsm::HsmProvider::Entrust,
            kipuka::config::HsmProvider::Utimaco => kipuka_hsm::HsmProvider::Utimaco,
            kipuka::config::HsmProvider::Kryoptic => kipuka_hsm::HsmProvider::Kryoptic,
            kipuka::config::HsmProvider::ThalesCsp => kipuka_hsm::HsmProvider::ThalesCsp,
            kipuka::config::HsmProvider::ThalesTct => kipuka_hsm::HsmProvider::ThalesTct,
        };

        Some(Arc::new(kipuka_hsm::HsmContext::new(
            ctx, provider, slot, session,
        )))
    } else {
        None
    };

    // ── Dogtag PKI pool ──────────────────────────────────────────────────────
    let dogtag = if let Some(ref dogtag_cfg) = config.dogtag {
        tracing::info!(
            ca_url = %dogtag_cfg.ca_url,
            profile_id = %dogtag_cfg.profile_id,
            "initializing Dogtag PKI client pool"
        );
        let pool = kipuka_dogtag::DogtagPool::new(
            std::slice::from_ref(dogtag_cfg),
            3,  // failure_threshold: mark unhealthy after 3 consecutive failures
            60, // cooldown_secs: wait 60s before re-checking unhealthy backends
        )
        .map_err(|e| format!("Dogtag pool init failed: {e}"))?;
        Some(Arc::new(pool))
    } else {
        None
    };

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

    // ── GSSAPI credential ────────────────────────────────────────────────────
    let (gss_cred, gssapi_require_crypto): (Option<Arc<dyn std::any::Any + Send + Sync>>, bool) =
        init_gssapi_cred(&config)?;

    // ── Build AppState ───────────────────────────────────────────────────────
    let state = AppStateBuilder::new()
        .config(config.clone())
        .secrets(secrets.clone())
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

    let hsm_for_tls = hsm.clone();
    let state = if let Some(h) = hsm {
        state.hsm(h)
    } else {
        state
    };

    let state = if let Some(d) = dogtag {
        state.dogtag(d)
    } else {
        state
    };

    let state = if let Some(cred) = gss_cred {
        state.gss_cred(cred)
    } else {
        state
    };

    let state = state.gssapi_require_crypto(gssapi_require_crypto);

    let app_state = state.build();

    // ── Router ───────────────────────────────────────────────────────────────
    let app_state_arc = Arc::new(app_state.clone());
    let app = kipuka::routes::build_router(app_state_arc.clone());

    // ── CoAP/DTLS server (RFC 9483) ─────────────────────────────────────────
    if let Some(ref coap_cfg) = config.coap
        && coap_cfg.enabled
    {
        let coap_state = app_state_arc.clone();
        let tls_cfg = &config.tls;

        // Read TLS cert/key for DTLS (same material as HTTP TLS).
        // Fail early with a clear message if files are missing.
        let cert_pem = std::fs::read(&tls_cfg.cert_file).map_err(|e| {
            format!(
                "CoAP/DTLS: failed to read server certificate '{}': {e}",
                tls_cfg.cert_file
            )
        })?;
        let key_pem = std::fs::read(&tls_cfg.key_file).map_err(|e| {
            format!(
                "CoAP/DTLS: failed to read server private key '{}': {e}",
                tls_cfg.key_file
            )
        })?;
        let ca_pem = std::fs::read(&tls_cfg.ca_file).map_err(|e| {
            format!(
                "CoAP/DTLS: failed to read CA certificate '{}': {e}",
                tls_cfg.ca_file
            )
        })?;

        let listen_addr = coap_cfg.listen_addr.clone();
        let block_size = coap_cfg.block_size;
        let max_payload = coap_cfg.max_payload;
        let max_sessions = coap_cfg.max_sessions;
        let session_timeout = std::time::Duration::from_secs(coap_cfg.session_timeout_secs);

        tokio::spawn(async move {
            tracing::info!(listen = %listen_addr, "starting CoAP/DTLS server (RFC 9483)");
            match kipuka_coap::CoapDtlsServer::bind(
                &listen_addr,
                &cert_pem,
                &key_pem,
                &ca_pem,
                block_size,
                max_payload,
                max_sessions,
                session_timeout,
            )
            .await
            {
                Ok(server) => {
                    // Bridge CoAP EST requests to the shared EST logic.
                    let handler = kipuka::routes::coap::CoapEstHandler::new(coap_state);
                    if let Err(e) = server.run(Arc::new(handler)).await {
                        tracing::error!(error = %e, "CoAP server error");
                    }
                }
                Err(e) => tracing::error!(error = %e, "failed to start CoAP server"),
            }
        });
    }

    // ── Server startup ───────────────────────────────────────────────────────
    let listen_addr = config.server.effective_listen_addr();
    tracing::info!(listen = %listen_addr, "starting EST server");

    if config.tls.enabled {
        tracing::info!("TLS enabled — building acceptor");
        let acceptor = kipuka::tls::build_tls_acceptor(&config.tls, hsm_for_tls.as_ref()).map_err(|e| e.to_string())?;

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
        let crl_interval_secs = state.config.crl_refresh_interval_secs;
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(crl_interval_secs));
            loop {
                interval.tick().await;
                tracing::debug!("CRL refresh tick");

                for (_ca_id, ca) in state.cas.iter() {
                    if let Err(e) = regenerate_crl(&state, ca).await {
                        tracing::error!(ca_id = %ca.id, error = %e, "CRL regeneration failed");
                    }
                }
            }
        });
    }

    // ── Audit log rotation ───────────────────────────────────────────────
    {
        let state = state.clone();
        tokio::spawn(async move {
            use kipuka::config::audit::RotationPolicy;
            use std::path::Path;

            let audit = &state.config.audit;

            if !audit.enabled || audit.rotation_policy == RotationPolicy::Never {
                tracing::debug!("audit rotation disabled, background task exiting");
                return;
            }

            let check_interval = if let Some(override_secs) = audit.rotation_check_interval_secs {
                std::time::Duration::from_secs(override_secs)
            } else {
                match audit.rotation_policy {
                    RotationPolicy::Size => std::time::Duration::from_secs(3600),
                    RotationPolicy::Weekly => std::time::Duration::from_secs(86400),
                    _ => std::time::Duration::from_secs(86400),
                }
            };
            let mut interval = tokio::time::interval(check_interval);

            let log_path = audit.log_path.clone();
            let max_file_size = audit.max_file_size;
            let retention_count = audit.retention_count;
            let rotation_policy = audit.rotation_policy.clone();
            let mut last_weekly_rotation: Option<std::time::Instant> = None;

            loop {
                interval.tick().await;
                tracing::debug!("audit rotation tick");

                let needs_rotation = match rotation_policy {
                    RotationPolicy::Size => match tokio::fs::metadata(&log_path).await {
                        Ok(meta) => meta.len() >= max_file_size,
                        Err(_) => false,
                    },
                    RotationPolicy::Daily => tokio::fs::metadata(&log_path).await.is_ok(),
                    RotationPolicy::Weekly => {
                        let should = match last_weekly_rotation {
                            None => true,
                            Some(last) => {
                                last.elapsed() >= std::time::Duration::from_secs(7 * 86400)
                            }
                        };
                        should && tokio::fs::metadata(&log_path).await.is_ok()
                    }
                    RotationPolicy::Never => false,
                };

                if !needs_rotation {
                    continue;
                }

                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let rotated_path = format!("{log_path}.{timestamp}");

                match tokio::fs::rename(&log_path, &rotated_path).await {
                    Ok(()) => {
                        tracing::info!(from = %log_path, to = %rotated_path, "audit log rotated");
                        if rotation_policy == RotationPolicy::Weekly {
                            last_weekly_rotation = Some(std::time::Instant::now());
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, path = %log_path, "failed to rotate audit log");
                        continue;
                    }
                }

                let path = Path::new(&log_path);
                if let (Some(parent), Some(base)) =
                    (path.parent(), path.file_name().and_then(|n| n.to_str()))
                {
                    let base = base.to_string();
                    if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
                        let mut rotated = Vec::new();
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            let name = entry.file_name().to_string_lossy().to_string();
                            if name.starts_with(&base) && name != base {
                                rotated.push(entry.path());
                            }
                        }
                        rotated.sort();
                        while rotated.len() > retention_count as usize {
                            if let Some(old) = rotated.first() {
                                let _ = tokio::fs::remove_file(old).await;
                                rotated.remove(0);
                            }
                        }
                    }
                }
            }
        });
    }

    // ── OTP cleanup ──────────────────────────────────────────────────────
    if state.otp_store.is_some() {
        let otp_cleanup_secs = state.config.otp.cleanup_interval_secs;
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(otp_cleanup_secs));
            loop {
                interval.tick().await;
                tracing::debug!("OTP cleanup tick");
                let now_str = chrono::Utc::now().to_rfc3339();
                let sql = kipuka::db::pg_sql("DELETE FROM otp_tokens WHERE expires_at < ?");
                match sqlx::query(sql).bind(&now_str).execute(&state.db).await {
                    Ok(result) => {
                        let removed = result.rows_affected();
                        if removed > 0 {
                            tracing::info!(removed, "cleaned up expired OTP tokens");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "OTP cleanup failed");
                    }
                }
            }
        });
    }
}

/// Regenerate the CRL for a single CA.
async fn regenerate_crl(state: &AppState, ca: &Arc<CaState>) -> Result<(), String> {
    use synta::ToDer as _;
    use synta_certificate::CertificateListBuilder;

    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(kipuka::db::pg_sql(
        "SELECT serial, revocation_time, revocation_reason \
             FROM certificates WHERE ca_id = ? AND status = 'revoked'",
    ))
    .bind(&ca.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("DB query for revoked certs failed: {e}"))?;

    let count = rows.len();

    let ca_cert = synta_certificate::Certificate::from_der(&ca.cert_der)
        .map_err(|e| format!("CA cert parse failed: {e}"))?;
    let issuer_der = ca_cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| format!("issuer Name encode failed: {e}"))?;

    let sig_alg_der: &[u8] = match ca.hash_algorithm.as_str() {
        "sha256" => &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
            0x00,
        ],
        "sha384" => &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05,
            0x00,
        ],
        "sha512" => &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05,
            0x00,
        ],
        // ML-DSA CAs use "none" — the signature algorithm is determined by
        // the key type (FIPS 204).  OID 2.16.840.1.101.3.4.3.18 = id-ml-dsa-65.
        // The actual OID is selected by synta-certificate based on the key.
        "none" => &[
            0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
        ],
        other => return Err(format!("unsupported hash algorithm for CRL: {other}")),
    };

    let now = chrono::Utc::now();
    let this_update = now.format("%Y%m%d%H%M%SZ").to_string();
    let next_update = (now + chrono::Duration::hours(1))
        .format("%Y%m%d%H%M%SZ")
        .to_string();

    let mut builder = CertificateListBuilder::new()
        .issuer(&issuer_der)
        .this_update(&this_update)
        .next_update(&next_update)
        .signature_algorithm(sig_alg_der);

    for (serial_hex, rev_time, rev_reason) in &rows {
        let serial_bytes = hex::decode(serial_hex).unwrap_or_default();
        let reason_code: Option<u8> = rev_reason.as_deref().map(|r| match r {
            "keyCompromise" => 1,
            "cACompromise" => 2,
            "affiliationChanged" => 3,
            "superseded" => 4,
            "cessationOfOperation" => 5,
            "certificateHold" => 6,
            "removeFromCRL" => 8,
            "privilegeWithdrawn" => 9,
            "aACompromise" => 10,
            _ => 0,
        });
        builder = builder.revoke(&serial_bytes, rev_time, reason_code);
    }

    let tbs_der = builder
        .build()
        .map_err(|e| format!("CRL TBS build failed: {e}"))?;

    let ca_cfg = state
        .config
        .cas
        .iter()
        .find(|c| c.id == ca.id)
        .ok_or_else(|| format!("no CaConfig for CA '{}'", ca.id))?;

    let pem = std::fs::read(&ca_cfg.key_file)
        .map_err(|e| format!("failed to read CA key {}: {e}", ca_cfg.key_file))?;
    let pem_key = synta_certificate::BackendPrivateKey::from_pem(&pem, None)
        .map_err(|e| format!("CA key parse failed: {e}"))?;

    // Sign synchronously and drop the non-Send signer before any await.
    // For ML-DSA CAs (hash_algorithm == "none"), pass "" so synta-certificate
    // uses the key's native algorithm without a separate hash step.
    let (signature, crl_der) = {
        use synta_certificate::PrivateKey as _;
        let effective_hash = if ca.hash_algorithm == "none" {
            ""
        } else {
            &ca.hash_algorithm
        };
        let signer = pem_key.as_signer(effective_hash);
        let sig = signer
            .sign_tbs_erased(&tbs_der)
            .map_err(|e| format!("CRL signing failed: {e}"))?;

        let crl = CertificateListBuilder::assemble(&tbs_der, sig_alg_der, &sig)
            .map_err(|e| format!("CRL assembly failed: {e}"))?;
        (sig, crl)
    };

    let _ = &signature; // suppress unused warning

    {
        let mut cache = ca.crl_cache.lock();
        *cache = Some((crl_der, std::time::Instant::now()));
    }

    tracing::info!(ca_id = %ca.id, revoked_count = count, "CRL regenerated");

    kipuka::audit::record(
        &state.db,
        &state.audit,
        kipuka::audit::AuditEvent::new(kipuka::audit::AuditEventType::CrlGenerate)
            .with_ca_id(&ca.id)
            .with_detail(format!("CRL generated with {count} revoked entries")),
    )
    .await;

    Ok(())
}

/// Initialize a GSSAPI server credential if GSSAPI authentication is configured.
///
/// When the `gssapi` feature is enabled, this acquires a GSS credential from
/// the system's Kerberos keytab (or gssproxy) for accepting SPNEGO tokens.
/// Without the feature, a placeholder `()` credential is stored so the auth
/// layer can distinguish "GSSAPI configured but no FFI" from "GSSAPI not
/// configured at all".
///
/// Returns `(credential, require_crypto_verification)`.
fn init_gssapi_cred(
    config: &Config,
) -> Result<(Option<Arc<dyn std::any::Any + Send + Sync>>, bool), String> {
    let gssapi_cfg = match config.admin.as_ref().and_then(|a| a.gssapi.as_ref()) {
        Some(cfg) => cfg,
        None => return Ok((None, true)),
    };

    let require_crypto = gssapi_cfg.require_crypto_verification;

    // Set the keytab environment variable before credential acquisition.
    if let Some(ref keytab) = gssapi_cfg.keytab_file {
        // SAFETY: This is safe to set before any multi-threaded GSS-API
        // calls occur, as we are still in the single-threaded startup path.
        unsafe {
            std::env::set_var("KRB5_KTNAME", keytab);
        }
        tracing::info!(keytab = %keytab, "KRB5_KTNAME set for GSSAPI");
    }

    #[cfg(feature = "gssapi")]
    {
        tracing::info!(
            service = %gssapi_cfg.service_name,
            require_crypto = require_crypto,
            "acquiring GSSAPI server credential via libgssapi"
        );

        let service_str = format!("{}@", gssapi_cfg.service_name);
        let name = libgssapi::name::Name::new(
            service_str.as_bytes(),
            Some(libgssapi::oid::GSS_NT_HOSTBASED_SERVICE),
        )
        .map_err(|e| format!("GSS name creation failed for '{service_str}': {e}"))?;

        let cred = libgssapi::credential::Cred::acquire(
            Some(&name),
            None, // default lifetime
            libgssapi::credential::CredUsage::Accept,
            None, // default mechanisms (includes SPNEGO + Kerberos)
        )
        .map_err(|e| format!("GSS credential acquisition failed: {e}"))?;

        tracing::info!("GSSAPI server credential acquired successfully");
        #[allow(clippy::needless_return)]
        return Ok((Some(Arc::new(cred)), require_crypto));
    }

    #[cfg(not(feature = "gssapi"))]
    {
        if require_crypto {
            tracing::warn!(
                "GSSAPI is configured with require_crypto_verification=true but the `gssapi` \
                 feature is not compiled in.  GSSAPI authentication will be rejected at runtime.  \
                 Either compile with `--features gssapi` or set require_crypto_verification=false."
            );
        } else {
            tracing::info!(
                "GSSAPI configured in structural-parsing mode (require_crypto_verification=false). \
                 Kerberos tickets will NOT be cryptographically verified."
            );
        }

        // Store a placeholder so the auth layer knows GSSAPI is configured.
        Ok((
            Some(Arc::new(()) as Arc<dyn std::any::Any + Send + Sync>),
            require_crypto,
        ))
    }
}
