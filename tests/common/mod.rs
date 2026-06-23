//! Shared test utilities for kipuka integration tests.
//!
//! Provides:
//! - [`TestServer`] — start kipuka with in-memory SQLite, ephemeral TLS, random port
//! - [`TestCa`] — self-signed CA for test cert issuance
//! - [`TestClient`] — reqwest client with mTLS and base64 encoding for EST
//! - Helper functions for CSR generation, OTP provisioning, server readiness

pub mod pki;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use indexmap::IndexMap;
use parking_lot::Mutex;

use kipuka::audit::AuditState;
use kipuka::config::Config;
use kipuka::state::{AppState, AppStateBuilder, CaState};

// ── TestCa ──────────────────────────────────────────────────────────────────

/// Minimal self-signed CA for test certificate issuance.
///
/// Holds a CA certificate (DER) and private key generated at construction.
/// Used to populate [`CaState`] during test server startup.
pub struct TestCa {
    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,
    /// DER-encoded CA private key.
    pub key_der: Vec<u8>,
    /// PEM-encoded CA certificate (for client trust config).
    pub cert_pem: Vec<u8>,
    /// PEM-encoded CA private key.
    pub key_pem: Vec<u8>,
}

impl TestCa {
    /// Generate a new self-signed RSA 2048 test CA.
    ///
    /// The CA certificate has:
    /// - Subject: `CN=Kipuka Test CA, O=Kipuka Integration Tests`
    /// - Basic Constraints: CA:TRUE
    /// - Key Usage: keyCertSign, cRLSign
    /// - Validity: 1 year from now
    pub fn new() -> Self {
        let (cert_pem, key_pem, cert_der) = pki::generate_self_signed_ca(
            "CN=Kipuka Test CA,O=Kipuka Integration Tests",
            365,
        );
        let key_der = pki::pem_to_der(&key_pem);
        Self {
            cert_der,
            key_der,
            cert_pem,
            key_pem,
        }
    }

    /// Build a [`CaState`] from this test CA for insertion into [`AppState`].
    pub fn to_ca_state(&self, id: &str) -> CaState {
        CaState {
            id: id.to_string(),
            key_type: "rsa:2048".to_string(),
            cert_der: self.cert_der.clone(),
            cert_chain: vec![self.cert_der.clone()],
            hash_algorithm: "sha256".to_string(),
            validity_days: 365,
            crl_url: None,
            ocsp_url: None,
            crl_cache: Mutex::new(None),
            cab_forum_compliant: false,
        }
    }
}

// ── TestServer ──────────────────────────────────────────────────────────────

/// A kipuka test server running on an ephemeral port with in-memory SQLite.
///
/// # Usage
///
/// ```rust,ignore
/// let server = TestServer::start().await;
/// let url = server.base_url();
/// // ... make HTTP requests against url ...
/// // Server shuts down when `server` is dropped.
/// ```
pub struct TestServer {
    /// The bound address (127.0.0.1:random_port).
    pub addr: SocketAddr,
    /// The test CA used by this server.
    pub ca: TestCa,
    /// Application state (for direct OTP provisioning, etc.).
    pub state: Arc<AppState>,
    /// Handle to the background server task (cancelled on drop).
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    /// Start a test server with default configuration.
    ///
    /// Uses:
    /// - In-memory SQLite database
    /// - Plain HTTP (no TLS) for simplicity
    /// - OTP authentication enabled
    /// - All EST endpoints enabled
    pub async fn start() -> Self {
        Self::start_with_config(test_config()).await
    }

    /// Start a test server with custom TOML configuration string.
    pub async fn start_with_config(config: Config) -> Self {
        let ca = TestCa::new();

        // Initialize in-memory database
        let (db, db_kind) = kipuka::db::init_pool(&config.database)
            .await
            .expect("failed to init test DB pool");

        kipuka::db::run_migrations(&db)
            .await
            .expect("failed to run test DB migrations");

        let db_ro = db.clone();

        // Build CA state
        let mut cas = IndexMap::new();
        let ca_state = Arc::new(ca.to_ca_state("default"));
        cas.insert("default".to_string(), ca_state);

        // Build OTP store
        let otp_store = if config.otp.enabled {
            Some(kipuka_otp::OtpStore::placeholder())
        } else {
            None
        };

        let audit = Arc::new(AuditState::new());

        let mut builder = AppStateBuilder::new()
            .config(Arc::new(config))
            .db(db)
            .db_ro(db_ro)
            .db_kind(db_kind)
            .cas(cas)
            .default_ca_id("default".to_string())
            .audit(audit);

        if let Some(otp) = otp_store {
            builder = builder.otp_store(otp);
        }

        let app_state = builder.build();
        let state = Arc::new(app_state);

        // Bind to an ephemeral port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test listener");
        let addr = listener.local_addr().unwrap();

        // Build the router
        let router = kipuka::routes::build_router(state.clone());

        // Start serving in a background task
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("test server error");
        });

        // Wait for the server to be ready
        wait_for_server(&format!("http://{addr}"), Duration::from_secs(5)).await;

        Self {
            addr,
            ca,
            state,
            _shutdown_tx: shutdown_tx,
        }
    }

    /// Base URL for EST endpoints: `http://127.0.0.1:{port}`
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// EST base URL: `http://127.0.0.1:{port}/.well-known/est`
    pub fn est_url(&self) -> String {
        format!("http://{}/.well-known/est", self.addr)
    }

    /// Admin API base URL: `http://127.0.0.1:{port}/admin`
    pub fn admin_url(&self) -> String {
        format!("http://{}/admin", self.addr)
    }
}

// ── TestClient ──────────────────────────────────────────────────────────────

/// HTTP client configured for EST protocol interactions.
///
/// Handles:
/// - Base64 encoding/decoding of DER payloads
/// - Correct Content-Type headers for EST operations
/// - Optional mTLS client certificate
/// - HTTP Basic auth for OTP enrollment
pub struct TestClient {
    inner: reqwest::Client,
    base_url: String,
}

impl TestClient {
    /// Create a test client without mTLS (for /cacerts, unauthenticated tests).
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build test HTTP client");
        Self {
            inner: client,
            base_url: base_url.to_string(),
        }
    }

    /// GET an EST endpoint and return the response.
    pub async fn est_get(&self, path: &str) -> reqwest::Response {
        self.inner
            .get(format!("{}/.well-known/est/{}", self.base_url, path))
            .send()
            .await
            .expect("EST GET request failed")
    }

    /// POST to an EST endpoint with PKCS#10 content type and base64 body.
    pub async fn est_post_csr(
        &self,
        path: &str,
        csr_der: &[u8],
        auth: Option<(&str, &str)>,
    ) -> reqwest::Response {
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr_der);

        let mut req = self
            .inner
            .post(format!("{}/.well-known/est/{}", self.base_url, path))
            .header("Content-Type", "application/pkcs10")
            .header("Content-Transfer-Encoding", "base64")
            .body(csr_b64);

        if let Some((user, pass)) = auth {
            req = req.basic_auth(user, Some(pass));
        }

        req.send().await.expect("EST POST request failed")
    }

    /// POST to an EST endpoint with a raw body and custom content type.
    pub async fn est_post_raw(
        &self,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> reqwest::Response {
        self.inner
            .post(format!("{}/.well-known/est/{}", self.base_url, path))
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await
            .expect("EST POST raw request failed")
    }

    /// GET an admin endpoint with Bearer token auth.
    pub async fn admin_get(&self, path: &str) -> reqwest::Response {
        self.inner
            .get(format!("{}/admin/{}", self.base_url, path))
            .header("Authorization", "Bearer test-admin-token")
            .send()
            .await
            .expect("admin GET request failed")
    }

    /// POST to an admin endpoint with Bearer token auth and JSON body.
    pub async fn admin_post(&self, path: &str, json: &serde_json::Value) -> reqwest::Response {
        self.inner
            .post(format!("{}/admin/{}", self.base_url, path))
            .header("Authorization", "Bearer test-admin-token")
            .header("Content-Type", "application/json")
            .json(json)
            .send()
            .await
            .expect("admin POST request failed")
    }

    /// DELETE an admin endpoint with Bearer token auth.
    pub async fn admin_delete(&self, path: &str) -> reqwest::Response {
        self.inner
            .delete(format!("{}/admin/{}", self.base_url, path))
            .header("Authorization", "Bearer test-admin-token")
            .send()
            .await
            .expect("admin DELETE request failed")
    }
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Generate a test PKCS#10 CSR with the given subject CN.
///
/// Returns `(csr_der, private_key_der)`.
///
/// The CSR is signed with an ephemeral RSA 2048 key by default.
/// Pass `"ec:P-256"` for ECDSA or `"rsa:2048"` for RSA.
pub fn generate_test_csr(subject: &str, key_type: &str) -> (Vec<u8>, Vec<u8>) {
    pki::generate_csr(subject, key_type)
}

/// Generate a random test OTP string.
///
/// Returns a 24-character alphanumeric token suitable for HTTP Basic auth.
pub fn generate_test_otp() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Wait for a server to become reachable at the given URL.
///
/// Polls the URL with exponential backoff until a successful TCP connection
/// or the timeout elapses.
pub async fn wait_for_server(url: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    let mut delay = Duration::from_millis(10);

    loop {
        if start.elapsed() > timeout {
            panic!("test server at {url} did not become ready within {timeout:?}");
        }

        // Try a simple TCP connect to see if the port is open
        let addr = url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        if let Ok(_) = tokio::net::TcpStream::connect(addr).await {
            return;
        }

        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(500));
    }
}

/// Build a minimal test configuration for kipuka.
///
/// Uses in-memory SQLite, TLS disabled, OTP enabled, all EST endpoints on.
pub fn test_config() -> Config {
    let toml_str = r#"
[server]
listen_addr = "127.0.0.1:0"

[database]
url = "sqlite::memory:"
run_migrations = true

[ca]
key_file = "/dev/null"
cert_file = "/dev/null"
validity_days = 90

[est]
simpleenroll = true
simplereenroll = true
fullcmc = true
serverkeygen = true
csrattrs = true

[otp]
enabled = true
entropy_bits = 128
ttl_seconds = 3600
max_usage = 1

[audit]
enabled = true
"#;
    toml::from_str(toml_str).expect("failed to parse test config TOML")
}

// ── Assertion helpers ───────────────────────────────────────────────────────

/// Assert that a response has the EST PKCS#7 certs-only content type.
#[macro_export]
macro_rules! assert_est_pkcs7_content_type {
    ($resp:expr) => {{
        let ct = $resp
            .headers()
            .get("content-type")
            .expect("missing Content-Type header")
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/pkcs7-mime"),
            "Expected application/pkcs7-mime, got: {ct}"
        );
        assert!(
            ct.contains("smime-type=certs-only"),
            "Expected smime-type=certs-only, got: {ct}"
        );
    }};
}

/// Assert that a response body is valid base64-encoded DER.
#[macro_export]
macro_rules! assert_est_base64_der {
    ($body:expr) => {{
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode($body.trim())
            .expect("response body is not valid base64");
        assert!(!decoded.is_empty(), "decoded DER body is empty");
        assert_eq!(
            decoded[0], 0x30,
            "DER should start with SEQUENCE tag (0x30), got: {:#04x}",
            decoded[0]
        );
        decoded
    }};
}

/// Assert that a response has the CSR attributes content type.
#[macro_export]
macro_rules! assert_est_csrattrs_content_type {
    ($resp:expr) => {{
        let ct = $resp
            .headers()
            .get("content-type")
            .expect("missing Content-Type header")
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/csrattrs"),
            "Expected application/csrattrs, got: {ct}"
        );
    }};
}

use base64::Engine as _;
