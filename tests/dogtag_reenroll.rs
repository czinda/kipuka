//! Exercise the production handlers with a local Dogtag REST fixture. TLS
//! authentication itself is covered by tls_client_auth; these tests catch
//! issuer selection and policy bypasses before an external signing request.

#[allow(dead_code)]
mod common;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    body::{Bytes, to_bytes},
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kipuka::{
    auth::{AuthMethod, AuthResult, EstAuth},
    routes::LabelExtractor,
    state::AppState,
};
use serde_json::{Value, json};

struct Fixture {
    server: common::TestServer,
    state: AppState,
    auth: AuthResult,
    csr: Vec<u8>,
    certificate: Vec<u8>,
    submissions: Arc<AtomicUsize>,
    backend: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.backend.abort();
    }
}

impl Fixture {
    async fn new(status: &str, backend_error: bool) -> Self {
        let server = common::TestServer::start().await;
        let (_, _, client_der) = common::pki::generate_client_cert(
            "renewal.example.test",
            &server.ca.cert_pem,
            &server.ca.key_pem,
            1,
        );
        let (csr, _) = common::generate_test_csr("renewal.example.test", "rsa:2048");
        let issuer = common::TestCa::new();
        let request = openssl::x509::X509Req::from_der(&csr).unwrap();
        let ca = openssl::x509::X509::from_der(&issuer.cert_der).unwrap();
        let key = openssl::pkey::PKey::private_key_from_pem(&issuer.key_pem).unwrap();
        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(
            &openssl::bn::BigNum::from_u32(42)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        cert.set_subject_name(request.subject_name()).unwrap();
        cert.set_issuer_name(ca.subject_name()).unwrap();
        cert.set_pubkey(&request.public_key().unwrap()).unwrap();
        cert.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let cert = cert.build();
        let certificate = cert.to_der().unwrap();
        let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
        let submissions = Arc::new(AtomicUsize::new(0));
        let counter = submissions.clone();
        let expected_csr = csr.clone();
        let status = status.to_owned();
        let router = Router::new()
            .route("/ca/rest/account/login", post(|| async { StatusCode::NO_CONTENT }))
            .route("/ca/rest/certrequests", post(move |Json(body): Json<Value>| {
                let counter = counter.clone();
                let status = status.clone();
                let expected_csr = expected_csr.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(body["ProfileID"], "testEnrollment");
                    let attrs = body["Input"][0]["Attribute"].as_array().unwrap();
                    let value = attrs.iter().find(|a| a["name"] == "cert_request").unwrap()["Value"].as_str().unwrap();
                    assert_eq!(openssl::x509::X509Req::from_pem(value.as_bytes()).unwrap().to_der().unwrap(), expected_csr);
                    if backend_error {
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    } else {
                        Json(json!({"entries": [{"requestId": "7", "requestStatus": status, "certId": "0x2a"}]})).into_response()
                    }
                }
            }))
            .route("/ca/rest/certs/0x2a", get(move || {
                let cert_pem = cert_pem.clone();
                async move { Json(json!({"Encoded": cert_pem})) }
            }))
            // An agent without approval rights must leave the request pending.
            .route("/ca/rest/agent/certrequests/7", get(|| async { StatusCode::FORBIDDEN }))
            .route("/ca/rest/agent/certrequests/7/approve", post(|| async { StatusCode::FORBIDDEN }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.pem"), &issuer.cert_pem).unwrap();
        let dogtag: kipuka_dogtag::DogtagConfig = toml::from_str(&format!(
            "ca_url='http://{addr}'\nagent_cert_file=''\nagent_key_file=''\nca_cert_file='{}'\nprofile_id='testEnrollment'\nusername='fixture'\npassword='fixture'\nretry_max=0\ntimeout_secs=2\n",
            dir.path().join("ca.pem").display()
        )).unwrap();
        let mut state = (*server.state).clone();
        let mut config = (*state.config).clone();
        config.ocsp.enabled = false;
        config.dogtag = Some(dogtag.clone());
        state.config = Arc::new(config);
        state.dogtag = Some(Arc::new(
            kipuka_dogtag::DogtagPool::new(&[dogtag], 3, 30).unwrap(),
        ));
        let auth = AuthResult {
            identity: "renewal.example.test".into(),
            method: AuthMethod::Mtls,
            client_cert_der: Some(client_der),
            subject_dn: Some("CN=renewal.example.test".into()),
            subject_alt_names: vec![],
            extended_key_usage: vec![],
        };
        Self {
            server,
            state,
            auth,
            csr,
            certificate,
            submissions,
            backend,
            _dir: dir,
        }
    }

    async fn enroll(
        &self,
        renewal: bool,
        auth: AuthResult,
        label: LabelExtractor,
        csr: &[u8],
    ) -> Response {
        let state = State(Arc::new(self.state.clone()));
        let body = Bytes::from(STANDARD.encode(csr));
        let result = if renewal {
            kipuka::routes::simplereenroll::post_simplereenroll(EstAuth(auth), label, state, body)
                .await
        } else {
            kipuka::routes::simpleenroll::post_simpleenroll(EstAuth(auth), label, state, body).await
        };
        result.unwrap_or_else(IntoResponse::into_response)
    }

    fn label(&self) -> LabelExtractor {
        LabelExtractor::resolve(&self.state, None).unwrap()
    }
}

#[tokio::test]
async fn renewal_uses_dogtag_and_returns_its_certificate() {
    let fixture = Fixture::new("complete", false).await;
    for renewal in [false, true] {
        let response = fixture
            .enroll(renewal, fixture.auth.clone(), fixture.label(), &fixture.csr)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/pkcs7-mime; smime-type=certs-only"
        );
        assert_eq!(response.headers()["content-transfer-encoding"], "base64");
        let body = to_bytes(response.into_body(), 100_000).await.unwrap();
        let der = STANDARD
            .decode(
                body.iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let pkcs7 = openssl::pkcs7::Pkcs7::from_der(&der).unwrap();
        let certificates = pkcs7.signed().unwrap().certificates().unwrap();
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].to_der().unwrap(), fixture.certificate);
    }
    assert_eq!(fixture.submissions.load(Ordering::SeqCst), 2);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = 'cert.reenroll'")
            .fetch_one(&fixture.server.state.db)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn renewal_preserves_dogtag_pending_response() {
    let fixture = Fixture::new("pending", false).await;
    let response = fixture
        .enroll(true, fixture.auth.clone(), fixture.label(), &fixture.csr)
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers()["retry-after"],
        fixture
            .state
            .config
            .est
            .disconnected_retry_after_secs
            .to_string()
    );
    assert!(
        to_bytes(response.into_body(), 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.submissions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn renewal_reports_backend_failure_without_local_fallback_or_replay() {
    let fixture = Fixture::new("complete", true).await;
    let response = fixture
        .enroll(true, fixture.auth.clone(), fixture.label(), &fixture.csr)
        .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(fixture.submissions.load(Ordering::SeqCst), 1);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn renewal_checks_authentication_subject_signature_and_authorization_before_dogtag() {
    let fixture = Fixture::new("complete", false).await;
    let mut otp = fixture.auth.clone();
    otp.method = AuthMethod::Otp;
    assert_eq!(
        fixture
            .enroll(true, otp, fixture.label(), &fixture.csr)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut other = fixture.auth.clone();
    other.subject_dn = Some("CN=other.example.test".into());
    assert_eq!(
        fixture
            .enroll(true, other, fixture.label(), &fixture.csr)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut tampered = fixture.csr.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        fixture
            .enroll(true, fixture.auth.clone(), fixture.label(), &tampered)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut denied = fixture.label();
    denied.require_san_match = true;
    assert_eq!(
        fixture
            .enroll(true, fixture.auth.clone(), denied, &fixture.csr)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(fixture.submissions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn renewal_revocation_failure_blocks_dogtag() {
    let mut fixture = Fixture::new("complete", false).await;
    let mut config = (*fixture.state.config).clone();
    config.ocsp.enabled = true;
    config.ocsp.soft_fail = false;
    fixture.state.config = Arc::new(config);
    let response = fixture
        .enroll(true, fixture.auth.clone(), fixture.label(), &fixture.csr)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.submissions.load(Ordering::SeqCst), 0);
}
