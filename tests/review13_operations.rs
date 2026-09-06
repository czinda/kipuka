#[allow(dead_code)]
mod common;

#[tokio::test]
async fn admin_mtls_requests_certificate_when_est_authentication_is_disabled() {
    use kipuka::config::{AdminAuthMethod, ClientAuthMode};
    use std::io::Read;
    use tokio::io::AsyncWriteExt;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = common::TestCa::new();
    let (client_cert, client_key, client_der) =
        common::pki::generate_client_cert("synthetic-admin", &ca.cert_pem, &ca.key_pem, 1);
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, &ca.cert_pem).unwrap();
    std::fs::write(&key_path, &ca.key_pem).unwrap();
    let config = common::test_config();
    let mut est = config.tls.clone();
    est.client_auth = ClientAuthMode::None;
    est.cert_file = cert_path.to_str().unwrap().into();
    est.key_file = key_path.to_str().unwrap().into();
    est.ca_file = cert_path.to_str().unwrap().into();
    let mut admin = config.admin.unwrap();
    admin.auth_method = AdminAuthMethod::Mtls;
    admin.admin_ca_file = Some(cert_path.to_str().unwrap().into());
    let tls = kipuka::tls::admin_listener_config(&est, &admin);
    let acceptor = kipuka::tls::build_tls_acceptor(&tls, None).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(socket).await.unwrap();
        let peer = stream.get_ref().1.peer_certificates().unwrap()[0].to_vec();
        stream.write_all(b"ok").await.unwrap();
        peer
    });
    tokio::task::spawn_blocking(move || {
        let mut connector =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
        connector
            .set_certificate(&openssl::x509::X509::from_pem(&client_cert).unwrap())
            .unwrap();
        connector
            .set_private_key(&openssl::pkey::PKey::private_key_from_pem(&client_key).unwrap())
            .unwrap();
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut stream = connector.build().connect("localhost", socket).unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"ok");
    })
    .await
    .unwrap();
    assert_eq!(server.await.unwrap(), client_der);
}
