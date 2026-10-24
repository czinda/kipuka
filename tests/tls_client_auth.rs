//! Exercise the production TLS acceptor with an independent OpenSSL client.
//! PQ cases require OpenSSL 3.5+; classical policy tests run on older versions.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use kipuka::config::{ClientAuthMode, TlsConfig};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    dir: tempfile::TempDir,
}

fn openssl(dir: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl Fixture {
    fn new(pq: bool, usage: &str, days: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let key_args = if pq {
            vec!["genpkey", "-algorithm", "ML-DSA-87"]
        } else {
            vec![
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
            ]
        };
        for name in ["ca.key", "client.key"] {
            let mut args = key_args.clone();
            args.extend(["-out", name]);
            openssl(path, &args);
        }
        openssl(
            path,
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "2",
                "-subj",
                "/CN=TLS Test CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        openssl(
            path,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-out",
                "server.key",
            ],
        );
        for (name, eku, validity, serial) in [
            ("server", "serverAuth", "1", "1"),
            ("client", usage, days, "2"),
        ] {
            openssl(
                path,
                &[
                    "req",
                    "-new",
                    "-key",
                    &format!("{name}.key"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN={name}.example.test"),
                ],
            );
            std::fs::write(
                path.join(format!("{name}.ext")),
                format!(
                    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
                 extendedKeyUsage={eku}\nsubjectAltName=DNS:{name}.example.test\n\
                 subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                ),
            )
            .unwrap();
            openssl(
                path,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-set_serial",
                    serial,
                    "-days",
                    "1",
                    "-extfile",
                    &format!("{name}.ext"),
                    "-out",
                    &format!("{name}.pem"),
                ],
            );
            if validity == "-1" {
                use openssl::asn1::Asn1Time;
                use openssl::x509::{
                    X509,
                    extension::{
                        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
                    },
                };
                let original =
                    X509::from_pem(&std::fs::read(path.join("client.pem")).unwrap()).unwrap();
                let mut expired = X509::builder().unwrap();
                expired.set_version(2).unwrap();
                expired.set_serial_number(original.serial_number()).unwrap();
                expired.set_subject_name(original.subject_name()).unwrap();
                expired.set_issuer_name(original.issuer_name()).unwrap();
                expired.set_pubkey(&original.public_key().unwrap()).unwrap();
                expired
                    .set_not_before(&Asn1Time::from_unix(1).unwrap())
                    .unwrap();
                expired
                    .set_not_after(&Asn1Time::from_unix(2).unwrap())
                    .unwrap();
                expired
                    .append_extension(BasicConstraints::new().critical().build().unwrap())
                    .unwrap();
                expired
                    .append_extension(
                        KeyUsage::new()
                            .critical()
                            .digital_signature()
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                expired
                    .append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
                    .unwrap();
                let ca = X509::from_pem(&std::fs::read(path.join("ca.pem")).unwrap()).unwrap();
                let aki = AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .build(&expired.x509v3_context(Some(&ca), None))
                    .unwrap();
                expired.append_extension(aki).unwrap();
                let ca_key = openssl::pkey::PKey::private_key_from_pem(
                    &std::fs::read(path.join("ca.key")).unwrap(),
                )
                .unwrap();
                let digest = if pq {
                    openssl::hash::MessageDigest::null()
                } else {
                    openssl::hash::MessageDigest::sha256()
                };
                expired.sign(&ca_key, digest).unwrap();
                std::fs::write(path.join("client.pem"), expired.build().to_pem().unwrap()).unwrap();
            }
        }
        Self { dir }
    }

    async fn connect(
        &self,
        auth: ClientAuthMode,
        client: Option<&Fixture>,
    ) -> Result<bool, String> {
        // Production uses this same provider installation; no test verifier.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = TlsConfig {
            cert_file: self.dir.path().join("server.pem").to_str().unwrap().into(),
            key_file: self.dir.path().join("server.key").to_str().unwrap().into(),
            ca_file: self.dir.path().join("ca.pem").to_str().unwrap().into(),
            client_auth: auth,
            ..Default::default()
        };
        let acceptor = kipuka::tls::build_tls_acceptor(&config, None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut tls = acceptor.accept(socket).await.map_err(|e| e.to_string())?;
            let authenticated = tls
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty());
            let mut input = [0u8; 1];
            tls.read_exact(&mut input)
                .await
                .map_err(|e| e.to_string())?;
            tls.write_all(&input).await.map_err(|e| e.to_string())?;
            Ok::<_, String>(authenticated)
        });

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        connector
            .set_ca_file(self.dir.path().join("ca.pem"))
            .unwrap();
        if let Some(client) = client {
            connector
                .set_certificate_chain_file(client.dir.path().join("client.pem"))
                .unwrap();
            connector
                .set_private_key_file(
                    client.dir.path().join("client.key"),
                    openssl::ssl::SslFiletype::PEM,
                )
                .unwrap();
        }
        let connector = connector.build();
        let client_result = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let socket =
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut tls = connector
                .connect("server.example.test", socket)
                .map_err(|e| e.to_string())?;
            tls.write_all(b"x").map_err(|e| e.to_string())?;
            let mut echo = [0u8; 1];
            tls.read_exact(&mut echo).map_err(|e| e.to_string())?;
            assert_eq!(&echo, b"x");
            Ok::<_, String>(())
        })
        .await
        .unwrap();
        let server_result = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        match (server_result, client_result) {
            (Ok(peer), Ok(())) => Ok(peer),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

#[tokio::test]
async fn trusted_ml_dsa_client_is_authenticated() {
    let available = Command::new("openssl")
        .args(["list", "-signature-algorithms"])
        .output()
        .unwrap();
    if !String::from_utf8_lossy(&available.stdout).contains("ML-DSA-87") {
        eprintln!("SKIP: ML-DSA TLS requires OpenSSL 3.5+");
        return;
    }
    let fixture = Fixture::new(true, "clientAuth", "1");
    assert_eq!(
        fixture
            .connect(ClientAuthMode::Required, Some(&fixture))
            .await,
        Ok(true)
    );
}

#[tokio::test]
async fn pq_chain_validation_rejects_untrusted_expired_wrong_purpose_and_tampered_clients() {
    let available = Command::new("openssl")
        .args(["list", "-signature-algorithms"])
        .output()
        .unwrap();
    if !String::from_utf8_lossy(&available.stdout).contains("ML-DSA-87") {
        eprintln!("SKIP: ML-DSA TLS requires OpenSSL 3.5+");
        return;
    }
    let fixture = Fixture::new(true, "clientAuth", "1");
    let untrusted = Fixture::new(true, "clientAuth", "1");
    assert!(
        fixture
            .connect(ClientAuthMode::Required, Some(&untrusted))
            .await
            .is_err()
    );
    for (purpose, days) in [("serverAuth", "1"), ("clientAuth", "-1")] {
        let invalid = Fixture::new(true, purpose, days);
        assert!(
            invalid
                .connect(ClientAuthMode::Optional, Some(&invalid))
                .await
                .is_err()
        );
    }
    let path = fixture.dir.path().join("client.pem");
    let mut der = openssl::x509::X509::from_pem(&std::fs::read(&path).unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    *der.last_mut().unwrap() ^= 1;
    std::fs::write(
        path,
        openssl::x509::X509::from_der(&der)
            .unwrap()
            .to_pem()
            .unwrap(),
    )
    .unwrap();
    assert!(
        fixture
            .connect(ClientAuthMode::Required, Some(&fixture))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn classical_client_authentication_is_preserved() {
    let fixture = Fixture::new(false, "clientAuth", "1");
    assert_eq!(
        fixture
            .connect(ClientAuthMode::Required, Some(&fixture))
            .await,
        Ok(true)
    );
}

#[tokio::test]
async fn optional_tls_allows_no_certificate_but_requires_valid_presented_certificate() {
    let fixture = Fixture::new(false, "clientAuth", "1");
    assert_eq!(
        fixture.connect(ClientAuthMode::Optional, None).await,
        Ok(false)
    );
    assert_eq!(
        fixture
            .connect(ClientAuthMode::Optional, Some(&fixture))
            .await,
        Ok(true)
    );
    let invalid = Fixture::new(false, "serverAuth", "1");
    assert!(
        invalid
            .connect(ClientAuthMode::Optional, Some(&invalid))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn required_tls_rejects_missing_and_untrusted_client_certificates() {
    let fixture = Fixture::new(false, "clientAuth", "1");
    assert!(
        fixture
            .connect(ClientAuthMode::Required, None)
            .await
            .is_err()
    );
    let untrusted = Fixture::new(false, "clientAuth", "1");
    assert!(
        fixture
            .connect(ClientAuthMode::Required, Some(&untrusted))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn client_certificate_purpose_expiry_and_signature_are_checked() {
    let server_only = Fixture::new(false, "serverAuth", "1");
    assert!(
        server_only
            .connect(ClientAuthMode::Required, Some(&server_only))
            .await
            .is_err()
    );
    let expired = Fixture::new(false, "clientAuth", "-1");
    assert!(
        expired
            .connect(ClientAuthMode::Required, Some(&expired))
            .await
            .is_err()
    );
    let tampered = Fixture::new(false, "clientAuth", "1");
    let path = tampered.dir.path().join("client.pem");
    let mut der = openssl::x509::X509::from_pem(&std::fs::read(&path).unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    *der.last_mut().unwrap() ^= 1;
    std::fs::write(
        path,
        openssl::x509::X509::from_der(&der)
            .unwrap()
            .to_pem()
            .unwrap(),
    )
    .unwrap();
    assert!(
        tampered
            .connect(ClientAuthMode::Required, Some(&tampered))
            .await
            .is_err()
    );
}
