//! Test PKI material generation.
//!
//! Uses the `openssl` CLI (available on all test targets) to generate
//! ephemeral certificates and keys.  This avoids pulling in a Rust
//! OpenSSL binding as a dev-dependency and matches the deployment
//! environment where OpenSSL is always present.
//!
//! All material is ephemeral — generated into tempfiles and returned
//! as byte vectors.  Nothing touches the filesystem permanently.

use std::process::Command;

/// Generate a self-signed CA certificate and private key.
///
/// Returns `(cert_pem, key_pem, cert_der)`.
///
/// The CA certificate has:
/// - Subject: the provided `subject_dn` (OpenSSL `-subj` format)
/// - Basic Constraints: CA:TRUE, pathlen:0
/// - Key Usage: keyCertSign, cRLSign
/// - Validity: `validity_days` days
/// - RSA 2048 key
pub fn generate_self_signed_ca(
    subject_dn: &str,
    validity_days: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let key_path = dir.path().join("ca.key");
    let cert_path = dir.path().join("ca.crt");
    let cert_der_path = dir.path().join("ca.der");

    // Generate RSA key
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl genpkey");
    assert!(status.success(), "openssl genpkey failed");

    // Generate self-signed CA cert
    let subj = if subject_dn.starts_with('/') {
        subject_dn.to_string()
    } else {
        // Convert "CN=...,O=..." to "/CN=.../O=..."
        format!("/{}", subject_dn.replace(',', "/"))
    };

    let status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            &validity_days.to_string(),
            "-subj",
            &subj,
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ])
        .status()
        .expect("failed to run openssl req");
    assert!(status.success(), "openssl req (CA cert) failed");

    // Convert cert to DER
    let status = Command::new("openssl")
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            cert_der_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl x509 -outform DER");
    assert!(status.success(), "openssl x509 DER conversion failed");

    let cert_pem = std::fs::read(&cert_path).expect("failed to read CA cert PEM");
    let key_pem = std::fs::read(&key_path).expect("failed to read CA key PEM");
    let cert_der = std::fs::read(&cert_der_path).expect("failed to read CA cert DER");

    (cert_pem, key_pem, cert_der)
}

/// Generate a TLS server certificate signed by the given CA.
///
/// Returns `(cert_pem, key_pem)`.
///
/// The server cert has:
/// - Subject: `CN={hostname}`
/// - SAN: `DNS:{hostname}, IP:127.0.0.1`
/// - Extended Key Usage: serverAuth
/// - Validity: `validity_days`
pub fn generate_server_cert(
    hostname: &str,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
    validity_days: u32,
) -> (Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let ca_cert_path = dir.path().join("ca.crt");
    let ca_key_path = dir.path().join("ca.key");
    let key_path = dir.path().join("server.key");
    let csr_path = dir.path().join("server.csr");
    let cert_path = dir.path().join("server.crt");
    let ext_path = dir.path().join("server.ext");

    std::fs::write(&ca_cert_path, ca_cert_pem).unwrap();
    std::fs::write(&ca_key_path, ca_key_pem).unwrap();

    // Generate server key
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl genpkey");
    assert!(status.success());

    // Generate CSR
    let status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            csr_path.to_str().unwrap(),
            "-subj",
            &format!("/CN={hostname}"),
        ])
        .status()
        .expect("failed to run openssl req");
    assert!(status.success());

    // Write extensions file
    let ext_content = format!(
        "subjectAltName=DNS:{hostname},IP:127.0.0.1\n\
         extendedKeyUsage=serverAuth\n\
         basicConstraints=critical,CA:FALSE\n"
    );
    std::fs::write(&ext_path, ext_content).unwrap();

    // Sign with CA
    let status = Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-in",
            csr_path.to_str().unwrap(),
            "-CA",
            ca_cert_path.to_str().unwrap(),
            "-CAkey",
            ca_key_path.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            &validity_days.to_string(),
            "-extfile",
            ext_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl x509 -req");
    assert!(status.success());

    let cert_pem = std::fs::read(&cert_path).unwrap();
    let key_pem = std::fs::read(&key_path).unwrap();

    (cert_pem, key_pem)
}

/// Generate a client mTLS certificate signed by the given CA.
///
/// Returns `(cert_pem, key_pem, cert_der)`.
///
/// The client cert has:
/// - Subject: `CN={identity}`
/// - Extended Key Usage: clientAuth
/// - Validity: `validity_days`
pub fn generate_client_cert(
    identity: &str,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
    validity_days: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let ca_cert_path = dir.path().join("ca.crt");
    let ca_key_path = dir.path().join("ca.key");
    let key_path = dir.path().join("client.key");
    let csr_path = dir.path().join("client.csr");
    let cert_path = dir.path().join("client.crt");
    let cert_der_path = dir.path().join("client.der");
    let ext_path = dir.path().join("client.ext");

    std::fs::write(&ca_cert_path, ca_cert_pem).unwrap();
    std::fs::write(&ca_key_path, ca_key_pem).unwrap();

    // Generate client key
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl genpkey");
    assert!(status.success());

    // Generate CSR
    let status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            csr_path.to_str().unwrap(),
            "-subj",
            &format!("/CN={identity}"),
        ])
        .status()
        .expect("failed to run openssl req");
    assert!(status.success());

    // Write extensions file
    let ext_content = "extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE\n";
    std::fs::write(&ext_path, ext_content).unwrap();

    // Sign with CA
    let status = Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-in",
            csr_path.to_str().unwrap(),
            "-CA",
            ca_cert_path.to_str().unwrap(),
            "-CAkey",
            ca_key_path.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            &validity_days.to_string(),
            "-extfile",
            ext_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl x509 -req");
    assert!(status.success());

    // Convert to DER
    let status = Command::new("openssl")
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            cert_der_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run openssl x509 -outform DER");
    assert!(status.success());

    let cert_pem = std::fs::read(&cert_path).unwrap();
    let key_pem = std::fs::read(&key_path).unwrap();
    let cert_der = std::fs::read(&cert_der_path).unwrap();

    (cert_pem, key_pem, cert_der)
}

/// Generate an expired client certificate (validity: -1 day, already expired).
///
/// Returns `(cert_pem, key_pem)`.
pub fn generate_expired_client_cert(
    identity: &str,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // Generate a cert with 0 days validity (already expired upon signing)
    let (cert_pem, key_pem, _der) = generate_client_cert(identity, ca_cert_pem, ca_key_pem, 0);
    (cert_pem, key_pem)
}

/// Generate a PKCS#10 CSR with the given subject and key type.
///
/// Returns `(csr_der, private_key_der)`.
///
/// Supported key types: `"rsa:2048"`, `"ec:P-256"`, `"ec:P-384"`.
pub fn generate_csr(subject: &str, key_type: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let key_path = dir.path().join("req.key");
    let csr_path = dir.path().join("req.csr");
    let csr_der_path = dir.path().join("req.csr.der");
    let key_der_path = dir.path().join("req.key.der");

    // Generate key
    let key_args: Vec<&str> = match key_type {
        "ec:P-256" => vec![
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            key_path.to_str().unwrap(),
        ],
        "ec:P-384" => vec![
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-384",
            "-out",
            key_path.to_str().unwrap(),
        ],
        _ => vec![
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ],
    };

    let status = Command::new("openssl")
        .args(&key_args)
        .status()
        .expect("failed to run openssl genpkey for CSR");
    assert!(status.success(), "openssl genpkey (CSR key) failed");

    // Generate CSR
    let subj = if subject.starts_with('/') {
        subject.to_string()
    } else {
        format!("/CN={subject}")
    };

    let status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            csr_path.to_str().unwrap(),
            "-subj",
            &subj,
        ])
        .status()
        .expect("failed to run openssl req (CSR)");
    assert!(status.success(), "openssl req (CSR) failed");

    // Convert CSR to DER
    let status = Command::new("openssl")
        .args([
            "req",
            "-in",
            csr_path.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            csr_der_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to convert CSR to DER");
    assert!(status.success());

    // Convert key to DER
    let status = Command::new("openssl")
        .args([
            "pkey",
            "-in",
            key_path.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            key_der_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to convert key to DER");
    assert!(status.success());

    let csr_der = std::fs::read(&csr_der_path).expect("failed to read CSR DER");
    let key_der = std::fs::read(&key_der_path).expect("failed to read key DER");

    (csr_der, key_der)
}

/// Generate an ML-DSA CSR (requires OpenSSL 3.5+).
///
/// Returns `Ok((csr_der, key_pem))` or `Err` if OpenSSL 3.5+ is not available.
///
/// Supported levels: `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"`.
pub fn generate_mldsa_csr(subject: &str, level: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Check OpenSSL version >= 3.5
    if !openssl_supports_mldsa() {
        return Err("OpenSSL 3.5+ with ML-DSA support not available".into());
    }

    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let key_path = dir.path().join("mldsa.key");
    let csr_path = dir.path().join("mldsa.csr");
    let csr_der_path = dir.path().join("mldsa.csr.der");

    let algorithm = match level {
        "ml-dsa-44" | "mldsa44" => "mldsa44",
        "ml-dsa-65" | "mldsa65" => "mldsa65",
        "ml-dsa-87" | "mldsa87" => "mldsa87",
        other => return Err(format!("unsupported ML-DSA level: {other}")),
    };

    // Generate ML-DSA key
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            algorithm,
            "-out",
            key_path.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("openssl genpkey (ML-DSA): {e}"))?;

    if !status.success() {
        return Err("openssl genpkey (ML-DSA) failed".into());
    }

    // Generate CSR
    let subj = if subject.starts_with('/') {
        subject.to_string()
    } else {
        format!("/CN={subject}")
    };

    let status = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-key",
            key_path.to_str().unwrap(),
            "-out",
            csr_path.to_str().unwrap(),
            "-subj",
            &subj,
        ])
        .status()
        .map_err(|e| format!("openssl req (ML-DSA CSR): {e}"))?;

    if !status.success() {
        return Err("openssl req (ML-DSA CSR) failed".into());
    }

    // Convert to DER
    let status = Command::new("openssl")
        .args([
            "req",
            "-in",
            csr_path.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            csr_der_path.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("CSR DER conversion: {e}"))?;

    if !status.success() {
        return Err("CSR DER conversion failed".into());
    }

    let csr_der = std::fs::read(&csr_der_path).map_err(|e| e.to_string())?;
    let key_pem = std::fs::read(&key_path).map_err(|e| e.to_string())?;

    Ok((csr_der, key_pem))
}

/// Check whether the system OpenSSL supports ML-DSA (version >= 3.5).
pub fn openssl_supports_mldsa() -> bool {
    let output = Command::new("openssl").args(["version"]).output();

    match output {
        Ok(o) if o.status.success() => {
            let version_str = String::from_utf8_lossy(&o.stdout);
            // Parse "OpenSSL 3.5.0 ..." or similar
            if let Some(ver) = version_str.split_whitespace().nth(1) {
                let parts: Vec<&str> = ver.split('.').collect();
                if parts.len() >= 2 {
                    let major: u32 = parts[0].parse().unwrap_or(0);
                    let minor: u32 = parts[1].parse().unwrap_or(0);
                    return major > 3 || (major == 3 && minor >= 5);
                }
            }
            false
        }
        _ => false,
    }
}

/// Convert PEM to DER by stripping headers and base64-decoding.
pub fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    let pem_str = String::from_utf8_lossy(pem);
    let b64: String = pem_str
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .expect("failed to decode PEM base64")
}

use base64::Engine as _;
