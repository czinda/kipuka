//! kipuka-keygen — PKCS#11 key generation CLI for Kryoptic HSM.
//!
//! Generates key pairs in a PKCS#11 token that `pkcs11-tool` cannot
//! create — specifically ML-DSA-87 (FIPS 204) post-quantum signing keys.
//!
//! # Usage
//!
//! ```bash
//! # Generate ML-DSA-87 key pair (post-quantum)
//! kipuka-keygen --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
//!     --token pq-kipuka-tls --pin 1234 \
//!     --algorithm ml-dsa-87 --label my-signing-key
//!
//! # Generate RSA-4096 key pair
//! kipuka-keygen --module /path/to/pkcs11.so \
//!     --token rsa-root --pin 1234 \
//!     --algorithm rsa:4096 --label root-ca-signing
//!
//! # List objects in a token
//! kipuka-keygen --module /path/to/pkcs11.so \
//!     --token pq-kipuka-tls --pin 1234 --list
//! ```

use std::process::ExitCode;

use clap::Parser;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, MlDsaParameterSetType};
use cryptoki::session::UserType;
use cryptoki::types::{AuthPin, Ulong};
use tracing::{error, info};

#[derive(Parser)]
#[command(
    name = "kipuka-keygen",
    about = "Generate PKCS#11 key pairs in Kryoptic HSM (ML-DSA-87, RSA, ECDSA)"
)]
struct Cli {
    /// Path to the PKCS#11 module (.so)
    #[arg(long, default_value = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so")]
    module: String,

    /// Token label to use
    #[arg(long)]
    token: String,

    /// User PIN for the token
    #[arg(long)]
    pin: String,

    /// Key algorithm: ml-dsa-87, ml-dsa-65, ml-dsa-44, rsa:2048, rsa:4096, ec:p256, ec:p384
    #[arg(long, default_value = "ml-dsa-87")]
    algorithm: String,

    /// Label for the generated key pair (CKA_LABEL)
    #[arg(long, default_value = "signing-key")]
    label: String,

    /// Key ID (hex byte, e.g. "01")
    #[arg(long, default_value = "01")]
    id: String,

    /// List objects in the token instead of generating
    #[arg(long)]
    list: bool,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let pkcs11 = match Pkcs11::new(&cli.module) {
        Ok(ctx) => ctx,
        Err(e) => {
            error!(module = %cli.module, error = %e, "failed to load PKCS#11 module");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        error!(error = %e, "failed to initialize PKCS#11");
        return ExitCode::FAILURE;
    }

    // Find token by label
    let slot = match find_token(&pkcs11, &cli.token) {
        Some(s) => s,
        None => {
            error!(token = %cli.token, "token not found");
            list_tokens(&pkcs11);
            return ExitCode::FAILURE;
        }
    };

    let session = match pkcs11.open_rw_session(slot) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to open RW session");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = session.login(UserType::User, Some(&AuthPin::new(cli.pin.clone().into()))) {
        error!(error = %e, "login failed");
        return ExitCode::FAILURE;
    }

    info!(token = %cli.token, "logged in");

    if cli.list {
        return list_objects(&session);
    }

    let id = hex::decode(&cli.id).unwrap_or_else(|_| vec![0x01]);

    match cli.algorithm.to_lowercase().as_str() {
        "ml-dsa-87" | "mldsa87" => generate_ml_dsa(&session, MlDsaParameterSetType::ML_DSA_87, &cli.label, &id),
        "ml-dsa-65" | "mldsa65" => generate_ml_dsa(&session, MlDsaParameterSetType::ML_DSA_65, &cli.label, &id),
        "ml-dsa-44" | "mldsa44" => generate_ml_dsa(&session, MlDsaParameterSetType::ML_DSA_44, &cli.label, &id),
        s if s.starts_with("rsa:") => {
            let bits: u32 = s[4..].parse().unwrap_or(4096);
            generate_rsa(&session, bits, &cli.label, &id)
        }
        s if s.starts_with("ec:") => {
            let curve_oid = match &s[3..] {
                "p256" | "p-256" => vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                "p384" | "p-384" => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
                "p521" | "p-521" => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
                other => {
                    error!("unknown EC curve: {other}");
                    return ExitCode::FAILURE;
                }
            };
            generate_ecdsa(&session, &curve_oid, &cli.label, &id)
        }
        other => {
            error!("unknown algorithm: {other}. Use ml-dsa-87, rsa:4096, ec:p384, etc.");
            ExitCode::FAILURE
        }
    }
}

fn find_token(pkcs11: &Pkcs11, label: &str) -> Option<cryptoki::slot::Slot> {
    pkcs11
        .get_slots_with_initialized_token()
        .ok()?
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .map(|info| info.label().trim() == label)
                .unwrap_or(false)
        })
}

fn list_tokens(pkcs11: &Pkcs11) {
    eprintln!("Available tokens:");
    if let Ok(slots) = pkcs11.get_slots_with_initialized_token() {
        for s in slots {
            if let Ok(info) = pkcs11.get_token_info(s) {
                eprintln!("  - {}", info.label().trim());
            }
        }
    }
}

fn generate_ml_dsa(
    session: &cryptoki::session::Session,
    param_set: MlDsaParameterSetType,
    label: &str,
    id: &[u8],
) -> ExitCode {
    info!(param_set = ?param_set, label, "generating ML-DSA key pair via CKM_ML_DSA_KEY_PAIR_GEN");

    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(param_set.into()),
    ];

    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(param_set.into()),
    ];

    match session.generate_key_pair(&Mechanism::MlDsaKeyPairGen, &pub_template, &priv_template) {
        Ok((pub_handle, priv_handle)) => {
            println!(
                "OK: ML-DSA key pair generated — pub={:?}, priv={:?}, label='{label}'",
                pub_handle,
                priv_handle,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "ML-DSA key generation failed");
            ExitCode::FAILURE
        }
    }
}

fn generate_rsa(
    session: &cryptoki::session::Session,
    bits: u32,
    label: &str,
    id: &[u8],
) -> ExitCode {
    info!(bits, label, "generating RSA key pair");

    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Verify(true),
        Attribute::Encrypt(true),
        Attribute::ModulusBits(Ulong::from(bits as u64)),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    ];

    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Decrypt(true),
    ];

    match session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template) {
        Ok((pub_handle, priv_handle)) => {
            println!(
                "OK: RSA-{bits} key pair generated — pub={:?}, priv={:?}, label='{label}'",
                pub_handle,
                priv_handle,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "RSA key generation failed");
            ExitCode::FAILURE
        }
    }
}

fn generate_ecdsa(
    session: &cryptoki::session::Session,
    curve_oid: &[u8],
    label: &str,
    id: &[u8],
) -> ExitCode {
    info!(label, "generating ECDSA key pair");

    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Verify(true),
        Attribute::EcParams(curve_oid.to_vec()),
    ];

    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
    ];

    match session.generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template) {
        Ok((pub_handle, priv_handle)) => {
            println!(
                "OK: ECDSA key pair generated — pub={:?}, priv={:?}, label='{label}'",
                pub_handle,
                priv_handle,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "ECDSA key generation failed");
            ExitCode::FAILURE
        }
    }
}

fn list_objects(session: &cryptoki::session::Session) -> ExitCode {
    let attrs = vec![Attribute::Token(true)];
    match session.find_objects(&attrs) {
        Ok(objects) => {
            if objects.is_empty() {
                println!("No objects found.");
                return ExitCode::SUCCESS;
            }
            println!("{:<8} {:<15} {:<12} {}", "Handle", "Class", "KeyType", "Label");
            println!("{}", "-".repeat(60));
            for obj in objects {
                let info = session.get_attributes(
                    obj,
                    &[AttributeType::Class, AttributeType::KeyType, AttributeType::Label],
                );
                let (class, key_type, label) = match info {
                    Ok(attrs) => {
                        let class = attrs.iter().find_map(|a| {
                            if let Attribute::Class(c) = a { Some(format!("{c:?}")) } else { None }
                        }).unwrap_or_else(|| "?".into());
                        let key_type = attrs.iter().find_map(|a| {
                            if let Attribute::KeyType(k) = a { Some(format!("{k:?}")) } else { None }
                        }).unwrap_or_else(|| "-".into());
                        let label = attrs.iter().find_map(|a| {
                            if let Attribute::Label(l) = a {
                                Some(String::from_utf8_lossy(l).to_string())
                            } else { None }
                        }).unwrap_or_else(|| "?".into());
                        (class, key_type, label)
                    }
                    Err(_) => ("?".into(), "?".into(), "?".into()),
                };
                println!("{:?}\t{:<15} {:<12} {}", obj, class, key_type, label);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "failed to list objects");
            ExitCode::FAILURE
        }
    }
}
