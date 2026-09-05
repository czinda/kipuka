//! Shared certificate lifecycle and issuer checks.
use chrono::{DateTime, Utc};
use synta_certificate::{Certificate, SignatureVerifier};

pub(crate) fn time(t: &synta_certificate::Time) -> Result<DateTime<Utc>, String> {
    let (y, m, d, h, n, s) = match t {
        synta_certificate::Time::UtcTime(t) => (t.year, t.month, t.day, t.hour, t.minute, t.second),
        synta_certificate::Time::GeneralTime(t) => {
            (t.year, t.month, t.day, t.hour, t.minute, t.second)
        }
    };
    chrono::NaiveDate::from_ymd_opt(y.into(), m.into(), d.into())
        .and_then(|d| d.and_hms_opt(h.into(), n.into(), s.into()))
        .map(|d| d.and_utc())
        .ok_or_else(|| "invalid certificate time".into())
}
pub(crate) fn valid_now(der: &[u8]) -> Result<(), String> {
    let cert = Certificate::from_der(der).map_err(|e| e.to_string())?;
    let v = &cert.tbs_certificate.validity;
    let now = Utc::now();
    if now < time(&v.not_before)? || now > time(&v.not_after)? {
        return Err("certificate outside validity period".into());
    }
    Ok(())
}
pub(crate) fn issued_by(der: &[u8], issuer: &[u8]) -> bool {
    let check = || -> Result<(), String> {
        let c = Certificate::from_der(der).map_err(|e| e.to_string())?;
        let i = Certificate::from_der(issuer).map_err(|e| e.to_string())?;
        if c.tbs_certificate.issuer.as_bytes() != i.tbs_certificate.subject.as_bytes() {
            return Err("issuer name mismatch".into());
        }
        let r = synta_certificate::cert_byte_ranges(der).ok_or("invalid certificate")?;
        let ir = synta_certificate::cert_byte_ranges(issuer).ok_or("invalid issuer")?;
        synta_certificate::default_signature_verifier()
            .verify_certificate_signature(
                &der[r.tbs],
                &der[r.signature_algorithm],
                c.signature_value.as_bytes(),
                &issuer[ir.subject_public_key_info],
            )
            .map_err(|e| e.to_string())
    };
    check().is_ok()
}
pub(crate) fn issuer_for(der: &[u8], app: &crate::state::AppState) -> Result<Vec<u8>, String> {
    let mut candidates: Vec<Vec<u8>> = app
        .cas
        .values()
        .flat_map(|ca| ca.cert_chain.iter().cloned())
        .collect();
    let mut paths = Vec::new();
    paths.push(app.config.tls.ca_file.as_str());
    if let Some(admin) = &app.config.admin
        && let Some(path) = &admin.admin_ca_file
    {
        paths.push(path);
    }
    for path in paths {
        if path.is_empty() {
            continue;
        }
        if let Ok(bytes) = std::fs::read(path) {
            let mut reader = std::io::BufReader::new(bytes.as_slice());
            candidates.extend(
                rustls_pemfile::certs(&mut reader)
                    .filter_map(Result::ok)
                    .map(|c| c.to_vec()),
            );
        }
    }
    candidates
        .into_iter()
        .find(|ca| issued_by(der, ca))
        .ok_or_else(|| "no verified issuer for certificate".into())
}
