use crate::error::{CliError, CliResult};
use kipuka_est::cacerts::CaCertsResponse;

/// Result of a successful `/cacerts` operation.
///
/// Wraps the raw PKCS#7 DER and provides methods to extract individual
/// certificates and format output as PEM or DER.
pub struct CaCertsResult {
    response: CaCertsResponse,
}

impl CaCertsResult {
    pub(crate) fn new(response: CaCertsResponse) -> Self {
        Self { response }
    }

    /// Returns the raw PKCS#7 certs-only DER bytes.
    pub fn pkcs7_der(&self) -> &[u8] {
        self.response.pkcs7_der()
    }

    /// Extracts individual X.509 certificate DER blobs from the PKCS#7 structure
    /// by parsing the ASN.1 ContentInfo/SignedData envelope directly.
    pub fn certificate_ders(&self) -> CliResult<Vec<Vec<u8>>> {
        extract_certs_from_pkcs7_der(self.response.pkcs7_der())
    }

    /// Formats all certificates as concatenated PEM text.
    pub fn format_pem(&self) -> CliResult<String> {
        let certs = self.certificate_ders()?;
        let mut pem = String::new();
        for der in &certs {
            pem.push_str(&pem_encode(der, "CERTIFICATE"));
        }
        Ok(pem)
    }
}

/// Extracts X.509 certificate DER blobs from a PKCS#7 SignedData structure.
///
/// PKCS#7 ContentInfo (RFC 2315 / RFC 5652):
/// ```text
/// ContentInfo ::= SEQUENCE {
///   contentType  OID (1.2.840.113549.1.7.2 = signedData),
///   content      [0] EXPLICIT SignedData
/// }
/// SignedData ::= SEQUENCE {
///   version          INTEGER,
///   digestAlgorithms SET OF,
///   encapContentInfo ContentInfo,
///   certificates     [0] IMPLICIT SET OF Certificate,  ← target
///   crls             [1] IMPLICIT SET OF CRL,          (optional)
///   signerInfos      SET OF
/// }
/// ```
///
/// For certs-only, digestAlgorithms is empty, encapContentInfo has no content,
/// signerInfos is empty, and certificates holds the CA chain.
fn extract_certs_from_pkcs7_der(der: &[u8]) -> CliResult<Vec<Vec<u8>>> {
    let mut pos = 0;

    // Parse outer ContentInfo SEQUENCE
    let (_, content_end) = parse_tlv(der, pos)?;
    let _ = content_end; // we'll walk inside

    // Skip outer SEQUENCE tag+length
    pos = skip_tag_length(der, pos)?;

    // Parse contentType OID — skip it
    let (_, oid_end) = parse_tlv(der, pos)?;
    pos = oid_end;

    // Parse [0] EXPLICIT content
    if pos >= der.len() || (der[pos] & 0xe0) != 0xa0 {
        return Err(CliError::Cert(
            "Missing [0] EXPLICIT content in ContentInfo".into(),
        ));
    }
    pos = skip_tag_length(der, pos)?;

    // Now inside SignedData SEQUENCE
    pos = skip_tag_length(der, pos)?;

    // Skip version INTEGER
    let (_, ver_end) = parse_tlv(der, pos)?;
    pos = ver_end;

    // Skip digestAlgorithms SET OF
    let (_, da_end) = parse_tlv(der, pos)?;
    pos = da_end;

    // Skip encapContentInfo SEQUENCE
    let (_, eci_end) = parse_tlv(der, pos)?;
    pos = eci_end;

    // Now we should be at certificates [0] IMPLICIT (tag 0xa0)
    if pos >= der.len() {
        return Err(CliError::Cert("No certificates field in SignedData".into()));
    }

    if der[pos] != 0xa0 {
        return Err(CliError::Cert(format!(
            "Expected certificates [0] IMPLICIT (0xa0), got 0x{:02x}",
            der[pos]
        )));
    }

    // Parse the [0] IMPLICIT SET — its contents are the raw certificate DER blobs
    let (certs_content_start, certs_end) = parse_tlv(der, pos)?;
    let certs_region = &der[certs_content_start..certs_end];

    // Each element in the SET is a Certificate (SEQUENCE)
    let mut certs = Vec::new();
    let mut cpos = 0;
    while cpos < certs_region.len() {
        if certs_region[cpos] != 0x30 {
            break;
        }
        let cert_start = cpos;
        let (_, cert_end) = parse_tlv(certs_region, cpos)?;
        certs.push(certs_region[cert_start..cert_end].to_vec());
        cpos = cert_end;
    }

    if certs.is_empty() {
        return Err(CliError::Cert("No certificates found in PKCS#7".into()));
    }

    Ok(certs)
}

/// Parses a DER TLV (Tag-Length-Value) at the given position.
/// Returns (content_start, element_end).
fn parse_tlv(der: &[u8], pos: usize) -> CliResult<(usize, usize)> {
    if pos >= der.len() {
        return Err(CliError::Cert("Unexpected end of DER data".into()));
    }

    // Skip tag byte(s)
    let mut i = pos + 1;
    // High-tag-number form (tag >= 31)
    if der[pos] & 0x1f == 0x1f {
        while i < der.len() && der[i] & 0x80 != 0 {
            i += 1;
        }
        i += 1; // final tag byte
    }

    if i >= der.len() {
        return Err(CliError::Cert("Truncated DER tag".into()));
    }

    // Parse length
    let length_byte = der[i];
    i += 1;

    let (content_start, length) = if length_byte < 0x80 {
        (i, length_byte as usize)
    } else if length_byte == 0x80 {
        return Err(CliError::Cert(
            "Indefinite length not supported in DER".into(),
        ));
    } else {
        let num_bytes = (length_byte & 0x7f) as usize;
        if i + num_bytes > der.len() {
            return Err(CliError::Cert("Truncated DER length".into()));
        }
        let mut len: usize = 0;
        for &b in &der[i..i + num_bytes] {
            len = len
                .checked_shl(8)
                .and_then(|l| l.checked_add(b as usize))
                .ok_or_else(|| CliError::Cert("DER length overflow".into()))?;
        }
        (i + num_bytes, len)
    };

    let element_end = content_start
        .checked_add(length)
        .ok_or_else(|| CliError::Cert("DER length overflow".into()))?;

    if element_end > der.len() {
        return Err(CliError::Cert(format!(
            "DER element extends beyond data: need {element_end}, have {}",
            der.len()
        )));
    }

    Ok((content_start, element_end))
}

/// Skips the tag and length bytes of a TLV, returning the content start position.
fn skip_tag_length(der: &[u8], pos: usize) -> CliResult<usize> {
    let (content_start, _) = parse_tlv(der, pos)?;
    Ok(content_start)
}

fn pem_encode(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_encode_roundtrip() {
        use base64::Engine;

        let data = b"hello world";
        let pem = pem_encode(data, "TEST");
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert!(pem.ends_with("-----END TEST-----\n"));

        let b64_line: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64_line)
            .unwrap();
        assert_eq!(decoded, data);
    }
}
