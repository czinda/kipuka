//! Domain name and identity matching for TLS certificates (RFC 6125).
//!
//! Implements the rules for verifying that a TLS certificate is valid for
//! a given reference identifier (hostname, IP address, or email address).
//!
//! ## RFC 6125 compliance
//!
//! - **Section 6.4.1**: case-insensitive comparison for DNS names.
//! - **Section 6.4.3**: wildcard matching — only the leftmost label may be
//!   a wildcard (`*`), no partial wildcards, wildcard does not match dots.
//! - **Section 6.4.4**: if SANs are present, the subject CN MUST be ignored.
//! - **Section 6.5.2**: IP address matching via iPAddress SAN entries.
//!
//! ## Usage in Kipuka
//!
//! - POP linking in `/simpleenroll` and `/simplereenroll` (mTLS client cert
//!   identity vs. CSR subject) — see [`super::mtls`].
//! - EST server certificate validation by clients (informational; the
//!   actual TLS validation is done by rustls, but this module provides
//!   the matching logic for EST-specific identity checks).

use std::net::IpAddr;

/// Check whether a certificate DNS name pattern matches a hostname.
///
/// RFC 6125 Section 6.4.3 — wildcard matching rules:
///
/// 1. Only the leftmost label may be a wildcard: `*.example.com` is valid,
///    `foo.*.example.com` is NOT.
/// 2. No partial wildcards: `f*.example.com` is NOT allowed.
/// 3. The wildcard does not match across label boundaries (dots):
///    `*.example.com` matches `foo.example.com` but NOT `foo.bar.example.com`.
/// 4. The wildcard MUST NOT match the empty string: `*.example.com` does NOT
///    match `example.com`.
///
/// RFC 6125 Section 6.4.1: comparison is case-insensitive (ASCII fold).
///
/// IDN/A-labels (punycode): both pattern and hostname are compared in their
/// A-label (ASCII-compatible encoding) form.  This function does not perform
/// U-label to A-label conversion; callers must ensure both inputs use the
/// same encoding.
pub fn matches_domain(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();

    // Reject empty inputs.
    if pattern.is_empty() || hostname.is_empty() {
        return false;
    }

    // Strip trailing dots for comparison.
    let pattern = pattern.trim_end_matches('.');
    let hostname = hostname.trim_end_matches('.');

    // Non-wildcard: exact match.
    if !pattern.starts_with("*.") {
        // Reject patterns that contain a wildcard in any position other
        // than the leftmost label (e.g., "foo.*.example.com").
        if pattern.contains('*') {
            return false;
        }
        return pattern == hostname;
    }

    // Wildcard matching: pattern starts with "*.".
    let wildcard_suffix = &pattern[2..]; // everything after "*."

    // The suffix must not be empty (reject "*." alone).
    if wildcard_suffix.is_empty() {
        return false;
    }

    // Reject partial wildcards (the entire leftmost label must be "*").
    // Since we already checked starts_with("*."), and the leftmost label
    // is everything before the first dot, this is satisfied.

    // Reject patterns with wildcards in non-leftmost positions.
    if wildcard_suffix.contains('*') {
        return false;
    }

    // RFC 6125 §6.4.3: the wildcard MUST NOT match the empty string,
    // so `*.example.com` does not match `example.com`.
    // The hostname must have at least one label before the suffix.
    match hostname.strip_suffix(wildcard_suffix) {
        None => false,
        Some(prefix) => {
            // The prefix must end with a dot (the separator between the
            // matched label and the suffix) and contain exactly one label
            // (no additional dots, since wildcard doesn't cross boundaries).
            if !prefix.ends_with('.') {
                return false;
            }
            let matched_label = &prefix[..prefix.len() - 1];
            // The matched label must be non-empty and contain no dots.
            !matched_label.is_empty() && !matched_label.contains('.')
        }
    }
}

/// Check whether a certificate iPAddress SAN matches a client IP address.
///
/// RFC 6125 Section 6.5.2: iPAddress SANs contain the binary encoding
/// of the IP address (4 bytes for IPv4, 16 bytes for IPv6).  Matching
/// is an exact binary comparison — no CIDR or subnet matching.
pub fn matches_ip(cert_ip: &IpAddr, client_ip: &IpAddr) -> bool {
    cert_ip == client_ip
}

/// Check whether a certificate rfc822Name SAN matches an email address.
///
/// RFC 6125 Section 6.4.4 / RFC 5280 Section 4.2.1.6:
///
/// - The local-part (before `@`) is case-sensitive per RFC 5321.
/// - The domain-part (after `@`) is case-insensitive.
/// - If the pattern is a bare domain (no `@`), it matches any email
///   address at that domain.
pub fn matches_email(pattern: &str, email: &str) -> bool {
    if pattern.is_empty() || email.is_empty() {
        return false;
    }

    match (pattern.split_once('@'), email.split_once('@')) {
        // Pattern has local-part: full match required.
        (Some((pat_local, pat_domain)), Some((email_local, email_domain))) => {
            // Local-part: case-sensitive per RFC 5321.
            // Domain-part: case-insensitive.
            pat_local == email_local
                && pat_domain.to_ascii_lowercase() == email_domain.to_ascii_lowercase()
        }
        // Pattern is bare domain: matches any address at that domain.
        (None, Some((_email_local, email_domain))) => {
            pattern.to_ascii_lowercase() == email_domain.to_ascii_lowercase()
        }
        // No '@' in the email — malformed.
        _ => false,
    }
}

/// Validate that a DER-encoded certificate is authorized for a given identity.
///
/// RFC 6125 Section 6.4.4: the validation algorithm is:
///
/// 1. If the certificate contains Subject Alternative Name (SAN) entries,
///    check each entry against the expected identity.  The subject CN is
///    ignored entirely when SANs are present.
/// 2. If no SANs are present, fall back to the subject Common Name (CN).
///    This fallback is deprecated by RFC 6125 but still widely used.
///
/// The expected identity may be a DNS hostname, an IP address, or an
/// email address.  The function determines the type by attempting to
/// parse as an IP address first, then checking for `@` (email), then
/// treating it as a DNS name.
///
/// # Returns
///
/// * `Ok(true)` — the certificate matches the expected identity.
/// * `Ok(false)` — the certificate does not match.
/// * `Err(...)` — the certificate could not be parsed.
pub fn validate_identity(cert_der: &[u8], expected: &str) -> Result<bool, String> {
    if cert_der.is_empty() {
        return Err("empty certificate DER".into());
    }
    if expected.is_empty() {
        return Err("empty expected identity".into());
    }

    // Extract SANs from the certificate.
    // TODO: Replace with real X.509 parsing via `x509-cert` or `synta_certificate`.
    let sans = extract_sans(cert_der);

    if !sans.is_empty() {
        // RFC 6125 §6.4.4: when SANs are present, check them exclusively.
        let matched = check_sans_against_identity(&sans, expected);
        return Ok(matched);
    }

    // No SANs — fall back to subject CN (deprecated per RFC 6125 §6.4.4).
    let cn = extract_subject_cn(cert_der);
    match cn {
        Some(cn_value) => {
            // Try DNS match on the CN.
            if let Ok(ip) = expected.parse::<IpAddr>() {
                // CN should not be used for IP matching per RFC 6125,
                // but some legacy implementations do. We reject it.
                let _ = ip;
                Ok(false)
            } else {
                Ok(matches_domain(&cn_value, expected))
            }
        }
        None => Ok(false),
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// SAN entry types extracted from a certificate.
#[derive(Debug, Clone)]
enum SanEntry {
    /// dNSName (tag 2) — a DNS hostname or wildcard pattern.
    Dns(String),
    /// iPAddress (tag 7) — an IP address.
    Ip(IpAddr),
    /// rfc822Name (tag 1) — an email address.
    Email(String),
}

/// Extract Subject Alternative Name entries from a DER-encoded certificate.
///
/// TODO: Replace with real ASN.1 parsing.  This is a placeholder that
/// returns an empty list; the real implementation needs to parse the
/// SAN extension (OID 2.5.29.17) from the TBSCertificate extensions.
fn extract_sans(_cert_der: &[u8]) -> Vec<SanEntry> {
    // Placeholder — real implementation parses X.509 SAN extension.
    Vec::new()
}

/// Extract the subject Common Name from a DER-encoded certificate.
///
/// TODO: Replace with real ASN.1 parsing.
fn extract_subject_cn(_cert_der: &[u8]) -> Option<String> {
    // Placeholder — real implementation parses the subject RDN sequence
    // and extracts the CN attribute (OID 2.5.4.3).
    None
}

/// Check a list of SAN entries against an expected identity.
fn check_sans_against_identity(sans: &[SanEntry], expected: &str) -> bool {
    // Determine the type of expected identity.
    if let Ok(expected_ip) = expected.parse::<IpAddr>() {
        // IP address: match against iPAddress SANs.
        sans.iter().any(|san| matches!(san, SanEntry::Ip(ip) if matches_ip(ip, &expected_ip)))
    } else if expected.contains('@') {
        // Email address: match against rfc822Name SANs.
        sans.iter().any(|san| matches!(san, SanEntry::Email(e) if matches_email(e, expected)))
    } else {
        // DNS hostname: match against dNSName SANs.
        sans.iter().any(|san| matches!(san, SanEntry::Dns(d) if matches_domain(d, expected)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── matches_domain (RFC 6125 §6.4.3) ────────────────────────────────

    #[test]
    fn exact_domain_match() {
        assert!(matches_domain("example.com", "example.com"));
        assert!(matches_domain("example.com", "EXAMPLE.COM"));
        assert!(matches_domain("Example.Com", "example.com"));
    }

    #[test]
    fn exact_domain_no_match() {
        assert!(!matches_domain("example.com", "other.com"));
        assert!(!matches_domain("example.com", "sub.example.com"));
    }

    #[test]
    fn wildcard_basic_match() {
        assert!(matches_domain("*.example.com", "foo.example.com"));
        assert!(matches_domain("*.example.com", "bar.example.com"));
        assert!(matches_domain("*.EXAMPLE.COM", "foo.example.com"));
    }

    #[test]
    fn wildcard_does_not_match_parent() {
        // RFC 6125 §6.4.3: wildcard MUST NOT match the empty string.
        assert!(!matches_domain("*.example.com", "example.com"));
    }

    #[test]
    fn wildcard_does_not_cross_dots() {
        // RFC 6125 §6.4.3: wildcard does not match across label boundaries.
        assert!(!matches_domain("*.example.com", "foo.bar.example.com"));
    }

    #[test]
    fn partial_wildcard_rejected() {
        // RFC 6125 §6.4.3: partial wildcards are NOT allowed.
        assert!(!matches_domain("f*.example.com", "foo.example.com"));
    }

    #[test]
    fn wildcard_in_non_leftmost_label_rejected() {
        assert!(!matches_domain("foo.*.example.com", "foo.bar.example.com"));
    }

    #[test]
    fn empty_inputs() {
        assert!(!matches_domain("", "example.com"));
        assert!(!matches_domain("example.com", ""));
        assert!(!matches_domain("", ""));
    }

    #[test]
    fn trailing_dots_normalized() {
        assert!(matches_domain("example.com.", "example.com"));
        assert!(matches_domain("example.com", "example.com."));
        assert!(matches_domain("*.example.com.", "foo.example.com."));
    }

    #[test]
    fn punycode_a_labels() {
        // IDN domains in A-label form.
        assert!(matches_domain("xn--nxasmq6b.example.com", "xn--nxasmq6b.example.com"));
        assert!(matches_domain("*.xn--nxasmq6b.com", "foo.xn--nxasmq6b.com"));
    }

    // ── matches_ip (RFC 6125 §6.5.2) ────────────────────────────────────

    #[test]
    fn ipv4_match() {
        let cert_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(matches_ip(&cert_ip, &client_ip));
    }

    #[test]
    fn ipv4_no_match() {
        let cert_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        assert!(!matches_ip(&cert_ip, &client_ip));
    }

    #[test]
    fn ipv6_match() {
        let cert_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let client_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(matches_ip(&cert_ip, &client_ip));
    }

    #[test]
    fn ipv4_vs_ipv6_no_match() {
        let cert_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!matches_ip(&cert_ip, &client_ip));
    }

    // ── matches_email ────────────────────────────────────────────────────

    #[test]
    fn email_exact_match() {
        assert!(matches_email("user@example.com", "user@example.com"));
    }

    #[test]
    fn email_domain_case_insensitive() {
        assert!(matches_email("user@Example.COM", "user@example.com"));
    }

    #[test]
    fn email_local_part_case_sensitive() {
        assert!(!matches_email("User@example.com", "user@example.com"));
    }

    #[test]
    fn email_domain_only_pattern() {
        assert!(matches_email("example.com", "anyone@example.com"));
        assert!(matches_email("EXAMPLE.COM", "user@example.com"));
    }

    #[test]
    fn email_no_match() {
        assert!(!matches_email("user@example.com", "user@other.com"));
        assert!(!matches_email("alice@example.com", "bob@example.com"));
    }

    #[test]
    fn email_empty_inputs() {
        assert!(!matches_email("", "user@example.com"));
        assert!(!matches_email("user@example.com", ""));
    }

    // ── validate_identity (RFC 6125 §6.4.4) ─────────────────────────────

    #[test]
    fn validate_identity_rejects_empty_cert() {
        assert!(validate_identity(&[], "example.com").is_err());
    }

    #[test]
    fn validate_identity_rejects_empty_expected() {
        assert!(validate_identity(&[0x30], "").is_err());
    }
}
