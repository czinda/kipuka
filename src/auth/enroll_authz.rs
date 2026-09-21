//! Enrollment authorization: bind the authenticated requester to the CSR and
//! enforce per-label name-authorization policy (NIAP CA PP FDP_ACF.1).
//!
//! RFC 7030 authenticates the *requester* (via mTLS, OTP, or GSSAPI) but says
//! little about *what* that requester may ask for.  Without an explicit binding
//! an OTP holder provisioned for `device-a.example.com` can submit a CSR whose
//! subject/SAN names `device-b.example.com` and receive a valid certificate for
//! an identity it was never authorized to hold.  This module closes that gap.
//!
//! Two independent controls, both driven by the per-label configuration:
//!
//! 1. **Identity binding** (`require_cn_match`, `require_san_match`) — the
//!    authenticated identity MUST appear in the CSR, either as the subject
//!    Common Name or as a Subject Alternative Name entry.
//! 2. **Name authorization** (`permitted_dns_names`, `permitted_ip_addresses`,
//!    `permitted_emails`) — an allowlist applied to the requested SANs.  When a
//!    list is non-empty, every SAN of that type in the CSR MUST match at least
//!    one entry, so a label can be constrained to a bounded namespace.
//!
//! The matching primitives are the RFC 6125 matchers in [`super::name_match`],
//! shared with mTLS POP linking so identity comparison is consistent across the
//! server (wildcards, case folding, IP binary compare, email local/domain
//! case rules).
//!
//! When no control is configured (all fields false/empty), `authorize_csr` is a
//! no-op — existing deployments keep their current behavior until an operator
//! opts in.  NIAP-evaluated deployments set `require_cn_match` or
//! `require_san_match` to satisfy FDP_ACF.1.

use std::net::IpAddr;

use synta_certificate::csr::CertificationRequest;

use super::name_match::{matches_domain, matches_email, matches_ip};

/// Per-label enrollment authorization policy.
///
/// Borrowed from an [`crate::routes::LabelExtractor`] for the lifetime of a
/// single enrollment request; no allocation.
#[derive(Debug, Clone, Copy)]
pub struct EnrollAuthzPolicy<'a> {
    /// Require the CSR subject Common Name to equal the authenticated identity
    /// (case-insensitive).  FDP_ACF.1 identity binding.
    pub require_cn_match: bool,
    /// Require the authenticated identity to appear as a Subject Alternative
    /// Name entry of the matching type.  FDP_ACF.1 identity binding.
    pub require_san_match: bool,
    /// Allowlist of permitted dNSName patterns (RFC 6125).  When non-empty,
    /// every dNSName SAN in the CSR must match one entry.
    pub permitted_dns_names: &'a [String],
    /// Allowlist of permitted iPAddress SANs (textual form).  When non-empty,
    /// every iPAddress SAN in the CSR must equal one entry.
    pub permitted_ip_addresses: &'a [String],
    /// Allowlist of permitted rfc822Name patterns.  When non-empty, every
    /// rfc822Name SAN in the CSR must match one entry.
    pub permitted_emails: &'a [String],
}

impl EnrollAuthzPolicy<'_> {
    /// `true` when the policy enforces nothing (all controls off/empty).
    pub fn is_noop(&self) -> bool {
        !self.require_cn_match
            && !self.require_san_match
            && self.permitted_dns_names.is_empty()
            && self.permitted_ip_addresses.is_empty()
            && self.permitted_emails.is_empty()
    }
}

/// Authorize a parsed CSR against the authenticated identity and label policy.
///
/// Returns `Ok(())` when the request is authorized, or `Err(reason)` with a
/// human-readable explanation suitable for a `403 Forbidden` response and an
/// `enroll.reject` audit detail.  The reason never echoes secret material —
/// only the requested names, which the client already knows.
pub fn authorize_csr(
    csr: &CertificationRequest,
    identity: &str,
    policy: &EnrollAuthzPolicy,
) -> Result<(), String> {
    if policy.is_noop() {
        return Ok(());
    }

    let cn = csr_subject_cn(csr);
    let sans = csr_sans(csr);
    check_names(cn.as_deref(), &sans, identity, policy)
}

/// Pure authorization decision over already-extracted CSR identifiers.
///
/// Separated from [`authorize_csr`] so the policy logic can be unit-tested with
/// hand-built identifiers without constructing and signing a full CSR.
fn check_names(
    cn: Option<&str>,
    sans: &[(u32, Vec<u8>)],
    identity: &str,
    policy: &EnrollAuthzPolicy,
) -> Result<(), String> {
    // ── Identity binding (FDP_ACF.1) ───────────────────────────────────────
    // An identity-binding policy is meaningless without an authenticated
    // identity.  With an empty identity, an empty CSR Common Name would
    // "match" it (both `""`) and let an unauthenticated requester satisfy
    // `require_cn_match`.  Fail closed: when the label demands identity
    // binding, require that an identity was actually presented.
    if (policy.require_cn_match || policy.require_san_match) && identity.is_empty() {
        return Err(
            "enrollment authorization requires an authenticated identity, but none was presented"
                .to_string(),
        );
    }

    if policy.require_cn_match {
        match cn {
            Some(cn) if cn.eq_ignore_ascii_case(identity) => {}
            Some(cn) => {
                return Err(format!(
                    "CSR Common Name {cn:?} does not match authenticated identity {identity:?}"
                ));
            }
            None => {
                return Err(
                    "require_cn_match is set but the CSR carries no Common Name".to_string()
                );
            }
        }
    }

    if policy.require_san_match && !identity_in_sans(sans, identity) {
        return Err(format!(
            "authenticated identity {identity:?} is not present in the CSR subjectAltName"
        ));
    }

    // ── Name authorization allowlist (FDP_ACF.1) ───────────────────────────
    for (tag, content) in sans {
        match *tag {
            synta_certificate::general_name::DNS_NAME if !policy.permitted_dns_names.is_empty() => {
                let name = std::str::from_utf8(content)
                    .map_err(|_| "CSR contains a non-UTF-8 dNSName SAN".to_string())?;
                if !policy
                    .permitted_dns_names
                    .iter()
                    .any(|pat| matches_domain(pat, name))
                {
                    return Err(format!("dNSName {name:?} is not permitted for this label"));
                }
            }
            synta_certificate::general_name::RFC822_NAME if !policy.permitted_emails.is_empty() => {
                let email = std::str::from_utf8(content)
                    .map_err(|_| "CSR contains a non-UTF-8 rfc822Name SAN".to_string())?;
                if !policy
                    .permitted_emails
                    .iter()
                    .any(|pat| matches_email(pat, email))
                {
                    return Err(format!(
                        "rfc822Name {email:?} is not permitted for this label"
                    ));
                }
            }
            synta_certificate::general_name::IP_ADDRESS
                if !policy.permitted_ip_addresses.is_empty() =>
            {
                let ip = san_ip(content)
                    .ok_or_else(|| "CSR contains a malformed iPAddress SAN".to_string())?;
                let permitted = policy.permitted_ip_addresses.iter().any(|entry| {
                    entry
                        .parse::<IpAddr>()
                        .map(|p| matches_ip(&p, &ip))
                        .unwrap_or(false)
                });
                if !permitted {
                    return Err(format!("iPAddress {ip} is not permitted for this label"));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Authorize a DER-encoded CSR against the authenticated identity and label
/// policy.  Convenience wrapper over [`authorize_csr`] for callers that hold
/// raw CSR bytes rather than a parsed [`CertificationRequest`].
///
/// A malformed CSR is reported as an authorization failure (the enroll handler
/// that parses it for issuance will surface the parse error in detail).
pub fn authorize_csr_der(
    csr_der: &[u8],
    identity: &str,
    policy: &EnrollAuthzPolicy,
) -> Result<(), String> {
    if policy.is_noop() {
        return Ok(());
    }
    let csr = CertificationRequest::from_der(csr_der)
        .map_err(|e| format!("CSR parse failed during authorization: {e}"))?;
    authorize_csr(&csr, identity, policy)
}

/// Extract the subject Common Name (OID 2.5.4.3) from a CSR.
///
/// Returns the last CN when multiple are present, matching the LDAP/RFC 4519
/// convention used by [`super::name_match`] for certificates.
fn csr_subject_cn(csr: &CertificationRequest) -> Option<String> {
    let subject_der = csr.certification_request_info.subject.to_der().ok()?;
    synta_certificate::parse_name_attrs(&subject_der)
        .into_iter()
        .rev()
        .find(|(oid, _)| oid == "2.5.4.3")
        .map(|(_, value)| value)
}

/// Extract Subject Alternative Names from a CSR's `extensionRequest` attribute
/// (PKCS#9 OID 1.2.840.113549.1.9.14) as `(tag, content)` pairs, exactly as
/// [`synta_certificate::parse_general_names`] returns for a certificate.
fn csr_sans(csr: &CertificationRequest) -> Vec<(u32, Vec<u8>)> {
    let Some(attrs) = csr.certification_request_info.attributes.as_ref() else {
        return Vec::new();
    };
    for attr in attrs.elements() {
        if attr.attr_type.components() != synta_certificate::oids::PKCS9_EXTENSION_REQUEST {
            continue;
        }
        // extensionRequest values: SET OF Extensions; each value is a
        // SEQUENCE OF Extension — exactly what find_extension_value scans.
        for value in attr.attr_values.elements() {
            if let Some(san_value) = synta_certificate::find_extension_value(
                value.as_bytes(),
                synta_certificate::oids::SUBJECT_ALT_NAME,
            ) {
                return synta_certificate::parse_general_names(san_value);
            }
        }
    }
    Vec::new()
}

/// Whether the authenticated identity appears among the CSR SAN entries.
///
/// The identity type is inferred (IP → email → DNS) and matched against SAN
/// entries of the corresponding type using the RFC 6125 matchers.  SAN entries
/// act as the pattern (so a wildcard dNSName may cover the identity).
fn identity_in_sans(sans: &[(u32, Vec<u8>)], identity: &str) -> bool {
    if let Ok(ip) = identity.parse::<IpAddr>() {
        sans.iter().any(|(tag, content)| {
            *tag == synta_certificate::general_name::IP_ADDRESS
                && san_ip(content).is_some_and(|s| matches_ip(&s, &ip))
        })
    } else if identity.contains('@') {
        sans.iter().any(|(tag, content)| {
            *tag == synta_certificate::general_name::RFC822_NAME
                && std::str::from_utf8(content).is_ok_and(|s| matches_email(s, identity))
        })
    } else {
        sans.iter().any(|(tag, content)| {
            *tag == synta_certificate::general_name::DNS_NAME
                && std::str::from_utf8(content).is_ok_and(|s| matches_domain(s, identity))
        })
    }
}

/// Decode an iPAddress SAN content (4 or 16 raw bytes) into an [`IpAddr`].
fn san_ip(content: &[u8]) -> Option<IpAddr> {
    match content.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(content).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(content).ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::general_name::{DNS_NAME, IP_ADDRESS, RFC822_NAME};

    // Tests target the pure `check_names` decision with hand-built identifiers,
    // so the policy logic is exercised without constructing and signing a CSR.
    // CSR parsing (`csr_subject_cn`/`csr_sans`) is covered by the integration
    // suite that issues certificates end-to-end.

    fn dns(name: &str) -> (u32, Vec<u8>) {
        (DNS_NAME, name.as_bytes().to_vec())
    }
    fn email(addr: &str) -> (u32, Vec<u8>) {
        (RFC822_NAME, addr.as_bytes().to_vec())
    }
    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> (u32, Vec<u8>) {
        (IP_ADDRESS, vec![a, b, c, d])
    }

    fn empty_policy() -> EnrollAuthzPolicy<'static> {
        EnrollAuthzPolicy {
            require_cn_match: false,
            require_san_match: false,
            permitted_dns_names: &[],
            permitted_ip_addresses: &[],
            permitted_emails: &[],
        }
    }

    #[test]
    fn noop_policy_allows_anything() {
        let policy = empty_policy();
        assert!(policy.is_noop());
        let sans = [dns("device-a.example.com")];
        assert!(check_names(Some("device-b.example.com"), &sans, "someone-else", &policy).is_ok());
    }

    #[test]
    fn cn_match_accepts_matching_identity() {
        let policy = EnrollAuthzPolicy {
            require_cn_match: true,
            ..empty_policy()
        };
        assert!(
            check_names(
                Some("device-a.example.com"),
                &[],
                "device-a.example.com",
                &policy
            )
            .is_ok()
        );
        // Case-insensitive.
        assert!(
            check_names(
                Some("device-a.example.com"),
                &[],
                "DEVICE-A.EXAMPLE.COM",
                &policy
            )
            .is_ok()
        );
    }

    #[test]
    fn cn_match_rejects_mismatch_and_missing_cn() {
        let policy = EnrollAuthzPolicy {
            require_cn_match: true,
            ..empty_policy()
        };
        assert!(
            check_names(
                Some("device-b.example.com"),
                &[],
                "device-a.example.com",
                &policy
            )
            .is_err()
        );
        // No CN present at all is a rejection, not a bypass.
        assert!(check_names(None, &[], "device-a.example.com", &policy).is_err());
    }

    #[test]
    fn san_match_requires_identity_in_san() {
        let policy = EnrollAuthzPolicy {
            require_san_match: true,
            ..empty_policy()
        };
        let sans = [dns("device-a.example.com"), dns("alt.example.com")];
        assert!(check_names(Some("unused"), &sans, "device-a.example.com", &policy).is_ok());
        assert!(check_names(Some("unused"), &sans, "device-x.example.com", &policy).is_err());
    }

    #[test]
    fn san_match_covers_ip_and_email_identities() {
        let policy = EnrollAuthzPolicy {
            require_san_match: true,
            ..empty_policy()
        };
        let sans = [ipv4(10, 0, 0, 1), email("device@example.com")];
        assert!(check_names(None, &sans, "10.0.0.1", &policy).is_ok());
        assert!(check_names(None, &sans, "10.0.0.2", &policy).is_err());
        assert!(check_names(None, &sans, "device@example.com", &policy).is_ok());
        assert!(check_names(None, &sans, "other@example.com", &policy).is_err());
    }

    #[test]
    fn wildcard_san_covers_identity() {
        // A wildcard dNSName SAN in the CSR may cover the bound identity.
        let policy = EnrollAuthzPolicy {
            require_san_match: true,
            ..empty_policy()
        };
        let sans = [dns("*.example.com")];
        assert!(check_names(None, &sans, "device-a.example.com", &policy).is_ok());
    }

    #[test]
    fn permitted_dns_allowlist_bounds_the_namespace() {
        let allow = vec!["*.example.com".to_string()];
        let policy = EnrollAuthzPolicy {
            permitted_dns_names: &allow,
            ..empty_policy()
        };
        assert!(check_names(Some("cn"), &[dns("device-a.example.com")], "id", &policy).is_ok());
        // Every dNSName must be permitted — one rogue name fails the request.
        let mixed = [dns("device-a.example.com"), dns("device-a.evil.com")];
        assert!(check_names(Some("cn"), &mixed, "id", &policy).is_err());
    }

    #[test]
    fn permitted_ip_allowlist_matches_binary() {
        let allow = vec!["10.0.0.0".to_string(), "10.0.0.1".to_string()];
        let policy = EnrollAuthzPolicy {
            permitted_ip_addresses: &allow,
            ..empty_policy()
        };
        assert!(check_names(None, &[ipv4(10, 0, 0, 1)], "id", &policy).is_ok());
        assert!(check_names(None, &[ipv4(10, 0, 0, 9)], "id", &policy).is_err());
    }

    #[test]
    fn allowlist_ignores_san_types_without_a_list() {
        // permitted_dns_names is set but the CSR only has an email SAN; with no
        // permitted_emails list, the email SAN is unconstrained.
        let allow = vec!["*.example.com".to_string()];
        let policy = EnrollAuthzPolicy {
            permitted_dns_names: &allow,
            ..empty_policy()
        };
        assert!(check_names(Some("cn"), &[email("anyone@anywhere.test")], "id", &policy).is_ok());
    }
}
