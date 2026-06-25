# kipuka Implementation Plan — Synta Integration

**Status: All tracks complete.** This document is retained as a historical implementation record. See [architecture.md](architecture.md) for current system architecture.

All work reuses existing synta-certificate/synta-krb5 infrastructure.
No new helpers that duplicate synta APIs.

## Track 1: CMS Auth + CMS-EST ✅ COMPLETE

### 1a. CMS SignedData verification — ✅ Implemented (`auth/cms_auth.rs`)
- [x] Parse with `synta::Decoder` → `cms_rfc5652_types::ContentInfo` → `SignedData`
- [x] Extract signer cert from `SignedData.certificates` via `certs_from_pkcs7()`
- [x] Verify signature with `crypto::default_signature_verifier()`
- [x] Extract eContent payload
- **Implementation:** `verify_cms_signed_data()` and `extract_signer_identity()`

### 1b. CMS EnvelopedData construction — ✅ Implemented (`auth/cms_auth.rs`)
- [x] Use `default_create_enveloped_data(plaintext, recipients, enc_alg)`
- [x] Recipient cert from client's mTLS cert DER
- **Implementation:** `build_cms_enveloped_data()`

### 1c. CMS-EST endpoints — ✅ Implemented (`routes/cms_est.rs`)
- [x] Unwrap CMS → extract CSR → call existing enrollment logic → wrap response in CMS
- [x] /cms/simpleenroll, /cms/simplereenroll, /cms/serverkeygen, /cms/fullcmc
- **Implementation:** 4 active endpoints with full CMS unwrap/wrap flow

## Track 2: CMP Protocol ✅ COMPLETE

### CMP v3 (RFC 9810) — ✅ Implemented (`routes/cmp.rs`, `config/cmp.rs`)
- [x] Parse `PKIMessage` using `cmp_types::PKIMessage::from_der()`
- [x] Route by body type (ir/cr/kur/p10cr/rr/genm)
- [x] Build response with `CMPMessageBuilder::new().sender().recipient().transaction_id().body_*()`
- [x] For ir/cr: extract CRMF via `crmf_types::CertReqMsg`, issue cert, return ip/cp
- [x] Signature-based and MAC-based message protection
- **Implementation:** Full CMP v3 support with configuration in `config/cmp.rs`

## Track 3: CSR Validation + POP Linking ✅ COMPLETE

### CSR Validation — ✅ Implemented
- [x] Parse CSR with synta's `CertificationRequest` type
- [x] Verify self-signature with `default_signature_verifier()`
- [x] Validate key size, algorithm, extensions
- [x] POP linking: extract challengePassword attribute, compare with TLS binding
- **Implementation:** Integrated throughout enrollment endpoints with comprehensive validation

## Track 4: Security — OCSP Verification + CRL Fallback ✅ COMPLETE

### Revocation Checking — ✅ Implemented (`ocsp/mod.rs`, `auth/mtls.rs`)
- [x] OCSP response signature verification using `default_signature_verifier()`
- [x] CRL parsing via `crl::CertificateList::from_der()`, serial number lookup
- [x] CRL signature verification
- [x] Integrate as fallback when OCSP is unreachable
- **Implementation:**
  - OCSP client with response caching in `src/ocsp/mod.rs`
  - CRL fallback via `check_crl_fallback()` in `src/auth/mtls.rs`
  - CRL fetching, serial number lookup, signature verification
  - Integrated as revocation checking in mTLS authentication

## Track 5: STAR + GSSAPI ✅ COMPLETE

### STAR (RFC 8739) — ✅ Implemented (`star/mod.rs`, `star/renewal.rs`)
- [x] Use `CertificateBuilder` for short-lived certs
- [x] PKCS#7 wrapping for certificate responses
- [x] Background renewal task with order lifecycle management
- [x] Configurable certificate lifetime
- **Implementation:** Full STAR protocol with background renewal task

### GSSAPI/Kerberos — ✅ Implemented (`state.rs`)
- [x] Parse SPNEGO with `synta_krb5::gssapi_spnego::NegTokenInit`
- [x] Extract principal from AP-REQ
- [x] Delegate crypto to libgssapi FFI
- [x] Integration with `gssapi_require_crypto` flag
- **Implementation:**
  - `init_gssapi_cred()` for credential initialization
  - SPNEGO authentication path in auth flow
  - Full Kerberos/GSSAPI support for enrollment
