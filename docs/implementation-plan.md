# kipuka Implementation Plan — Synta Integration

All work reuses existing synta-certificate/synta-krb5 infrastructure.
No new helpers that duplicate synta APIs.

## Track 1: CMS Auth + CMS-EST (enables encrypted EST)

### 1a. CMS SignedData verification (`auth/cms_auth.rs:148-190`)
- Parse with `synta::Decoder` → `cms_rfc5652_types::ContentInfo` → `SignedData`
- Extract signer cert from `SignedData.certificates` via `certs_from_pkcs7()`
- Verify signature with `crypto::default_signature_verifier()`
- Extract eContent payload

### 1b. CMS EnvelopedData construction (`auth/cms_auth.rs:250-300`)
- Use `default_create_enveloped_data(plaintext, recipients, enc_alg)`
- Recipient cert from client's mTLS cert DER

### 1c. CMS-EST endpoints (`routes/cms_est.rs` — 4 stubs)
- Unwrap CMS → extract CSR → call existing enrollment logic → wrap response in CMS
- /cms/simpleenroll, /cms/simplereenroll, /cms/serverkeygen, /cms/fullcmc

## Track 2: CMP Protocol (`routes/cmp.rs`)
- Parse `PKIMessage` using `cmp_types::PKIMessage::from_der()`
- Route by body type (ir/cr/kur/p10cr/rr/genm)
- Build response with `CMPMessageBuilder::new().sender().recipient().transaction_id().body_*()`
- For ir/cr: extract CRMF via `crmf_types::CertReqMsg`, issue cert, return ip/cp

## Track 3: CSR Validation + POP Linking
- Parse CSR with synta's `CertificationRequest` type
- Verify self-signature with `default_signature_verifier()`
- Validate key size, algorithm, extensions
- POP linking: extract challengePassword attribute, compare with TLS binding

## Track 4: Security — OCSP Verification + CRL Fallback
- OCSP response signature verification using `default_signature_verifier()`
- CRL parsing via `crl::CertificateList::from_der()`, serial number lookup
- CRL signature verification
- Integrate as fallback when OCSP is unreachable

## Track 5: STAR + GSSAPI
- STAR: use `CertificateBuilder` for short-lived certs, PKCS#7 wrapping
- GSSAPI: parse SPNEGO with `synta_krb5::gssapi_spnego::NegTokenInit`,
  extract principal from AP-REQ, delegate crypto to libgssapi FFI
