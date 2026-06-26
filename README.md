# kipuka

An EST (RFC 7030) enrollment server with Multi-CA High Availability, HSM support,
and NIAP CA Protection Profile compliance. Built in Rust on the
[Synta](https://codeberg.org/abbra/synta) ASN.1/X.509 library. Architecture
inspired by the [Akamu](https://codeberg.org/abbra/akamu) ACME server.

> **kipuka** (Hawaiian): an area of older land surrounded by younger lava flows --
> an island of stability. Like a kipuka preserves established growth amid change,
> this server provides a stable certificate enrollment service amid evolving
> security requirements.

| | |
|---|---|
| **Container image** | `registry.kipuka.dev/heebus/kipuka` |
| **API docs** | [kipuka.dev/api/](https://kipuka.dev/api/) |
| **Project site** | [kipuka.dev](https://kipuka.dev) |
| **CI/CD** | GitLab CI on [codeberg.org](https://codeberg.org/czinda/kipuka) |

## Features

### EST Protocol (RFC 7030)
- **All six EST operations**: `/cacerts`, `/simpleenroll`, `/simplereenroll`,
  `/fullcmc`, `/serverkeygen`, `/csrattrs`
- **Server-side key generation** (`/serverkeygen`): RSA, ECDSA, ML-DSA, ML-KEM
  with encrypted private key return via CMS EnvelopedData
- **Full CMC support** (`/fullcmc`): RFC 5272 PKIData/PKIResponse via synta-cmc
- **CMS-EST endpoints** (RFC 8295): `/cms/simpleenroll`, `/cms/simplereenroll`,
  `/cms/serverkeygen`, `/cms/fullcmc` for CMS-wrapped EST operations
- **STAR certificates** (RFC 8739): short-lived auto-renewal with configurable
  lifetime and renewal window
- **EST Renewal Info** (draft-ietf-lamps-est-renewal-info): `GET /renewal-info/:cert_id`
  returning JSON `suggestedWindow` for renewal scheduling
- **CSR Attributes Template** (RFC 9908): server-specified subject DN, key algorithm,
  and required extensions via `CertificationRequestInfoTemplate`
- **EST labels**: multiple certificate profiles via path-based label routing

### CMP Protocol (RFC 4210)
- **Certificate enrollment and revocation** via CMP messages
- **General messages** for CA capability discovery
- **MAC-based protection** with PBKDF2 key derivation (RFC 4210 S5.1.3.1)
- **Signature-based protection** verification over header||body

### Cryptographic Operations
- **CMS SignedData verification** with signedAttrs support (RFC 5652 S5.4)
- **CMS EnvelopedData construction** for encrypted EST responses
- **OCSP stapling** and response signature verification
- **CRL distribution point** fetching with revocation checking
- **CSR self-signature validation** with key size enforcement
- **Real certificate parsing** via synta-certificate (no placeholders)
- **CNSA Suite profile validation** (RFC 8603)
- **Post-quantum algorithm pairing** validation (RFC 9688/9882/9936)

### Infrastructure
- **Multi-CA with HA failover**: active-passive, round-robin, weighted, and
  latency-based strategies
- **HSM support**: Entrust nShield, Utimaco CryptoServer, Kryoptic (dev/test),
  Thales Luna (CSP11/TCT)
- **Dogtag PKI integration**: CA enrollment, KRA server-side key generation,
  CMC passthrough via REST API
- **Multiple database backends**: SQLite, PostgreSQL, MariaDB (via sqlx Any driver)
- **Admin API**: certificate listing with database query, filters, and pagination

### Authentication
- **OTP authentication**: one-time passwords for initial enrollment with
  configurable expiration, use limits, and per-profile binding
- **mTLS client authentication**: certificate-based re-enrollment
- **GSSAPI/Kerberos authentication**: enterprise SSO via optional libgssapi FFI

### PQC and Compliance
- **PQC-ready**: ML-DSA signing (FIPS 204), ML-KEM key encapsulation (FIPS 203),
  and composite hybrid algorithms via Synta and PKCS#11
- **Audit logging**: NIAP FAU_GEN.1 compliant event recording
- **synta-cmc crate**: RFC 5272 CMC protocol implementation covering 13 RFCs

### CoAP/DTLS Transport (RFC 7252 / RFC 9483)
- **EST-coaps** (RFC 9148): EST enrollment over CoAP/DTLS for constrained devices
- **OpenSSL DTLS transport**: UDP socket binding with client certificate extraction
- **CoapDtlsServer**: full DTLS server with EST operation bridging
- **Block-wise transfer** (RFC 7959): chunked payloads for constrained devices
- **187 tests** including 69 CoAP/DTLS-specific tests

### Testing and Deployment
- **idm-ci integration**: Beaker-based testing with Dogtag PKI on RHEL 10

## Quick Start

### Container (fastest)

```bash
# Pull the container image (no login required)
podman pull registry.kipuka.dev/heebus/kipuka:latest        # x86_64
podman pull registry.kipuka.dev/heebus/kipuka:latest-arm64   # arm64

# Verify the image
podman run --rm registry.kipuka.dev/heebus/kipuka:latest --version

# Run with a configuration file
podman run --rm \
  -v ./kipuka.toml:/etc/kipuka/kipuka.toml:ro \
  -v ./certs:/etc/kipuka/certs:ro \
  -p 9443:9443 \
  registry.kipuka.dev/heebus/kipuka:latest
```

### Build from source

```bash
# Build
cargo build --release

# Generate test CA and server certificates
# (use your own CA infrastructure for production)
./contrib/gen-test-certs.sh

# Copy and edit configuration
cp kipuka.toml.example kipuka.toml
$EDITOR kipuka.toml

# Run database migrations
cargo run -- migrate --config kipuka.toml

# Start the server
cargo run --release -- --config kipuka.toml
```

## Configuration

See [`kipuka.toml.example`](kipuka.toml.example) for a fully documented configuration file.

Minimal configuration:

```toml
[server]
listen = "0.0.0.0:8443"

[tls]
cert = "/etc/kipuka/server.pem"
key = "/etc/kipuka/server.key"

[tls.client_auth]
trust_anchors = "/etc/kipuka/client-ca.pem"

[db]
url = "sqlite:///var/lib/kipuka/kipuka.db"

[[ca]]
id = "main"
cert = "/etc/kipuka/ca.pem"
key = "/etc/kipuka/ca.key"
```

## Compliance

### Protocol Standards

| Standard | Scope | Status |
|----------|-------|--------|
| RFC 7030 | EST (Enrollment over Secure Transport) | Core implementation |
| RFC 8951 | EST clarifications | Implemented |
| RFC 8295 | CMS-EST (EST with CMS) | /cms/* endpoints |
| RFC 4210 | CMP (Certificate Management Protocol) | Enrollment, revocation, general messages |
| RFC 8739 | STAR (Short-Term Automatic Renewal) | Short-lived auto-renewal certificates |
| RFC 5272 | CMC (Certificate Management over CMS) | /fullcmc endpoint via synta-cmc |
| RFC 6402 | CMC Updates | Implemented |
| RFC 5273 | CMC Transport Protocols | HTTP transport |
| RFC 5274 | CMC Compliance Requirements | Per-agent-type validation |
| RFC 5652 | CMS (Cryptographic Message Syntax) | SignedData verification, EnvelopedData construction |
| RFC 4211 | CRMF (Certificate Request Message Format) | In TaggedRequest |
| RFC 2986 | PKCS#10 (Certification Request Syntax) | Primary CSR format |
| RFC 5280 | X.509 PKI Certificate and CRL Profile | Via synta-certificate |
| RFC 7252 | CoAP (Constrained Application Protocol) | CoAP transport layer |
| RFC 9483 | DTLS (Datagram TLS) as Transport for EST | EST-coaps via kipuka-coap |
| RFC 9148 | EST-coaps (EST over CoAP) | Constrained device enrollment |
| RFC 7959 | CoAP Block-Wise Transfers | Large payload support |
| RFC 9908 | CSR Attributes Clarification | CSR template mode for /csrattrs |
| draft-est-renewal-info | EST Renewal Information | GET /renewal-info/:cert_id |

### Algorithm and Security Standards

| Standard | Scope | Status |
|----------|-------|--------|
| RFC 5753 | ECC Algorithms in CMS | ECDSA/ECDH OIDs |
| RFC 5754 | SHA-2 Algorithms with CMS | Algorithm conventions |
| RFC 5816 | ESSCertIDv2 for CMS | Signing cert attribute |
| RFC 8603 | CNSA Suite Profile | Profile validation |
| RFC 9688/9882/9936 | Post-Quantum CMS (ML-DSA/ML-KEM) | Algorithm pairing validation |
| RFC 7906 | NSA CMS Key Management Attributes | Key provenance OIDs |

### Compliance Frameworks

| Standard | Scope | Status |
|----------|-------|--------|
| CA/B Forum BR | Certificate profiles, validity | Enforced |
| NIAP CA PP v2.0 | Protection Profile | Mapped ([docs](docs/compliance/niap-ca-pp.md)) |
| FIPS 140-3 | Cryptographic modules | Via HSM integration |

## HSM Compatibility

| Vendor | Model | PKCS#11 | Key Gen | Signing | Key Wrap | Status |
|--------|-------|---------|---------|---------|----------|--------|
| Entrust | nShield Connect/Solo | v2.40 | RSA, EC | RSA, ECDSA | AES-WRAP, RSA-OAEP | Supported |
| Utimaco | CryptoServer Se/CP5 | v2.40 | RSA, EC | RSA, ECDSA | AES-WRAP | Supported |
| Kryoptic | SoftHSM-compatible | v2.40 | RSA, EC | RSA, ECDSA | AES-WRAP | Dev/Test |
| Thales | Luna 7 (CSP11/TCT) | v2.40 | RSA, EC | RSA, ECDSA | AES-WRAP, RSA-OAEP | Supported |

See [`docs/compliance/hsm-compatibility.md`](docs/compliance/hsm-compatibility.md) for
detailed per-vendor configuration and known limitations.

## Architecture

Cargo workspace with 6 internal crates:

```
                          Clients
                            |
                  TLS + mTLS/OTP/GSSAPI
                            |
                    +-------+-------+
                    |   kipuka-est  |     axum routes: EST, CMS-EST,
                    |               |     CMP, STAR, admin API
                    +---+---+---+---+
                        |   |   |
              +---------+   |   +---------+
              |             |             |
         kipuka-otp    kipuka-hsm    kipuka-util
         OTP lifecycle  PKCS#11      shared types
              |         HSM ops         & config
              |             |
              |        kipuka-dogtag     synta-cmc
              |         Dogtag PKI      RFC 5272 CMC
              |         REST client     13 RFC coverage
              |
         +----+----+       kipuka-coap
         |   sqlx  |       CoAP/DTLS transport
         | sqlite  |       (RFC 7252/9483)
         | postgres|
         | mariadb |
         +---------+
```

See [`docs/architecture.md`](docs/architecture.md) for detailed component diagrams,
EST operation data flows, and HSM integration points.

## Development

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run tests
cargo test

# Lint
cargo clippy --all-features -- -D warnings

# Format check
cargo fmt --all -- --check

# Run with config
cargo run -- --config kipuka.toml
```

See [`docs/PROJECT.md`](docs/PROJECT.md) for EST protocol testing with `curl` and
`openssl`, HSM development setup with Kryoptic, and database migration procedures.

## CI/CD

GitLab CI pipelines run on [codeberg.org](https://codeberg.org/czinda/kipuka).
Pipeline configuration lives in [`.gitlab-ci.yml`](.gitlab-ci.yml) with stage
definitions in [`.gitlab/ci/`](.gitlab/ci/).

| Stage | Jobs |
|-------|------|
| **lint** | `rustfmt`, `clippy`, license audit, shell lint |
| **build** | Debug build, release build, `cargo doc` |
| **test** | Unit tests, protocol-specific tests |
| **security** | `cargo audit`, license compliance, FIPS validation |
| **integration** | Dogtag PKI end-to-end, EST interop (idm-ci / Beaker) |
| **package** | OCI container image (`registry.kipuka.dev/heebus/kipuka`), RPM (placeholder) |
| **deploy** | Beaker hardware tests, GitLab Pages ([kipuka.dev](https://kipuka.dev)) |

## Requirements Tracking

This project implements requirements from
[RHELBU-3536](https://issues.redhat.com/browse/RHELBU-3536).

## License

Licensed under either of

GNU General Public License v3.0 or later ([LICENSE](LICENSE) or
https://www.gnu.org/licenses/gpl-3.0.html)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be licensed under the GPL-3.0-or-later,
without any additional terms or conditions.
