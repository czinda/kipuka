<!-- Implementation scope is tracked in docs/support-boundaries.md. -->
# kipuka

An EST (RFC 7030) enrollment server with Multi-CA High Availability, HSM support,
and structured audit logging. Built in Rust on the
[Synta](https://codeberg.org/abbra/synta) ASN.1/X.509 library. Architecture
inspired by the [Akamu](https://codeberg.org/abbra/akamu) ACME server.

> **kipuka** (Hawaiian): an area of older land surrounded by younger lava flows --
> an island of stability. Like a kipuka preserves established growth amid change,
> this server provides a stable certificate enrollment service amid evolving
> security requirements.

| | |
|---|---|
| **Container image** | `quay.io/czinda/kipuka` |
| **API docs** | [kipuka.dev/api/](https://kipuka.dev/api/) |
| **Project site** | [kipuka.dev](https://kipuka.dev) |

## Features

### EST Protocol (RFC 7030)
- **All six EST operations**: `/cacerts`, `/simpleenroll`, `/simplereenroll`,
  `/fullcmc`, `/serverkeygen`, `/csrattrs`
- **Server-side key generation** (`/serverkeygen`): RSA, ECDSA, ML-DSA, ML-KEM
  with encrypted private key return via CMS EnvelopedData
- **Full CMC support** (`/fullcmc`): RFC 5272 PKIData/PKIResponse via synta-cmc
- **Experimental CMS-wrapped endpoints**: `/cms/simpleenroll`, `/cms/simplereenroll`,
  `/cms/serverkeygen`, `/cms/fullcmc` for CMS-wrapped EST operations
- **Custom EST automatic-renewal orders**: short-lived auto-renewal with configurable
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
- **Audit logging**: structured event recording; no independent NIAP certification claimed
- **synta-cmc crate**: RFC 5272 CMC protocol implementation covering 13 RFCs

### CoAP/DTLS Transport (RFC 7252 / RFC 9148)
- **EST-coaps** (RFC 9148): EST enrollment over CoAP/DTLS for constrained devices
- **OpenSSL DTLS transport**: UDP socket binding with client certificate extraction
- **CoapDtlsServer**: full DTLS server with EST operation bridging
- **Block-wise transfer** (RFC 7959): chunked payloads for constrained devices
- **187 tests** including 69 CoAP/DTLS-specific tests

### Testing and Conformance
- **Protocol smoke suites**: mix live endpoint checks with source inspection.
  Source checks, skipped scenarios and passing test counts do not establish
  standards conformance or secure interoperability. See
  [support and assurance boundaries](docs/support-boundaries.md).
- **idm-ci integration**: Beaker-based testing with Dogtag PKI on RHEL 10

```bash
# Run conformance suite against a running server
./contrib/conformance/run-all.sh

# Full lifecycle: deploy, test, teardown
./contrib/conformance/run-all.sh --deploy
```

## Quick Start

### Container (fastest)

```bash
# Pull the container image (no login required)
podman pull quay.io/czinda/kipuka:latest        # x86_64
podman pull quay.io/czinda/kipuka:latest-arm64   # arm64

# Verify the image
podman run --rm quay.io/czinda/kipuka:latest --version

# Run with a configuration file
podman run --rm \
  -v ./kipuka.toml:/etc/kipuka/kipuka.toml:ro \
  -v ./certs:/etc/kipuka/certs:ro \
  -p 9443:9443 \
  quay.io/czinda/kipuka:latest
```

### Build from source

Use Rust 1.88 or newer, OpenSSL 3.5 or newer with development headers,
`pkg-config`, Clang and CMake. Synta is pinned to a full Git revision in
Cargo.toml and Cargo.lock; no sibling checkout is required. Local development
patches belong in an uncommitted Cargo configuration.

```bash
# Build
cargo build --locked --release

# Generate test CA and server certificates
# (use your own CA infrastructure for production)
./contrib/gen-test-certs.sh

# Copy and edit configuration
cp kipuka.toml.example kipuka.toml
$EDITOR kipuka.toml

# Start the server
cargo run --release -- --config kipuka.toml
```

## Configuration

See [`kipuka.toml.example`](kipuka.toml.example) for a fully documented configuration file.

Minimal configuration (paths must exist and contain your deployment certificates):

```toml
[server]
listen_addr = "0.0.0.0:8443"

[tls]
cert_file = "/etc/kipuka/server.pem"
key_file = "/etc/kipuka/server.key"
ca_file = "/etc/kipuka/client-ca.pem"

[database]
url = "sqlite:///var/lib/kipuka/kipuka.db?mode=rwc"
run_migrations = true

[[ca]]
id = "main"
cert_file = "/etc/kipuka/ca.pem"
key_file = "/etc/kipuka/ca.key"
```

Migrations run at startup when `database.run_migrations = true`; there is no
`migrate` subcommand. The database directory must already exist and be writable.


## Standards references and implementation scope

### Protocol Standards

| Standard | Scope | Status |
|----------|-------|--------|
| RFC 7030 | EST (Enrollment over Secure Transport) | Core implementation |
| RFC 8951 | EST clarifications | Implemented |
| RFC 8295 | EST extensions for PAL packages | Not implemented by custom /cms/* routes |
| RFC 4210 | CMP (Certificate Management Protocol) | Enrollment, revocation, general messages |
| RFC 8739 | ACME STAR extension | Not implemented; custom EST renewal is distinct |
| RFC 5272 | CMC (Certificate Management over CMS) | /fullcmc endpoint via synta-cmc |
| RFC 6402 | CMC Updates | Implemented |
| RFC 5273 | CMC Transport Protocols | HTTP transport |
| RFC 5274 | CMC Compliance Requirements | Per-agent-type validation |
| RFC 5652 | CMS (Cryptographic Message Syntax) | SignedData verification, EnvelopedData construction |
| RFC 4211 | CRMF (Certificate Request Message Format) | In TaggedRequest |
| RFC 2986 | PKCS#10 (Certification Request Syntax) | Primary CSR format |
| RFC 5280 | X.509 PKI Certificate and CRL Profile | Via synta-certificate |
| RFC 7252 | CoAP (Constrained Application Protocol) | CoAP transport layer |
| RFC 9483 | Lightweight CMP Profile | No complete conformance claim |
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

### Standards references and implementation scope Frameworks

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
cargo build --locked --release

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
