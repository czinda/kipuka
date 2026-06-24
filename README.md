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
| **CI/CD** | GitLab CI on `gitlab.heebh.st` and `gitlab.cee.redhat.com` |

## Features

- **All six RFC 7030 EST operations**: `/cacerts`, `/simpleenroll`, `/simplereenroll`,
  `/fullcmc`, `/serverkeygen`, `/csrattrs`
- **Multi-CA with HA failover**: active-passive, round-robin, weighted, and
  latency-based strategies
- **HSM support**: Entrust nShield, Utimaco CryptoServer, Kryoptic (dev/test),
  Thales Luna (CSP11/TCT)
- **Dogtag PKI integration**: REST API client for Red Hat Certificate System
  (enrollment, revocation, KRA server-side key generation)
- **OTP authentication**: one-time passwords for initial enrollment with
  configurable expiration, use limits, and per-profile binding
- **mTLS client authentication**: certificate-based re-enrollment
- **GSSAPI/Kerberos authentication**: enterprise SSO integration
- **EST labels**: multiple certificate profiles via path-based label routing
- **PQC-ready**: ML-DSA signing (FIPS 204), ML-KEM key encapsulation (FIPS 203),
  and composite hybrid algorithms via Synta and PKCS#11
- **Audit logging**: NIAP FAU_GEN.1 compliant event recording
- **Multiple database backends**: SQLite, PostgreSQL, MariaDB (via sqlx Any driver)
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

| Standard | Scope | Status |
|----------|-------|--------|
| RFC 7030 | EST protocol | Core implementation |
| RFC 8951 | EST clarifications | Implemented |
| RFC 5272 | CMC (Full) | /fullcmc endpoint |
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
                       TLS + mTLS/OTP
                            |
                    +-------+-------+
                    |   kipuka-est  |     axum routes, EST protocol
                    +---+---+---+---+
                        |   |   |
              +---------+   |   +---------+
              |             |             |
         kipuka-otp    kipuka-hsm    kipuka-util
         OTP lifecycle  PKCS#11      shared types
              |         HSM ops         & config
              |             |
              |        kipuka-dogtag
              |         Dogtag PKI
              |         REST client
              |
         +----+----+       kipuka-coap
         |   sqlx  |       CoAP transport
         | sqlite  |       (RFC 7252)
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

GitLab CI pipelines run on both `codeberg.org` and `gitlab.cee.redhat.com`.
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
