# kipuka

An EST (RFC 7030) enrollment server with Multi-CA High Availability, HSM support,
and NIAP CA Protection Profile compliance. Built in Rust on the
[Synta](https://codeberg.org/abbra/synta) ASN.1/X.509 library.

> **kipuka** (Hawaiian): an area of older land surrounded by younger lava flows --
> an island of stability. Like a kipuka preserves established growth amid change,
> this server provides a stable certificate enrollment service amid evolving
> security requirements.

## Features

- **All six RFC 7030 EST operations**: `/cacerts`, `/simpleenroll`, `/simplereenroll`,
  `/fullcmc`, `/serverkeygen`, `/csrattrs`
- **Multi-CA with HA failover**: active-passive, round-robin, and weighted strategies
- **HSM support**: Entrust nShield, Utimaco CryptoServer, Kryoptic (dev/test),
  Thales Luna (CSP11/TCT)
- **OTP authentication**: one-time passwords for initial enrollment with
  configurable expiration, use limits, and per-profile binding
- **mTLS client authentication**: certificate-based re-enrollment
- **GSSAPI/Kerberos authentication**: enterprise SSO integration
- **EST labels**: multiple certificate profiles via path-based label routing
- **PQC-ready**: architecture supports post-quantum algorithm migration
  via Synta and PKCS#11
- **Audit logging**: NIAP FAU_GEN.1 compliant event recording
- **Multiple database backends**: SQLite, PostgreSQL, MariaDB

## Quick Start

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
              |         HSM ops
              |             |
         +----+----+   +---+---+
         |   sqlx  |   | HSM   |
         | sqlite  |   | PKCS  |
         | postgres|   | #11   |
         | mariadb |   +-------+
         +---------+
```

## Requirements Tracking

This project implements requirements from
[RHELBU-3536](https://issues.redhat.com/browse/RHELBU-3536).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
