# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Fedora 42 builder — OpenSSL 3.5+ required for ML-DSA-87 (PQC) TLS support.
# Debian bookworm ships OpenSSL 3.0 which cannot process ML-DSA-87 certificates.
FROM registry.fedoraproject.org/fedora:42 AS builder

RUN dnf install -y \
        rust cargo gcc clang clang-devel cmake pkg-config \
        openssl-devel krb5-devel cyrus-sasl-devel \
    && dnf clean all

WORKDIR /build
COPY . .
RUN cargo build --release --all-features \
    && strip target/release/kipuka

# Collect runtime shared libraries.
RUN mkdir -p /runtime-libs && \
    cp -L /usr/lib64/libssl.so*         /runtime-libs/ && \
    cp -L /usr/lib64/libcrypto.so*      /runtime-libs/ && \
    cp -L /usr/lib64/libgssapi_krb5.so* /runtime-libs/ && \
    cp -L /usr/lib64/libkrb5.so*        /runtime-libs/ && \
    cp -L /usr/lib64/libk5crypto.so*    /runtime-libs/ && \
    cp -L /usr/lib64/libcom_err.so*     /runtime-libs/ && \
    cp -L /usr/lib64/libkrb5support.so* /runtime-libs/ && \
    cp -L /usr/lib64/libkeyutils.so*    /runtime-libs/ && \
    cp -L /usr/lib64/libresolv.so*      /runtime-libs/ && \
    cp -L /usr/lib64/libsasl2.so*       /runtime-libs/ 2>/dev/null || true

# ── Stage 2: Hardened Runtime ─────────────────────────────────────────────────
FROM registry.fedoraproject.org/fedora:42

RUN dnf install -y ca-certificates openssl-libs krb5-libs cyrus-sasl-lib \
    && dnf clean all \
    && useradd -r -s /sbin/nologin kipuka

COPY --from=builder /build/target/release/kipuka /usr/local/bin/kipuka
COPY web/ /var/www/kipuka/web/

USER kipuka
EXPOSE 9443
ENTRYPOINT ["kipuka"]
CMD ["--config", "/etc/kipuka/kipuka.toml"]
