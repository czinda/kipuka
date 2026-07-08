# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Uses the hummingbird Rust builder which ships OpenSSL 3.5+ (PQC-capable).
# Standard Fedora 42 / Debian images ship OpenSSL 3.2 / 3.0 which cannot
# compile native-ossl (needs EVP_PKEY_sign_message_final from OpenSSL 3.4+).
FROM quay.io/hummingbird/rust:latest-builder AS builder

RUN dnf install -y \
        git clang openssl-devel sqlite-devel \
        krb5-devel cyrus-sasl-devel p11-kit-devel \
    && dnf clean all

WORKDIR /build
COPY . .
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --release --all-features \
    && strip target/release/kipuka

# Collect runtime shared libraries for the slim runtime stage.
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
    cp -L /usr/lib64/libsasl2.so*       /runtime-libs/ && \
    cp -L /usr/lib64/libsqlite3.so*     /runtime-libs/ 2>/dev/null || true && \
    cp -L /usr/lib64/libp11-kit.so*     /runtime-libs/ 2>/dev/null || true && \
    cp -L /usr/lib64/p11-kit-client.so  /runtime-libs/ 2>/dev/null || true && \
    cp -L /usr/lib64/libffi.so*         /runtime-libs/ 2>/dev/null || true

# Build passwd/group for the runtime stage.
RUN cp /etc/passwd /runtime-libs/passwd && \
    echo 'kipuka:x:1001:1001:kipuka:/app:/sbin/nologin' >> /runtime-libs/passwd && \
    cp /etc/group /runtime-libs/group && \
    echo 'kipuka:x:1001:' >> /runtime-libs/group

# ── Stage 2: Hardened Runtime ─────────────────────────────────────────────────
FROM quay.io/hummingbird/core-runtime:latest-openssl

USER root

# Runtime shared libraries (OpenSSL 3.5+, krb5, sasl, sqlite).
COPY --from=builder /runtime-libs/*.so* /usr/lib64/
COPY --from=builder /runtime-libs/passwd /etc/passwd
COPY --from=builder /runtime-libs/group /etc/group

RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
RUN mkdir -p /var/lib/kipuka /etc/kipuka /var/www/kipuka \
             /etc/pkcs11/modules /var/run/kryoptic && \
    chown -R 1001:1001 /var/lib/kipuka /etc/kipuka /var/www/kipuka /var/run/kryoptic && \
    echo 'remote: unix:path=/var/run/kryoptic/pkcs11.sock' > /etc/pkcs11/modules/kryoptic.module

COPY --from=builder --chown=1001:1001 /build/target/release/kipuka /usr/local/bin/kipuka
COPY --chown=1001:1001 web/ /var/www/kipuka/web/

USER 1001
EXPOSE 9443
ENTRYPOINT ["kipuka"]
CMD ["--config", "/etc/kipuka/kipuka.toml"]
