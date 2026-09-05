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
    cargo build --locked --release --all-features \
    && strip target/release/kipuka

# Required runtime dependencies must be present; never hide a failed copy.
RUN set -eu; mkdir -p /runtime-libs; \
    for lib in libssl libcrypto libgssapi_krb5 libkrb5 libk5crypto \
               libcom_err libkrb5support libkeyutils libresolv libsasl2 libsqlite3; do \
        cp -L /usr/lib64/${lib}.so* /runtime-libs/; \
    done; \
    for lib in /usr/lib64/libp11-kit.so* /usr/lib64/p11-kit-client.so /usr/lib64/libffi.so*; do \
        if [ -f "$lib" ]; then cp -L "$lib" /runtime-libs/; fi; \
    done

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

RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} +
RUN mkdir -p /var/lib/kipuka /etc/kipuka /var/www/kipuka \
             /etc/pkcs11/modules /var/lib/softhsm/tokens && \
    chown -R 1001:1001 /var/lib/kipuka /etc/kipuka /var/www/kipuka \
                       /var/lib/softhsm

COPY --from=builder --chown=1001:1001 /build/target/release/kipuka /usr/local/bin/kipuka
COPY --chown=1001:1001 web/ /var/www/kipuka/web/

USER 1001
EXPOSE 9443
ENTRYPOINT ["kipuka"]
CMD ["--config", "/etc/kipuka/kipuka.toml"]
