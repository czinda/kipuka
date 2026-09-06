# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Uses the hummingbird Rust builder with OpenSSL 3.5+ for PQC support.
FROM quay.io/hummingbird/rust:latest-builder AS builder

RUN dnf install -y \
        git clang findutils openssl-devel sqlite-devel \
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

# Assemble the runtime filesystem using builder tools: the minimal runtime
# intentionally does not provide find, mkdir, or chown.
FROM quay.io/hummingbird/core-runtime:latest-openssl AS runtime-base

FROM builder AS runtime-assembly
COPY --from=runtime-base / /runtime-root/
COPY --from=builder /runtime-libs/*.so* /runtime-root/usr/lib64/
COPY --from=builder /runtime-libs/passwd /runtime-root/etc/passwd
COPY --from=builder /runtime-libs/group /runtime-root/etc/group
COPY --from=builder /build/target/release/kipuka /runtime-root/usr/local/bin/kipuka
COPY web/ /runtime-root/var/www/kipuka/web/
RUN mkdir -p /runtime-root/var/lib/kipuka /runtime-root/etc/kipuka \
             /runtime-root/etc/pkcs11/modules /runtime-root/var/lib/softhsm/tokens && \
    chown -R 1001:1001 /runtime-root/var/lib/kipuka /runtime-root/etc/kipuka \
                       /runtime-root/var/www/kipuka /runtime-root/var/lib/softhsm && \
    find /runtime-root -xdev -perm /6000 -type f -exec chmod a-s {} +

# Preserve the runtime base metadata and apply the prepared filesystem.
FROM runtime-base
COPY --from=runtime-assembly /runtime-root/ /
USER 1001
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/kipuka"]
CMD ["--config", "/etc/kipuka/kipuka.toml"]
