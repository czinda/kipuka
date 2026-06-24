FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libssl-dev pkg-config clang cmake libclang-dev libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --all-features \
    && strip target/release/kipuka

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /sbin/nologin kipuka

COPY --from=builder /build/target/release/kipuka /usr/local/bin/kipuka
COPY web/ /var/www/kipuka/web/

USER kipuka
EXPOSE 9443
ENTRYPOINT ["kipuka"]
CMD ["--config", "/etc/kipuka/kipuka.toml"]
