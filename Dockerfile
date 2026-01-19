# syntax=docker/dockerfile:1.7
FROM rust:slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        musl-tools \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

COPY . .

RUN cargo build --release --locked -p server --target x86_64-unknown-linux-musl \
    && install -Dm755 target/x86_64-unknown-linux-musl/release/server /runtime/lockbox-server

FROM scratch AS runtime

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /runtime/lockbox-server /usr/local/bin/lockbox-server

WORKDIR /data
ENV RUST_LOG=info
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/lockbox-server"]
