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

# Copy only the workspace files needed for building the server
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server
COPY cli ./cli

RUN cargo build --release --locked -p server --target x86_64-unknown-linux-musl \
    && install -Dm755 target/x86_64-unknown-linux-musl/release/server /runtime/lockbox-server

# Create non-root user files for scratch
RUN echo "lockbox:x:10001:10001::/data:/sbin/nologin" > /runtime/passwd \
    && echo "lockbox:x:10001:" > /runtime/group \
    && mkdir -p /runtime/data && chown 10001:10001 /runtime/data

FROM scratch AS runtime

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /runtime/passwd /etc/passwd
COPY --from=builder /runtime/group /etc/group
COPY --from=builder --chmod=0555 /runtime/lockbox-server /usr/local/bin/lockbox-server
COPY --from=builder --chown=10001:10001 /runtime/data /data

USER 10001:10001
WORKDIR /data
ENV RUST_LOG=info
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/lockbox-server"]
