# Multi-stage build for the axum API (workspace).
FROM rust:1.96-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p zero-trust-auth-demo

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/zero-trust-auth-demo /usr/local/bin/
WORKDIR /app
EXPOSE 8002
CMD ["zero-trust-auth-demo"]
