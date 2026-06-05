# syntax=docker/dockerfile:1.4

FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . /build

WORKDIR /build
RUN cargo build --release && strip target/release/run-coord

FROM debian:bookworm-slim AS runtime

ARG IDS_PATH="ids"

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/run-coord /app/run-coord
COPY $IDS_PATH /app/ids

ENTRYPOINT ["/app/run-coord"]
