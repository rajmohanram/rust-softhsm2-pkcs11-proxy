# Multi-stage build for the combined pkcs11-proxy + SoftHSM2 image
# All glibc — Debian builder and runtime

# --- Stage 1: Build all Rust binaries ---
FROM rust:1.94 AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    protobuf-compiler libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml ./
COPY proto/ proto/
COPY pkcs11-common/ pkcs11-common/
COPY pkcs11-proxy-client/ pkcs11-proxy-client/
COPY pkcs11-proxyd/ pkcs11-proxyd/

RUN cargo build --release

# --- Stage 2: Final Debian slim image ---
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    softhsm2 \
    opensc \
    openssl \
    tini \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/softhsm/tokens /etc/pkcs11-proxy \
 && chmod 0777 /var/lib/softhsm /var/lib/softhsm/tokens

# Copy Rust-built binaries (all glibc-linked, matching Debian runtime)
COPY --from=builder /build/target/release/pkcs11-proxyd /usr/bin/pkcs11-proxyd
COPY --from=builder /build/target/release/libpkcs11_proxy_client.so /usr/lib/libpkcs11-proxy.so
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Default SoftHSM2 config
RUN printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = INFO\nslots.removable = false\n' > /etc/softhsm2.conf

ENV SOFTHSM2_CONF=/etc/softhsm2.conf \
    PKCS11_PROXY_TLS_PSK_FILE=/etc/pkcs11-proxy/client.psk

VOLUME ["/var/lib/softhsm/tokens", "/etc/pkcs11-proxy"]

EXPOSE 2345

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["pkcs11-proxyd", "--module", "/usr/lib/softhsm/libsofthsm2.so", "--listen", "0.0.0.0:2345", "--psk-file", "/etc/pkcs11-proxy/client.psk"]
