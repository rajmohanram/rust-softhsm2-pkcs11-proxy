# Example: OpenBao HSM image with the Rust pkcs11-proxy client library
# Copies libpkcs11-proxy.so from the CI-published proxy image.

FROM ghcr.io/rajmohanram/softhsm2-pkcs11-proxy:latest AS proxy

FROM openbao/openbao-hsm-ubi:2.5

COPY --from=proxy /usr/lib/libpkcs11-proxy.so /usr/local/lib/libpkcs11-proxy.so

ENV PKCS11_PROXY_TLS_PSK_FILE=/etc/openbao/client.psk
