#!/bin/sh
set -eu

log() {
  printf '[entrypoint] %s\n' "$*"
}

PSK_FILE="${PKCS11_PROXY_TLS_PSK_FILE:-/etc/pkcs11-proxy/client.psk}"

# Generate PSK file if it doesn't exist
if [ ! -s "$PSK_FILE" ]; then
  mkdir -p "$(dirname "$PSK_FILE")"
  identity="${PKCS11_PROXY_TLS_PSK_IDENTITY:-client}"
  secret="${PKCS11_PROXY_TLS_PSK:-$(openssl rand -hex 16)}"
  printf '%s:%s\n' "$identity" "$secret" > "$PSK_FILE"
  chmod 0644 "$PSK_FILE"
  log "Generated TLS-PSK credentials at $PSK_FILE"
else
  chmod 0644 "$PSK_FILE"
  log "Using existing PSK file at $PSK_FILE"
fi

exec "$@"
