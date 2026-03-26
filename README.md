# softhsm2-pkcs11-proxy

A PKCS#11 network proxy written in Rust with SoftHSM2, designed for [OpenBao](https://openbao.org) HSM auto-unseal.

## Why?

The C-based [SUNET/pkcs11-proxy](https://github.com/SUNET/pkcs11-proxy) cannot serialize PKCS#11 mechanism parameters that contain pointers. This breaks both mechanisms OpenBao supports:

- **CKM_AES_GCM** — `CK_GCM_PARAMS` has `pIv` and `pAAD` pointers
- **CKM_RSA_PKCS_OAEP** — `CK_RSA_PKCS_OAEP_PARAMS` has `pSourceData` pointer

This proxy solves it with proper deep serialization of all pointer-containing parameter structures over a protobuf/TLS-PSK transport.

## Architecture

```text
┌──────────────┐       TLS-PSK / protobuf        ┌──────────────────┐
│   OpenBao    │                                 │   pkcs11-proxyd  │
│              │                                 │                  │
│  libpkcs11-  ├────────────────────────────────►│  ──► SoftHSM2    │
│  proxy.so    │                                 │  ──► Luna HSM    │
│  (client)    │                                 │  ──► any PKCS#11 │
└──────────────┘                                 └──────────────────┘
```

## Quick Start

```bash
# Pull the image
docker pull ghcr.io/rajmohanram/softhsm2-pkcs11-proxy:latest

# Run the proxy
docker run -d --name softhsm-proxy \
  -e PKCS11_PROXY_TLS_PSK_IDENTITY=openbao \
  -e PKCS11_PROXY_TLS_PSK=0123456789abcdef0123456789abcdef \
  -v softhsm-tokens:/var/lib/softhsm/tokens \
  -p 2345:2345 \
  ghcr.io/rajmohanram/softhsm2-pkcs11-proxy:latest

# Initialize token and generate unseal key
docker exec softhsm-proxy softhsm2-util --init-token \
  --free --label openbao --pin 5678 --so-pin 1234
docker exec softhsm-proxy pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 5678 --token-label openbao \
  --keygen --key-type aes:32 --label openbao-unseal --id 01

# Restart proxy to pick up the new token
docker restart softhsm-proxy
```

See [deploy/docker](deploy/docker) for a full Docker Compose example with OpenBao, or [deploy/kubernetes](deploy/kubernetes) for Kubernetes manifests.

## Configuration

### Environment Variables

| Variable                        | Description                                           | Default                        |
| ------------------------------- | ----------------------------------------------------- | ------------------------------ |
| `PKCS11_PROXY_TLS_PSK`          | Hex-encoded pre-shared key                            | _(auto-generated if not set)_  |
| `PKCS11_PROXY_TLS_PSK_IDENTITY` | PSK identity string                                   | `client`                       |
| `PKCS11_PROXY_TLS_PSK_FILE`     | Path to PSK file (`identity:hex_key`)                 | `/etc/pkcs11-proxy/client.psk` |
| `PKCS11_PROXY_SOCKET`           | Server address (client-side)                          | —                              |
| `PKCS11_PROXY_LOG_LEVEL`        | Log level (`error`, `warn`, `info`, `debug`, `trace`) | `info`                         |

PSK resolution order: `PKCS11_PROXY_TLS_PSK` env var > `PKCS11_PROXY_TLS_PSK_FILE` file > auto-generate (server only).

### Server CLI

```bash
pkcs11-proxyd \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --listen 0.0.0.0:2345 \
  --psk-file /etc/pkcs11-proxy/client.psk
```

### OpenBao Seal Configuration

```hcl
seal "pkcs11" {
  lib         = "/usr/local/lib/libpkcs11-proxy.so"
  token_label = "openbao"
  pin         = "5678"
  key_label   = "openbao-unseal"
  mechanism   = "CKM_AES_GCM"
}
```

## Building from Source

```bash
# Prerequisites: Rust 1.94+, protobuf compiler
make build        # debug build
make release      # release build
make docker       # Docker image
make lint         # clippy
make test         # tests
```

## Image Contents

The published image (`ghcr.io/rajmohanram/softhsm2-pkcs11-proxy`) includes:

- `pkcs11-proxyd` — server daemon
- `libpkcs11-proxy.so` — client library (copy into your OpenBao image)
- SoftHSM2 + OpenSC tools
- Entrypoint with auto PSK generation

## Project Structure

```text
pkcs11-common/        Shared protobuf protocol, TLS-PSK, PSK parsing
pkcs11-proxy-client/  Client .so (PKCS#11 C API, loaded by OpenBao)
pkcs11-proxyd/        Server daemon (dispatches to real PKCS#11 module)
proto/                Protobuf schema
scripts/              Entrypoint script
deploy/docker/        Docker Compose example
deploy/kubernetes/    Kubernetes sample manifests
```

## License

MIT
