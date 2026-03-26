//! Global connection state for the proxy client.
//!
//! A single TLS-PSK connection is maintained to the proxy server. It is
//! established lazily on the first RPC call and guarded by a mutex so that
//! only one PKCS#11 call is in-flight at a time.

use std::net::TcpStream;
use std::path::Path;

use once_cell::sync::Lazy;
use openssl::ssl::SslStream;
use parking_lot::Mutex;
use tracing::{debug, error};

use pkcs11_common::protocol::{Request, Response};
use pkcs11_common::{
    build_client_connector, load_psk_file, load_psk_from_env, read_message, write_message,
};

/// Holds the live TLS stream to the proxy server.
pub struct ClientState {
    stream: SslStream<TcpStream>,
}

/// Global, lazily-initialized, mutex-guarded connection state.
static STATE: Lazy<Mutex<Option<ClientState>>> = Lazy::new(|| Mutex::new(None));

/// Establish (or re-establish) the TLS-PSK connection to the server.
///
/// PSK credentials are resolved in order:
/// 1. `PKCS11_PROXY_TLS_PSK` + `PKCS11_PROXY_TLS_PSK_IDENTITY` env vars
/// 2. `PKCS11_PROXY_TLS_PSK_FILE` file path
///
/// Connection target:
/// - `PKCS11_PROXY_SOCKET` – a `tls://host:port` URL
fn connect() -> Result<ClientState, pkcs11_common::ProxyError> {
    let url = std::env::var("PKCS11_PROXY_SOCKET").map_err(|_| {
        pkcs11_common::ProxyError::Protocol("PKCS11_PROXY_SOCKET env var not set".into())
    })?;

    // Parse the tls:// URL.
    let addr = url.strip_prefix("tls://").ok_or_else(|| {
        pkcs11_common::ProxyError::Protocol(format!(
            "PKCS11_PROXY_SOCKET must start with tls:// (got {url})"
        ))
    })?;

    debug!("connecting to proxy server at {addr}");

    // Resolve PSK: env vars first, then file.
    let psk = if let Some(entry) = load_psk_from_env()? {
        debug!("using PSK from PKCS11_PROXY_TLS_PSK env var");
        entry
    } else {
        let psk_path = std::env::var("PKCS11_PROXY_TLS_PSK_FILE").map_err(|_| {
            pkcs11_common::ProxyError::Protocol(
                "neither PKCS11_PROXY_TLS_PSK nor PKCS11_PROXY_TLS_PSK_FILE is set".into(),
            )
        })?;
        debug!("using PSK from file {psk_path}");
        load_psk_file(Path::new(&psk_path))?
    };

    let connector = build_client_connector(&psk)?;

    let tcp = TcpStream::connect(addr)?;
    // The domain name is not verified for PSK, but openssl requires a value.
    let stream = connector
        .connect("pkcs11-proxy", tcp)
        .map_err(|e| pkcs11_common::ProxyError::Protocol(format!("TLS handshake failed: {e}")))?;

    debug!("TLS-PSK connection established");

    Ok(ClientState { stream })
}

/// Send a protobuf `Request` over the global connection and return the
/// `Response`.
///
/// If the connection is not yet established it will be created. If the
/// send/receive fails the connection is torn down so that the next call
/// will attempt to reconnect.
pub fn send_request(request: &Request) -> Result<Response, pkcs11_common::ProxyError> {
    let mut guard = STATE.lock();

    // Ensure we have a connection.
    if guard.is_none() {
        *guard = Some(connect()?);
    }

    let state = guard.as_mut().unwrap();

    // Write request.
    let write_result = write_message(&mut state.stream, request);
    if let Err(e) = write_result {
        error!("failed to write request: {e}");
        *guard = None; // tear down broken connection
        return Err(e);
    }

    // Read response.
    let read_result: Result<Response, _> = read_message(&mut state.stream);
    match read_result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!("failed to read response: {e}");
            *guard = None;
            Err(e)
        }
    }
}

/// Tear down the global connection (used by `C_Finalize`).
pub fn disconnect() {
    let mut guard = STATE.lock();
    *guard = None;
}
