//! TLS-PSK accept loop and per-connection handler.

use std::net::TcpListener;

use anyhow::{Context, Result};
use openssl::ssl::SslStream;
use tracing::{error, info, warn};

use pkcs11_common::protocol::Request;
use pkcs11_common::{build_server_acceptor, read_message, write_message, PskEntry};

use crate::handler;
use crate::session_map::SessionMap;

/// Start the TLS-PSK server.
pub async fn run_server(listen_addr: &str, psk: PskEntry) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .with_context(|| format!("failed to bind to {listen_addr}"))?;

    info!(addr = %listen_addr, "server listening");

    let acceptor = build_server_acceptor(&psk).context("failed to build TLS-PSK acceptor")?;

    tokio::task::spawn_blocking(move || {
        for stream in listener.incoming() {
            let tcp_stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    error!("accept error: {e}");
                    continue;
                }
            };

            let peer_addr = tcp_stream.peer_addr().ok();
            info!(peer = ?peer_addr, "new TCP connection");

            let ssl_stream = match acceptor.accept(tcp_stream) {
                Ok(s) => s,
                Err(e) => {
                    error!(peer = ?peer_addr, "TLS handshake failed: {e}");
                    continue;
                }
            };

            info!(peer = ?peer_addr, "TLS-PSK handshake complete");

            std::thread::spawn(move || {
                handle_connection(ssl_stream, peer_addr);
            });
        }
    })
    .await?;

    Ok(())
}

fn handle_connection(
    mut stream: SslStream<std::net::TcpStream>,
    peer: Option<std::net::SocketAddr>,
) {
    let session_map = SessionMap::new();

    loop {
        let request: Request = match read_message(&mut stream) {
            Ok(req) => req,
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("eof") || msg.contains("EOF") || msg.contains("UnexpectedEof") {
                    info!(peer = ?peer, "client disconnected");
                } else {
                    warn!(peer = ?peer, "read error (disconnecting): {e}");
                }
                break;
            }
        };

        let response = handler::dispatch(&session_map, request);

        if let Err(e) = write_message(&mut stream, &response) {
            warn!(peer = ?peer, "write error (disconnecting): {e}");
            break;
        }
    }

    cleanup_sessions(&session_map);
}

fn cleanup_sessions(session_map: &SessionMap) {
    let real_handles = session_map.all_real_handles();
    if real_handles.is_empty() {
        return;
    }

    info!(
        count = real_handles.len(),
        "cleaning up sessions after disconnect"
    );

    let func_list = handler::get_function_list();
    if func_list.is_null() {
        error!("cannot get function list for session cleanup");
        return;
    }

    for real_handle in real_handles {
        unsafe {
            if let Some(close_session) = (*func_list).C_CloseSession {
                let rv = close_session(real_handle as cryptoki_sys::CK_SESSION_HANDLE);
                if rv != cryptoki_sys::CKR_OK {
                    warn!(
                        session = real_handle,
                        rv, "C_CloseSession failed during cleanup"
                    );
                }
            }
        }
    }

    session_map.clear();
}
