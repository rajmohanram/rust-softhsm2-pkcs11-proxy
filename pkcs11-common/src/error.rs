/// Errors produced by the PKCS#11 proxy common layer.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] openssl::error::ErrorStack),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("PKCS#11 error: 0x{0:x}")]
    Pkcs11(u64),
}
