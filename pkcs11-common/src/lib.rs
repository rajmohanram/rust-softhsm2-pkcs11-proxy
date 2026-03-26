pub mod error;
pub mod protocol;
pub mod psk;
pub mod tls;

pub use error::ProxyError;
pub use protocol::{read_message, write_message};
pub use psk::{load_psk_file, load_psk_from_env, PskEntry};
pub use tls::{build_client_connector, build_server_acceptor};

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ProxyError>;
