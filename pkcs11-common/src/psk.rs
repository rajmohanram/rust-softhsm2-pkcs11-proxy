use std::path::Path;

use crate::error::ProxyError;

/// A single PSK identity and its associated key material.
#[derive(Debug, Clone)]
pub struct PskEntry {
    pub identity: String,
    pub key: Vec<u8>,
}

/// Load a PSK file and return the first entry.
///
/// The file format is one entry per line:
///
/// ```text
/// identity:hex_encoded_key
/// ```
///
/// Only the first non-empty line is used.
pub fn load_psk_file(path: &Path) -> crate::Result<PskEntry> {
    let contents = std::fs::read_to_string(path)?;

    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| ProxyError::Protocol("PSK file is empty or has no valid entries".into()))?;

    let (identity, hex_key) = line
        .split_once(':')
        .ok_or_else(|| ProxyError::Protocol("PSK line missing ':' delimiter".into()))?;

    if identity.is_empty() {
        return Err(ProxyError::Protocol("PSK identity is empty".into()));
    }

    let key = hex::decode(hex_key.trim())
        .map_err(|e| ProxyError::Protocol(format!("invalid hex in PSK key: {e}")))?;

    if key.is_empty() {
        return Err(ProxyError::Protocol("PSK key is empty".into()));
    }

    Ok(PskEntry {
        identity: identity.to_string(),
        key,
    })
}

/// Load PSK credentials from environment variables.
///
/// - `PKCS11_PROXY_TLS_PSK_IDENTITY` – the PSK identity (defaults to `client`)
/// - `PKCS11_PROXY_TLS_PSK` – the hex-encoded pre-shared key
///
/// Returns `None` if `PKCS11_PROXY_TLS_PSK` is not set.
pub fn load_psk_from_env() -> crate::Result<Option<PskEntry>> {
    let hex_key = match std::env::var("PKCS11_PROXY_TLS_PSK") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };

    let identity =
        std::env::var("PKCS11_PROXY_TLS_PSK_IDENTITY").unwrap_or_else(|_| "client".to_string());

    let key = hex::decode(hex_key.trim())
        .map_err(|e| ProxyError::Protocol(format!("invalid hex in PKCS11_PROXY_TLS_PSK: {e}")))?;

    if key.is_empty() {
        return Err(ProxyError::Protocol(
            "PKCS11_PROXY_TLS_PSK is set but empty after decode".into(),
        ));
    }

    Ok(Some(PskEntry { identity, key }))
}
