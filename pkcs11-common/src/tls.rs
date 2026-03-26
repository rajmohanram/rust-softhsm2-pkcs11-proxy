use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVersion};

use crate::psk::PskEntry;

/// PSK cipher suites used for both client and server.
const PSK_CIPHERS: &str = "PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256";

/// Build an `SslConnector` configured for TLS-PSK.
///
/// The connector uses TLS 1.2 with PSK cipher suites and installs a PSK
/// client callback that returns the identity and key from `psk`.
pub fn build_client_connector(psk: &PskEntry) -> crate::Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_cipher_list(PSK_CIPHERS)?;

    // Disable certificate verification — PSK provides authentication.
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);

    let identity = psk.identity.clone();
    let key = psk.key.clone();

    builder.set_psk_client_callback(move |_ssl, _hint, identity_buf, psk_buf| {
        let id_bytes = identity.as_bytes();
        // identity_buf must be null-terminated.
        if id_bytes.len() + 1 > identity_buf.len() {
            return Ok(0);
        }
        identity_buf[..id_bytes.len()].copy_from_slice(id_bytes);
        identity_buf[id_bytes.len()] = 0;

        if key.len() > psk_buf.len() {
            return Ok(0);
        }
        psk_buf[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });

    Ok(builder.build())
}

/// Build an `SslAcceptor` configured for TLS-PSK.
///
/// The acceptor uses TLS 1.2 with PSK cipher suites and installs a PSK
/// server callback that validates the client identity and returns the key.
pub fn build_server_acceptor(psk: &PskEntry) -> crate::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_cipher_list(PSK_CIPHERS)?;

    // No certificate needed for PSK.
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);

    let expected_identity = psk.identity.clone();
    let key = psk.key.clone();

    builder.set_psk_server_callback(move |_ssl, client_identity, psk_buf| {
        let id_matches = client_identity
            .map(|id| id == expected_identity.as_bytes())
            .unwrap_or(false);

        if !id_matches {
            return Ok(0);
        }

        if key.len() > psk_buf.len() {
            return Ok(0);
        }
        psk_buf[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });

    Ok(builder.build())
}
