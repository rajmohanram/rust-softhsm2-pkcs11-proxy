// Include protobuf-generated code produced by prost during the build step.
include!(concat!(env!("OUT_DIR"), "/pkcs11_proxy.rs"));

use std::io::{Read, Write};

use prost::Message;

use crate::error::ProxyError;

/// Write a length-prefixed protobuf message to `stream`.
///
/// The wire format is a 4-byte big-endian length followed by the serialised
/// protobuf bytes.
pub fn write_message(stream: &mut impl Write, msg: &impl Message) -> crate::Result<()> {
    let encoded = msg.encode_to_vec();
    let len = encoded.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&encoded)?;
    stream.flush()?;
    Ok(())
}

/// Read a length-prefixed protobuf message from `stream`.
///
/// Expects the same wire format produced by [`write_message`]: 4-byte
/// big-endian length followed by protobuf bytes.
pub fn read_message<M: Message + Default>(stream: &mut impl Read) -> crate::Result<M> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Guard against unreasonably large frames (16 MiB limit).
    const MAX_FRAME: usize = 16 * 1024 * 1024;
    if len > MAX_FRAME {
        return Err(ProxyError::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME})"
        )));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    let msg = M::decode(buf.as_slice())
        .map_err(|e| ProxyError::Protocol(format!("protobuf decode error: {e}")))?;
    Ok(msg)
}
