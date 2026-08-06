//! The pkt-line framing git's long-running filter protocol speaks.
//!
//! A packet is four hexadecimal digits of length — counting those four bytes —
//! followed by the payload. `0000` is a flush, which ends a list. Payloads are
//! arbitrary bytes, so nothing here may become a `String`.

use std::io::{Read, Write};

use crate::{Error, Result};

/// Largest payload one packet can carry: git's limit minus the length prefix.
pub const MAX_PAYLOAD: usize = 65516;

/// One item read from the stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Packet {
    /// A payload, without its length prefix.
    Data(Vec<u8>),
    /// The `0000` that ends a list.
    Flush,
}

/// Reads one packet.
///
/// # Errors
///
/// [`Error::Io`] on a read failure, [`Error::Format`] on a malformed length.
pub fn read_packet(input: &mut impl Read) -> Result<Packet> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;

    // Four hexadecimal digits and nothing else. `from_str_radix` alone would
    // accept `+abc`, and this is the one parser standing between a malformed
    // stream and the rest of the filter.
    if !length.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Format(
            "the filter protocol sent a non-hex packet length".into(),
        ));
    }
    let text = std::str::from_utf8(&length)
        .map_err(|_| Error::Format("the filter protocol sent a non-hex packet length".into()))?;
    let length = usize::from_str_radix(text, 16)
        .map_err(|_| Error::Format(format!("the filter protocol sent a bad length `{text}`")))?;

    if length == 0 {
        return Ok(Packet::Flush);
    }
    if length < 4 {
        return Err(Error::Format(format!(
            "the filter protocol sent an impossible packet length {length}"
        )));
    }

    let mut payload = vec![0u8; length - 4];
    input.read_exact(&mut payload)?;
    Ok(Packet::Data(payload))
}

/// Writes one payload, splitting it across packets when it is too long.
///
/// # Errors
///
/// [`Error::Io`] on a write failure.
pub fn write_data(output: &mut impl Write, payload: &[u8]) -> Result<()> {
    for chunk in payload.chunks(MAX_PAYLOAD) {
        write!(output, "{:04x}", chunk.len() + 4)?;
        output.write_all(chunk)?;
    }
    Ok(())
}

/// Writes a flush and pushes everything out.
///
/// The flush is useless if it sits in a buffer: git is waiting for it before it
/// will say anything else, so this is where a missing flush turns into a hang.
///
/// # Errors
///
/// [`Error::Io`] on a write failure.
pub fn write_flush(output: &mut impl Write) -> Result<()> {
    output.write_all(b"0000")?;
    output.flush()?;
    Ok(())
}

/// Reads packets until the next flush, returning their payloads.
///
/// # Errors
///
/// As [`read_packet`].
pub fn read_until_flush(input: &mut impl Read) -> Result<Vec<Vec<u8>>> {
    let mut items = Vec::new();
    loop {
        match read_packet(input)? {
            Packet::Flush => return Ok(items),
            Packet::Data(payload) => items.push(payload),
        }
    }
}

/// Reads packets until the next flush and concatenates them.
///
/// # Errors
///
/// As [`read_packet`].
pub fn read_content(input: &mut impl Read) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    loop {
        match read_packet(input)? {
            Packet::Flush => return Ok(content),
            Packet::Data(payload) => content.extend_from_slice(&payload),
        }
    }
}
