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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_round_trips() {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"version=2\n").expect("writing must succeed");
        write_flush(&mut buffer).expect("writing must succeed");

        let mut cursor = buffer.as_slice();
        assert_eq!(
            read_packet(&mut cursor).expect("reading must succeed"),
            Packet::Data(b"version=2\n".to_vec())
        );
        assert_eq!(
            read_packet(&mut cursor).expect("reading must succeed"),
            Packet::Flush
        );
    }

    #[test]
    fn the_length_prefix_counts_itself() {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"abc").expect("writing must succeed");
        assert_eq!(&buffer[..4], b"0007");
    }

    #[test]
    fn binary_payloads_survive() {
        let content: Vec<u8> = (0u8..=255).collect();
        let mut buffer = Vec::new();
        write_data(&mut buffer, &content).expect("writing must succeed");
        write_flush(&mut buffer).expect("writing must succeed");

        let mut cursor = buffer.as_slice();
        assert_eq!(
            read_content(&mut cursor).expect("reading must succeed"),
            content
        );
    }

    #[test]
    fn a_payload_larger_than_one_packet_is_split_and_rejoined() {
        let content: Vec<u8> = (0u8..=255).cycle().take(MAX_PAYLOAD * 2 + 17).collect();
        let mut buffer = Vec::new();
        write_data(&mut buffer, &content).expect("writing must succeed");
        write_flush(&mut buffer).expect("writing must succeed");

        let mut cursor = buffer.as_slice();
        assert_eq!(
            read_content(&mut cursor).expect("reading must succeed"),
            content
        );
    }

    #[test]
    fn an_empty_payload_writes_nothing_but_the_flush() {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"").expect("writing must succeed");
        write_flush(&mut buffer).expect("writing must succeed");
        assert_eq!(buffer, b"0000");

        let mut cursor = buffer.as_slice();
        assert!(
            read_content(&mut cursor)
                .expect("reading must succeed")
                .is_empty()
        );
    }

    #[test]
    fn a_malformed_length_is_refused() {
        let mut cursor = b"zzzz".as_slice();
        assert!(read_packet(&mut cursor).is_err());

        let mut cursor = b"0002".as_slice();
        assert!(read_packet(&mut cursor).is_err());
    }

    #[test]
    fn a_list_reads_until_its_flush() {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"command=clean\n").expect("writing");
        write_data(&mut buffer, b"pathname=a.env\n").expect("writing");
        write_flush(&mut buffer).expect("writing");

        let mut cursor = buffer.as_slice();
        let items = read_until_flush(&mut cursor).expect("reading must succeed");
        assert_eq!(items.len(), 2);
        assert_eq!(items[1], b"pathname=a.env\n");
    }
}
