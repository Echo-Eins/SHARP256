//! What a stream carrier says on the wire: a preamble each way, then
//! datagrams in frames.
//!
//! ```text
//! preamble   "SHRP" | version (1) | kind | 0 0                 8 bytes
//! frame      length (u16) | port (u16) | datagram[length]
//! ```
//!
//! The preamble says what the stream leads to — a receiver, or a relay —
//! and the side that accepted the stream sends the same eight bytes back,
//! which tells the side that opened it that a SHARP-256 endpoint is there
//! and not, say, a web server on port 443. A frame carries one datagram,
//! exactly as it would have gone over UDP. Its port is the relay's port the
//! datagram is to or from (0 for the relay's control port), and 0 on a
//! stream to a receiver. A frame of length 0 is nothing (and ignored); one
//! whose length has its top bit set is the carrier's own business, not a
//! datagram (see `tls`), and longer than any datagram otherwise.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The preamble's length.
pub const PREAMBLE_LEN: usize = 8;
const MAGIC: [u8; 4] = *b"SHRP";
/// The carrier format's version, in every preamble.
const VERSION: u8 = 1;

/// The header in front of every frame.
pub const HEADER_LEN: usize = 4;
/// The largest datagram anything here sends: the UDP payload of a jumbo
/// frame. A frame claiming more is not one.
pub const MAX_DATAGRAM: usize = crate::protocol::constants::UDP_PAYLOAD_JUMBO;
/// Set in the length of a frame of the carrier's own.
const OWN: u16 = 0x8000;

/// What a stream leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A receiver: its datagrams, on port 0.
    Receiver,
    /// A relay: its control port's datagrams (port 0) and its pairs' (each
    /// on its own port).
    Relay,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::Receiver => 1,
            Kind::Relay => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Kind::Receiver),
            2 => Some(Kind::Relay),
            _ => None,
        }
    }
}

/// The preamble for a stream to `kind`.
pub fn preamble(kind: Kind) -> [u8; PREAMBLE_LEN] {
    let mut p = [0u8; PREAMBLE_LEN];
    p[..4].copy_from_slice(&MAGIC);
    p[4] = VERSION;
    p[5] = kind.code();
    p
}

/// What a preamble says the stream leads to, if it is one of ours, of this
/// version.
pub fn parse_preamble(p: &[u8; PREAMBLE_LEN]) -> Option<Kind> {
    if p[..4] != MAGIC || p[4] != VERSION || p[6..] != [0, 0] {
        return None;
    }
    Kind::from_code(p[5])
}

/// One frame read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A datagram, to or from `port`.
    Datagram { port: u16, data: Vec<u8> },
    /// The carrier's own (see `tls`).
    Own(Vec<u8>),
}

/// The header of a frame carrying `len` bytes on `port`.
pub fn header(len: usize, port: u16) -> [u8; HEADER_LEN] {
    debug_assert!(len <= MAX_DATAGRAM);
    let l = (len as u16).to_be_bytes();
    let p = port.to_be_bytes();
    [l[0], l[1], p[0], p[1]]
}

/// The header of a frame of the carrier's own carrying `len` bytes.
pub fn own_header(len: usize) -> [u8; HEADER_LEN] {
    debug_assert!(len <= MAX_DATAGRAM);
    let l = (len as u16 | OWN).to_be_bytes();
    [l[0], l[1], 0, 0]
}

/// Reads the next frame, skipping empty ones. `Ok(None)` when the stream
/// ends between frames; an error when it ends inside one, or a frame is
/// longer than any datagram.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    loop {
        let mut head = [0u8; HEADER_LEN];
        // A clean end is one that comes before a frame's first byte.
        let first = r.read(&mut head[..1]).await?;
        if first == 0 {
            return Ok(None);
        }
        r.read_exact(&mut head[1..]).await?;
        let len_field = u16::from_be_bytes([head[0], head[1]]);
        let port = u16::from_be_bytes([head[2], head[3]]);
        let own = len_field & OWN != 0;
        let len = (len_field & !OWN) as usize;
        if len > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a frame of {} bytes, more than any datagram", len),
            ));
        }
        if len == 0 && !own {
            continue;
        }
        let mut data = vec![0u8; len];
        r.read_exact(&mut data).await?;
        return Ok(Some(if own {
            Frame::Own(data)
        } else {
            Frame::Datagram { port, data }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preamble_says_what_the_stream_leads_to_and_nothing_else_parses() {
        for kind in [Kind::Receiver, Kind::Relay] {
            assert_eq!(parse_preamble(&preamble(kind)), Some(kind));
        }
        let mut p = preamble(Kind::Relay);
        p[4] = 2;
        assert_eq!(parse_preamble(&p), None, "another version");
        let mut p = preamble(Kind::Relay);
        p[5] = 3;
        assert_eq!(parse_preamble(&p), None, "another kind");
        let mut p = preamble(Kind::Receiver);
        p[7] = 1;
        assert_eq!(parse_preamble(&p), None, "reserved bytes set");
        assert_eq!(parse_preamble(b"GET / HT"), None, "a web client");
    }

    #[tokio::test]
    async fn frames_come_back_as_written_whatever_the_reads_cut() {
        let mut wire = Vec::new();
        let datagrams: Vec<(u16, Vec<u8>)> = vec![
            (0, b"control".to_vec()),
            (40_001, vec![7u8; 1452]),
            (0, vec![1u8; MAX_DATAGRAM]),
        ];
        for (port, d) in &datagrams {
            wire.extend_from_slice(&header(d.len(), *port));
            wire.extend_from_slice(d);
            // Nothing between them, as a writer may send to keep a NAT open.
            wire.extend_from_slice(&header(0, 0));
        }
        wire.extend_from_slice(&own_header(3));
        wire.extend_from_slice(b"own");
        // Read through a reader that hands over a byte or a few at a time.
        let (mut client, mut server) = tokio::io::duplex(7);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&wire).await.unwrap();
        });
        for (port, d) in &datagrams {
            let f = read_frame(&mut server).await.unwrap().unwrap();
            assert_eq!(
                f,
                Frame::Datagram {
                    port: *port,
                    data: d.clone()
                }
            );
        }
        assert_eq!(
            read_frame(&mut server).await.unwrap(),
            Some(Frame::Own(b"own".to_vec()))
        );
        writer.await.unwrap();
        assert_eq!(read_frame(&mut server).await.unwrap(), None, "a clean end");
    }

    #[tokio::test]
    async fn a_frame_longer_than_any_datagram_or_cut_short_is_an_error() {
        let l = ((MAX_DATAGRAM + 1) as u16).to_be_bytes();
        let long = [l[0], l[1], 0, 0];
        let mut r: &[u8] = &long;
        assert!(read_frame(&mut r).await.is_err());
        let mut cut: &[u8] = &[0, 10, 0, 0, 1, 2, 3];
        assert!(read_frame(&mut cut).await.is_err());
        let mut half_header: &[u8] = &[0, 10];
        assert!(read_frame(&mut half_header).await.is_err());
    }
}
