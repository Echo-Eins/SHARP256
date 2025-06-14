use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
pub mod detector;

pub use detector::{detect_max_payload, FragmentationInfo};

use crate::protocol::constants::{MAX_PAYLOAD_SIZE_GSO, MAX_PAYLOAD_SIZE_MTU};

const FRAG_TEST_PREFIX: &[u8] = b"SHARP_FRAG_TEST";
const FRAG_ACK_PREFIX: &[u8] = b"SHARP_FRAG_ACK";

async fn send_test(socket: &UdpSocket, peer: SocketAddr, size: usize) -> Result<bool> {
    let mut buf = Vec::with_capacity(size + FRAG_TEST_PREFIX.len() + 4);
    buf.extend_from_slice(FRAG_TEST_PREFIX);
    buf.extend_from_slice(&(size as u32).to_be_bytes());
    buf.resize(size + FRAG_TEST_PREFIX.len() + 4, 0);

    socket.send_to(&buf, peer).await?;

    let mut recv = vec![0u8; 32];
    match timeout(Duration::from_secs(2), socket.recv_from(&mut recv)).await {
        Ok(Ok((n, addr))) if addr == peer && n >= FRAG_ACK_PREFIX.len() + 4 => {
            if &recv[..FRAG_ACK_PREFIX.len()] == FRAG_ACK_PREFIX {
                let ret_size = u32::from_be_bytes(
                    recv[FRAG_ACK_PREFIX.len()..FRAG_ACK_PREFIX.len() + 4]
                        .try_into()
                        .unwrap(),
                ) as usize;
                return Ok(ret_size == size);
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Determine maximum allowed fragment size with real network check.
pub async fn check_fragmentation(socket: &UdpSocket, peer: SocketAddr) -> Result<usize> {
    if send_test(socket, peer, MAX_PAYLOAD_SIZE_GSO).await? {
        Ok(MAX_PAYLOAD_SIZE_GSO)
    } else if send_test(socket, peer, MAX_PAYLOAD_SIZE_MTU).await? {
        Ok(MAX_PAYLOAD_SIZE_MTU)
    } else {
        Ok(MAX_PAYLOAD_SIZE_MTU)
    }
}

/// Handle incoming fragmentation test packet on receiver.
pub async fn handle_fragmentation_packet(
    socket: &UdpSocket,
    data: &[u8],
    peer: SocketAddr,
) -> Result<bool> {
    if data.starts_with(FRAG_TEST_PREFIX) && data.len() >= FRAG_TEST_PREFIX.len() + 4 {
        let size = u32::from_be_bytes(
            data[FRAG_TEST_PREFIX.len()..FRAG_TEST_PREFIX.len() + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let mut ack = Vec::with_capacity(FRAG_ACK_PREFIX.len() + 4);
        ack.extend_from_slice(FRAG_ACK_PREFIX);
        ack.extend_from_slice(&(size as u32).to_be_bytes());
        socket.send_to(&ack, peer).await?;
        tracing::info!("Fragmentation test from {} with size {} bytes", peer, size);
        return Ok(true);
    }
    Ok(false)
}