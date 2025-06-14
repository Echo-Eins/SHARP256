use crate::protocol::constants::{MAX_PAYLOAD_SIZE_GSO, MAX_PAYLOAD_SIZE_MTU};
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Information about detected fragmentation
#[derive(Debug, Clone, Copy)]
pub struct FragmentationInfo {
    pub max_payload_size: usize,
}

/// Try sending datagrams of decreasing size to determine maximum allowed payload.
/// This performs actual sends to the provided peer and observes OS errors.
pub async fn detect_max_payload(
    socket: &UdpSocket,
    peer: SocketAddr,
) -> io::Result<FragmentationInfo> {
    // Candidate sizes from large to small
    let candidates = [
        MAX_PAYLOAD_SIZE_GSO,
        48 * 1024,
        32 * 1024,
        16 * 1024,
        MAX_PAYLOAD_SIZE_MTU,
    ];

    for &size in &candidates {
        let test_buf = vec![0u8; size];
        match socket.send_to(&test_buf, peer).await {
            Ok(_) => {
                tracing::info!("Fragmentation check succeeded for {} bytes", size);
                return Ok(FragmentationInfo {
                    max_payload_size: size,
                });
            }
            Err(e) => {
                tracing::warn!("Fragmentation check failed for {} bytes: {}", size, e);
            }
        }
    }

    Ok(FragmentationInfo {
        max_payload_size: MAX_PAYLOAD_SIZE_MTU,
    })
}