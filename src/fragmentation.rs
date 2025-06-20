use crate::protocol::constants::{MAX_PAYLOAD_SIZE_GSO, MAX_PAYLOAD_SIZE_MTU};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use rand::Rng;
use crate::protocol::constants::*;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tokio::time::{sleep};

#[cfg(unix)]
use libc::{IPPROTO_IP, IPPROTO_IPV6, IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_MTU, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO, IPV6_PMTUDISC_DONT, IPV6_MTU};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
const EMSGSIZE: i32 = libc::EMSGSIZE;
#[cfg(windows)]
const EMSGSIZE: i32 = 10040; // WSAEMSGSIZE
const FRAG_REQ_PREFIX: &[u8] = b"SHARP_FRAG_REQ";
const FRAG_ACK_PREFIX: &[u8] = b"SHARP_FRAG_ACK";
const FRAG_TIMEOUT: Duration = Duration::from_millis(500);

/// Information about detected fragmentation limits
#[derive(Debug, Clone)]
pub struct FragmentationInfo {
    pub max_payload_size: usize,
    pub supports_gso: bool,
    pub path_mtu: usize,
    pub tested_successfully: Vec<usize>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_df(socket: &UdpSocket, v6: bool, enable: bool) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    unsafe {
        let (level, optname, val) = if v6 {
            let val = if enable { IPV6_PMTUDISC_DO } else { IPV6_PMTUDISC_DONT };
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER, val)
        } else {
            let val = if enable { IP_PMTUDISC_DO } else { IP_PMTUDISC_DONT };
            (IPPROTO_IP, IP_MTU_DISCOVER, val)
        };
        let val: libc::c_int = val;
        if libc::setsockopt(
            fd,
            level,
            optname,
            &val as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        ) == -1
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_df(_socket: &UdpSocket, _v6: bool, _enable: bool) -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_pmtu(socket: &UdpSocket, v6: bool) -> Option<usize> {
    let fd = socket.as_raw_fd();
    unsafe {
        let (level, opt) = if v6 {
            (IPPROTO_IPV6, IPV6_MTU)
        } else {
            (IPPROTO_IP, IP_MTU)
        };
        let mut mtu: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            level,
            opt,
            &mut mtu as *mut _ as *mut _,
            &mut len,
        ) == -1
        {
            None
        } else {
            Some(mtu as usize)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn get_pmtu(_socket: &UdpSocket, _v6: bool) -> Option<usize> {
    None
}

/// Test for UDP fragmentation between peers
pub async fn check_fragmentation(socket: &UdpSocket, peer: SocketAddr) -> Result<usize> {
    tracing::info!("Checking fragmentation limits with {}", peer);

    for attempt in 0..3 {
        let test_id = rand::thread_rng().gen::<u32>();
        let request = create_frag_test_request(test_id);

        socket
            .send_to(&request, peer)
            .await
            .with_context(|| "failed to send fragmentation request")?;

    // Wait for response
        let mut buffer = vec![0u8; 1024];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) if addr == peer && size >= 12 && &buffer[..8] == b"SHARP_FR" => {
                let max_size = u32::from_be_bytes(buffer[8..12].try_into().unwrap()) as usize;
                tracing::info!("Peer reports max payload size: {} bytes", max_size);
                return Ok(max_size);
            }
            _ => {
                tracing::debug!("No response to fragmentation request attempt {}", attempt + 1);
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    // If no response, perform active probing
    let info = detect_max_payload(socket, peer).await?;
    Ok(info.max_payload_size)
}

/// Detect maximum payload size through active probing
pub async fn detect_max_payload(socket: &UdpSocket, peer: SocketAddr) -> Result<FragmentationInfo> {
    tracing::info!("Detecting maximum payload size to {}", peer);

    // Test sizes to try (in order)
    let test_sizes = vec![
        // Start with common sizes
        1200,   // Safe for most networks
        1400,   // Close to typical MTU
        1472,   // Maximum for 1500 MTU (1500 - 20 IP - 8 UDP)
        8192,   // Jumbo frame boundary
        16384,  // Common GSO size
        32768,  // Half of max GSO
        65507,  // Maximum UDP payload (65535 - 20 IP - 8 UDP)
    ];

    let mut max_working = 0;
    let mut tested_successfully = Vec::new();
    let mut supports_gso = false;

    for &size in &test_sizes {
        if test_payload_size(socket, peer, size).await {
            max_working = size;
            tested_successfully.push(size);

            if size > MAX_PAYLOAD_SIZE_MTU {
                supports_gso = true;
            }

            tracing::debug!("Size {} bytes: OK", size);
        } else {
            tracing::debug!("Size {} bytes: Failed", size);
            break; // Don't test larger sizes
        }
    }

    // If basic MTU test failed, use binary search for precise MTU
    if max_working < 1200 {
        max_working = binary_search_mtu(socket, peer, 576, 1500).await?;
    }

    // Determine path MTU using socket info or fallback calculation
    let path_mtu = get_pmtu(socket, peer.is_ipv6()).unwrap_or_else(|| {
        if peer.is_ipv6() {
            if max_working <= (MTU_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE) {
                max_working + IPV6_HEADER_SIZE + UDP_HEADER_SIZE
            } else {
                MTU_SIZE
            }
        } else if max_working <= (MTU_SIZE - IPV4_HEADER_SIZE - UDP_HEADER_SIZE) {
            max_working + IPV4_HEADER_SIZE + UDP_HEADER_SIZE
        } else {
            MTU_SIZE
        }
    });

    let info = FragmentationInfo {
        max_payload_size: max_working,
        supports_gso,
        path_mtu,
        tested_successfully,
    };

    tracing::info!("Fragmentation detection complete: max_payload={}, GSO={}, path_mtu={}",
        info.max_payload_size,
        info.supports_gso,
        info.path_mtu
    );

    Ok(info)
}

/// Test if a specific payload size works
async fn test_payload_size(socket: &UdpSocket, peer: SocketAddr, size: usize) -> bool {
    let v6 = peer.is_ipv6();
    let _ = set_df(socket, v6, true);

    let test_id = rand::thread_rng().gen::<u32>();

    // Create test packet with specific size
    let mut packet = vec![0u8; size];
    packet[0..8].copy_from_slice(b"SHARP_TS");
    packet[8..12].copy_from_slice(&test_id.to_be_bytes());
    packet[12..16].copy_from_slice(&(size as u32).to_be_bytes());

    // Fill with pattern for integrity check
    for i in 16..size {
        packet[i] = (i % 256) as u8;
    }

    // Try sending the packet
    match socket.send_to(&packet, peer).await {
        Ok(_) => {}
        Err(e) => {
            if let Some(code) = e.raw_os_error() {
                if code == EMSGSIZE {
                    let _ = set_df(socket, v6, false);
                    return false;
                }
            }
            let _ = set_df(socket, v6, false);
            return false;
        }
    }

    // Wait for acknowledgment
    let mut buffer = vec![0u8; 256];
    let result = match timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await {
        Ok(Ok((recv_size, addr))) if addr == peer => {
            if recv_size >= 16 && &buffer[..8] == b"SHARP_TA" {
                let recv_id = u32::from_be_bytes(buffer[8..12].try_into().unwrap());
                let recv_size = u32::from_be_bytes(buffer[12..16].try_into().unwrap()) as usize;

                recv_id == test_id && recv_size == size
            } else {
                false
            }
        }
        _ => false,
    };
    let _ = set_df(socket, v6, false);
    result
}

/// Binary search for precise MTU
async fn binary_search_mtu(
    socket: &UdpSocket,
    peer: SocketAddr,
    min: usize,
    max: usize
) -> Result<usize> {
    let mut low = min;
    let mut high = max;
    let mut best = min;

    while low <= high {
        let mid = (low + high) / 2;

        if test_payload_size(socket, peer, mid).await {
            best = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    Ok(best)
}

/// Handle incoming fragmentation test packets
pub async fn handle_fragmentation_packet(
    socket: &UdpSocket,
    data: &[u8],
    addr: SocketAddr
) -> Result<bool> {
    if data.len() < 8 {
        return Ok(false);
    }

    match &data[..8] {
        b"SHARP_TS" => {
            // Test size packet - verify and acknowledge
            if data.len() >= 16 {
                let test_id = u32::from_be_bytes(data[8..12].try_into()?);
                let expected_size = u32::from_be_bytes(data[12..16].try_into()?) as usize;

                if data.len() == expected_size {
                    // Verify pattern
                    let mut valid = true;
                    for i in 16..data.len() {
                        if data[i] != (i % 256) as u8 {
                            valid = false;
                            break;
                        }
                    }

                    if valid {
                        // Send acknowledgment
                        let mut ack = vec![0u8; 16];
                        ack[0..8].copy_from_slice(b"SHARP_TA");
                        ack[8..12].copy_from_slice(&test_id.to_be_bytes());
                        ack[12..16].copy_from_slice(&expected_size.to_be_bytes());

                        let _ = socket.send_to(&ack, addr).await;
                    }
                }
            }
            Ok(true)
        }
        b"SHARP_FT" => {
            // Fragmentation test request - respond with our limits
            if data.len() >= 12 {
                let test_id = u32::from_be_bytes(data[8..12].try_into()?);

                // Determine our maximum receive size
                let our_max: u32 = if cfg!(target_os = "linux") {
                    65_507 // Linux typically supports full UDP
                } else {
                    8_192 // Conservative for other platforms
                };

                let mut response = vec![0u8; 16];
                response[0..8].copy_from_slice(b"SHARP_FR");
                response[8..12].copy_from_slice(&our_max.to_be_bytes());
                response[12..16].copy_from_slice(&test_id.to_be_bytes());

                let _ = socket.send_to(&response, addr).await;
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Create fragmentation test request packet
fn create_frag_test_request(test_id: u32) -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[0..8].copy_from_slice(b"SHARP_FT");
    packet[8..12].copy_from_slice(&test_id.to_be_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fragmentation_info() {
        let info = FragmentationInfo {
            max_payload_size: 1472,
            supports_gso: false,
            path_mtu: 1500,
            tested_successfully: vec![1200, 1400, 1472],
        };

        assert_eq!(info.max_payload_size, 1472);
        assert!(!info.supports_gso);
        assert_eq!(info.path_mtu, 1500);
    }
}