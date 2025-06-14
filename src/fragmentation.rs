use anyhow::Result;
use tokio::net::UdpSocket;
use std::net::SocketAddr;

pub struct FragmentationInfo {
    pub max_payload_size: usize,
}

pub async fn check_fragmentation(_socket: &UdpSocket, _peer: SocketAddr) -> Result<usize> {
    Ok(0)
}

pub async fn detect_max_payload(_socket: &UdpSocket, _peer: SocketAddr) -> Result<FragmentationInfo> {
    Ok(FragmentationInfo { max_payload_size: 1200 })
}

pub async fn handle_fragmentation_packet(_socket: &UdpSocket, _data: &[u8], _addr: SocketAddr) -> Result<bool> {
    Ok(false)
}