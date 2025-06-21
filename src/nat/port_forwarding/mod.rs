// src/nat/port_forwarding/mod.rs
//! Port forwarding implementation with UPnP-IGD, NAT-PMP and PCP support
//!
//! Implements:
//! - UPnP-IGD v1/v2 (RFC 6970)
//! - NAT-PMP (RFC 6886) - Full implementation.
//!   The client tracks the gateway's `server epoch` on every request and
//!   automatically recreates mappings if the epoch changes.
//! - PCP (Port Control Protocol) (RFC 6887) - Full implementation

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::{UdpSocket, TcpStream};
use tokio::time::{timeout, interval, sleep};
use tokio::sync::{RwLock as AsyncRwLock, Mutex};
use parking_lot::RwLock;

use bytes::{Bytes, BytesMut, Buf, BufMut};
use hyper::http::{Request, Response, StatusCode};
use xmltree::{Element, XMLNode};
use rand::RngCore;

use crate::nat::error::{NatError, NatPmpError, PcpError, NatResult};
use crate::nat::metrics::NatMetricsCollector;

/// Port mapping protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MappingProtocol {
    /// Universal Plug and Play Internet Gateway Device
    UPnPIGD,

    /// NAT Port Mapping Protocol (RFC 6886)
    NatPMP,

    /// Port Control Protocol (RFC 6887)
    PCP,
}

/// Port mapping configuration
#[derive(Debug, Clone)]
pub struct PortMappingConfig {
    /// External port (0 = any available)
    pub external_port: u16,

    /// Internal port
    pub internal_port: u16,

    /// Protocol (TCP or UDP)
    pub protocol: Protocol,

    /// Mapping lifetime in seconds
    pub lifetime: u32,

    /// Description for the mapping
    pub description: String,

    /// Enable automatic renewal
    pub auto_renew: bool,

    /// Preferred protocols to try
    pub preferred_protocols: Vec<MappingProtocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    Both,
}

impl Default for PortMappingConfig {
    fn default() -> Self {
        Self {
            external_port: 0,
            internal_port: 0,
            protocol: Protocol::Both,
            lifetime: 7200, // 2 hours as recommended
            description: "SHARP P2P Connection".to_string(),
            auto_renew: true,
            preferred_protocols: vec![
                MappingProtocol::PCP,      // Most modern and feature-rich
                MappingProtocol::UPnPIGD,  // Most common in home routers
                MappingProtocol::NatPMP,   // Apple devices and some routers
            ],
        }
    }
}

/// Active port mapping
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Unique mapping ID
    pub id: uuid::Uuid,

    /// Protocol used
    pub protocol: MappingProtocol,

    /// External address
    pub external_addr: SocketAddr,

    /// Internal address
    pub internal_addr: SocketAddr,

    /// Transport protocol
    pub transport: Protocol,

    /// Mapping lifetime
    pub lifetime: Duration,

    /// Creation time
    pub created_at: Instant,

    /// Gateway address
    pub gateway: IpAddr,

    /// Nonce for PCP
    pub nonce: Option<[u8; 12]>,

    /// Mapping epoch (for NAT-PMP/PCP)
    pub epoch: Option<u32>,
}

/// Port forwarding service
pub struct PortForwardingService {
    /// Active mappings
    mappings: Arc<AsyncRwLock<HashMap<uuid::Uuid, PortMapping>>>,

    /// UPnP-IGD client
    upnp_client: Arc<UPnPClient>,

    /// NAT-PMP client
    natpmp_client: Arc<NatPMPClient>,

    /// PCP client
    pcp_client: Arc<PCPClient>,

    /// Renewal task handle
    renewal_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Statistics
    stats: Arc<PortForwardingStats>,
}

/// Port forwarding statistics
#[derive(Debug)]
struct PortForwardingStats {
    /// Successful mappings by protocol
    success_count: RwLock<HashMap<MappingProtocol, usize>>,

    /// Failed attempts by protocol
    failure_count: RwLock<HashMap<MappingProtocol, usize>>,

    /// Average mapping time by protocol
    avg_mapping_time: RwLock<HashMap<MappingProtocol, Duration>>,

    /// Last error by protocol
    last_error: RwLock<HashMap<MappingProtocol, String>>,
}

impl PortForwardingService {
    /// Create new port forwarding service
    pub async fn new() -> NatResult<Self> {
        let service = Self {
            mappings: Arc::new(AsyncRwLock::new(HashMap::new())),
            upnp_client: Arc::new(UPnPClient::new()),
            natpmp_client: Arc::new(NatPMPClient::new()),
            pcp_client: Arc::new(PCPClient::new()),
            renewal_task: Arc::new(Mutex::new(None)),
            stats: Arc::new(PortForwardingStats::new()),
        };

        // Start renewal task
        service.start_renewal_task().await;

        // Log available protocols
        tracing::info!("Port forwarding service initialized");

        Ok(service)
    }

    /// Create port mapping with intelligent fallback
    pub async fn create_mapping(
        &self,
        config: PortMappingConfig,
    ) -> NatResult<PortMapping> {
        let start_time = Instant::now();
        let mut last_error = None;

        // Calculate timeout for each protocol based on recommendations
        let protocol_timeouts = HashMap::from([
            (MappingProtocol::UPnPIGD, Duration::from_secs(5)),
            (MappingProtocol::NatPMP, Duration::from_secs(3)),
            (MappingProtocol::PCP, Duration::from_secs(5)),
        ]);

        // Try protocols in order of preference
        for protocol in &config.preferred_protocols {
            tracing::info!("Trying {} for port mapping", protocol_name(*protocol));

            let protocol_start = Instant::now();
            let timeout_duration = protocol_timeouts.get(protocol)
                .copied()
                .unwrap_or(Duration::from_secs(5));

            let result = match protocol {
                MappingProtocol::PCP => {
                    timeout(
                        timeout_duration,
                        self.pcp_client.create_mapping(&config)
                    ).await
                }
                MappingProtocol::UPnPIGD => {
                    timeout(
                        timeout_duration,
                        self.upnp_client.create_mapping(&config)
                    ).await
                }
                MappingProtocol::NatPMP => {
                    timeout(
                        timeout_duration,
                        self.natpmp_client.create_mapping(&config)
                    ).await
                }
            };

            match result {
                Ok(Ok(mapping)) => {
                    let elapsed = protocol_start.elapsed();
                    tracing::info!(
                        "{} mapping created successfully in {:?}: {} -> {}",
                        protocol_name(*protocol),
                        elapsed,
                        mapping.external_addr,
                        mapping.internal_addr
                    );

                    self.store_mapping(mapping.clone()).await;
                    self.stats.record_success(*protocol, elapsed);

                    return Ok(mapping);
                }
                Ok(Err(e)) => {
                    tracing::warn!("{} failed: {}", protocol_name(*protocol), e);
                    self.stats.record_failure(*protocol, e.to_string());
                    last_error = Some(e);
                }
                Err(_) => {
                    let error_msg = format!("{} timed out after {:?}",
                                            protocol_name(*protocol), timeout_duration);
                    tracing::warn!("{}", error_msg);
                    self.stats.record_failure(*protocol, error_msg);
                    last_error = Some(NatError::Timeout(timeout_duration));
                }
            }

            // Small delay before trying next protocol
            if protocol != config.preferred_protocols.last().unwrap() {
                sleep(Duration::from_millis(100)).await;
            }
        }

        // All protocols failed
        let total_time = start_time.elapsed();
        tracing::error!(
            "All port forwarding protocols failed after {:?}",
            total_time
        );

        Err(last_error.unwrap_or_else(||
            NatError::NotSupported("No port forwarding protocol available".to_string())
        ))
    }

    /// Delete port mapping
    pub async fn delete_mapping(&self, id: uuid::Uuid) -> NatResult<()> {
        let mapping = {
            let mut mappings = self.mappings.write().await;
            mappings.remove(&id)
        };

        if let Some(mapping) = mapping {
            tracing::info!(
                "Deleting {} mapping: {}",
                protocol_name(mapping.protocol),
                mapping.external_addr
            );

            match mapping.protocol {
                MappingProtocol::PCP => {
                    self.pcp_client.delete_mapping(&mapping).await?;
                }
                MappingProtocol::UPnPIGD => {
                    self.upnp_client.delete_mapping(&mapping).await?;
                }
                MappingProtocol::NatPMP => {
                    self.natpmp_client.delete_mapping(&mapping).await?;
                }
            }
        }

        Ok(())
    }

    /// Get all active mappings
    pub async fn get_mappings(&self) -> Vec<PortMapping> {
        self.mappings.read().await.values().cloned().collect()
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> String {
        self.stats.format_stats().await
    }

    /// Store mapping
    async fn store_mapping(&self, mapping: PortMapping) {
        self.mappings.write().await.insert(mapping.id, mapping);
    }

    /// Start automatic renewal task
    async fn start_renewal_task(&self) {
        let mappings = self.mappings.clone();
        let upnp = self.upnp_client.clone();
        let natpmp = self.natpmp_client.clone();
        let pcp = self.pcp_client.clone();

        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let mappings_to_renew: Vec<_> = {
                    let mappings = mappings.read().await;
                    mappings.values()
                        .filter(|m| {
                            // Renew when 2/3 of lifetime has passed
                            let elapsed = m.created_at.elapsed();
                            elapsed >= m.lifetime * 2 / 3
                        })
                        .cloned()
                        .collect()
                };

                for mapping in mappings_to_renew {
                    tracing::debug!(
                        "Renewing {} mapping {}",
                        protocol_name(mapping.protocol),
                        mapping.id
                    );

                    let result = match mapping.protocol {
                        MappingProtocol::PCP => pcp.renew_mapping(&mapping).await,
                        MappingProtocol::UPnPIGD => upnp.renew_mapping(&mapping).await,
                        MappingProtocol::NatPMP => natpmp.renew_mapping(&mapping).await,
                    };

                    if let Err(e) = result {
                        tracing::warn!(
                            "Failed to renew {} mapping {}: {}",
                            protocol_name(mapping.protocol),
                            mapping.id,
                            e
                        );

                        // Remove failed mapping
                        mappings.write().await.remove(&mapping.id);
                    } else {
                        // Update renewed timestamp
                        if let Some(m) = mappings.write().await.get_mut(&mapping.id) {
                            m.created_at = Instant::now();
                        }
                    }
                }
            }
        });

        *self.renewal_task.lock().await = Some(task);
    }
}

/// UPnP-IGD client implementation
struct UPnPClient {
    /// Discovered devices
    devices: Arc<AsyncRwLock<Vec<UPnPDevice>>>,

    /// Discovery state
    discovery_done: Arc<AsyncRwLock<bool>>,
}

#[derive(Debug, Clone)]
struct UPnPDevice {
    /// Device location URL
    location: String,

    /// Control URL
    control_url: String,

    /// Service type
    service_type: String,

    /// External IP address
    external_ip: IpAddr,
}

impl UPnPClient {
    fn new() -> Self {
        Self {
            devices: Arc::new(AsyncRwLock::new(Vec::new())),
            discovery_done: Arc::new(AsyncRwLock::new(false)),
        }
    }

    /// Discover UPnP devices
    async fn discover(&self) -> NatResult<()> {
        // Check if already discovered
        if *self.discovery_done.read().await {
            return Ok(());
        }

        const SSDP_MULTICAST: &str = "239.255.255.250:1900";
        const SSDP_SEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
                                   HOST: 239.255.255.250:1900\r\n\
                                   ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                                   MAN: \"ssdp:discover\"\r\n\
                                   MX: 3\r\n\r\n";

        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Enable multicast
        if let Ok(addr) = socket.local_addr() {
            if let IpAddr::V4(ip) = addr.ip() {
                socket.join_multicast_v4(
                    Ipv4Addr::new(239, 255, 255, 250),
                    ip
                ).ok();
            }
        }

        socket.send_to(SSDP_SEARCH.as_bytes(), SSDP_MULTICAST).await?;

        let mut buf = vec![0u8; 1500];
        let timeout_duration = Duration::from_secs(3);
        let start_time = Instant::now();

        while start_time.elapsed() < timeout_duration {
            match timeout(
                Duration::from_millis(500),
                socket.recv_from(&mut buf)
            ).await {
                Ok(Ok((size, _addr))) => {
                    let response = String::from_utf8_lossy(&buf[..size]);

                    // Parse SSDP response
                    if let Some(location) = Self::parse_ssdp_location(&response) {
                        match self.fetch_device_info(&location).await {
                            Ok(device) => {
                                tracing::info!("Found UPnP device at {}", location);
                                self.devices.write().await.push(device);
                            }
                            Err(e) => {
                                tracing::debug!("Failed to fetch device info from {}: {}", location, e);
                            }
                        }
                    }
                }
                _ => continue,
            }
        }

        *self.discovery_done.write().await = true;

        let device_count = self.devices.read().await.len();
        if device_count == 0 {
            return Err(NatError::NotSupported("No UPnP devices found".to_string()));
        }

        tracing::info!("UPnP discovery complete: {} device(s) found", device_count);
        Ok(())
    }

    /// Parse SSDP location header
    fn parse_ssdp_location(response: &str) -> Option<String> {
        response.lines()
            .find(|line| line.to_lowercase().starts_with("location:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| s.trim().to_string())
    }

    /// Fetch device information
    async fn fetch_device_info(&self, location: &str) -> NatResult<UPnPDevice> {
        // Fetch device description XML
        let response = reqwest::get(location).await
            .map_err(|e| NatError::Platform(format!("Failed to fetch UPnP device: {}", e)))?;

        let xml = response.text().await
            .map_err(|e| NatError::Platform(format!("Failed to read UPnP response: {}", e)))?;

        // Parse XML
        let root = Element::parse(xml.as_bytes())
            .map_err(|e| NatError::Platform(format!("Failed to parse UPnP XML: {}", e)))?;

        // Extract control URL and service type
        let (control_url, service_type) = Self::extract_wan_service(&root)
            .ok_or_else(|| NatError::Platform("No WAN service found".to_string()))?;

        // Get external IP
        let external_ip = self.get_external_ip(location, &control_url, &service_type).await?;

        Ok(UPnPDevice {
            location: location.to_string(),
            control_url,
            service_type,
            external_ip,
        })
    }

    /// Extract WAN service from device XML
    fn extract_wan_service(root: &Element) -> Option<(String, String)> {
        // Navigate through the XML structure to find WAN IP/PPP Connection service
        let device = root.get_child("device")?;

        // Check device services
        if let Some(service_info) = Self::find_wan_service_in_device(device) {
            return Some(service_info);
        }

        // Check embedded devices
        if let Some(device_list) = device.get_child("deviceList") {
            for child in &device_list.children {
                if let XMLNode::Element(embedded_device) = child {
                    if embedded_device.name == "device" {
                        if let Some(service_info) = Self::find_wan_service_in_device(embedded_device) {
                            return Some(service_info);
                        }
                    }
                }
            }
        }

        None
    }

    /// Find WAN service in a device element
    fn find_wan_service_in_device(device: &Element) -> Option<(String, String)> {
        let service_list = device.get_child("serviceList")?;

        for child in &service_list.children {
            if let XMLNode::Element(service) = child {
                if let Some(service_type) = service.get_child("serviceType") {
                    let st = service_type.get_text()?;
                    if st.contains("WANIPConnection") || st.contains("WANPPPConnection") {
                        let control_url = service.get_child("controlURL")?.get_text()?;
                        return Some((control_url.to_string(), st.to_string()));
                    }
                }
            }
        }

        None
    }

    /// Get external IP address
    async fn get_external_ip(
        &self,
        base_url: &str,
        control_url: &str,
        service_type: &str,
    ) -> NatResult<IpAddr> {
        let soap_action = format!("\"{}#GetExternalIPAddress\"", service_type);
        let soap_body = format!(
            r#"<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                        s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:GetExternalIPAddress xmlns:u="{}"/>
                </s:Body>
            </s:Envelope>"#,
            service_type
        );

        let full_url = if control_url.starts_with("http") {
            control_url.to_string()
        } else {
            format!("{}{}", base_url, control_url)
        };

        let client = reqwest::Client::new();
        let response = client.post(&full_url)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", soap_action)
            .body(soap_body)
            .send()
            .await
            .map_err(|e| NatError::Platform(format!("SOAP request failed: {}", e)))?;

        let body = response.text().await
            .map_err(|e| NatError::Platform(format!("Failed to read SOAP response: {}", e)))?;

        // Parse external IP from response
        let root = Element::parse(body.as_bytes())
            .map_err(|e| NatError::Platform(format!("Failed to parse SOAP response: {}", e)))?;

        // Extract IP address - navigate through SOAP structure
        let ip_str = root.get_child("Body")
            .and_then(|b| {
                // Find the response element (might have namespace prefix)
                b.children.iter().find_map(|child| {
                    if let XMLNode::Element(elem) = child {
                        if elem.name.ends_with("GetExternalIPAddressResponse") {
                            return Some(elem);
                        }
                    }
                    None
                })
            })
            .and_then(|r| r.get_child("NewExternalIPAddress"))
            .and_then(|ip| ip.get_text())
            .ok_or_else(|| NatError::Platform("No external IP in response".to_string()))?;

        ip_str.parse()
            .map_err(|e| NatError::Platform(format!("Invalid IP address: {}", e)))
    }

    /// Create port mapping
    async fn create_mapping(&self, config: &PortMappingConfig) -> NatResult<PortMapping> {
        // Ensure we have discovered devices
        self.discover().await?;

        let devices = self.devices.read().await;
        let device = devices.first()
            .ok_or_else(|| NatError::NotSupported("No UPnP devices found".to_string()))?;

        // Get internal IP
        let internal_ip = get_local_ip()?;

        // Determine external port
        let external_port = if config.external_port == 0 {
            // Try to use same as internal port first
            config.internal_port
        } else {
            config.external_port
        };

        let protocols = match config.protocol {
            Protocol::TCP => vec!["TCP"],
            Protocol::UDP => vec!["UDP"],
            Protocol::Both => vec!["TCP", "UDP"],
        };

        let mut successful_port = None;

        for protocol in protocols {
            match self.add_port_mapping(
                device,
                external_port,
                config.internal_port,
                &internal_ip,
                protocol,
                config.lifetime,
                &config.description,
            ).await {
                Ok(port) => {
                    successful_port = Some(port);
                }
                Err(e) => {
                    // Try alternative ports on conflict
                    if e.to_string().contains("ConflictInMappingEntry") || e.to_string().contains("718") {
                        for offset in 1..10 {
                            let alt_port = external_port + offset;
                            if let Ok(port) = self.add_port_mapping(
                                device,
                                alt_port,
                                config.internal_port,
                                &internal_ip,
                                protocol,
                                config.lifetime,
                                &config.description,
                            ).await {
                                successful_port = Some(port);
                                break;
                            }
                        }
                    }

                    if successful_port.is_none() {
                        return Err(e);
                    }
                }
            }
        }

        let final_external_port = successful_port
            .ok_or_else(|| NatError::Platform("Failed to create any port mapping".to_string()))?;

        Ok(PortMapping {
            id: uuid::Uuid::new_v4(),
            protocol: MappingProtocol::UPnPIGD,
            external_addr: SocketAddr::new(device.external_ip, final_external_port),
            internal_addr: SocketAddr::new(internal_ip, config.internal_port),
            transport: config.protocol,
            lifetime: Duration::from_secs(config.lifetime as u64),
            created_at: Instant::now(),
            gateway: device.external_ip,
            nonce: None,
            epoch: None,
        })
    }

    /// Add port mapping via SOAP
    async fn add_port_mapping(
        &self,
        device: &UPnPDevice,
        external_port: u16,
        internal_port: u16,
        internal_ip: &IpAddr,
        protocol: &str,
        lifetime: u32,
        description: &str,
    ) -> NatResult<u16> {
        let soap_action = format!("\"{}#AddPortMapping\"", device.service_type);
        let soap_body = format!(
            r#"<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                        s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:AddPortMapping xmlns:u="{}">
                        <NewRemoteHost></NewRemoteHost>
                        <NewExternalPort>{}</NewExternalPort>
                        <NewProtocol>{}</NewProtocol>
                        <NewInternalPort>{}</NewInternalPort>
                        <NewInternalClient>{}</NewInternalClient>
                        <NewEnabled>1</NewEnabled>
                        <NewPortMappingDescription>{}</NewPortMappingDescription>
                        <NewLeaseDuration>{}</NewLeaseDuration>
                    </u:AddPortMapping>
                </s:Body>
            </s:Envelope>"#,
            device.service_type,
            external_port,
            protocol,
            internal_port,
            internal_ip,
            description,
            lifetime
        );

        let full_url = if device.control_url.starts_with("http") {
            device.control_url.clone()
        } else {
            // Build full URL from location
            if let Ok(url) = url::Url::parse(&device.location) {
                format!("{}://{}{}",
                        url.scheme(),
                        url.host_str().unwrap_or(""),
                        device.control_url
                )
            } else {
                format!("{}{}", device.location, device.control_url)
            }
        };

        let client = reqwest::Client::new();
        let response = client.post(&full_url)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", soap_action)
            .body(soap_body)
            .send()
            .await
            .map_err(|e| NatError::Platform(format!("Failed to add port mapping: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();

            // Parse SOAP error
            if let Ok(root) = Element::parse(error_body.as_bytes()) {
                if let Some(fault) = root.get_child("Body")
                    .and_then(|b| b.get_child("Fault")) {

                    let error_code = fault.get_child("detail")
                        .and_then(|d| d.get_child("UPnPError"))
                        .and_then(|e| e.get_child("errorCode"))
                        .and_then(|c| c.get_text())
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|| "Unknown".to_string());

                    let error_desc = fault.get_child("detail")
                        .and_then(|d| d.get_child("UPnPError"))
                        .and_then(|e| e.get_child("errorDescription"))
                        .and_then(|d| d.get_text())
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|| "Unknow error".to_string())    ;

                    return Err(NatError::Platform(
                        format!("UPnP error {}: {}", error_code, error_desc)
                    ));
                }
            }

            return Err(NatError::Platform(
                format!("UPnP AddPortMapping failed with status {}", status)
            ));
        }

        Ok(external_port)
    }

    /// Delete port mapping
    async fn delete_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        let devices = self.devices.read().await;
        let device = devices.first()
            .ok_or_else(|| NatError::NotSupported("No UPnP devices found".to_string()))?;

        let protocols = match mapping.transport {
            Protocol::TCP => vec!["TCP"],
            Protocol::UDP => vec!["UDP"],
            Protocol::Both => vec!["TCP", "UDP"],
        };

        for protocol in protocols {
            self.delete_port_mapping(
                device,
                mapping.external_addr.port(),
                protocol,
            ).await?;
        }

        Ok(())
    }

    /// Delete port mapping via SOAP
    async fn delete_port_mapping(
        &self,
        device: &UPnPDevice,
        external_port: u16,
        protocol: &str,
    ) -> NatResult<()> {
        let soap_action = format!("\"{}#DeletePortMapping\"", device.service_type);
        let soap_body = format!(
            r#"<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                        s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:DeletePortMapping xmlns:u="{}">
                        <NewRemoteHost></NewRemoteHost>
                        <NewExternalPort>{}</NewExternalPort>
                        <NewProtocol>{}</NewProtocol>
                    </u:DeletePortMapping>
                </s:Body>
            </s:Envelope>"#,
            device.service_type,
            external_port,
            protocol
        );

        let full_url = if device.control_url.starts_with("http") {
            device.control_url.clone()
        } else {
            format!("{}{}", device.location, device.control_url)
        };

        let client = reqwest::Client::new();
        let response = client.post(&full_url)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", soap_action)
            .body(soap_body)
            .send()
            .await
            .map_err(|e| NatError::Platform(format!("Failed to delete port mapping: {}", e)))?;

        if !response.status().is_success() {
            // Deletion failure is not critical
            tracing::debug!("UPnP DeletePortMapping returned status {}", response.status());
        }

        Ok(())
    }

    /// Renew port mapping
    async fn renew_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        // UPnP renewal is done by re-adding the mapping
        let config = PortMappingConfig {
            external_port: mapping.external_addr.port(),
            internal_port: mapping.internal_addr.port(),
            protocol: mapping.transport,
            lifetime: mapping.lifetime.as_secs() as u32,
            description: "SHARP P2P Connection (Renewed)".to_string(),
            auto_renew: true,
            preferred_protocols: vec![MappingProtocol::UPnPIGD],
        };

        self.create_mapping(&config).await?;
        Ok(())
    }
}

/// NAT-PMP client implementation (RFC 6886)
///
// /// The NAT gateway returns a `server epoch` value with every response.
// /// We store this epoch after each external address or port mapping
// /// request. When renewing an existing mapping we obtain a fresh epoch
// /// via `get_external_address()` and compare it to the epoch saved for
// /// the mapping. If the values differ the gateway has likely rebooted,
// /// so the client reinitializes itself and recreates the mapping.

struct NatPMPClient {
    /// Gateway address
    gateway: Arc<AsyncRwLock<Option<Ipv4Addr>>>,

    /// Server epoch
    server_epoch: Arc<AsyncRwLock<u32>>,

    /// Socket for NAT-PMP communication
    socket: Arc<AsyncRwLock<Option<Arc<UdpSocket>>>>,
}

impl NatPMPClient {
    fn new() -> Self {
        Self {
            gateway: Arc::new(AsyncRwLock::new(None)),
            server_epoch: Arc::new(AsyncRwLock::new(0)),
            socket: Arc::new(AsyncRwLock::new(None)),
        }
    }

    /// Initialize NAT-PMP client
    async fn initialize(&self) -> NatResult<()> {
        // Get default gateway
        let gateway = self.discover_gateway().await?;

        // Create socket for NAT-PMP
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        *self.socket.write().await = Some(Arc::new(socket));

        // Get initial external address to verify NAT-PMP is working
        let _ = self.get_external_address().await?;

        tracing::info!("NAT-PMP initialized with gateway {}", gateway);
        Ok(())
    }

    /// Discover NAT-PMP gateway
    async fn discover_gateway(&self) -> NatResult<Ipv4Addr> {
        // Check if already discovered
        if let Some(gw) = *self.gateway.read().await {
            return Ok(gw);
        }

        // Try to get default gateway
        let gateway = get_default_gateway()?
            .ok_or_else(|| NatError::NotSupported("No default gateway found".to_string()))?;

        match gateway {
            IpAddr::V4(v4) => {
                *self.gateway.write().await = Some(v4);
                Ok(v4)
            }
            IpAddr::V6(_) => Err(NatError::NotSupported("NAT-PMP requires IPv4".to_string())),
        }
    }

    /// Get external address
    async fn get_external_address(&self) -> NatResult<Ipv4Addr> {
        let gateway = match *self.gateway.read().await {
            Some(gw) => gw,
            None => self.discover_gateway().await?,
        };

        let socket = self.get_or_create_socket().await?;

        // Build request (opcode 0)
        let mut request = BytesMut::with_capacity(2);
        request.put_u8(0); // Version
        request.put_u8(0); // Opcode (external address)

        // NAT-PMP uses exponential backoff for retries
        let mut retry_delay = Duration::from_millis(2000);
        let max_retries = 5;

        for attempt in 0..max_retries {
            socket.send_to(&request, (gateway, 5351)).await?;

            // Wait for response with timeout
            let mut buf = vec![0u8; 12];
            match timeout(retry_delay, socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    if addr.ip() != IpAddr::V4(gateway) || addr.port() != 5351 {
                        continue; // Ignore responses from wrong address
                    }

                    if size < 12 {
                        return Err(NatPmpError::InvalidResponse("Response too short").into());
                    }

                    let mut response = &buf[..];
                    let version = response.get_u8();
                    let opcode = response.get_u8();
                    let result_code = response.get_u16();
                    let epoch = response.get_u32();

                    if version != 0 {
                        return Err(NatPmpError::InvalidResponse("Unsupported version").into());
                    }

                    if opcode != 128 { // 128 = response to opcode 0
                        return Err(NatPmpError::InvalidResponse("Invalid opcode").into());
                    }

                    if result_code != 0 {
                        return Err(NatPmpError::from_code(result_code).into());
                    }

                    *self.server_epoch.write().await = epoch;

                    let external_ip = Ipv4Addr::new(
                        response.get_u8(),
                        response.get_u8(),
                        response.get_u8(),
                        response.get_u8(),
                    );

                    tracing::debug!("NAT-PMP external IP: {}, epoch: {}", external_ip, epoch);
                    return Ok(external_ip);
                }
                Ok(Err(e)) => {
                    if attempt == max_retries - 1 {
                        return Err(e.into());
                    }
                }
                Err(_) => {
                    if attempt == max_retries - 1 {
                        return Err(NatError::Timeout(retry_delay));
                    }
                }
            }

            // Double the retry delay for next attempt
            retry_delay *= 2;
        }

        Err(NatPmpError::InvalidResponse("Request failed after retries").into())
    }

    /// Create port mapping
    async fn create_mapping(&self, config: &PortMappingConfig) -> NatResult<PortMapping> {
        // Initialize if needed
        if self.gateway.read().await.is_none() {
            self.initialize().await?;
        }

        let gateway = (*self.gateway.read().await)
            .ok_or_else(|| NatError::Platform("NAT-PMP not initialized".to_string()))?;

        let external_ip = self.get_external_address().await?;
        let internal_ip = get_local_ip()?;

        let protocols = match config.protocol {
            Protocol::TCP => vec![(1u8, "TCP")],
            Protocol::UDP => vec![(2u8, "UDP")],
            Protocol::Both => vec![(1u8, "TCP"), (2u8, "UDP")],
        };

        let mut successful_port = None;
        let mut successful_epoch = None;

        for (opcode, _protocol_name) in &protocols {
            let external_port = if config.external_port == 0 {
                config.internal_port
            } else {
                config.external_port
            };

            match self.map_port(
                gateway,
                *opcode,
                config.internal_port,
                external_port,
                config.lifetime,
            ).await {
                Ok((mapped_port, epoch)) => {
                    successful_port = Some(mapped_port);
                    successful_epoch = Some(epoch);
                }
                Err(e) => {
                    if protocols.len() == 1 {
                        return Err(e);
                    }
                    // Continue with next protocol if Both was requested
                }
            }
        }

        let final_port = successful_port
            .ok_or_else(|| NatPmpError::InvalidResponse("Failed to create mapping").into())?;

        Ok(PortMapping {
            id: uuid::Uuid::new_v4(),
            protocol: MappingProtocol::NatPMP,
            external_addr: SocketAddr::new(IpAddr::V4(external_ip), final_port),
            internal_addr: SocketAddr::new(internal_ip, config.internal_port),
            transport: config.protocol,
            lifetime: Duration::from_secs(config.lifetime as u64),
            created_at: Instant::now(),
            gateway: IpAddr::V4(gateway),
            nonce: None,
            epoch: successful_epoch,
        })
    }

    /// Map port using NAT-PMP
    async fn map_port(
        &self,
        gateway: Ipv4Addr,
        opcode: u8,
        internal_port: u16,
        external_port: u16,
        lifetime: u32,
    ) -> NatResult<(u16, u32)> {
        let socket = self.get_or_create_socket().await?;

        // Build mapping request
        let mut request = BytesMut::with_capacity(12);
        request.put_u8(0);                    // Version
        request.put_u8(opcode);               // Opcode (1=TCP, 2=UDP)
        request.put_u16(0);                   // Reserved
        request.put_u16(internal_port);       // Internal port
        request.put_u16(external_port);       // Requested external port
        request.put_u32(lifetime);            // Lifetime

        // NAT-PMP uses exponential backoff
        let mut retry_delay = Duration::from_millis(250);
        let max_retries = 3;

        for attempt in 0..max_retries {
            socket.send_to(&request, (gateway, 5351)).await?;

            // Wait for response
            let mut buf = vec![0u8; 16];
            match timeout(retry_delay, socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    if addr.ip() != IpAddr::V4(gateway) || addr.port() != 5351 {
                        continue;
                    }

                    if size < 16 {
                        return Err(NatPmpError::InvalidResponse("response too short").into());
                    }

                    let mut response = &buf[..];
                    let version = response.get_u8();
                    let resp_opcode = response.get_u8();
                    let result_code = response.get_u16();
                    let epoch = response.get_u32();
                    let resp_internal = response.get_u16();
                    let mapped_external = response.get_u16();
                    let mapped_lifetime = response.get_u32();

                    if version != 0 || resp_opcode != (opcode + 128) {
                        return Err(NatPmpError::InvalidResponse("invalid response").into());
                    }

                    if result_code != 0 {
                        return Err(NatPmpError::from_code(result_code).into());
                    }

                    // Verify internal port matches
                    if resp_internal != internal_port {
                        return Err(NatPmpError::InvalidResponse("internal port mismatch").into());
                    }

                    *self.server_epoch.write().await = epoch;

                    tracing::info!(
                        "NAT-PMP mapping created: {}:{} -> {} for {} seconds",
                        internal_port,
                        external_port,
                        mapped_external,
                        mapped_lifetime
                    );

                    return Ok((mapped_external, epoch));
                }
                Ok(Err(e)) => {
                    if attempt == max_retries - 1 {
                        return Err(e.into());
                    }
                }
                Err(_) => {
                    if attempt == max_retries - 1 {
                        return Err(NatError::Timeout(retry_delay));
                    }
                }
            }

            retry_delay *= 2;
        }

        Err(NatPmpError::InvalidResponse("Mapping request failed after retries").into())
    }

    /// Delete port mapping
    async fn delete_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        if let IpAddr::V4(gateway) = mapping.gateway {
            let protocols = match mapping.transport {
                Protocol::TCP => vec![1u8],
                Protocol::UDP => vec![2u8],
                Protocol::Both => vec![1u8, 2u8],
            };

            for opcode in protocols {
                // Delete by setting lifetime to 0
                let _ = self.map_port(
                    gateway,
                    opcode,
                    mapping.internal_addr.port(),
                    mapping.external_addr.port(),
                    0, // lifetime = 0 means delete
                ).await;
            }
        }

        Ok(())
    }

    /// Renew port mapping
    async fn renew_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        if let IpAddr::V4(gateway) = mapping.gateway {
            // Check if the gateway has restarted by comparing epochs
            if let Some(saved_epoch) = mapping.epoch {
                let _ = self.get_external_address().await?;
                let current_epoch = *self.server_epoch.read().await;

                if current_epoch != saved_epoch {
                    tracing::debug!(
                        "NAT-PMP server epoch changed from {} to {}, reinitializing",
                        saved_epoch,
                        current_epoch
                    );

                    // Reinitialize and recreate the mapping
                    self.initialize().await?;

                    let protocols = match mapping.transport {
                        Protocol::TCP => vec![1u8],
                        Protocol::UDP => vec![2u8],
                        Protocol::Both => vec![1u8, 2u8],
                    };

                    for opcode in protocols {
                        self.map_port(
                            gateway,
                            opcode,
                            mapping.internal_addr.port(),
                            mapping.external_addr.port(),
                            mapping.lifetime.as_secs() as u32,
                        ).await?;
                    }

                    return Ok(());
                }
            }

            let protocols = match mapping.transport {
                Protocol::TCP => vec![1u8],
                Protocol::UDP => vec![2u8],
                Protocol::Both => vec![1u8, 2u8],
            };

            for opcode in protocols {
                self.map_port(
                    gateway,
                    opcode,
                    mapping.internal_addr.port(),
                    mapping.external_addr.port(),
                    mapping.lifetime.as_secs() as u32,
                ).await?;
            }
        }

        Ok(())
    }

    /// Get or create socket
    async fn get_or_create_socket(&self) -> NatResult<Arc<UdpSocket>> {
        if let Some(socket) = &*self.socket.read().await {
            return Ok(socket.clone());
        }

        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        *self.socket.write().await = Some(socket.clone());
        Ok(socket)
    }

    /// Convert NAT-PMP error code to string
    fn error_code_to_string(code: u16) -> &'static str {
        match code {
            1 => "Unsupported Version",
            2 => "Not Authorized/Refused",
            3 => "Network Failure",
            4 => "Out of Resources",
            5 => "Unsupported Opcode",
            _ => "Unknown Error",
        }
    }
}

/// PCP client implementation (RFC 6887)
struct PCPClient {
    /// PCP server address
    server: Arc<AsyncRwLock<Option<SocketAddr>>>,

    /// Client epoch
    client_epoch: Arc<AsyncRwLock<u32>>,

    /// Socket for PCP communication
    socket: Arc<AsyncRwLock<Option<Arc<UdpSocket>>>>,
}

impl PCPClient {
    fn new() -> Self {
        Self {
            server: Arc::new(AsyncRwLock::new(None)),
            client_epoch: Arc::new(AsyncRwLock::new(0)),
            socket: Arc::new(AsyncRwLock::new(None)),
        }
    }

    /// Initialize PCP client
    async fn initialize(&self) -> NatResult<()> {
        // Discover PCP server
        let server = self.discover_server().await?;

        // Create socket for PCP
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        *self.socket.write().await = Some(Arc::new(socket));

        // Generate initial client epoch
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        *self.client_epoch.write().await = epoch;

        tracing::info!("PCP initialized with server {}", server);
        Ok(())
    }

    /// Discover PCP server
    async fn discover_server(&self) -> NatResult<SocketAddr> {
        // Check if already discovered
        if let Some(s) = *self.server.read().await {
            return Ok(s);
        }

        // Try default gateway on PCP port (5351)
        let gateway = get_default_gateway()?
            .ok_or_else(|| NatError::NotSupported("No default gateway found".to_string()))?;

        let server = SocketAddr::new(gateway, 5351);

        // Verify server responds to ANNOUNCE
        if self.verify_server(&server).await.is_ok() {
            *self.server.write().await = Some(server);
            return Ok(server);
        }

        // Try multicast discovery
        if let Ok(discovered) = self.multicast_discovery().await {
            *self.server.write().await = Some(discovered);
            return Ok(discovered);
        }

        Err(NatError::NotSupported("No PCP server found".to_string()))
    }

    /// Verify PCP server with ANNOUNCE
    async fn verify_server(&self, server: &SocketAddr) -> NatResult<()> {
        let socket = self.get_or_create_socket().await?;

        // Create ANNOUNCE request
        let request = self.create_announce_request()?;

        socket.send_to(&request, server).await?;

        let mut buf = vec![0u8; 1100];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((size, addr))) if addr.ip() == server.ip() => {
                if size >= 24 && buf[0] == 2 && buf[1] == 129 { // Version 2, ANNOUNCE response
                    return Ok(());
                }
            }
            _ => {}
        }

        Err(NatError::Platform("PCP server verification failed".to_string()))
    }

    /// Multicast discovery for PCP servers
    async fn multicast_discovery(&self) -> NatResult<SocketAddr> {
        // PCP uses the same multicast address as mDNS but different port
        const PCP_MULTICAST_V4: &str = "224.0.0.1:5350";
        const PCP_MULTICAST_V6: &str = "[ff02::1]:5350";

        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Try IPv4 multicast
        if let Ok(addr) = socket.local_addr() {
            if let IpAddr::V4(ip) = addr.ip() {
                socket.join_multicast_v4(
                    Ipv4Addr::new(224, 0, 0, 1),
                    ip
                ).ok();
            }
        }

        // Send ANNOUNCE to multicast
        let request = self.create_announce_request()?;
        let _ = socket.send_to(&request, PCP_MULTICAST_V4).await;

        // Wait for responses
        let mut buf = vec![0u8; 1100];
        match timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Ok(Ok((size, addr))) => {
                if size >= 24 && buf[0] == 2 && buf[1] == 129 {
                    return Ok(SocketAddr::new(addr.ip(), 5351));
                }
            }
            _ => {}
        }

        Err(NatError::Platform("No PCP server found via multicast".to_string()))
    }

    /// Create ANNOUNCE request
    fn create_announce_request(&self) -> NatResult<Vec<u8>> {
        let mut request = BytesMut::with_capacity(24);

        // Common header
        request.put_u8(2);          // Version
        request.put_u8(0);          // Opcode (ANNOUNCE)
        request.put_u16(0);         // Reserved
        request.put_u32(0);         // Requested lifetime (0 for ANNOUNCE)

        // Client IP address (all zeros for ANNOUNCE)
        request.put_slice(&[0u8; 16]);

        Ok(request.to_vec())
    }

    /// Create port mapping
    async fn create_mapping(&self, config: &PortMappingConfig) -> NatResult<PortMapping> {
        // Initialize if needed
        if self.server.read().await.is_none() {
            self.initialize().await?;
        }

        let server = (*self.server.read().await)
            .ok_or_else(|| NatError::Platform("PCP not initialized".to_string()))?;

        let internal_ip = get_local_ip()?;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let protocols = match config.protocol {
            Protocol::TCP => vec![6u8],
            Protocol::UDP => vec![17u8],
            Protocol::Both => vec![6u8, 17u8],
        };

        let external_port = if config.external_port == 0 {
            config.internal_port
        } else {
            config.external_port
        };

        let mut external_ip = None;
        let mut successful_port = None;
        let mut successful_epoch = None;

        for protocol in protocols {
            match self.map_port(
                server,
                internal_ip,
                config.internal_port,
                external_port,
                protocol,
                config.lifetime,
                &nonce,
            ).await {
                Ok((ext_ip, mapped_port, epoch)) => {
                    if external_ip.is_none() {
                        external_ip = Some(ext_ip);
                    }
                    successful_port = Some(mapped_port);
                    successful_epoch = Some(epoch);
                }
                Err(e) => {
                    if config.protocol != Protocol::Both {
                        return Err(e);
                    }
                    // Continue with next protocol if Both was requested
                }
            }
        }

        let external_ip = external_ip
            .ok_or_else(|| PcpError::InvalidResponse("Missing external ip").into())?;
        let final_port = successful_port
            .ok_or_else(|| PcpError::InvalidResponse("Failed to create mapping").into())?;

        Ok(PortMapping {
            id: uuid::Uuid::new_v4(),
            protocol: MappingProtocol::PCP,
            external_addr: SocketAddr::new(external_ip, final_port),
            internal_addr: SocketAddr::new(internal_ip, config.internal_port),
            transport: config.protocol,
            lifetime: Duration::from_secs(config.lifetime as u64),
            created_at: Instant::now(),
            gateway: server.ip(),
            nonce: Some(nonce),
            epoch: successful_epoch,
        })
    }

    /// Create MAP request
    async fn map_port(
        &self,
        server: SocketAddr,
        internal_ip: IpAddr,
        internal_port: u16,
        external_port: u16,
        protocol: u8,
        lifetime: u32,
        nonce: &[u8; 12],
    ) -> NatResult<(IpAddr, u16, u32)> {
        let socket = self.get_or_create_socket().await?;

        // Build PCP MAP request
        let mut request = BytesMut::with_capacity(60);

        // Common header
        request.put_u8(2);          // Version
        request.put_u8(1);          // Opcode (MAP)
        request.put_u16(0);         // Reserved
        request.put_u32(lifetime);  // Requested lifetime

        // Client IP address (128 bits)
        match internal_ip {
            IpAddr::V4(v4) => {
                // IPv4-mapped IPv6
                request.put_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
                request.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                request.put_slice(&v6.octets());
            }
        }

        // MAP-specific data
        request.put_slice(nonce);               // Mapping nonce
        request.put_u8(protocol);               // Protocol
        request.put_u8(0);                      // Reserved
        request.put_u16(0);                     // Reserved
        request.put_u16(internal_port);         // Internal port
        request.put_u16(external_port);         // Suggested external port

        // Suggested external IP (128 bits) - all zeros for "no preference"
        request.put_slice(&[0u8; 16]);

        // PCP uses initial RTO of 3 seconds with binary exponential backoff
        let mut retry_delay = Duration::from_secs(5);
        let max_retries = 6;

        for attempt in 0..max_retries {
            socket.send_to(&request, server).await?;

            // Wait for response
            let mut buf = vec![0u8; 1100];
            match timeout(retry_delay, socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    if addr != server {
                        continue;
                    }

                    if size < 60 {
                        return Err(NatError::Platform("Invalid PCP response size".to_string()));
                    }

                    let mut response = &buf[..size];

                    // Parse response header
                    let version = response.get_u8();
                    let opcode = response.get_u8();
                    let _reserved = response.get_u8();
                    let result_code = response.get_u8();
                    let granted_lifetime = response.get_u32();
                    let epoch = response.get_u32();
                    response.advance(12); // Reserved

                    if version != 2 {
                        return Err(PcpError::InvalidResponse("Unsupported version").into());
                    }

                    if opcode != 129 {  // 129 = MAP response
                        return Err(PcpError::InvalidResponse("Invalid opcode").into());
                    }

                    if result_code != 0 {
                        return Err(PcpError::from_code(result_code).into())
                    }

                    // Parse MAP response
                    let resp_nonce = response.copy_to_bytes(12);
                    if resp_nonce.as_ref() != nonce {
                        return Err(PcpError::InvalidResponse("Nonce mismatch").into());
                    }

                    let _protocol = response.get_u8();
                    response.advance(3);  // Reserved
                    let _internal_port = response.get_u16();
                    let assigned_external_port = response.get_u16();

                    // Parse assigned external IP
                    let mut ip_bytes = [0u8; 16];
                    response.copy_to_slice(&mut ip_bytes);

                    let external_ip = if ip_bytes[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] {
                        // IPv4-mapped IPv6
                        IpAddr::V4(Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]))
                    } else {
                        IpAddr::V6(Ipv6Addr::from(ip_bytes))
                    };

                    tracing::info!(
                        "PCP mapping created: {}:{} -> {}:{} for {} seconds",
                        internal_ip,
                        internal_port,
                        external_ip,
                        assigned_external_port,
                        granted_lifetime
                    );

                    return Ok((external_ip, assigned_external_port, epoch));
                }
                Ok(Err(e)) => {
                    if attempt == max_retries - 1 {
                        return Err(e.into());
                    }
                }
                Err(_) => {
                    if attempt == max_retries - 1 {
                        return Err(NatError::Timeout(retry_delay));
                    }
                }
            }

            // Double the retry delay, capped at 1024 seconds
            retry_delay = (retry_delay * 2).min(Duration::from_secs(1024));
        }
        Err(PcpError::InvalidResponse("mapping request failed after retries").into())
    }

    /// Delete port mapping
    async fn delete_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        if let Some(nonce) = &mapping.nonce {
            let server = (*self.server.read().await)
                .ok_or_else(|| NatError::Platform("PCP not initialized".to_string()))?;

            let protocols = match mapping.transport {
                Protocol::TCP => vec![6u8],
                Protocol::UDP => vec![17u8],
                Protocol::Both => vec![6u8, 17u8],
            };

            for protocol in protocols {
                // Delete by setting lifetime to 0
                let _ = self.map_port(
                    server,
                    mapping.internal_addr.ip(),
                    mapping.internal_addr.port(),
                    mapping.external_addr.port(),
                    protocol,
                    0, // lifetime = 0 means delete
                    nonce,
                ).await;
            }
        }

        Ok(())
    }

    /// Renew port mapping
    async fn renew_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        if let Some(nonce) = &mapping.nonce {
            let server = SocketAddr::new(mapping.gateway, 5351);

            let protocols = match mapping.transport {
                Protocol::TCP => vec![6u8],
                Protocol::UDP => vec![17u8],
                Protocol::Both => vec![6u8, 17u8],
            };

            for protocol in protocols {
                self.map_port(
                    server,
                    mapping.internal_addr.ip(),
                    mapping.internal_addr.port(),
                    mapping.external_addr.port(),
                    protocol,
                    mapping.lifetime.as_secs() as u32,
                    nonce,
                ).await?;
            }
        }

        Ok(())
    }

    /// Get or create socket
    async fn get_or_create_socket(&self) -> NatResult<Arc<UdpSocket>> {
        if let Some(socket) = &*self.socket.read().await {
            return Ok(socket.clone());
        }

        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        *self.socket.write().await = Some(socket.clone());
        Ok(socket)
    }

    /// Convert PCP result code to string
    fn result_code_to_string(code: u8) -> &'static str {
        match code {
            1 => "Unsupported Version",
            2 => "Not Authorized",
            3 => "Malformed Request",
            4 => "Unsupported Opcode",
            5 => "Unsupported Option",
            6 => "Malformed Option",
            7 => "Network Failure",
            8 => "No Resources",
            9 => "Unsupported Protocol",
            10 => "User Ex Quota",
            11 => "Cannot Provide External",
            12 => "Address Mismatch",
            13 => "Excessive Remote Peers",
            _ => "Unknown Error",
        }
    }
}

/// Get local IP address
fn get_local_ip() -> NatResult<IpAddr> {
    use local_ip_address::local_ip;

    local_ip()
        .map_err(|e| NatError::Platform(format!("Failed to get local IP: {}", e)))
}

/// Get default gateway
fn get_default_gateway() -> NatResult<Option<IpAddr>> {
    // Platform-specific implementation
    #[cfg(target_os = "windows")]
    {
        use winapi::um::iphlpapi::GetAdaptersInfo;
        use winapi::um::iptypes::IP_ADAPTER_INFO;
        use std::mem;
        use std::ptr;

        unsafe {
            let mut size: u32 = 0;
            GetAdaptersInfo(ptr::null_mut(), &mut size);

            if size == 0 {
                return Ok(None);
            }

            let mut buffer = vec![0u8; size as usize];
            let adapter_info = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

            if GetAdaptersInfo(adapter_info, &mut size) == 0 {
                let adapter = &*adapter_info;

                let gateway_str = std::ffi::CStr::from_ptr(
                    adapter.GatewayList.IpAddress.String.as_ptr()
                ).to_string_lossy();

                if let Ok(ip) = gateway_str.parse::<IpAddr>() {
                    if !ip.is_unspecified() {
                        return Ok(Some(ip));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Parse /proc/net/route
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        if let Ok(file) = File::open("/proc/net/route") {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1) {
                if let Ok(line) = line {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        // Check if this is the default route (destination 00000000)
                        if parts[1] == "00000000" {
                            // Gateway is in hex, little-endian
                            if let Ok(gateway_hex) = u32::from_str_radix(parts[2], 16) {
                                let gateway = Ipv4Addr::new(
                                    (gateway_hex & 0xFF) as u8,
                                    ((gateway_hex >> 8) & 0xFF) as u8,
                                    ((gateway_hex >> 16) & 0xFF) as u8,
                                    ((gateway_hex >> 24) & 0xFF) as u8,
                                );
                                if !gateway.is_unspecified() {
                                    return Ok(Some(IpAddr::V4(gateway)));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Use netstat -nr to get routing table
        use std::process::Command;

        if let Ok(output) = Command::new("netstat")
            .args(&["-nr", "-f", "inet"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("default") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(ip) = parts[1].parse::<IpAddr>() {
                            return Ok(Some(ip));
                        }
                    }
                }
            }
        }
    }

    // Fallback: try common gateway addresses
    let common_gateways = [
        "192.168.1.1",
        "192.168.0.1",
        "192.168.2.1",
        "10.0.0.1",
        "172.16.0.1",
    ];

    for gateway in &common_gateways {
        if let Ok(ip) = gateway.parse::<IpAddr>() {
            // Try to ping the gateway
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if socket.connect((ip, 80)).is_ok() {
                    return Ok(Some(ip));
                }
            }
        }
    }

    Ok(None)
}

/// Get protocol name for logging
fn protocol_name(protocol: MappingProtocol) -> &'static str {
    match protocol {
        MappingProtocol::UPnPIGD => "UPnP-IGD",
        MappingProtocol::NatPMP => "NAT-PMP",
        MappingProtocol::PCP => "PCP",
    }
}

impl PortForwardingStats {
    fn new() -> Self {
        Self {
            success_count: RwLock::new(HashMap::new()),
            failure_count: RwLock::new(HashMap::new()),
            avg_mapping_time: RwLock::new(HashMap::new()),
            last_error: RwLock::new(HashMap::new()),
        }
    }

    fn record_success(&self, protocol: MappingProtocol, duration: Duration) {
        {
            let mut success = self.success_count.write();
            *success.entry(protocol).or_insert(0) += 1;
        }

        {
            let mut times = self.avg_mapping_time.write();
            let entry = times.entry(protocol).or_insert(Duration::ZERO);
            let count = self.success_count.read().get(&protocol).copied().unwrap_or(1) as u32;
            if count > 0 {
                *entry = (*entry * (count - 1) + duration) / count;
            }
        }
    }

    fn record_failure(&self, protocol: MappingProtocol, error: String) {
        {
            let mut failures = self.failure_count.write();
            *failures.entry(protocol).or_insert(0) += 1;
        }

        {
            let mut errors = self.last_error.write();
            errors.insert(protocol, error);
        }
    }

    async fn format_stats(&self) -> String {
        let success = self.success_count.read();
        let failures = self.failure_count.read();
        let times = self.avg_mapping_time.read();
        let errors = self.last_error.read();

        let mut output = String::from("Port Forwarding Statistics:\n");

        for protocol in &[MappingProtocol::UPnPIGD, MappingProtocol::NatPMP, MappingProtocol::PCP] {
            let s = success.get(protocol).copied().unwrap_or(0);
            let f = failures.get(protocol).copied().unwrap_or(0);
            let total = s + f;

            if total > 0 {
                let success_rate = (s as f64 / total as f64) * 100.0;
                output.push_str(&format!(
                    "\n{}:\n  Success: {}/{} ({:.1}%)\n",
                    protocol_name(*protocol), s, total, success_rate
                ));

                if let Some(avg_time) = times.get(protocol) {
                    output.push_str(&format!("  Avg time: {:?}\n", avg_time));
                }

                if let Some(last_err) = errors.get(protocol) {
                    output.push_str(&format!("  Last error: {}\n", last_err));
                }
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_forwarding_service() {
        let service = PortForwardingService::new().await.unwrap();

        let config = PortMappingConfig {
            external_port: 0,
            internal_port: 12345,
            protocol: Protocol::UDP,
            lifetime: 3600,
            description: "Test mapping".to_string(),
            auto_renew: false,
            preferred_protocols: vec![MappingProtocol::PCP, MappingProtocol::NatPMP, MappingProtocol::UPnPIGD],
        };

        // This test requires a real NAT device
        match service.create_mapping(config).await {
            Ok(mapping) => {
                println!("Created mapping: {:?}", mapping);

                // Clean up
                service.delete_mapping(mapping.id).await.unwrap();
            }
            Err(e) => {
                eprintln!("Port forwarding test failed (expected without NAT): {}", e);
            }
        }

        // Print statistics
        println!("{}", service.get_statistics().await);
    }

    #[test]
    fn test_get_default_gateway() {
        match get_default_gateway() {
            Ok(Some(gateway)) => println!("Default gateway: {}", gateway),
            Ok(None) => println!("No default gateway found"),
            Err(e) => eprintln!("Error getting gateway: {}", e),
        }
    }
}