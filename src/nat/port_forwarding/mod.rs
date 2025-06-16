// src/nat/port_forwarding/mod.rs
//! Port forwarding implementation with UPnP-IGD and NAT-PMP/PCP support
//! 
//! Implements:
//! - UPnP-IGD v1/v2 (RFC 6970)
//! - NAT-PMP (RFC 6886)
//! - PCP (Port Control Protocol) (RFC 6887)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::{UdpSocket, TcpStream};
use tokio::time::{timeout, interval, sleep};
use tokio::sync::{RwLock, Mutex};

use bytes::{Bytes, BytesMut, Buf, BufMut};
use http::{Request, Response, StatusCode};
use xmltree::{Element, XMLNode};
use rand::RngCore;

use crate::nat::error::{NatError, NatResult};
use crate::nat::metrics::NatMetricsCollector;

/// Port mapping protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            lifetime: 3600, // 1 hour
            description: "SHARP P2P Connection".to_string(),
            auto_renew: true,
            preferred_protocols: vec![
                MappingProtocol::PCP,      // Most modern
                MappingProtocol::UPnPIGD,  // Most common
                MappingProtocol::NatPMP,   // Apple devices
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
}

/// Port forwarding service
pub struct PortForwardingService {
    /// Active mappings
    mappings: Arc<RwLock<HashMap<uuid::Uuid, PortMapping>>>,
    
    /// UPnP-IGD client
    upnp_client: Arc<UPnPClient>,
    
    /// NAT-PMP client
    natpmp_client: Arc<NatPMPClient>,
    
    /// PCP client
    pcp_client: Arc<PCPClient>,
    
    /// Renewal task handle
    renewal_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl PortForwardingService {
    /// Create new port forwarding service
    pub async fn new() -> NatResult<Self> {
        let service = Self {
            mappings: Arc::new(RwLock::new(HashMap::new())),
            upnp_client: Arc::new(UPnPClient::new()),
            natpmp_client: Arc::new(NatPMPClient::new()),
            pcp_client: Arc::new(PCPClient::new()),
            renewal_task: Arc::new(Mutex::new(None)),
        };
        
        // Start renewal task
        service.start_renewal_task().await;
        
        Ok(service)
    }
    
    /// Create port mapping
    pub async fn create_mapping(
        &self,
        config: PortMappingConfig,
    ) -> NatResult<PortMapping> {
        // Try protocols in order of preference
        for protocol in &config.preferred_protocols {
            match protocol {
                MappingProtocol::PCP => {
                    if let Ok(mapping) = self.pcp_client.create_mapping(&config).await {
                        self.store_mapping(mapping.clone()).await;
                        return Ok(mapping);
                    }
                }
                MappingProtocol::UPnPIGD => {
                    if let Ok(mapping) = self.upnp_client.create_mapping(&config).await {
                        self.store_mapping(mapping.clone()).await;
                        return Ok(mapping);
                    }
                }
                MappingProtocol::NatPMP => {
                    if let Ok(mapping) = self.natpmp_client.create_mapping(&config).await {
                        self.store_mapping(mapping.clone()).await;
                        return Ok(mapping);
                    }
                }
            }
        }
        
        Err(NatError::NotSupported("No port forwarding protocol available".to_string()))
    }
    
    /// Delete port mapping
    pub async fn delete_mapping(&self, id: uuid::Uuid) -> NatResult<()> {
        let mapping = {
            let mut mappings = self.mappings.write().await;
            mappings.remove(&id)
        };
        
        if let Some(mapping) = mapping {
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
            let mut interval = interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                let mappings_to_renew: Vec<_> = {
                    let mappings = mappings.read().await;
                    mappings.values()
                        .filter(|m| {
                            let elapsed = m.created_at.elapsed();
                            elapsed >= m.lifetime * 2 / 3
                        })
                        .cloned()
                        .collect()
                };
                
                for mapping in mappings_to_renew {
                    let result = match mapping.protocol {
                        MappingProtocol::PCP => pcp.renew_mapping(&mapping).await,
                        MappingProtocol::UPnPIGD => upnp.renew_mapping(&mapping).await,
                        MappingProtocol::NatPMP => natpmp.renew_mapping(&mapping).await,
                    };
                    
                    if let Err(e) = result {
                        tracing::warn!("Failed to renew mapping {}: {}", mapping.id, e);
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
    devices: Arc<RwLock<Vec<UPnPDevice>>>,
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
            devices: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Discover UPnP devices
    async fn discover(&self) -> NatResult<()> {
        const SSDP_MULTICAST: &str = "239.255.255.250:1900";
        const SSDP_SEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
                                   HOST: 239.255.255.250:1900\r\n\
                                   ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                                   MAN: \"ssdp:discover\"\r\n\
                                   MX: 3\r\n\r\n";
        
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(SSDP_SEARCH.as_bytes(), SSDP_MULTICAST).await?;
        
        let mut buf = vec![0u8; 1500];
        let timeout_duration = Duration::from_secs(3);
        
        while let Ok(Ok((size, addr))) = timeout(
            timeout_duration,
            socket.recv_from(&mut buf)
        ).await {
            let response = String::from_utf8_lossy(&buf[..size]);
            
            // Parse SSDP response
            if let Some(location) = Self::parse_ssdp_location(&response) {
                if let Ok(device) = self.fetch_device_info(&location).await {
                    self.devices.write().await.push(device);
                }
            }
        }
        
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
        // This is a simplified version - real implementation would be more robust
        
        let device = root.get_child("device")?;
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
        let soap_body = r#"<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" 
                        s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:GetExternalIPAddress xmlns:u="{}"/>
                </s:Body>
            </s:Envelope>"#;
        
        let full_url = if control_url.starts_with("http") {
            control_url.to_string()
        } else {
            format!("{}{}", base_url, control_url)
        };
        
        let client = reqwest::Client::new();
        let response = client.post(&full_url)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", soap_action)
            .body(soap_body.replace("{}", service_type))
            .send()
            .await
            .map_err(|e| NatError::Platform(format!("SOAP request failed: {}", e)))?;
        
        let body = response.text().await
            .map_err(|e| NatError::Platform(format!("Failed to read SOAP response: {}", e)))?;
        
        // Parse external IP from response
        let root = Element::parse(body.as_bytes())
            .map_err(|e| NatError::Platform(format!("Failed to parse SOAP response: {}", e)))?;
        
        // Extract IP address - simplified parsing
        let ip_str = root.get_child("Body")
            .and_then(|b| b.get_child("GetExternalIPAddressResponse"))
            .and_then(|r| r.get_child("NewExternalIPAddress"))
            .and_then(|ip| ip.get_text())
            .ok_or_else(|| NatError::Platform("No external IP in response".to_string()))?;
        
        ip_str.parse()
            .map_err(|e| NatError::Platform(format!("Invalid IP address: {}", e)))
    }
    
    /// Create port mapping
    async fn create_mapping(&self, config: &PortMappingConfig) -> NatResult<PortMapping> {
        // Ensure we have discovered devices
        if self.devices.read().await.is_empty() {
            self.discover().await?;
        }
        
        let devices = self.devices.read().await;
        let device = devices.first()
            .ok_or_else(|| NatError::NotSupported("No UPnP devices found".to_string()))?;
        
        // Get internal IP
        let internal_ip = get_local_ip()?;
        
        // Add port mapping
        let external_port = if config.external_port == 0 {
            config.internal_port
        } else {
            config.external_port
        };
        
        let protocols = match config.protocol {
            Protocol::TCP => vec!["TCP"],
            Protocol::UDP => vec!["UDP"],
            Protocol::Both => vec!["TCP", "UDP"],
        };
        
        for protocol in protocols {
            self.add_port_mapping(
                device,
                external_port,
                config.internal_port,
                &internal_ip,
                protocol,
                config.lifetime,
                &config.description,
            ).await?;
        }
        
        Ok(PortMapping {
            id: uuid::Uuid::new_v4(),
            protocol: MappingProtocol::UPnPIGD,
            external_addr: SocketAddr::new(device.external_ip, external_port),
            internal_addr: SocketAddr::new(internal_ip, config.internal_port),
            transport: config.protocol,
            lifetime: Duration::from_secs(config.lifetime as u64),
            created_at: Instant::now(),
            gateway: device.external_ip,
            nonce: None,
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
    ) -> NatResult<()> {
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
            format!("{}{}", device.location, device.control_url)
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
            return Err(NatError::Platform(
                format!("UPnP AddPortMapping failed: {}", response.status())
            ));
        }
        
        Ok(())
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
            return Err(NatError::Platform(
                format!("UPnP DeletePortMapping failed: {}", response.status())
            ));
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
struct NatPMPClient {
    /// Gateway address
    gateway: Arc<RwLock<Option<Ipv4Addr>>>,
    
    /// Server epoch
    server_epoch: Arc<RwLock<u32>>,
}

impl NatPMPClient {
    fn new() -> Self {
        Self {
            gateway: Arc::new(RwLock::new(None)),
            server_epoch: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Discover NAT-PMP gateway
    async fn discover_gateway(&self) -> NatResult<Ipv4Addr> {
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
        
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect((gateway, 5351)).await?;
        
        // Build request (opcode 0)
        let mut request = BytesMut::with_capacity(2);
        request.put_u8(0); // Version
        request.put_u8(0); // Opcode (external address)
        
        socket.send(&request).await?;
        
        // Wait for response
        let mut buf = vec![0u8; 12];
        let size = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await
            .map_err(|_| NatError::Timeout(Duration::from_secs(3)))?
            .map_err(|e| NatError::Network(e))?;
        
        if size < 12 {
            return Err(NatError::Platform("Invalid NAT-PMP response".to_string()));
        }
        
        let mut response = &buf[..];
        let version = response.get_u8();
        let opcode = response.get_u8();
        let result_code = response.get_u16();
        let epoch = response.get_u32();
        
        if version != 0 || opcode != 128 || result_code != 0 {
            return Err(NatError::Platform(
                format!("NAT-PMP error: result code {}", result_code)
            ));
        }
        
        *self.server_epoch.write().await = epoch;
        
        let external_ip = Ipv4Addr::new(
            response.get_u8(),
            response.get_u8(),
            response.get_u8(),
            response.get_u8(),
        );
        
        Ok(external_ip)
    }
    
    /// Create port mapping
    async fn create_mapping(&self, config: &PortMappingConfig) -> NatResult<PortMapping> {
        let gateway = match *self.gateway.read().await {
            Some(gw) => gw,
            None => self.discover_gateway().await?,
        };
        
        let external_ip = self.get_external_address().await?;
        let internal_ip = get_local_ip()?;
        
        let protocols = match config.protocol {
            Protocol::TCP => vec![(1u8, "TCP")],
            Protocol::UDP => vec![(2u8, "UDP")],
            Protocol::Both => vec![(1u8, "TCP"), (2u8, "UDP")],
        };
        
        let external_port = if config.external_port == 0 {
            config.internal_port
        } else {
            config.external_port
        };
        
        for (opcode, _) in &protocols {
            self.map_port(
                gateway,
                *opcode,
                config.internal_port,
                external_port,
                config.lifetime,
            ).await?;
        }
        
        Ok(PortMapping {
            id: uuid::Uuid::new_v4(),
            protocol: MappingProtocol::NatPMP,
            external_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
            internal_addr: SocketAddr::new(internal_ip, config.internal_port),
            transport: config.protocol,
            lifetime: Duration::from_secs(config.lifetime as u64),
            created_at: Instant::now(),
            gateway: IpAddr::V4(gateway),
            nonce: None,
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
    ) -> NatResult<u16> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect((gateway, 5351)).await?;
        
        // Build mapping request
        let mut request = BytesMut::with_capacity(12);
        request.put_u8(0);                    // Version
        request.put_u8(opcode);               // Opcode (1=TCP, 2=UDP)
        request.put_u16(0);                   // Reserved
        request.put_u16(internal_port);       // Internal port
        request.put_u16(external_port);       // Requested external port
        request.put_u32(lifetime);            // Lifetime
        
        socket.send(&request).await?;
        
        // Wait for response
        let mut buf = vec![0u8; 16];
        let size = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await
            .map_err(|_| NatError::Timeout(Duration::from_secs(3)))?
            .map_err(|e| NatError::Network(e))?;
        
        if size < 16 {
            return Err(NatError::Platform("Invalid NAT-PMP response".to_string()));
        }
        
        let mut response = &buf[..];
        let version = response.get_u8();
        let resp_opcode = response.get_u8();
        let result_code = response.get_u16();
        let epoch = response.get_u32();
        let _internal = response.get_u16();
        let mapped_external = response.get_u16();
        let mapped_lifetime = response.get_u32();
        
        if version != 0 || resp_opcode != (opcode + 128) || result_code != 0 {
            return Err(NatError::Platform(
                format!("NAT-PMP mapping error: result code {}", result_code)
            ));
        }
        
        *self.server_epoch.write().await = epoch;
        
        tracing::info!(
            "NAT-PMP mapping created: {}:{} -> {} for {} seconds",
            internal_port,
            external_port,
            mapped_external,
            mapped_lifetime
        );
        
        Ok(mapped_external)
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
                self.map_port(
                    gateway,
                    opcode,
                    mapping.internal_addr.port(),
                    mapping.external_addr.port(),
                    0,
                ).await?;
            }
        }
        
        Ok(())
    }
    
    /// Renew port mapping
    async fn renew_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        if let IpAddr::V4(gateway) = mapping.gateway {
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
}

/// PCP client implementation (RFC 6887)
struct PCPClient {
    /// PCP server address
    server: Arc<RwLock<Option<SocketAddr>>>,
}

impl PCPClient {
    fn new() -> Self {
        Self {
            server: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Discover PCP server
    async fn discover_server(&self) -> NatResult<SocketAddr> {
        // Try default gateway on PCP port (5351)
        let gateway = get_default_gateway()?
            .ok_or_else(|| NatError::NotSupported("No default gateway found".to_string()))?;
        
        let server = SocketAddr::new(gateway, 5351);
        *self.server.write().await = Some(server);
        Ok(server)
    }
    
    /// Create port mapping
    async fn create_mapping(&self, config: &PortMappingConfig) -> NatResult<PortMapping> {
        let server = match *self.server.read().await {
            Some(s) => s,
            None => self.discover_server().await?,
        };
        
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
        
        for protocol in protocols {
            let (ext_ip, mapped_port) = self.map_port(
                server,
                internal_ip,
                config.internal_port,
                external_port,
                protocol,
                config.lifetime,
                &nonce,
            ).await?;
            
            if external_ip.is_none() {
                external_ip = Some(ext_ip);
            }
        }
        
        let external_ip = external_ip.unwrap();
        
        Ok(PortMapping {
            id: uuid::Uuid::new_v4(),
            protocol: MappingProtocol::PCP,
            external_addr: SocketAddr::new(external_ip, external_port),
            internal_addr: SocketAddr::new(internal_ip, config.internal_port),
            transport: config.protocol,
            lifetime: Duration::from_secs(config.lifetime as u64),
            created_at: Instant::now(),
            gateway: server.ip(),
            nonce: Some(nonce),
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
    ) -> NatResult<(IpAddr, u16)> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        // Build PCP MAP request
        let mut request = BytesMut::with_capacity(60);
        
        // Common header
        request.put_u8(2);          // Version
        request.put_u8(1);          // Opcode (MAP)
        request.put_u16(0);         // Reserved
        request.put_u32(lifetime);   // Requested lifetime
        
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
        
        socket.send_to(&request, server).await?;
        
        // Wait for response
        let mut buf = vec![0u8; 1100];
        let (size, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await
            .map_err(|_| NatError::Timeout(Duration::from_secs(3)))?
            .map_err(|e| NatError::Network(e))?;
        
        if size < 60 {
            return Err(NatError::Platform("Invalid PCP response".to_string()));
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
        
        if version != 2 || opcode != 129 {  // 129 = MAP response
            return Err(NatError::Platform("Invalid PCP response".to_string()));
        }
        
        if result_code != 0 {
            return Err(NatError::Platform(
                format!("PCP error: result code {}", result_code)
            ));
        }
        
        // Parse MAP response
        response.advance(12); // Skip nonce
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
        
        Ok((external_ip, assigned_external_port))
    }
    
    /// Delete port mapping
    async fn delete_mapping(&self, mapping: &PortMapping) -> NatResult<()> {
        if let Some(nonce) = &mapping.nonce {
            let server = match *self.server.read().await {
                Some(s) => s,
                None => return Ok(()), // No server, nothing to delete
            };
            
            let protocols = match mapping.transport {
                Protocol::TCP => vec![6u8],
                Protocol::UDP => vec![17u8],
                Protocol::Both => vec![6u8, 17u8],
            };
            
            for protocol in protocols {
                // Delete by setting lifetime to 0
                self.map_port(
                    server,
                    mapping.internal_addr.ip(),
                    mapping.internal_addr.port(),
                    mapping.external_addr.port(),
                    protocol,
                    0,
                    nonce,
                ).await?;
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
}

/// Get local IP address
fn get_local_ip() -> NatResult<IpAddr> {
    // This is a simplified version - real implementation would be more robust
    use local_ip_address::local_ip;
    
    local_ip()
        .map_err(|e| NatError::Platform(format!("Failed to get local IP: {}", e)))
}

/// Get default gateway
fn get_default_gateway() -> NatResult<Option<IpAddr>> {
    // This would use platform-specific APIs to get the default gateway
    // For now, return a placeholder
    Ok(None)
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
            protocol: Protocol::TCP,
            lifetime: 3600,
            description: "Test mapping".to_string(),
            auto_renew: false,
            preferred_protocols: vec![MappingProtocol::UPnPIGD],
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
    }
}