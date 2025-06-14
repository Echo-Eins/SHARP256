use anyhow::Context;
use super::NatResult as Result;
use std::net::IpAddr;

use parking_lot::RwLock;
use std::sync::Arc;
use igd::aio::{search_gateway, Gateway};

use igd::{AddAnyPortError, PortMappingProtocol, RequestError, SearchError, SearchOptions};

use if_addrs::get_if_addrs;

use std::time::Duration;
use url::Url;
use xmltree::Element;

use std::time::Instant;

const SEARCH_REQUEST_V2: &str = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:urn:schemas-upnp-org:service:WANIPConnection:2\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n";

async fn search_gateway_v2(options: SearchOptions) -> Result<Gateway, SearchError> {
    use hyper::Client;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    const MAX_RESPONSE_SIZE: usize = 1500;

    let mut socket = UdpSocket::bind(&options.bind_addr).await?;
    // send search request with IGD v2 service type
    socket
        .send_to(SEARCH_REQUEST_V2.as_bytes(), &options.broadcast_address)
        .await
        .map(|_| ())
        .map_err(SearchError::from)?;

    async fn receive_search_response(
        socket: &mut UdpSocket,
    ) -> Result<(Vec<u8>, SocketAddr), SearchError> {
        let mut buff = [0u8; MAX_RESPONSE_SIZE];
        let (n, from) = socket
            .recv_from(&mut buff)
            .await
            .map_err(SearchError::from)?;
        Ok((buff[..n].to_vec(), from))
    }

    let search_response = receive_search_response(&mut socket);
    let (response_body, from) = match options.timeout {
        Some(t) => timeout(t, search_response).await?,
        None => search_response.await,
    }?;

    let text = std::str::from_utf8(&response_body).map_err(SearchError::from)?;
    let (addr, root_url) = parse_search_result(text)?;

    async fn get_control_urls(
        addr: &std::net::SocketAddrV4,
        path: &str,
    ) -> Result<(String, String), SearchError> {
        let uri = format!("http://{}{}", addr, path)
            .parse()
            .map_err(SearchError::from)?;
        let client = Client::new();
        let resp = hyper::body::to_bytes(client.get(uri).await?.into_body())
            .await
            .map_err(SearchError::from)?;
        parse_control_urls(std::io::Cursor::new(&resp))
    }

    async fn get_control_schemas(
        addr: &std::net::SocketAddrV4,
        url: &str,
    ) -> Result<HashMap<String, Vec<String>>, SearchError> {
        let uri = format!("http://{}{}", addr, url)
            .parse()
            .map_err(SearchError::from)?;
        let client = Client::new();
        let resp = hyper::body::to_bytes(client.get(uri).await?.into_body())
            .await
            .map_err(SearchError::from)?;
        parse_schemas(std::io::Cursor::new(&resp))
    }

    let (control_schema_url, control_url) = get_control_urls(&addr, &root_url).await?;
    let control_schema = get_control_schemas(&addr, &control_schema_url).await?;

    let addr = addr;

    Ok(Gateway {
        addr,
        root_url,
        control_url,
        control_schema_url,
        control_schema,
    })
}

fn parse_search_result(text: &str) -> Result<(std::net::SocketAddrV4, String), SearchError> {
    for line in text.lines() {
        let l = line.trim();
        if l.to_ascii_lowercase().starts_with("location:") {
            if let Some(colon) = l.find(':') {
                let url_text = l[colon + 1..].trim();
                let url = Url::parse(url_text).map_err(|_| SearchError::InvalidResponse)?;
                let addr = url
                    .host_str()
                    .ok_or(SearchError::InvalidResponse)?
                    .parse()
                    .map_err(|_| SearchError::InvalidResponse)?;
                let port = url
                    .port_or_known_default()
                    .ok_or(SearchError::InvalidResponse)?;
                return Ok((
                    std::net::SocketAddrV4::new(addr, port),
                    url.path().to_string(),
                ));
            }
        }
    }
    Err(SearchError::InvalidResponse)
}

fn parse_control_urls<R: std::io::Read>(reader: R) -> Result<(String, String), SearchError> {
    let root = Element::parse(reader)?;
    fn find_service(el: &Element) -> Option<(String, String)> {
        if el.name == "service" {
            let st = el.get_child("serviceType")?.get_text()?;
            if st == "urn:schemas-upnp-org:service:WANIPConnection:2"
                || st == "urn:schemas-upnp-org:service:WANIPConnection:1"
                || st == "urn:schemas-upnp-org:service:WANPPPConnection:1"
            {
                let scpd = el.get_child("SCPDURL")?.get_text()?.into_owned();
                let ctrl = el.get_child("controlURL")?.get_text()?.into_owned();
                return Some((scpd, ctrl));
            }
        }
        for child in &el.children {
            if let Some(elem) = child.as_element() {
                if let Some(res) = find_service(elem) {
                    return Some(res);
                }
            }
        }
        None
    }
    for child in &root.children {
        if let Some(elem) = child.as_element() {
            if elem.name == "device" {
                if let Some(res) = find_service(elem) {
                    return Ok(res);
                }
            }
        }
    }
    Err(SearchError::InvalidResponse)
}

fn parse_schemas<R: std::io::Read>(
    reader: R,
) -> Result<std::collections::HashMap<String, Vec<String>>, SearchError> {
    let root = Element::parse(reader)?;
    fn parse_action_list(el: &Element) -> Option<std::collections::HashMap<String, Vec<String>>> {
        let mut map = std::collections::HashMap::new();
        for child in &el.children {
            let action = child.as_element()?;
            if action.name == "action" {
                if let Some((name, args)) = parse_action(action) {
                    map.insert(name, args);
                }
            }
        }
        Some(map)
    }
    fn parse_action(el: &Element) -> Option<(String, Vec<String>)> {
        let name = el.get_child("name")?.get_text()?.into_owned();
        let mut args = Vec::new();
        if let Some(arg_list) = el.get_child("argumentList") {
            for arg in &arg_list.children {
                let arg = arg.as_element()?;
                if arg.name == "argument" {
                    if arg.get_child("direction")?.get_text()? == "in" {
                        args.push(arg.get_child("name")?.get_text()?.into_owned());
                    }
                }
            }
        }
        Some((name, args))
    }

    for child in &root.children {
        if let Some(al) = child.as_element() {
            if al.name == "actionList" {
                if let Some(map) = parse_action_list(al) {
                    return Ok(map);
                }
            }
        }
    }
    Err(SearchError::InvalidResponse)
}

/// UPnP клиент для управления port forwarding на роутере
pub struct UpnpClient {
    gateway: Option<Gateway>,
    local_ip: IpAddr,
    active_mappings: Arc<RwLock<Vec<PortMapping>>>,
    consecutive_failures: u8,
    state: CircuitState,
}

#[derive(Debug, Clone, Copy)]
enum CircuitState {
    Closed,
    Open { until: Instant },
    HalfOpen,
}

#[derive(Debug, Clone)]
struct PortMapping {
    external_port: u16,
    internal_port: u16,
    protocol: PortMappingProtocol,
    description: String,
    created_at: Instant,
    lease_duration: u32,
}

impl UpnpClient {
    /// Создание нового UPnP клиента с автоматическим обнаружением gateway
    pub async fn new() -> Result<Self> {
        // Определяем локальный IP
        let local_ip = Self::get_local_ip().await?;
        
        tracing::info!("Searching for UPnP gateway...");
        
        // Настройки поиска с таймаутом
        let search_options = SearchOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        
        // Ищем gateway
        // Сначала пробуем найти gateway по service type v2
        let gateway_res = match search_gateway_v2(SearchOptions {
            timeout: search_options.timeout,
            bind_addr: search_options.bind_addr,
            broadcast_address: search_options.broadcast_address,
        })
            .await
        {
            Ok(gw) => Ok(gw),
            Err(e) => {
                tracing::debug!("IGD v2 search failed: {}", e);
                search_gateway(search_options).await
            }
        };

        match gateway_res {
            Ok(gateway) => {
                tracing::info!("UPnP gateway found: {}", gateway.addr);
                
                // Получаем информацию о внешнем IP
                if let Ok(external_ip) = gateway.get_external_ip().await {
                    tracing::info!("External IP via UPnP: {}", external_ip);
                }
                
                Ok(Self {
                    gateway: Some(gateway),
                    local_ip,
                    active_mappings: Arc::new(RwLock::new(Vec::new())),
                    consecutive_failures: 0,
                    state: CircuitState::Closed,
                })
            }
            Err(e) => {
                tracing::warn!("No UPnP gateway found: {}", e);
                
                // Возвращаем клиент без gateway (будет работать как no-op)
                Ok(Self {
                    gateway: None,
                    local_ip,
                    active_mappings: Arc::new(RwLock::new(Vec::new())),
                    consecutive_failures: 0,
                    state: CircuitState::Closed,
                })
            }
        }
    }

    /// Добавление port mapping
    pub async fn add_port_mapping(
        &mut self,
        local_port: u16,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16> {
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| super::NatError::permanent("No UPnP gateway available"))?;

        // Circuit breaker: check current state
        match self.state {
            CircuitState::Open { until } => {
                if Instant::now() < until {
                    anyhow::bail!("UPnP mapping disabled due to previous failures")
                } else {
                    self.state = CircuitState::HalfOpen;
                }
            }
            _ => {}
        }

        let local_addr = match self.local_ip {
            IpAddr::V4(ip) => std::net::SocketAddrV4::new(ip, local_port),
            IpAddr::V6(_) => {
                return Err(super::NatError::permanent("UPnP requires an IPv4 local address"));
            }
        };

        match gateway
            .add_any_port(
                PortMappingProtocol::UDP,
                local_addr,
                lease_duration,
                description,
            )
            .await
        {
            Ok(port) => {
                tracing::info!(
                    "UPnP port mapping created: {} -> {}:{} ({}s lease)",
                    port,
                    self.local_ip,
                    local_port,
                    lease_duration
                );

                let mapping = PortMapping {
                    external_port: port,
                    internal_port: local_port,
                    protocol: PortMappingProtocol::UDP,
                    description: description.to_string(),
                    created_at: Instant::now(),
                    lease_duration,
                };
                self.active_mappings.write().push(mapping);

                self.consecutive_failures = 0;
                self.state = CircuitState::Closed;

                Ok(port)
            }
            Err(e) => match e {
                AddAnyPortError::ExternalPortInUse | AddAnyPortError::NoPortsAvailable => {
                    anyhow::bail!("Port conflict (error 718)");
                }
                AddAnyPortError::OnlyPermanentLeasesSupported => {
                    anyhow::bail!("Only permanent leases supported (error 725)");
                }
                AddAnyPortError::RequestError(RequestError::ErrorCode(726, ref msg)) => {
                    anyhow::bail!("Only wildcard remote host supported (error 726): {}", msg)
                }
                AddAnyPortError::RequestError(RequestError::ErrorCode(727, ref msg)) => {
                    anyhow::bail!("External port only supports wildcard (error 727): {}", msg)
                }
                other => {
                    anyhow::bail!("Failed to create port mapping: {}", other)
                }
            },
        }
    }

    /// Удаление port mapping
    pub async fn remove_port_mapping(&mut self, external_port: u16) -> Result<()> {
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| super::NatError::permanent("No UPnP gateway available"))?;

        // Ищем mapping в списке активных
        let mut mappings = self.active_mappings.write();
        if let Some(pos) = mappings
            .iter()
            .position(|m| m.external_port == external_port)
        {
            let mapping = mappings.remove(pos);
            
            // Удаляем mapping на gateway
            match gateway.remove_port(mapping.protocol, external_port).await {
                Ok(()) => {
                    tracing::info!("UPnP port mapping removed: {}", external_port);
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to remove port mapping: {}", e);
                    // Не считаем это критической ошибкой
                    Ok(())
                }
            }
        } else {
            tracing::warn!("Port mapping {} not found in active list", external_port);
            Ok(())
        }
    }

    /// Обновление lease времени для всех активных mappings
    pub async fn refresh_mappings(&self, lease_duration: u32) -> Result<()> {
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| super::NatError::permanent("No UPnP gateway available"))?;

        let mappings = self.active_mappings.read().clone();

        if lease_duration == 0 {
            tracing::debug!("Lease duration 0 - mappings valid until reboot, skipping refresh");
            return Ok(());
        }

        for mapping in mappings {
            let local_addr = match self.local_ip {
                IpAddr::V4(ip) => std::net::SocketAddrV4::new(ip, mapping.internal_port),
                IpAddr::V6(_) => {
                    tracing::warn!("Cannot refresh mapping for IPv6 local address");
                    continue;
                }
            };

            match gateway
                .add_port(
                    mapping.protocol,
                    mapping.external_port,
                    local_addr,
                    lease_duration,
                    &mapping.description,
                )
                .await
            {
                Ok(()) => {
                    tracing::debug!("Refreshed mapping for port {}", mapping.external_port);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to refresh mapping for port {}: {}",
                        mapping.external_port,
                        e
                    );
                }
            }
        }
        
        Ok(())
    }

    /// Получение внешнего IP адреса через UPnP
    pub async fn get_external_ip(&self) -> Result<IpAddr> {
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| super::NatError::permanent("No UPnP gateway available"))?;

        let external_ip = gateway
            .get_external_ip()
            .await
            .context("Failed to get external IP from UPnP gateway")?;
        
        Ok(IpAddr::V4(external_ip))
    }

    /// Очистка всех активных mappings
    pub async fn cleanup_all(&mut self) -> Result<()> {
        if let Some(gateway) = &self.gateway {
            let mappings = self.active_mappings.write().drain(..).collect::<Vec<_>>();
            
            for mapping in mappings {
                if let Err(e) = gateway
                    .remove_port(mapping.protocol, mapping.external_port)
                    .await
                {
                    tracing::warn!("Failed to remove mapping {}: {}", mapping.external_port, e);
                }
            }
            
            tracing::info!("All UPnP port mappings cleaned up");
        }
        
        Ok(())
    }

    /// Проверка доступности UPnP
    pub fn is_available(&self) -> bool {
        if self.gateway.is_none() {
            return false;
        }

        if let CircuitState::Open { until } = self.state {
            if Instant::now() < until {
                return false;
            }
        }

        true
    }

    /// Получение локального IP адреса
    async fn get_local_ip() -> Result<IpAddr> {
        // Пробуем определить IP через список интерфейсов
        if let Ok(addrs) = get_if_addrs() {
            for iface in addrs {
                if !iface.is_loopback() {
                    return Ok(iface.ip());
                }
            }
        }

        // Фолбек через подключение к публичному адресу
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        if socket.connect("8.8.8.8:80").await.is_ok() {
            return Ok(socket.local_addr()?.ip());
        }

        return Err(super::NatError::permanent("Failed to determine local IP"));
    }
}

impl Drop for UpnpClient {
    fn drop(&mut self) {
        if self.active_mappings.read().is_empty() {
            return;
        }

        let mappings = self.active_mappings.read().clone();
        if let Some(gateway) = self.gateway.clone() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.block_on(async {
                    for mapping in &mappings {
                        let _ = gateway
                            .remove_port(mapping.protocol, mapping.external_port)
                            .await;
                    }
                });
            } else if let Ok(rt) = tokio::runtime::Runtime::new() {
                rt.block_on(async {
                    for mapping in &mappings {
                        let _ = gateway
                            .remove_port(mapping.protocol, mapping.external_port)
                            .await;
                    }
                });
            }
        }
    }
}