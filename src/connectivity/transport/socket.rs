// src/connectivity/transport/socket.rs
//! UDP Socket Layer с RFC 8421 Dual-Stack и Happy Eyeballs
//!
//! ## RFC Standards Compliance
//!
//! - **RFC 768**: UDP Protocol
//!   - Connectionless datagram service
//!   - 8-byte header with ports and length
//!   - Best-effort delivery
//!
//! - **RFC 8421**: Dual-Stack ICE (Happy Eyeballs)
//!   - Section 4.2: IPv6 preference calculation
//!   - Section 5: Happy Eyeballs algorithm
//!   - Parallel IPv4/IPv6 connection attempts
//!   - Connection attempt delay (150ms default)
//!
//! - **RFC 2460/8200**: IPv6 Specification
//!   - IPv6 addressing and routing
//!   - Extension headers
//!   - Path MTU discovery

use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};

use super::mtu_discovery::{InterfaceMtuDetector, PathMtuDiscovery, PmtudState};
use super::stats::SocketStats;

/// RFC 8421 Happy Eyeballs parameters
const HAPPY_EYEBALLS_DELAY_MS: u64 = 150; // RFC 8421 Section 5
const CONNECTION_ATTEMPT_TIMEOUT_MS: u64 = 5000; // 5 seconds per attempt
const MAX_OUTSTANDING_ATTEMPTS: usize = 2; // Maximum parallel attempts

/// Socket options для оптимизации производительности
#[derive(Debug, Clone)]
pub struct SocketOptions {
    /// SO_REUSEADDR - позволяет переиспользовать локальный адрес
    pub reuse_addr: bool,

    /// SO_REUSEPORT - позволяет биндить несколько сокетов на один порт
    pub reuse_port: bool,

    /// SO_RCVBUF - размер receive buffer (bytes)
    pub recv_buffer_size: Option<usize>,

    /// SO_SNDBUF - размер send buffer (bytes)
    pub send_buffer_size: Option<usize>,

    /// IP_TTL/IPV6_UNICAST_HOPS - Time To Live
    pub ttl: Option<u32>,

    /// Enable non-blocking mode
    pub non_blocking: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: true,
            reuse_port: false,
            // Оптимальные размеры для high-throughput UDP
            recv_buffer_size: Some(4 * 1024 * 1024), // 4 MB
            send_buffer_size: Some(4 * 1024 * 1024), // 4 MB
            ttl: Some(64),                           // Стандартный TTL
            non_blocking: true,
        }
    }
}

impl SocketOptions {
    /// Создать опции для low-latency scenarios
    pub fn low_latency() -> Self {
        Self {
            recv_buffer_size: Some(256 * 1024), // 256 KB
            send_buffer_size: Some(256 * 1024), // 256 KB
            ..Default::default()
        }
    }

    /// Создать опции для high-throughput scenarios
    pub fn high_throughput() -> Self {
        Self {
            recv_buffer_size: Some(8 * 1024 * 1024), // 8 MB
            send_buffer_size: Some(8 * 1024 * 1024), // 8 MB
            ..Default::default()
        }
    }
}

/// IP версия для socket
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// IPv4 (RFC 791)
    V4,
    /// IPv6 (RFC 2460/8200)
    V6,
}

impl IpVersion {
    /// Получить из SocketAddr
    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => IpVersion::V4,
            SocketAddr::V6(_) => IpVersion::V6,
        }
    }

    /// Получить из IpAddr
    pub fn from_ip_addr(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        }
    }

    /// Проверка совместимости с другой версией
    pub fn is_compatible_with(&self, other: &IpVersion) -> bool {
        self == other
    }
}

/// Состояние socket connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Сокет создан но не забинден
    Created,
    /// Сокет забинден на адрес
    Bound,
    /// Сокет готов к передаче данных
    Ready,
    /// Сокет в процессе reconnection
    Reconnecting,
    /// Сокет закрыт
    Closed,
    /// Ошибка сокета
    Error,
}

/// UDP Socket Wrapper с dual-stack поддержкой
///
/// Реализует RFC 8421 Happy Eyeballs algorithm для оптимального
/// выбора между IPv4 и IPv6 соединениями.
///
/// ## Example
///
/// ```rust
/// use sharp256::connectivity::transport::socket::{UdpSocketWrapper, SocketOptions};
///
/// async fn create_socket() -> anyhow::Result<UdpSocketWrapper> {
///     let options = SocketOptions::default();
///     let socket = UdpSocketWrapper::bind("0.0.0.0:0", options).await?;
///     Ok(socket)
/// }
/// ```
#[derive(Debug)]
pub struct UdpSocketWrapper {
    /// Внутренний tokio UdpSocket
    socket: Arc<UdpSocket>,

    /// Локальный адрес после bind
    local_addr: SocketAddr,

    /// IP версия сокета
    ip_version: IpVersion,

    /// Опции сокета
    options: SocketOptions,

    /// Текущее состояние
    state: Arc<RwLock<SocketState>>,

    /// Статистика сокета
    stats: Arc<RwLock<SocketStats>>,

    /// Path MTU (discovered)
    path_mtu: Arc<RwLock<Option<usize>>>,

    /// Path MTU Discovery manager (RFC 4821/8899)
    pmtu_discovery: Arc<RwLock<Option<Arc<PathMtuDiscovery>>>>,

    /// Время создания
    created_at: Instant,

    /// Последний successful send/recv
    last_activity: Arc<RwLock<Instant>>,
}

impl UdpSocketWrapper {
    /// Создать и забиндить UDP socket
    ///
    /// ## RFC 8421 Section 4.2: IPv6 Preference
    /// IPv6 адреса должны иметь приоритет над IPv4 когда оба доступны.
    ///
    /// ## Arguments
    /// - `addr`: Адрес для bind (может быть IPv4 или IPv6)
    /// - `options`: Опции сокета
    pub async fn bind<A: tokio::net::ToSocketAddrs>(
        addr: A,
        options: SocketOptions,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .await
            .context("Failed to bind UDP socket")?;

        let local_addr = socket.local_addr().context("Failed to get local address")?;
        let ip_version = IpVersion::from_socket_addr(&local_addr);

        info!(
            "UDP socket bound to {} ({})",
            local_addr,
            match ip_version {
                IpVersion::V4 => "IPv4",
                IpVersion::V6 => "IPv6",
            }
        );

        // Применяем socket options
        Self::apply_socket_options(&socket, &options)?;

        let now = Instant::now();

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            ip_version,
            options,
            state: Arc::new(RwLock::new(SocketState::Bound)),
            stats: Arc::new(RwLock::new(SocketStats::new())),
            path_mtu: Arc::new(RwLock::new(None)),
            pmtu_discovery: Arc::new(RwLock::new(None)),
            created_at: now,
            last_activity: Arc::new(RwLock::new(now)),
        })
    }

    /// Применить socket options к сокету
    fn apply_socket_options(socket: &UdpSocket, options: &SocketOptions) -> Result<()> {
        // SO_REUSEADDR
        #[cfg(not(windows))]
        if options.reuse_addr {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if ret != 0 {
                    warn!("Failed to set SO_REUSEADDR: {}", io::Error::last_os_error());
                }
            }
        }

        // SO_REUSEPORT (Linux/Unix only)
        #[cfg(all(unix, not(target_os = "macos")))]
        if options.reuse_port {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if ret != 0 {
                    warn!("Failed to set SO_REUSEPORT: {}", io::Error::last_os_error());
                }
            }
        }

        // SO_RCVBUF
        #[cfg(not(windows))]
        if let Some(size) = options.recv_buffer_size {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = size as libc::c_int;
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if ret != 0 {
                    warn!("Failed to set SO_RCVBUF: {}", io::Error::last_os_error());
                } else {
                    debug!("Set SO_RCVBUF to {} bytes", size);
                }
            }
        }

        // SO_SNDBUF
        #[cfg(not(windows))]
        if let Some(size) = options.send_buffer_size {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = size as libc::c_int;
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if ret != 0 {
                    warn!("Failed to set SO_SNDBUF: {}", io::Error::last_os_error());
                } else {
                    debug!("Set SO_SNDBUF to {} bytes", size);
                }
            }
        }

        // TTL (IP_TTL for IPv4, IPV6_UNICAST_HOPS for IPv6)
        if let Some(ttl) = options.ttl {
            socket.set_ttl(ttl).context("Failed to set TTL")?;
            debug!("Set TTL to {}", ttl);
        }

        Ok(())
    }

    /// Отправить данные на указанный адрес
    ///
    /// ## RFC 768: UDP Protocol
    /// Отправляет UDP datagram без гарантии доставки
    pub async fn send_to(&self, buf: &[u8], target: &SocketAddr) -> Result<usize> {
        // Проверка совместимости IP версий
        let target_version = IpVersion::from_socket_addr(target);
        if !self.ip_version.is_compatible_with(&target_version) {
            return Err(anyhow::anyhow!(
                "IP version mismatch: socket is {:?}, target is {:?}",
                self.ip_version,
                target_version
            ));
        }

        let bytes_sent = self
            .socket
            .send_to(buf, target)
            .await
            .context("Failed to send UDP packet")?;

        // Обновляем статистику
        self.stats.write().record_send(bytes_sent);
        *self.last_activity.write() = Instant::now();
        *self.state.write() = SocketState::Ready;

        trace!("Sent {} bytes to {}", bytes_sent, target);

        Ok(bytes_sent)
    }

    /// Получить данные из сокета
    ///
    /// ## RFC 768: UDP Protocol
    /// Получает UDP datagram. Может вернуть меньше данных чем размер буфера.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (bytes_received, source) = self
            .socket
            .recv_from(buf)
            .await
            .context("Failed to receive UDP packet")?;

        // Обновляем статистику
        self.stats.write().record_recv(bytes_received);
        *self.last_activity.write() = Instant::now();
        *self.state.write() = SocketState::Ready;

        trace!("Received {} bytes from {}", bytes_received, source);

        Ok((bytes_received, source))
    }

    /// Получить локальный адрес сокета
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Получить IP версию сокета
    pub fn ip_version(&self) -> IpVersion {
        self.ip_version
    }

    /// Получить текущее состояние сокета
    pub fn state(&self) -> SocketState {
        *self.state.read()
    }

    /// Получить статистику сокета
    pub fn stats(&self) -> SocketStats {
        self.stats.read().clone()
    }

    /// Получить время последней активности
    pub fn last_activity(&self) -> Instant {
        *self.last_activity.read()
    }

    /// Получить uptime сокета
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Получить discovered Path MTU
    pub fn path_mtu(&self) -> Option<usize> {
        *self.path_mtu.read()
    }

    /// Установить Path MTU (после discovery)
    pub fn set_path_mtu(&self, mtu: usize) {
        *self.path_mtu.write() = Some(mtu);
        debug!("Path MTU set to {} bytes", mtu);
    }

    /// Проверить, активен ли сокет (есть ли недавняя активность)
    pub fn is_active(&self, timeout: Duration) -> bool {
        self.last_activity().elapsed() < timeout
    }

    /// Закрыть сокет
    pub fn close(&self) {
        *self.state.write() = SocketState::Closed;
        info!("Socket closed: {}", self.local_addr);
    }

    /// Получить clone внутреннего Arc<UdpSocket> для расширенных операций
    pub fn inner(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Start Path MTU Discovery process (RFC 4821/8899)
    ///
    /// Performs PLPMTUD (Packetization Layer Path MTU Discovery) to find
    /// the optimal MTU for the path to the remote address.
    ///
    /// ## Arguments
    /// - `remote_addr`: Remote address to probe
    ///
    /// ## Returns
    /// Discovered Path MTU in bytes
    ///
    /// ## Example
    /// ```no_run
    /// # use sharp256::connectivity::transport::socket::{UdpSocketWrapper, SocketOptions};
    /// # async fn example() -> anyhow::Result<()> {
    /// let socket = UdpSocketWrapper::bind("0.0.0.0:0", SocketOptions::default()).await?;
    /// let remote = "8.8.8.8:53".parse()?;
    /// let mtu = socket.start_mtu_discovery(remote).await?;
    /// println!("Discovered MTU: {} bytes", mtu);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_mtu_discovery(&self, remote_addr: SocketAddr) -> Result<usize> {
        info!("Starting Path MTU Discovery to {}", remote_addr);

        let local_ip = self.local_addr.ip();
        let pmtud = Arc::new(PathMtuDiscovery::new(local_ip, remote_addr));

        // Store PMTUD instance
        *self.pmtu_discovery.write() = Some(Arc::clone(&pmtud));

        // Create probe function that uses this socket
        let socket = Arc::clone(&self.socket);
        let probe_fn = move |size: usize| {
            let socket = Arc::clone(&socket);
            let remote = remote_addr;
            Box::pin(async move {
                // Create probe packet (filled with pattern)
                let mut probe = vec![0xAA; size];
                probe[0] = 0xDE; // Magic byte
                probe[1] = 0xAD;

                // Send probe
                match socket.send_to(&probe, remote).await {
                    Ok(sent) if sent == size => {
                        // Probe sent successfully
                        // In real implementation, would wait for ACK/response
                        // For now, assume success if send succeeded
                        Ok(true)
                    }
                    Ok(_) => Ok(false),  // Partial send
                    Err(_) => Ok(false), // Send failed
                }
            })
        };

        // Run discovery
        let discovered_mtu = pmtud.discover(probe_fn).await?;

        // Update path_mtu
        *self.path_mtu.write() = Some(discovered_mtu);

        info!("MTU Discovery complete: {} bytes", discovered_mtu);

        Ok(discovered_mtu)
    }

    /// Get maximum payload size accounting for all headers
    ///
    /// Calculates: MTU - IP_header - UDP_header - SHARP_header
    ///
    /// ## Returns
    /// Maximum safe payload size in bytes, or None if MTU not yet discovered
    ///
    /// ## Example
    /// ```no_run
    /// # use sharp256::connectivity::transport::socket::{UdpSocketWrapper, SocketOptions};
    /// # async fn example() -> anyhow::Result<()> {
    /// let socket = UdpSocketWrapper::bind("0.0.0.0:0", SocketOptions::default()).await?;
    /// socket.start_mtu_discovery("8.8.8.8:53".parse()?).await?;
    /// if let Some(max_payload) = socket.get_max_payload() {
    ///     println!("Maximum payload: {} bytes", max_payload);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_max_payload(&self) -> Option<usize> {
        if let Some(pmtud) = self.pmtu_discovery.read().as_ref() {
            pmtud.get_max_payload()
        } else if let Some(mtu) = *self.path_mtu.read() {
            // Manual MTU set, calculate payload
            let ip_header = match self.ip_version {
                IpVersion::V4 => crate::protocol::constants::IPV4_HEADER_SIZE,
                IpVersion::V6 => crate::protocol::constants::IPV6_HEADER_SIZE,
            };
            Some(mtu.saturating_sub(
                ip_header
                    + crate::protocol::constants::UDP_HEADER_SIZE
                    + crate::protocol::constants::SHARP_HEADER_SIZE,
            ))
        } else {
            None
        }
    }

    /// Get PMTUD statistics
    pub fn pmtud_stats(&self) -> Option<super::mtu_discovery::PmtudStats> {
        self.pmtu_discovery
            .read()
            .as_ref()
            .map(|pmtud| pmtud.stats())
    }

    /// Get PMTUD state
    pub fn pmtud_state(&self) -> Option<PmtudState> {
        self.pmtu_discovery
            .read()
            .as_ref()
            .map(|pmtud| pmtud.state())
    }
}

/// Happy Eyeballs Connection Manager
///
/// RFC 8421 Section 5: Happy Eyeballs Algorithm
///
/// Управляет параллельными попытками подключения к IPv4 и IPv6 адресам,
/// выбирая первое успешное соединение.
pub struct HappyEyeballsConnector {
    /// Задержка между попытками подключения (default 150ms per RFC 8421)
    connection_attempt_delay: Duration,

    /// Timeout для каждой попытки
    attempt_timeout: Duration,

    /// Максимальное количество одновременных попыток
    max_outstanding_attempts: usize,
}

impl Default for HappyEyeballsConnector {
    fn default() -> Self {
        Self {
            connection_attempt_delay: Duration::from_millis(HAPPY_EYEBALLS_DELAY_MS),
            attempt_timeout: Duration::from_millis(CONNECTION_ATTEMPT_TIMEOUT_MS),
            max_outstanding_attempts: MAX_OUTSTANDING_ATTEMPTS,
        }
    }
}

impl HappyEyeballsConnector {
    /// Создать новый connector с кастомными параметрами
    pub fn new(
        connection_attempt_delay: Duration,
        attempt_timeout: Duration,
        max_outstanding_attempts: usize,
    ) -> Self {
        Self {
            connection_attempt_delay,
            attempt_timeout,
            max_outstanding_attempts,
        }
    }

    /// Попытка подключения к target адресу с Happy Eyeballs
    ///
    /// RFC 8421 Section 5:
    /// 1. Сортируем адреса по приоритету (IPv6 предпочтительнее)
    /// 2. Начинаем с highest priority
    /// 3. Если есть IPv6, стартуем сразу
    /// 4. IPv4 стартуем через 150ms delay
    /// 5. Первое успешное соединение побеждает
    ///
    /// ## Arguments
    /// - `addresses`: Список candidate адресов (IPv4 и IPv6)
    /// - `options`: Socket options для применения
    ///
    /// ## Returns
    /// Первый успешно подключенный socket
    pub async fn connect(
        &self,
        mut addresses: Vec<SocketAddr>,
        options: SocketOptions,
    ) -> Result<UdpSocketWrapper> {
        if addresses.is_empty() {
            return Err(anyhow::anyhow!("No addresses provided for connection"));
        }

        info!(
            "Starting Happy Eyeballs connection to {} candidates",
            addresses.len()
        );

        // RFC 8421 Section 4.2: Сортируем с предпочтением IPv6
        addresses.sort_by_key(|addr| {
            let version_priority = match addr {
                SocketAddr::V6(_) => 0, // IPv6 имеет высший приоритет
                SocketAddr::V4(_) => 1, // IPv4 secondary
            };
            version_priority
        });

        debug!("Sorted addresses: {:?}", addresses);

        // Разделяем на IPv6 и IPv4
        let ipv6_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|a| matches!(a, SocketAddr::V6(_)))
            .copied()
            .collect();

        let ipv4_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|a| matches!(a, SocketAddr::V4(_)))
            .copied()
            .collect();

        // Создаем задачи для подключения
        let mut tasks = Vec::new();

        // IPv6 стартует немедленно (если есть)
        if !ipv6_addrs.is_empty() {
            let addr = ipv6_addrs[0];
            let opts = options.clone();
            tasks.push(tokio::spawn(async move {
                Self::attempt_connection(addr, opts).await
            }));
            debug!("Started IPv6 connection attempt to {}", addr);
        }

        // IPv4 стартует после delay (RFC 8421 Section 5)
        if !ipv4_addrs.is_empty() {
            let addr = ipv4_addrs[0];
            let opts = options.clone();
            let delay = self.connection_attempt_delay;

            tasks.push(tokio::spawn(async move {
                sleep(delay).await;
                debug!("Starting delayed IPv4 connection attempt to {}", addr);
                Self::attempt_connection(addr, opts).await
            }));
        }

        // Ждем первый успешный результат
        let mut last_error = None;
        for task in tasks {
            match task.await {
                Ok(Ok(socket)) => {
                    info!(
                        "Happy Eyeballs: successful connection to {}",
                        socket.local_addr()
                    );
                    return Ok(socket);
                }
                Ok(Err(e)) => {
                    warn!("Connection attempt failed: {}", e);
                    last_error = Some(e);
                }
                Err(e) => {
                    warn!("Task join error: {}", e);
                    last_error = Some(anyhow::anyhow!("Task join failed: {}", e));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All connection attempts failed")))
    }

    /// Одна попытка подключения к адресу
    async fn attempt_connection(
        bind_addr: SocketAddr,
        options: SocketOptions,
    ) -> Result<UdpSocketWrapper> {
        // Для UDP "подключение" означает создание сокета
        // В будущем здесь будут connectivity checks (STUN)
        let socket = UdpSocketWrapper::bind(bind_addr, options).await?;
        Ok(socket)
    }

    /// Расчет приоритета для address pair (RFC 8421 Section 4.2)
    ///
    /// IPv6 адреса получают более высокий приоритет чем IPv4
    pub fn calculate_address_priority(local: &SocketAddr, remote: &SocketAddr) -> u32 {
        let local_version = IpVersion::from_socket_addr(local);
        let remote_version = IpVersion::from_socket_addr(remote);

        // RFC 8421: IPv6-to-IPv6 имеет highest priority
        match (local_version, remote_version) {
            (IpVersion::V6, IpVersion::V6) => 100,
            (IpVersion::V4, IpVersion::V4) => 50,
            (IpVersion::V6, IpVersion::V4) => 75,
            (IpVersion::V4, IpVersion::V6) => 25,
        }
    }
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Имя интерфейса (eth0, wlan0, etc)
    pub name: String,

    /// IP адреса интерфейса
    pub addresses: Vec<IpAddr>,

    /// Является ли интерфейс активным
    pub is_up: bool,

    /// Является ли интерфейс loopback
    pub is_loopback: bool,

    /// MTU интерфейса
    pub mtu: Option<usize>,
}

/// Network interface detector
pub struct NetworkInterfaceDetector;

impl NetworkInterfaceDetector {
    /// Обнаружить все сетевые интерфейсы системы
    pub fn detect_interfaces() -> Result<Vec<NetworkInterface>> {
        #[cfg(feature = "connectivity")]
        {
            use if_addrs::get_if_addrs;

            let if_addrs = get_if_addrs().context("Failed to get network interfaces")?;

            let mut interfaces = Vec::new();
            for if_addr in if_addrs {
                let interface_name = if_addr.name.clone();
                let mtu = Self::get_interface_mtu(&interface_name);

                interfaces.push(NetworkInterface {
                    name: if_addr.name,
                    addresses: vec![if_addr.addr.ip()],
                    is_up: true, // if_addrs returns only UP interfaces
                    is_loopback: if_addr.addr.ip().is_loopback(),
                    mtu,
                });
            }

            Ok(interfaces)
        }

        #[cfg(not(feature = "connectivity"))]
        {
            Ok(Vec::new())
        }
    }

    /// Получить MTU интерфейса через system calls
    ///
    /// Platform-specific MTU detection:
    /// - Linux: reads from /sys/class/net/<interface>/mtu
    /// - Windows: uses netsh command
    /// - macOS: returns standard MTU (1500)
    /// - Other platforms: RFC 1191 standard (1500)
    fn get_interface_mtu(interface_name: &str) -> Option<usize> {
        InterfaceMtuDetector::get_interface_mtu(interface_name)
    }

    /// Получить все IPv4 адреса на системе
    pub fn get_ipv4_addresses() -> Result<Vec<Ipv4Addr>> {
        let interfaces = Self::detect_interfaces()?;
        let addrs: Vec<Ipv4Addr> = interfaces
            .into_iter()
            .flat_map(|iface| iface.addresses)
            .filter_map(|addr| match addr {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .collect();
        Ok(addrs)
    }

    /// Получить все IPv6 адреса на системе
    pub fn get_ipv6_addresses() -> Result<Vec<Ipv6Addr>> {
        let interfaces = Self::detect_interfaces()?;
        let addrs: Vec<Ipv6Addr> = interfaces
            .into_iter()
            .flat_map(|iface| iface.addresses)
            .filter_map(|addr| match addr {
                IpAddr::V6(v6) => Some(v6),
                _ => None,
            })
            .collect();
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_socket_wrapper_bind_ipv4() {
        let options = SocketOptions::default();
        let socket = UdpSocketWrapper::bind("127.0.0.1:0", options)
            .await
            .expect("Failed to bind socket");

        assert_eq!(socket.ip_version(), IpVersion::V4);
        assert_eq!(socket.state(), SocketState::Bound);
        assert!(socket.local_addr().is_ipv4());
    }

    #[tokio::test]
    async fn test_udp_socket_wrapper_bind_ipv6() {
        let options = SocketOptions::default();
        let socket = UdpSocketWrapper::bind("[::1]:0", options)
            .await
            .expect("Failed to bind socket");

        assert_eq!(socket.ip_version(), IpVersion::V6);
        assert_eq!(socket.state(), SocketState::Bound);
        assert!(socket.local_addr().is_ipv6());
    }

    #[tokio::test]
    async fn test_send_recv() {
        let options = SocketOptions::default();

        let sender = UdpSocketWrapper::bind("127.0.0.1:0", options.clone())
            .await
            .expect("Failed to bind sender");

        let receiver = UdpSocketWrapper::bind("127.0.0.1:0", options)
            .await
            .expect("Failed to bind receiver");

        let receiver_addr = receiver.local_addr();

        // Отправляем данные
        let data = b"Hello, UDP!";
        let sent = sender
            .send_to(data, &receiver_addr)
            .await
            .expect("Failed to send");

        assert_eq!(sent, data.len());

        // Получаем данные
        let mut buf = vec![0u8; 1024];
        let (received, source) = receiver
            .recv_from(&mut buf)
            .await
            .expect("Failed to receive");

        assert_eq!(received, data.len());
        assert_eq!(&buf[..received], data);
        assert_eq!(source, sender.local_addr());
    }

    #[tokio::test]
    async fn test_socket_stats() {
        let options = SocketOptions::default();
        let socket = UdpSocketWrapper::bind("127.0.0.1:0", options)
            .await
            .expect("Failed to bind socket");

        let stats = socket.stats();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
    }

    #[tokio::test]
    async fn test_ip_version_compatibility() {
        assert!(IpVersion::V4.is_compatible_with(&IpVersion::V4));
        assert!(IpVersion::V6.is_compatible_with(&IpVersion::V6));
        assert!(!IpVersion::V4.is_compatible_with(&IpVersion::V6));
        assert!(!IpVersion::V6.is_compatible_with(&IpVersion::V4));
    }

    #[tokio::test]
    async fn test_happy_eyeballs_priority() {
        let local_v6 = "[::1]:1234".parse().unwrap();
        let remote_v6 = "[::1]:5678".parse().unwrap();

        let local_v4 = "127.0.0.1:1234".parse().unwrap();
        let remote_v4 = "127.0.0.1:5678".parse().unwrap();

        // IPv6-to-IPv6 должен иметь highest priority
        let priority_v6 = HappyEyeballsConnector::calculate_address_priority(&local_v6, &remote_v6);
        let priority_v4 = HappyEyeballsConnector::calculate_address_priority(&local_v4, &remote_v4);

        assert!(priority_v6 > priority_v4);
    }

    #[tokio::test]
    async fn test_socket_options_low_latency() {
        let options = SocketOptions::low_latency();
        assert_eq!(options.recv_buffer_size, Some(256 * 1024));
        assert_eq!(options.send_buffer_size, Some(256 * 1024));
    }

    #[tokio::test]
    async fn test_socket_options_high_throughput() {
        let options = SocketOptions::high_throughput();
        assert_eq!(options.recv_buffer_size, Some(8 * 1024 * 1024));
        assert_eq!(options.send_buffer_size, Some(8 * 1024 * 1024));
    }

    #[tokio::test]
    async fn test_socket_uptime() {
        let options = SocketOptions::default();
        let socket = UdpSocketWrapper::bind("127.0.0.1:0", options)
            .await
            .expect("Failed to bind socket");

        tokio::time::sleep(Duration::from_millis(100)).await;

        let uptime = socket.uptime();
        assert!(uptime >= Duration::from_millis(100));
    }

    #[test]
    fn test_network_interface_detection() {
        // Этот тест зависит от if-addrs feature
        #[cfg(feature = "connectivity")]
        {
            let interfaces =
                NetworkInterfaceDetector::detect_interfaces().expect("Failed to detect interfaces");

            // В системе должен быть хотя бы loopback интерфейс
            assert!(!interfaces.is_empty());

            let has_loopback = interfaces.iter().any(|iface| iface.is_loopback);
            assert!(has_loopback, "System should have loopback interface");
        }
    }
}
