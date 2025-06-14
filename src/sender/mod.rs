use anyhow::Result;
use blake3::Hasher;
use bytes::BytesMut;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep, timeout, interval};

use uuid::Uuid;
use rand::Rng;

use crate::buffer::PacketBuffer;
use crate::file::FileManager;
use crate::protocol::{ack::*, constants::*, packet::*};
use crate::sao::{BatchMetrics, SaoSystem};
use crate::state::{StateManager, TransferState};

#[cfg(feature = "nat-traversal")]
use crate::nat::{NatManager, NatConfig};

pub struct Sender {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    /// Effective address after NAT discovery
    effective_peer_addr: Arc<RwLock<SocketAddr>>,
    /// Unique connection identifier
    connection_id: String,
    file_manager: Arc<FileManager>,
    packet_buffer: Arc<PacketBuffer>,
    sao_system: Arc<SaoSystem>,
    state_manager: Arc<StateManager>,
    transfer_state: Arc<RwLock<TransferState>>,
    use_encryption: bool,
    use_gso: Arc<RwLock<bool>>,
    max_payload_size: Arc<RwLock<usize>>,
    /// Last activity timestamp for keep-alive
    last_activity: Arc<RwLock<Instant>>,
    fragmentation_checked: Arc<RwLock<bool>>,
    #[cfg(feature = "nat-traversal")]
    nat_manager: Option<Arc<RwLock<NatManager>>>,
}

impl Sender {
    pub async fn new(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        file_path: &Path,
        use_encryption: bool,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        let actual_local = socket.local_addr()?;
        tracing::info!("Sender socket bound to {}", actual_local);

        let connection_id = Uuid::new_v4().to_string();
        tracing::info!(
            "Connection {}: establishing from {} to {}",
            connection_id,
            actual_local,
            peer_addr
        );

        let file_manager = FileManager::open_for_send(file_path)?;
        file_manager.init_mmap()?;

        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let transfer_state =
            TransferState::new(file_name, file_manager.size(), true, peer_addr.to_string());

        // Инициализация NAT manager если включен
        #[cfg(feature = "nat-traversal")]
        let nat_manager = {
            let config = NatConfig::default();
            let mut manager = NatManager::new(config);

            match manager.initialize(&socket).await {
                Ok(network_info) => {
                    tracing::info!("=== NAT Detection Results ===");
                    tracing::info!("Local address: {}", network_info.local_addr);
                    tracing::info!("Public address: {:?}", network_info.public_addr);
                    tracing::info!("NAT type: {:?}", network_info.nat_type);
                    tracing::info!("UPnP available: {}", network_info.upnp_available);
                    tracing::info!("============================");

                    Some(Arc::new(RwLock::new(manager)))
                }
                Err(e) => {
                    if e.is_transient() {
                        tracing::warn!("Transient NAT init error: {}. Retrying once...", e);
                        match manager.initialize(&socket).await {
                            Ok(_) => {
                                tracing::info!("Retry succeeded");
                                Some(Arc::new(RwLock::new(manager)))
                            }
                            Err(e2) => {
                                tracing::warn!("NAT initialization retry failed: {}. Continuing without it.", e2);
                                None
                            }
                        }
                    } else {
                        tracing::error!("Permanent NAT init error: {}. Disabling NAT features.", e);
                        None
                    }
                }
            }
        };

        Ok(Self {
            socket: Arc::new(socket),
            peer_addr,
            effective_peer_addr: Arc::new(RwLock::new(peer_addr)),
            connection_id,
            file_manager: Arc::new(file_manager),
            packet_buffer: Arc::new(PacketBuffer::new()),
            sao_system: Arc::new(SaoSystem::new()),
            state_manager: Arc::new(StateManager::new()?),
            transfer_state: Arc::new(RwLock::new(transfer_state)),
            use_encryption,
            use_gso: Arc::new(RwLock::new(false)),
            max_payload_size: Arc::new(RwLock::new(MAX_PAYLOAD_SIZE_MTU)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            fragmentation_checked: Arc::new(RwLock::new(false)),
            #[cfg(feature = "nat-traversal")]
            nat_manager,
        })
    }

    /// Determine maximum allowed payload size and log the result.
    pub async fn detect_fragmentation(&self) -> Result<usize> {
        if *self.fragmentation_checked.read() {
            return Ok(*self.max_payload_size.read());
        }

        let info = crate::fragmentation::detect_max_payload(&self.socket, self.peer_addr).await?;
        *self.max_payload_size.write() = info.max_payload_size;
        let gso = info.max_payload_size > MAX_PAYLOAD_SIZE_MTU;
        *self.use_gso.write() = gso;
        *self.fragmentation_checked.write() = true;
        tracing::info!("Selected payload size: {} bytes", info.max_payload_size);
        Ok(info.max_payload_size)
    }

    /// Получение адреса для подключения (с учетом NAT)
    pub async fn get_connectable_address(&self) -> Result<SocketAddr> {
        #[cfg(feature = "nat-traversal")]
        {
            if let Some(nat_manager) = &self.nat_manager {
                if let Ok(addr) = nat_manager.read().get_connectable_address() {
                    return Ok(addr);
                }
            }
        }

        // Fallback на локальный адрес
        Ok(self.socket.local_addr()?)
    }

    fn ip_is_private(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => v4.is_private(),
            std::net::IpAddr::V6(v6) => v6.is_unique_local(),
        }
    }

    /// Запуск keep-alive механизма
    async fn start_keep_alive(&self) {
        let socket = self.socket.clone();
        let peer_addr = self.effective_peer_addr.clone();
        let last_activity = self.last_activity.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let last = *last_activity.read();
                if last.elapsed() > Duration::from_secs(25) {
                    let keep_alive = b"SHARP_KEEPALIVE";
                    let peer = *peer_addr.read();

                    if let Err(e) = socket.send_to(keep_alive, peer).await {
                        tracing::warn!("Keep-alive send failed: {}", e);
                    } else {
                        tracing::trace!("Keep-alive sent to {}", peer);
                    }
                }
            }
        });
    }

    /// Проверка поддержки GSO/GRO
    async fn check_gso_support(&self) -> bool {
        // Попытка отправки большого пакета для проверки GSO
        let test_packet = vec![0u8; MAX_PACKET_SIZE];
        match self.socket.send_to(&test_packet, self.peer_addr).await {
            Ok(_) => {
                tracing::info!("GSO/GRO support detected");
                true
            }
            Err(_) => {
                tracing::info!("GSO/GRO not supported, using standard MTU");
                false
            }
        }
    }

    /// Начало передачи файла
    pub async fn start_transfer(&self) -> Result<()> {
        // Проверяем максимальную допустимую фрагментацию
        self.detect_fragmentation().await?;

        // Проверяем, есть ли сохраненное состояние
        let file_name = self
            .file_manager
            .path()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        if let Some(saved_state) = self.state_manager.find_state(&file_name, true)? {
            // Предлагаем возобновить передачу
            tracing::info!("Found saved transfer state from {}", saved_state.timestamp);
            self.resume_transfer(saved_state).await?;
        } else {
            // Начинаем новую передачу
            self.new_transfer().await?;
        }

        Ok(())
    }

    /// Начало новой передачи с учетом NAT и возможным изменением адреса
    async fn new_transfer(&self) -> Result<()> {
        let local_addr = self.socket.local_addr()?;

        // Определяем адреса для использования
        let (sender_addr, local_sender_addr) = {
            #[cfg(feature = "nat-traversal")]
            if let Some(nat_manager) = &self.nat_manager {
                match nat_manager.read().get_connectable_address() {
                    Ok(connectable) => {
                        tracing::info!("Using connectable address: {}", connectable);
                        (connectable, Some(local_addr))
                    }
                    Err(_) => {
                        tracing::info!("Using local address: {}", local_addr);
                        (local_addr, None)
                    }
                }
            } else {
                (local_addr, None)
            }

            #[cfg(not(feature = "nat-traversal"))]
            (local_addr, None)
        };

        // Проверяем, не в одной ли мы сети
        let same_network = sender_addr.ip() == self.peer_addr.ip()
            || (Self::ip_is_private(&local_addr.ip()) && Self::ip_is_private(&self.peer_addr.ip()));

        if same_network {
            tracing::info!("Detected same network configuration");
        }

        // Подготавливаем NAT traversal при необходимости
        #[cfg(feature = "nat-traversal")]
        if !same_network {
            if let Some(nat_manager) = &self.nat_manager {
                tracing::info!("Preparing NAT traversal to {}", self.peer_addr);
                match nat_manager
                    .read()
                    .prepare_connection(&self.socket, self.peer_addr, true)
                    .await
                {
                    Ok(()) => {
                        tracing::info!("Waiting for hole punch confirmation...");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        if e.is_transient() {
                            tracing::warn!("Transient NAT preparation error: {}", e);
                        } else {
                            tracing::error!("Permanent NAT preparation error: {}", e);
                        }
                    }
                }
            }
        }

        // Отправляем первичный ACK
        let initial_ack = InitialAck::new(
            self.file_manager
                .path()
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            self.file_manager.size(),
            sender_addr,
            self.peer_addr,
            self.connection_id.clone(),
            local_sender_addr,
            self.sao_system.batch_size(),
            self.use_encryption,
        );

        tracing::info!("=== Initial Connection ===");
        tracing::info!("Sender address: {}", sender_addr);
        tracing::info!("Target receiver: {}", self.peer_addr);
        if let Some(local) = local_sender_addr {
            tracing::info!("Local address: {}", local);
        }
        tracing::info!("========================");

        let ack_bytes = bincode::serialize(&initial_ack)?;
        let mut header = PacketHeader::new(PacketType::Ack);
        header.payload_length = ack_bytes.len() as u32;
        let packet = Packet::new(header, ack_bytes);

        // Отправляем и ждем ответ. При неудаче делаем до 7 попыток с экспоненциальной
        // задержкой: старт 500 мс, удвоение после каждой попытки и максимум 3200 мс.
        // К каждой задержке добавляется случайный джиттер ±50 мс. Суммарное время
        // ожидания составляет около 39.5 секунд.
        for attempt in 0..7 {
            tracing::info!("Sending initial ACK (attempt {})", attempt + 1);
            let peer = *self.effective_peer_addr.read();
            self.socket.send_to(&packet.to_bytes(), peer).await?;

            let mut buffer = vec![0u8; 65536];
            match timeout(Duration::from_secs(5), self.socket.recv_from(&mut buffer)).await {
                Ok(Ok((size, addr))) => {
                    tracing::info!("Received response from {} ({} bytes)", addr, size);

                    // Обновляем effective peer address если NAT поменял
                    if addr != self.peer_addr {
                        tracing::info!(
                            "Peer address changed from {} to {} (NAT detected)",
                            self.peer_addr,
                            addr
                        );
                        *self.effective_peer_addr.write() = addr;
                    }

                    let mut buf = BytesMut::from(&buffer[..size]);
                    if let Ok(response_packet) = Packet::from_bytes(&mut buf) {
                        if response_packet.header.packet_type == PacketType::Ack {
                            let response: InitialAckResponse =
                                bincode::deserialize(&response_packet.payload)?;
                            if response.accept_transfer {
                                tracing::info!("Transfer accepted by receiver");
                                *self.last_activity.write() = Instant::now();
                                self.start_keep_alive().await;
                                self.transfer_file().await?;
                                return Ok(());
                            } else {
                                anyhow::bail!("Transfer rejected: {:?}", response.reason);
                            }
                        }
                    }
                }
                Err(_) => {
                    tracing::warn!("Timeout waiting for initial ACK response");
                    if attempt == 2 && local_sender_addr.is_some() {
                        tracing::info!("Trying direct local connection...");
                    }
                }
                _ => {}
            }

            // Рассчитываем базовую задержку с экспоненциальным ростом
            let mut delay = 500u64.saturating_mul(1u64 << attempt);
            delay = delay.min(3200);

            // Применяем случайный джиттер ±50 мс
            let jitter: i64 = rand::thread_rng().gen_range(-50..=50);
            let jittered = if jitter.is_negative() {
                delay.saturating_sub(jitter.unsigned_abs())
            } else {
                delay.saturating_add(jitter as u64)
            };

            sleep(Duration::from_millis(jittered)).await;
        }

        anyhow::bail!("Failed to establish connection with receiver after 7 attempts")
    }

    /// Возобновление передачи
    async fn resume_transfer(&self, saved_state: TransferState) -> Result<()> {
        // Восстанавливаем состояние
        *self.transfer_state.write() = saved_state.clone();

        if let Some(sao_params) = saved_state.sao_params {
            self.sao_system.set_params(sao_params);
        }

        // Находим позицию в файле
        let resume_position = saved_state
            .find_resume_position(&self.file_manager)?
            .unwrap_or(saved_state.bytes_transferred);

        tracing::info!("Resuming transfer from position {}", resume_position);

        // Отправляем специальный ACK о возобновлении
        // TODO: Реализовать протокол возобновления

        self.transfer_file().await
    }

    /// Основной процесс передачи файла
    async fn transfer_file(&self) -> Result<()> {
        let (tx_packets, rx_packets) = mpsc::channel::<Packet>(100);
        let (tx_hashes, rx_hashes) = mpsc::channel::<(u32, Vec<blake3::Hash>)>(10);

        let packet_complete = Arc::new(Notify::new());
        let hash_complete = Arc::new(Notify::new());

        // Запускаем поток сборки и отправки пакетов
        let sender_self = self.clone();
        let packet_complete_sender = packet_complete.clone();
        let hash_complete_sender = hash_complete.clone();
        let sender_handle = tokio::spawn(async move {
            sender_self
                .packet_sender_task(
                    rx_packets,
                    rx_hashes,
                    packet_complete_sender,
                    hash_complete_sender,
                )
                .await
        });

        // Запускаем поток хеширования
        let hasher_self = self.clone();
        let hasher_handle =
            tokio::spawn(async move { hasher_self.hasher_task(tx_hashes, packet_complete).await });

        // Запускаем поток обработки ACK
        let ack_self = self.clone();
        let ack_handle = tokio::spawn(async move { ack_self.ack_handler_task().await });
        });

        // Основной цикл чтения и фрагментации файла
        self.file_reader_task(tx_packets, hash_complete).await?;

        // Ждем завершения всех задач
        let _ = tokio::try_join!(sender_handle, hasher_handle, ack_handle)?;

        Ok(())
    }
    /// Задача хеширования данных с пайплайнингом
    async fn hasher_task(
        self,
        tx_hashes: mpsc::Sender<(u32, Vec<blake3::Hash>)>,
        packet_complete: Arc<Notify>,
    ) -> Result<()> {
        let mut current_batch = 0u32;
        let mut batch_hashes = Vec::new();
        let mut hasher = Hasher::new();

        loop {
            // Ждем сигнал о готовности пакетов партии
            packet_complete.notified().await;

            let batch_size = self.sao_system.batch_size();

            // Хешируем все пакеты текущей партии
            for packet_num in 0..batch_size {
                if let Some(packet) = self.packet_buffer.get_packet(current_batch, packet_num) {
                    hasher.update(&packet.payload);
                    let hash = hasher.finalize();
                    batch_hashes.push(hash);
                    hasher.reset();

                    // Начинаем упреждающее хеширование следующей партии
                    if packet_num == batch_size - 1 {
                        tokio::spawn({
                            let buffer = self.packet_buffer.clone();
                            let next_batch = current_batch + 1;
                            async move {
                                // Упреждающе загружаем данные следующей партии
                                for i in 0..5 {
                                    let _ = buffer.get_packet(next_batch, i);
                                }
                            }
                        });
                    }
                }
            }

            // Переворачиваем стек хешей для удобства проверки
            batch_hashes.reverse();

            // Сохраняем хеши в буфер
            self.packet_buffer
                .add_batch_hashes(current_batch, batch_hashes.clone());

            // Отправляем хеши
            let hashes_to_send = batch_hashes.clone();
            let batch_to_send = current_batch;
            let tx = tx_hashes.clone();

            tokio::spawn(async move {
                let _ = tx.send((batch_to_send, hashes_to_send)).await;
            });

            batch_hashes.clear();
            current_batch += 1;
        }
    }

    /// Задача отправки пакетов и хешей
    async fn packet_sender_task(
        self,
        mut rx_packets: mpsc::Receiver<Packet>,
        mut rx_hashes: mpsc::Receiver<(u32, Vec<blake3::Hash>)>,
        packet_complete: Arc<Notify>,
        hash_complete: Arc<Notify>,
    ) -> Result<()> {
        let mut packets_in_batch = 0u16;
        let mut current_batch = 0u32;

        loop {
            tokio::select! {
                // Обработка пакетов данных
                Some(packet) = rx_packets.recv() => {
                    let is_last = packet.header.is_last_in_batch();

                    // Отправляем пакет
                    let peer = *self.effective_peer_addr.read();
                    self.socket.send_to(&packet.to_bytes(), peer).await?;

                    packets_in_batch += 1;

                    // Если это последний пакет в партии
                    if is_last {
                        // Сигнализируем потоку хеширования
                        packet_complete.notify_one();

                        // Добавляем метрику партии
                        let metrics = BatchMetrics::new(
                            current_batch,
                            packets_in_batch,
                            packets_in_batch as u64 * packet.header.payload_length as u64,
                        );
                        self.sao_system.add_batch_metrics(metrics);

                        packets_in_batch = 0;
                        current_batch += 1;
                    }
                }

                // Обработка хешей
                Some((batch_num, hashes)) = rx_hashes.recv() => {
                    // Создаем пакет с хешами
                    let hash_bytes: Vec<u8> = hashes.iter()
                        .flat_map(|h| h.as_bytes())
                        .copied()
                        .collect();

                    let mut header = PacketHeader::new(PacketType::Hash);
                    header.batch_number = batch_num;
                    header.payload_length = hash_bytes.len() as u32;

                    let hash_packet = Packet::new(header, hash_bytes);

                    // Отправляем пакет с хешами
                    let peer = *self.effective_peer_addr.read();
                    self.socket.send_to(&hash_packet.to_bytes(), peer).await?;

                    // Сигнализируем о готовности к следующей партии
                    hash_complete.notify_one();

                    // Проверяем, нужно ли отправить контрольный ACK
                    if (batch_num + 1) % BATCHES_BEFORE_ACK == 0 {
                        self.send_control_ack(batch_num).await?;
                    }
                }

                else => break,
            }
        }

        Ok(())
    }

    /// Отправка контрольного ACK
    async fn send_control_ack(&self, last_batch: u32) -> Result<()> {
        let batch_start = last_batch.saturating_sub(BATCHES_BEFORE_ACK - 1);
        let mut control_ack =
            ControlAck::new(batch_start, last_batch, self.sao_system.get_params());

        // Измеряем ping
        let ping_start = Instant::now();
        control_ack.ping_ms = 0.0; // Будет обновлено при получении ответа

        let ack_bytes = bincode::serialize(&control_ack)?;
        let mut header = PacketHeader::new(PacketType::Control);
        header.payload_length = ack_bytes.len() as u32;

        let packet = Packet::new(header, ack_bytes);
        let peer = *self.effective_peer_addr.read();
        self.socket.send_to(&packet.to_bytes(), peer).await?;

        Ok(())
    }

    /// Задача обработки входящих ACK
    async fn ack_handler_task(self) -> Result<()> {
        let mut buffer = vec![0u8; 65536];

        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, addr)) => {
                    *self.last_activity.write() = Instant::now();

                    let expected_peer = *self.effective_peer_addr.read();
                    if addr != expected_peer {
                        tracing::warn!(
                            "Received packet from unexpected address: {} (expected {})",
                            addr,
                            expected_peer
                        );

                        if addr.ip() == expected_peer.ip() || addr.ip() == self.peer_addr.ip() {
                            tracing::info!("Updating peer address to {}", addr);
                            *self.effective_peer_addr.write() = addr;
                        } else {
                            continue;
                        }
                    }

                    let mut buf = BytesMut::from(&buffer[..size]);

                    if let Ok(packet) = Packet::from_bytes(&mut buf) {
                        match packet.header.packet_type {
                            PacketType::Control => {
                                let control_ack: ControlAck =
                                    bincode::deserialize(&packet.payload)?;

                                // Обновляем SAO с данными от получателя
                                self.sao_system.update_from_ack(&control_ack);

                                if control_ack.is_all_received() {
                                    // Все пакеты получены, очищаем буфер
                                    self.packet_buffer
                                        .clear_before_batch(control_ack.batch_range_end);
                                    tracing::info!(
                                        "Batches {}-{} confirmed",
                                        control_ack.batch_range_start,
                                        control_ack.batch_range_end
                                    );
                                } else {
                                    // Есть потерянные пакеты, перезапрашиваем
                                    self.handle_retransmit_request(&control_ack).await?;
                                }

                                // Пересчитываем параметры SAO при необходимости
                                if self.sao_system.recalculate(control_ack.batch_range_end) {
                                    tracing::info!("SAO parameters updated");
                                }
                            }

                            PacketType::Ack => {
                                let final_ack: FinalAck = bincode::deserialize(&packet.payload)?;
                                if final_ack.transfer_complete {
                                    tracing::info!("Transfer completed successfully");
                                    tracing::info!("Average speed: {:.2} Mbps", final_ack.average_speed_mbps);

                                    // Удаляем файл состояния
                                    if let Ok(state_path) = self.state_manager.save_state(&self.transfer_state.read()) {
                                        TransferState::cleanup(&state_path)?;
                                    }

                                    return Ok(());
                                }
                            }

                            _ => {}
                        }
                    }
                }

                Ok(_) => {} // Игнорируем пакеты от других адресов

                Err(e) => {
                    tracing::error!("Socket error: {}", e);
                    // Сохраняем состояние при ошибке
                    self.save_state_on_error().await?;
                    return Err(e.into());
                }
            }
        }
    }
    
    /// Обработка запроса на перезапрос пакетов
    async fn handle_retransmit_request(&self, control_ack: &ControlAck) -> Result<()> {
        tracing::info!(
            "Retransmitting {} packets and {} hash batches",
            control_ack.lost_packets.len(),
            control_ack.lost_hashes.len()
        );
        
        // Перезапрашиваем потерянные пакеты
        for lost in &control_ack.lost_packets {
            if let Some(packet) = self
                .packet_buffer
                .get_packet(lost.batch_number, lost.packet_number)
            {
                // Устанавливаем флаг перезапроса
                let mut retransmit_packet = packet.clone();
                retransmit_packet.header.flags |= packet_flags::RETRANSMIT;

                let peer = *self.effective_peer_addr.read();
                self.socket.send_to(&retransmit_packet.to_bytes(), peer).await?;

                sleep(Duration::from_micros(100)).await; // Небольшая задержка между пакетами
            }
        }
        
        // Перезапрашиваем потерянные хеши
        for batch_num in &control_ack.lost_hashes {
            if let Some(hashes) = self.packet_buffer.get_batch_hashes(*batch_num) {
                let hash_bytes: Vec<u8> = hashes.iter()
                    .flat_map(|h| h.as_bytes())
                    .copied()
                    .collect();
                
                let mut header = PacketHeader::new(PacketType::Hash);
                header.batch_number = *batch_num;
                header.payload_length = hash_bytes.len() as u32;
                header.flags |= packet_flags::RETRANSMIT;
                
                let hash_packet = Packet::new(header, hash_bytes);
                let peer = *self.effective_peer_addr.read();
                self.socket.send_to(&hash_packet.to_bytes(), peer).await?;
            }
        }
        
        Ok(())
    }
    
    /// Сохранение состояния при ошибке
    async fn save_state_on_error(&self) -> Result<()> {
        let state = self.transfer_state.read().clone();
        let state_path = self.state_manager.save_state(&state)?;
        tracing::info!("Transfer state saved to {:?}", state_path);
        Ok(())
    }

    /// Чтение файла и отправка пакетов партиями
    async fn file_reader_task(
        &self,
        tx_packets: mpsc::Sender<Packet>,
        hash_complete: Arc<Notify>,
    ) -> Result<()> {
        let file_size = self.file_manager.size();
        let mut offset = 0u64;
        let mut batch_number = 0u32;

        while offset < file_size {
            let batch_size = self.sao_system.batch_size();
            for packet_idx in 0..batch_size {
                if offset >= file_size {
                    break;
                }

                let payload_limit = if *self.use_gso.read() {
                    MAX_PAYLOAD_SIZE_GSO
                } else {
                    MAX_PAYLOAD_SIZE_MTU
                };

                let remaining = file_size - offset;
                let to_read = remaining.min(payload_limit as u64) as usize;
                let data = self.file_manager.read_at(offset, to_read)?;

                let mut header = PacketHeader::new(PacketType::Data);
                header.batch_number = batch_number;
                header.packet_in_batch = packet_idx;
                header.total_packets = batch_size;
                header.payload_length = data.len() as u32;
                if packet_idx == batch_size - 1 || offset + to_read as u64 >= file_size {
                    header.set_last_in_batch();
                }

                let packet = Packet::new(header.clone(), data);
                self.packet_buffer.add_packet(batch_number, packet_idx, packet.clone());
                tx_packets.send(packet).await?;
                offset += to_read as u64;
            }

            // Ждем отправки хешей перед продолжением
            hash_complete.notified().await;
            batch_number += 1;
        }

        Ok(())
    }
}

impl Clone for Sender {
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            peer_addr: self.peer_addr,
            effective_peer_addr: self.effective_peer_addr.clone(),
            connection_id: self.connection_id.clone(),
            file_manager: self.file_manager.clone(),
            packet_buffer: self.packet_buffer.clone(),
            sao_system: self.sao_system.clone(),
            state_manager: self.state_manager.clone(),
            transfer_state: self.transfer_state.clone(),
            use_encryption: self.use_encryption,
            use_gso: self.use_gso.clone(),
            max_payload_size: self.max_payload_size.clone(),
            last_activity: self.last_activity.clone(),
            fragmentation_checked: self.fragmentation_checked.clone(),
            #[cfg(feature = "nat-traversal")]
            nat_manager: self.nat_manager.clone(),
        }
    }
}

// Cleanup при завершении
impl Drop for Sender {
    fn drop(&mut self) {
        #[cfg(feature = "nat-traversal")]
        {
            // Очищаем NAT маппинги
            if let Some(nat_manager) = &self.nat_manager {
                let client = nat_manager.write().take_upnp_client();
                if let Some(mut c) = client {
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        handle.spawn(async move {
                            if let Err(e) = c.cleanup_all().await {
                                tracing::warn!("Failed to cleanup NAT mappings: {}", e);
                            }
                        });
                    }
                }
            }
        }
    }
}