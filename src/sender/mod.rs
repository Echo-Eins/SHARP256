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
use tokio::time::{sleep, timeout};

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
    file_manager: Arc<FileManager>,
    packet_buffer: Arc<PacketBuffer>,
    sao_system: Arc<SaoSystem>,
    state_manager: Arc<StateManager>,
    transfer_state: Arc<RwLock<TransferState>>,
    use_encryption: bool,
    use_gso: Arc<RwLock<bool>>,
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
        let file_manager = FileManager::open_for_send(file_path)?;
        file_manager.init_mmap()?;
        
        let file_name = file_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        let transfer_state = TransferState::new(
            file_name,
            file_manager.size(),
            true,
            peer_addr.to_string(),
        );
        
        // Инициализация NAT manager если включен
        #[cfg(feature = "nat-traversal")]
        let nat_manager = {
            let config = NatConfig::default();
            let mut manager = NatManager::new(config);
            
            match manager.initialize(&socket).await {
                Ok(network_info) => {
                    tracing::info!("Network info: {:?}", network_info);
                    
                    // Если у нас есть публичный адрес, сообщаем его
                    if let Some(public_addr) = network_info.public_addr {
                        tracing::info!("Public address available: {}", public_addr);
                    }
                    
                    // Подготавливаем соединение с пиром
                    if let Err(e) = manager.prepare_connection(&socket, peer_addr, true).await {
                        tracing::warn!("Failed to prepare connection: {}", e);
                    }
                    
                    Some(Arc::new(RwLock::new(manager)))
                }
                Err(e) => {
                    tracing::warn!("NAT traversal initialization failed: {}. Continuing without it.", e);
                    None
                }
            }
        };
        
        Ok(Self {
            socket: Arc::new(socket),
            peer_addr,
            file_manager: Arc::new(file_manager),
            packet_buffer: Arc::new(PacketBuffer::new()),
            sao_system: Arc::new(SaoSystem::new()),
            state_manager: Arc::new(StateManager::new()?),
            transfer_state: Arc::new(RwLock::new(transfer_state)),
            use_encryption,
            use_gso: Arc::new(RwLock::new(false)),
            #[cfg(feature = "nat-traversal")]
            nat_manager,
        })
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
        // Проверяем поддержку GSO
        *self.use_gso.write() = self.check_gso_support().await;
        
        // Проверяем, есть ли сохраненное состояние
        let file_name = self.file_manager.path()
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
    
    /// Начало новой передачи
    async fn new_transfer(&self) -> Result<()> {
        let local_ip = self.socket.local_addr()?.ip();
        
        // Получаем адрес для подключения (может быть публичным через NAT)
        let connectable_addr = self.get_connectable_address().await?;
        
        // Отправляем первичный ACK
        let initial_ack = InitialAck::new(
            self.file_manager.path().file_name().unwrap_or_default().to_string_lossy().to_string(),
            self.file_manager.size(),
            connectable_addr.ip(), // Используем connectable адрес вместо локального
            self.peer_addr.ip(),
            self.sao_system.batch_size(),
            self.use_encryption,
        );
        
        tracing::info!("Sending initial ACK with connectable address: {}", connectable_addr);
        
        let ack_bytes = bincode::serialize(&initial_ack)?;
        let mut header = PacketHeader::new(PacketType::Ack);
        header.payload_length = ack_bytes.len() as u32;
        
        let packet = Packet::new(header, ack_bytes);
        
        // Отправляем и ждем ответ
        for attempt in 0..3 {
            self.socket.send_to(&packet.to_bytes(), self.peer_addr).await?;
            
            let mut buffer = vec![0u8; 65536];
            match timeout(Duration::from_secs(10), self.socket.recv_from(&mut buffer)).await {
                Ok(Ok((size, addr))) if addr == self.peer_addr => {
                    let mut buf = BytesMut::from(&buffer[..size]);
                    if let Ok(response_packet) = Packet::from_bytes(&mut buf) {
                        if response_packet.header.packet_type == PacketType::Ack {
                            let response: InitialAckResponse = bincode::deserialize(&response_packet.payload)?;
                            if response.accept_transfer {
                                tracing::info!("Transfer accepted by receiver");
                                self.transfer_file().await?;
                                return Ok(());
                            } else {
                                anyhow::bail!("Transfer rejected: {:?}", response.reason);
                            }
                        }
                    }
                }
                _ => {
                    tracing::warn!("Initial ACK attempt {} failed", attempt + 1);
                }
            }
        }
        
        anyhow::bail!("Failed to establish connection with receiver")
    }
    
    /// Возобновление передачи
    async fn resume_transfer(&self, saved_state: TransferState) -> Result<()> {
        // Восстанавливаем состояние
        *self.transfer_state.write() = saved_state.clone();
        
        if let Some(sao_params) = saved_state.sao_params {
            self.sao_system.set_params(sao_params);
        }
        
        // Находим позицию в файле
        let resume_position = saved_state.find_resume_position(&self.file_manager)?
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
                .packet_sender_task(rx_packets, rx_hashes, packet_complete_sender, hash_complete_sender)
                .await
        });
        
        // Запускаем поток хеширования
        let hasher_self = self.clone();
        let hasher_handle = tokio::spawn(async move {
            hasher_self.hasher_task(tx_hashes, packet_complete).await
        });
        
        // Запускаем поток обработки ACK
        let ack_self = self.clone();
        let ack_handle = tokio::spawn(async move {
            ack_self.ack_handler_task().await
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
            self.packet_buffer.add_batch_hashes(current_batch, batch_hashes.clone());
            
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
                    self.socket.send_to(&packet.to_bytes(), self.peer_addr).await?;
                    
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
                    self.socket.send_to(&hash_packet.to_bytes(), self.peer_addr).await?;
                    
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
        let mut control_ack = ControlAck::new(batch_start, last_batch, self.sao_system.get_params());
        
        // Измеряем ping
        let ping_start = Instant::now();
        control_ack.ping_ms = 0.0; // Будет обновлено при получении ответа
        
        let ack_bytes = bincode::serialize(&control_ack)?;
        let mut header = PacketHeader::new(PacketType::Control);
        header.payload_length = ack_bytes.len() as u32;
        
        let packet = Packet::new(header, ack_bytes);
        self.socket.send_to(&packet.to_bytes(), self.peer_addr).await?;
        
        Ok(())
    }
    
    /// Задача обработки входящих ACK
    async fn ack_handler_task(self) -> Result<()> {
        let mut buffer = vec![0u8; 65536];
        let last_sao_update = 0u32;
        
        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, addr)) if addr == self.peer_addr => {
                    let mut buf = BytesMut::from(&buffer[..size]);
                    
                    if let Ok(packet) = Packet::from_bytes(&mut buf) {
                        match packet.header.packet_type {
                            PacketType::Control => {
                                let control_ack: ControlAck = bincode::deserialize(&packet.payload)?;
                                
                                // Обновляем SAO с данными от получателя
                                self.sao_system.update_from_ack(&control_ack);
                                
                                if control_ack.is_all_received() {
                                    // Все пакеты получены, очищаем буфер
                                    self.packet_buffer.clear_before_batch(control_ack.batch_range_end);
                                    tracing::info!("Batches {}-{} confirmed", 
                                        control_ack.batch_range_start, control_ack.batch_range_end);
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
        tracing::info!("Retransmitting {} packets and {} hash batches", 
            control_ack.lost_packets.len(), control_ack.lost_hashes.len());
        
        // Перезапрашиваем потерянные пакеты
        for lost in &control_ack.lost_packets {
            if let Some(packet) = self.packet_buffer.get_packet(lost.batch_number, lost.packet_number) {
                // Устанавливаем флаг перезапроса
                let mut retransmit_packet = packet.clone();
                retransmit_packet.header.flags |= packet_flags::RETRANSMIT;
                
                self.socket.send_to(&retransmit_packet.to_bytes(), self.peer_addr).await?;
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
                self.socket.send_to(&hash_packet.to_bytes(), self.peer_addr).await?;
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
            file_manager: self.file_manager.clone(),
            packet_buffer: self.packet_buffer.clone(),
            sao_system: self.sao_system.clone(),
            state_manager: self.state_manager.clone(),
            transfer_state: self.transfer_state.clone(),
            use_encryption: self.use_encryption,
            use_gso: self.use_gso.clone(),
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