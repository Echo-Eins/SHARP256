use anyhow::Result;
use blake3::{Hash, Hasher};
use bytes::BytesMut;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use tokio::time::interval;

use crate::buffer::ReceiveBuffer;
use crate::file::FileManager;
use crate::protocol::{ack::*, constants::*, packet::*};
use crate::sao::SaoSystem;
use crate::state::{StateManager, TransferState};

#[cfg(feature = "nat-traversal")]
use crate::nat::{NatManager, NatConfig};

pub struct Receiver {
    socket: Arc<UdpSocket>,
    peer_addr: Arc<RwLock<Option<SocketAddr>>>,
    peer_local_addr: Arc<RwLock<Option<SocketAddr>>>,
    file_manager: Arc<RwLock<Option<Arc<FileManager>>>>,
    receive_buffer: Arc<ReceiveBuffer>,
    sao_system: Arc<SaoSystem>,
    state_manager: Arc<StateManager>,
    transfer_state: Arc<RwLock<Option<TransferState>>>,
    output_dir: PathBuf,
    start_time: Arc<RwLock<Option<Instant>>>,
    last_activity: Arc<RwLock<Option<Instant>>>,
    #[cfg(feature = "nat-traversal")]
    nat_manager: Option<Arc<RwLock<NatManager>>>,
}

impl Receiver {
    pub async fn new(local_addr: SocketAddr, output_dir: PathBuf) -> Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        let actual_local = socket.local_addr()?;

        tracing::info!("Receiver socket bound to {}", actual_local);

        // Создаем директорию для приема файлов
        tokio::fs::create_dir_all(&output_dir).await?;

        // Инициализация NAT manager
        #[cfg(feature = "nat-traversal")]
        let nat_manager = {
            let config = NatConfig::default();
            let mut manager = NatManager::new(config);

            match manager.initialize(&socket).await {
                Ok(network_info) => {
                    tracing::info!("Receiver network info: {:?}", network_info);

                    // Для получателя особенно важен UPnP для входящих соединений
                    if network_info.upnp_available && network_info.mapped_port.is_some() {
                        tracing::info!("UPnP port mapping active on port {}", 
                            network_info.mapped_port.unwrap());
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
            peer_addr: Arc::new(RwLock::new(None)),
            peer_local_addr: Arc::new(RwLock::new(None)),
            file_manager: Arc::new(RwLock::new(None)),
            receive_buffer: Arc::new(ReceiveBuffer::new()),
            sao_system: Arc::new(SaoSystem::new()),
            state_manager: Arc::new(StateManager::new()?),
            transfer_state: Arc::new(RwLock::new(None)),
            output_dir,
            start_time: Arc::new(RwLock::new(None)),
            last_activity: Arc::new(RwLock::new(None)),
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

    /// Запуск приема файлов
    pub async fn start(&self) -> Result<()> {
        let listen_addr = self.socket.local_addr()?;
        tracing::info!("=== Receiver Status ===");
        tracing::info!("Listening on: {}", listen_addr);

        #[cfg(feature = "nat-traversal")]
        {
            if let Ok(connectable) = self.get_connectable_address().await {
                tracing::info!("External address: {}", connectable);
                if connectable != listen_addr {
                    tracing::info!("Behind NAT - external connections should use: {}", connectable);
                }
            }
        }
        tracing::info!("Waiting for incoming transfers...");
        tracing::info!("======================");

        let mut buffer = vec![0u8; 65536];
        let mut packet_count = 0u64;
        let mut last_log = Instant::now();

        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, addr)) => {
                    packet_count += 1;

                    if last_log.elapsed() > Duration::from_secs(5) {
                        if let Some(peer) = *self.peer_addr.read() {
                            tracing::info!("Active transfer - packets recieved: {}, current reer: {}", packet_count, peer);
                        }
                        last_log = Instant::now();
                    }
                    if packet_count <= 10 {
                        tracing::debug!("Packet #{} from {} ({} bytes)", packet_count, addr, size);
                    }

                    if size == 15 && &buffer[..15] == b"SHARP_KEEPALIVE" {
                        tracing::trace!("Keep-alive received from {}", addr);
                        continue;
                    }

                    if size >= 16 && size <= 20 {
                        if &buffer[..12] == b"SHARP_PUNCH_" {
                            tracing::debug!("Hole punch packet from {}", addr);
                            let _ = self.socket.send_to(b"SHARP_PUNCH_ACK", addr).await;
                            continue;
                        }
                    }


                    let mut buf = BytesMut::from(&buffer[..size]);

                    if let Ok(packet) = Packet::from_bytes(&mut buf) {

                        match packet.header.packet_type {
                            PacketType::Ack => {
                                // Получен первичный ACK - начало новой передачи
                                if self.peer_addr.read().is_none() {
                                    tracing::info!("New transfer request from {}", addr);
                                    self.handle_initial_ack(packet, addr).await?;
                                } else {
                                    tracing::debug!("Ignoring ACK - transfer already in progress!")

                                }
                            }

                            PacketType::Data | PacketType::Hash | PacketType::Control => {
                                let peer_opt = *self.peer_addr.read();
                                let peer_local_opt = *self.peer_local_addr.read();

                                let mut is_valid_peer = if let Some(peer) = peer_opt {
                                    addr == peer || (peer_local_opt.is_some() && addr == peer_local_opt.unwrap())
                                } else {
                                    false
                                };

                                if !is_valid_peer {
                                    if let Some(peer) = peer_opt {
                                        if addr.ip() == peer.ip() && packet.header.magic_number == MAGIC_NUMBER {
                                            tracing::info!("Updating peer port from {} to {}", peer, addr);
                                            *self.peer_addr.write() = Some(addr);
                                            is_valid_peer = true;
                                        }
                                    }
                                }

                                if is_valid_peer {
                                    if Some(addr) != peer_opt {
                                        tracing::info!("Peer address updated from {:?} to {}", peer_opt, addr);
                                        *self.peer_addr.write() = Some(addr);
                                    }

                                    *self.last_activity.write() = Some(Instant::now());
                                    self.handle_transfer_packet(packet).await?;
                                } else {
                                    tracing::trace!("Ignoring packet from unexpected address: {}", addr);

                                }
                            }

                            PacketType::Resume => {
                                // Обработка запроса на возобновление
                                tracing::info!("Resume request from {}", addr);
                                self.handle_resume_request(packet, addr).await?;
                            }

                            _ => {
                                tracing::debug!("Unknown packet type from {}", addr);
                            }
                        }
                    } else {
                        tracing::trace!("Failed to parse packet from {}", addr);
                        }
                    }

                Err(e) => {
                    tracing::error!("Socket error: {}", e);
                    self.save_state_on_error().await?;
                }
            }
        }
    }

    /// Обработка первичного ACK
    async fn handle_initial_ack(&self, packet: Packet, sender_addr: SocketAddr) -> Result<()> {
        let initial_ack: InitialAck = bincode::deserialize(&packet.payload)?;

        tracing::info!(
            "Connection {}: establishing from {} to {}",
            initial_ack.connection_id,
            sender_addr,
            self.socket.local_addr()?
        );

        tracing::info!("=== Transfer Request ===");
        tracing::info!("From: {}", sender_addr);
        tracing::info!("Sender claims address: {}", initial_ack.sender_addr);
        if let Some(local) = initial_ack.local_sender_addr {
            tracing::info!("Sender local address: {}", local);
        }
        tracing::info!("File: {}", initial_ack.file_name);
        tracing::info!("Size: {} bytes ({:.2} MB)", initial_ack.file_size, initial_ack.file_size as f64 / 1024.0 / 1024.0);
        tracing::info!("=======================");

        let response_addr = if sender_addr != initial_ack.sender_addr {
            tracing::info!("NAT detected: actual address {} differs from claimed {}", sender_addr, initial_ack.sender_addr);
            sender_addr
        } else {
            sender_addr
        };

        // Подготавливаем NAT для соединения с отправителем
        #[cfg(feature = "nat-traversal")]
        {
            if let Some(nat_manager) = &self.nat_manager {
                tracing::info!("Preparing NAT connection to {}", response_addr);
                if let Err(e) = nat_manager.read().prepare_connection(&self.socket, response_addr, false).await {
                    tracing::warn!("Failed to prepare NAT connection: {}", e);
                }
            }
        }

        // Проверяем доступное место на диске
        let available_space = FileManager::check_disk_space()?;
        if available_space < initial_ack.file_size {
            let response = InitialAckResponse {
                accept_transfer: false,
                reason: Some(format!("Not enough disk space. Available: {} bytes", available_space)),
            };
            self.send_initial_response(response, sender_addr).await?;
            return Ok(());
        }

        // Создаем файл для приема
        let file_path = self.output_dir.join(&initial_ack.file_name);
        let file_manager = FileManager::create_for_receive(&file_path, initial_ack.file_size)?;
        file_manager.init_mmap()?;

        // Сохраняем информацию о передаче
        *self.peer_addr.write() = Some(response_addr);
        *self.peer_local_addr.write() = initial_ack.local_sender_addr;
        *self.file_manager.write() = Some(Arc::new(file_manager));
        *self.start_time.write() = Some(Instant::now());
        *self.last_activity.write() = Some(Instant::now());

        // Инициализируем состояние передачи
        let transfer_state = TransferState::new(
            initial_ack.file_name.clone(),
            initial_ack.file_size,
            false,
            response_addr.to_string(),
        );
        *self.transfer_state.write() = Some(transfer_state);

        // Устанавливаем начальные параметры SAO
        let mut sao_params = self.sao_system.get_params();
        sao_params.batch_size = initial_ack.batch_size;
        self.sao_system.set_params(sao_params);

        // Отправляем подтверждение
        let response = InitialAckResponse {
            accept_transfer: true,
            reason: None,
        };
        tracing::info!("Accepting transfer, sending response to {}", response_addr);
        self.send_initial_response(response, response_addr).await?;

        self.start_connection_monitor().await;

        // Запускаем обработку передачи
        self.start_transfer_processing().await?;

        Ok(())
    }

    /// Отправка ответа на первичный ACK
    async fn send_initial_response(&self, response: InitialAckResponse, addr: SocketAddr) -> Result<()> {
        let response_bytes = bincode::serialize(&response)?;
        let mut header = PacketHeader::new(PacketType::Ack);
        header.payload_length = response_bytes.len() as u32;

        let packet = Packet::new(header, response_bytes);
        self.socket.send_to(&packet.to_bytes(), addr).await?;

        Ok(())
    }

    /// Мониторинг активности соединения
    async fn start_connection_monitor(&self) {
        let last_activity = self.last_activity.clone();
        let peer_addr = self.peer_addr.clone();

        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(10));

            loop {
                check_interval.tick().await;

                if let Some(last) = *last_activity.read() {
                    let elapsed = last.elapsed();
                    if elapsed > Duration::from_secs(60) {
                        if let Some(peer) = *peer_addr.read() {
                            tracing::warn!("No activity from {} for {} seconds", peer, elapsed.as_secs());
                        }
                    }
                }
            }
        });
    }

    /// Запуск обработки передачи
    async fn start_transfer_processing(&self) -> Result<()> {
        let (tx_verify, rx_verify) = mpsc::channel::<(u32, Vec<Packet>, Vec<Hash>)>(10);
        let write_complete = Arc::new(Notify::new());

        // Запускаем поток проверки и записи
        let verifier_self = self.clone();
        let write_complete_ver = write_complete.clone();
        let verifier_handle = tokio::spawn(async move {
            verifier_self.verifier_task(rx_verify, write_complete_ver).await
        });

        // Запускаем поток сборки партий
        let assembler_self = self.clone();
        let assembler_handle = tokio::spawn(async move {
            assembler_self.batch_assembler_task(tx_verify, write_complete).await
        });

        // Ждем завершения
        let _ = tokio::try_join!(verifier_handle, assembler_handle)?;

        Ok(())
    }

    /// Обработка пакетов передачи
    async fn handle_transfer_packet(&self, packet: Packet) -> Result<()> {
        match packet.header.packet_type {
            PacketType::Data => {
                // Добавляем пакет в буфер
                if let Err(e) = self.receive_buffer.add_data_packet(packet) {
                    tracing::warn!("Failed to add data packet: {}", e);
                }
            }

            PacketType::Hash => {
                // Извлекаем хеши из пакета
                let hash_size = blake3::OUT_LEN;
                let hash_count = packet.payload.len() / hash_size;
                let mut hashes = Vec::with_capacity(hash_count);

                for i in 0..hash_count {
                    let start = i * hash_size;
                    let end = start + hash_size;
                    if let Ok(hash_bytes) = packet.payload[start..end].try_into() {
                        hashes.push(Hash::from_bytes(hash_bytes));
                    }
                }

                // Переворачиваем обратно (были перевернуты отправителем)
                hashes.reverse();

                if let Err(e) = self.receive_buffer.add_batch_hashes(packet.header.batch_number, hashes) {
                    tracing::warn!("Failed to add batch hashes: {}", e);
                }
            }

            PacketType::Control => {
                // Получен контрольный ACK от отправителя
                self.handle_control_ack(packet).await?;
            }

            _ => {}
        }

        Ok(())
    }

    /// Задача сборки и проверки партий
    async fn batch_assembler_task(
        self,
        tx_verify: mpsc::Sender<(u32, Vec<Packet>, Vec<Hash>)>,
        write_complete: Arc<Notify>,
    ) -> Result<()> {
        let mut processed_batches = 0u32;
        let mut check_interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            check_interval.tick().await;

            // Очищаем устаревшие партии
            self.receive_buffer.cleanup_expired();

            // Проверяем завершенные партии
            for batch_num in processed_batches.. {
                if let Some((packets, hashes)) = self.receive_buffer.get_completed_batch(batch_num) {
                    // Отправляем на проверку
                    if tx_verify.send((batch_num, packets, hashes)).await.is_err() {
                        break;
                    }

                    // Удаляем обработанную партию
                    self.receive_buffer.remove_batch(batch_num);
                    processed_batches = batch_num + 1;

                    // Ждем завершения записи
                    write_complete.notified().await;
                } else {
                    break;
                }
            }

            // Проверяем, завершена ли передача
            let should_finalize = {
                let state_opt = self.transfer_state.read();
                let fm_opt = self.file_manager.read();
                if let (Some(state), Some(fm)) = (&*state_opt, &*fm_opt) {
                    state.bytes_transferred >= fm.size()
                } else {
                    false
                }
            };
            if should_finalize {
                self.finalize_transfer().await?;
                return Ok(());
            }
        }
    }

    /// Задача проверки хешей и записи данных с асинхронной записью
    async fn verifier_task(
        self,
        mut rx_verify: mpsc::Receiver<(u32, Vec<Packet>, Vec<Hash>)>,
        write_complete: Arc<Notify>,
    ) -> Result<()> {
        let mut lost_packets = Vec::new();
        let mut lost_hashes = Vec::new();

        // Канал для асинхронной записи
        let (write_tx, mut write_rx) = mpsc::channel::<WriteTask>(32);

        // Запускаем поток асинхронной записи
        let file_manager = self.file_manager.clone();
        let write_handle = tokio::spawn(async move {
            while let Some(task) = write_rx.recv().await {
                let fm_opt = file_manager.read().clone();
                if let Some(fm) = fm_opt {
                    match fm.write_at_async(task.offset, &task.data).await {
                        Ok(()) => {
                            // Периодически синхронизируем на диск
                            if task.sync {
                                let _ = fm.sync_async().await;
                            }
                        }
                        Err(e) => {
                            tracing::error!("Write error at offset {}: {}", task.offset, e);
                        }
                    }
                }
            }
        });

        while let Some((batch_num, packets, expected_hashes)) = rx_verify.recv().await {
            let mut batch_valid = true;
            let mut write_tasks = Vec::new();

            // Проверяем хеши пакетов
            for (i, packet) in packets.iter().enumerate() {
                let mut hasher = Hasher::new();
                hasher.update(&packet.payload);
                let computed_hash = hasher.finalize();

                if i < expected_hashes.len() && computed_hash != expected_hashes[i] {
                    tracing::warn!("Hash mismatch for batch {} packet {}", batch_num, i);
                    lost_packets.push(LostPacket::new(batch_num, i as u16));
                    batch_valid = false;
                }
            }

            // Если хешей меньше, чем пакетов
            if expected_hashes.len() < packets.len() {
                lost_hashes.push(batch_num);
                batch_valid = false;
            }

            // Подготавливаем задачи записи, если партия валидна
            if batch_valid {
                for packet in &packets {
                    let offset = packet.header.calculate_file_offset(self.sao_system.batch_size());
                    write_tasks.push(WriteTask {
                        offset,
                        data: packet.payload.clone(),
                        sync: packet.header.is_last_in_batch(), // Синхронизируем в конце партии
                    });

                    // Обновляем состояние
                    if let Some(state) = &mut *self.transfer_state.write() {
                        state.update_progress(
                            packet.header.batch_number,
                            packet.header.packet_in_batch,
                            packet.payload.len() as u64,
                            Some(&packet.payload),
                        );
                    }
                }

                // Отправляем задачи на запись асинхронно
                for task in write_tasks {
                    if write_tx.send(task).await.is_err() {
                        tracing::error!("Write channel closed");
                        break;
                    }
                }
            }

            // Сигнализируем о завершении обработки партии
            write_complete.notify_one();

            // Проверяем, нужно ли отправить контрольный ACK
            if (batch_num + 1) % BATCHES_BEFORE_ACK == 0 {
                self.send_control_ack_response(
                    batch_num.saturating_sub(BATCHES_BEFORE_ACK - 1),
                    batch_num,
                    &lost_packets,
                    &lost_hashes,
                ).await?;

                // Очищаем списки после отправки
                lost_packets.clear();
                lost_hashes.clear();
            }
        }

        // Закрываем канал записи и ждем завершения
        drop(write_tx);
        let _ = write_handle.await;

        Ok(())
    }

    /// Обработка контрольного ACK от отправителя
    async fn handle_control_ack(&self, packet: Packet) -> Result<()> {
        let control_ack: ControlAck = bincode::deserialize(&packet.payload)?;

        // Обновляем параметры SAO
        self.sao_system.set_params(control_ack.sao_params);

        Ok(())
    }

    /// Отправка контрольного ACK получателя
    async fn send_control_ack_response(
        &self,
        batch_start: u32,
        batch_end: u32,
        lost_packets: &[LostPacket],
        lost_hashes: &[u32],
    ) -> Result<()> {
        let peer_opt = *self.peer_addr.read();
        if let Some(peer) = peer_opt {
            let mut control_ack = ControlAck::new(batch_start, batch_end, self.sao_system.get_params());

            // Добавляем потерянные пакеты
            control_ack.lost_packets = lost_packets.to_vec();
            control_ack.lost_hashes = lost_hashes.to_vec();

            // Измеряем ping (RTT). Для простоты оцениваем его как нулевой
            control_ack.ping_ms = 0.0; // TODO: Реализовать измерение

            let ack_bytes = bincode::serialize(&control_ack)?;
            let mut header = PacketHeader::new(PacketType::Control);
            header.payload_length = ack_bytes.len() as u32;

            let packet = Packet::new(header, ack_bytes);
            self.socket.send_to(&packet.to_bytes(), peer).await?;

            tracing::info!("Sent control ACK for batches {}-{}, lost packets: {}, lost hashes: {}",
                batch_start, batch_end, lost_packets.len(), lost_hashes.len());
        }

        Ok(())
    }

    /// Обработка запроса на возобновление передачи
    async fn handle_resume_request(&self, packet: Packet, sender_addr: SocketAddr) -> Result<()> {
        let resume_ack: crate::protocol::ack::ResumeAck = bincode::deserialize(&packet.payload)?;

        tracing::info!("Received resume request from {} for file {}", sender_addr, resume_ack.file_name);

        // Проверяем, есть ли у нас состояние для этого файла
        if let Some(saved_state) = self.state_manager.find_state(&resume_ack.file_name, false)? {
            // Проверяем совпадение параметров
            if saved_state.file_size == resume_ack.file_size &&
                saved_state.resume_token == resume_ack.resume_token &&
                saved_state.peer_address == sender_addr.to_string() {

                // Проверяем существование частично загруженного файла
                let file_path = self.output_dir.join(&resume_ack.file_name);
                if file_path.exists() {
                    // Открываем существующий файл
                    let file_manager = FileManager::open_for_send(&file_path)?;
                    file_manager.init_mmap()?;

                    let existing_size = saved_state.bytes_transferred.min(file_manager.size());
                    if existing_size > 0 {
                        let existing_data = file_manager.read_at(0, existing_size as usize)?;
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(&existing_data);
                        let partial_hash = hasher.finalize().to_string();

                        // Сравниваем хеши (если есть)
                        let hash_match = resume_ack.partial_file_hash == "unknown" ||
                            resume_ack.partial_file_hash == partial_hash;

                        if hash_match {
                            // Можем возобновить
                            let response = crate::protocol::ack::ResumeAckResponse {
                                can_resume: true,
                                resume_from_batch: saved_state.last_batch_number,
                                resume_from_packet: saved_state.last_packet_in_batch + 1,
                                reason: None,
                            };

                            // Восстанавливаем состояние
                            *self.peer_addr.write() = Some(sender_addr);
                            *self.file_manager.write() = Some(Arc::new(file_manager));
                            *self.transfer_state.write() = Some(saved_state);
                            *self.start_time.write() = Some(Instant::now());

                            self.send_resume_response(response, sender_addr).await?;

                            // Запускаем обработку передачи
                            self.start_transfer_processing().await?;

                            return Ok(());
                        }
                    }
                }
            }
        }

        // Не можем возобновить
        let response = crate::protocol::ack::ResumeAckResponse {
            can_resume: false,
            resume_from_batch: 0,
            resume_from_packet: 0,
            reason: Some("Cannot resume: state mismatch or file not found".to_string()),
        };

        self.send_resume_response(response, sender_addr).await?;
        Ok(())
    }

    /// Отправка ответа на запрос возобновления
    async fn send_resume_response(
        &self,
        response: crate::protocol::ack::ResumeAckResponse,
        addr: SocketAddr,
    ) -> Result<()> {
        let response_bytes = bincode::serialize(&response)?;
        let mut header = PacketHeader::new(PacketType::Resume);
        header.payload_length = response_bytes.len() as u32;

        let packet = Packet::new(header, response_bytes);
        self.socket.send_to(&packet.to_bytes(), addr).await?;

        Ok(())
    }

    /// Финализация передачи
    async fn finalize_transfer(&self) -> Result<()> {
        let fm_opt = self.file_manager.read().clone();
        let peer_opt = *self.peer_addr.read();
        let start_opt = *self.start_time.read();
        if let (Some(fm), Some(peer), Some(start_time)) = (fm_opt, peer_opt, start_opt) {

            // Вычисляем финальный хеш файла
            let file_data = fm.read_at(0, fm.size() as usize)?;
            let mut hasher = Hasher::new();
            hasher.update(&file_data);
            let file_hash = hasher.finalize();

            let transfer_time = start_time.elapsed();
            let average_speed = (fm.size() as f64 * 8.0) / (transfer_time.as_secs_f64() * 1_000_000.0);

            // Отправляем финальный ACK
            let final_ack = FinalAck {
                transfer_complete: true,
                total_bytes_received: fm.size(),
                file_hash: file_hash.to_string(),
                transfer_time_ms: transfer_time.as_millis() as u64,
                average_speed_mbps: average_speed,
            };

            let ack_bytes = bincode::serialize(&final_ack)?;
            let mut header = PacketHeader::new(PacketType::Ack);
            header.payload_length = ack_bytes.len() as u32;

            let packet = Packet::new(header, ack_bytes);
            self.socket.send_to(&packet.to_bytes(), peer).await?;

            tracing::info!("Transfer completed!");
            tracing::info!("File: {}", fm.path().display());
            tracing::info!("Size: {} bytes", fm.size());
            tracing::info!("Time: {:.2}s", transfer_time.as_secs_f64());
            tracing::info!("Speed: {:.2} Mbps", average_speed);
            tracing::info!("Hash: {}", file_hash);

            // Удаляем файл состояния
            if let Some(state) = &*self.transfer_state.read() {
                if let Ok(state_path) = self.state_manager.save_state(state) {
                    TransferState::cleanup(&state_path)?;
                }
            }

            // Очищаем состояние для следующей передачи
            *self.peer_addr.write() = None;
            *self.file_manager.write() = None;
            *self.transfer_state.write() = None;
            *self.start_time.write() = None;
        }

        Ok(())
    }

    /// Сохранение состояния при ошибке
    async fn save_state_on_error(&self) -> Result<()> {
        if let Some(state) = &*self.transfer_state.read() {
            let state_path = self.state_manager.save_state(state)?;
            tracing::info!("Transfer state saved to {:?}", state_path);
        }
        Ok(())
    }
}

// Структура задачи для асинхронной записи
struct WriteTask {
    offset: u64,
    data: Vec<u8>,
    sync: bool,
}

impl Clone for Receiver {
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            peer_addr: self.peer_addr.clone(),
            peer_local_addr: self.peer_local_addr.clone(),
            file_manager: self.file_manager.clone(),
            receive_buffer: self.receive_buffer.clone(),
            sao_system: self.sao_system.clone(),
            state_manager: self.state_manager.clone(),
            transfer_state: self.transfer_state.clone(),
            output_dir: self.output_dir.clone(),
            start_time: self.start_time.clone(),
            last_activity: self.last_activity.clone(),
            #[cfg(feature = "nat-traversal")]
            nat_manager: self.nat_manager.clone(),
        }
    }
}

// Cleanup при завершении
impl Drop for Receiver {
    fn drop(&mut self) {
        #[cfg(feature = "nat-traversal")]
        {
            // Очищаем NAT маппинги
            if let Some(nat_manager) = &self.nat_manager {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let manager = nat_manager.clone();
                    handle.block_on(async move {
                        let _ = manager.write().cleanup().await;
                    })
                }
            }
        }
    }
}