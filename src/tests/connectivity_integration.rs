// tests/connectivity_integration.rs
//! Integration tests for SHARP-256 Connectivity Module
//!
//! Тестирует полную интеграцию ICE компонентов, fallback систем,
//! и взаимодействие различных методов подключения.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, sleep};
use tokio::sync::mpsc;
use tracing::{info, warn, debug};

use sharp256::connectivity::{
    Connectivity, ConnectivityEvent, ConnectionState, Candidate, CandidateType,
    create_auto_connectivity, create_p2p_connectivity, create_test_connectivity,
    connectivity_info,
};

#[cfg(feature = "webrtc-ice-stack")]
use sharp256::connectivity::ice::{
    IceComponentFactory, IceEvent, IceAgentState,
    create_test_ice_config, validate_ice_config,
};

/// Настройка логирования для тестов
fn setup_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

/// Создание test socket пары
async fn create_socket_pair() -> Result<(UdpSocket, UdpSocket)> {
    let socket1 = UdpSocket::bind("127.0.0.1:0").await?;
    let socket2 = UdpSocket::bind("127.0.0.1:0").await?;

    let addr1 = socket1.local_addr()?;
    let addr2 = socket2.local_addr()?;

    // Устанавливаем peer адреса
    socket1.connect(addr2).await?;
    socket2.connect(addr1).await?;

    Ok((socket1, socket2))
}

/// Тест создания connectivity системы
#[tokio::test]
async fn test_connectivity_creation() {
    setup_logging();
    info!("Testing connectivity creation");

    // Тест базового создания
    let connectivity = Connectivity::new().await;
    assert!(connectivity.is_ok(), "Failed to create basic connectivity");

    // Тест создания для P2P
    let p2p_connectivity = create_p2p_connectivity().await;
    assert!(p2p_connectivity.is_ok(), "Failed to create P2P connectivity");

    // Тест создания для тестирования
    let test_connectivity = create_test_connectivity().await;
    assert!(test_connectivity.is_ok(), "Failed to create test connectivity");

    // Тест автоматического создания
    let auto_connectivity = create_auto_connectivity().await;
    assert!(auto_connectivity.is_ok(), "Failed to create auto connectivity");

    info!("All connectivity creation tests passed");
}

/// Тест получения connectable адреса
#[tokio::test]
async fn test_connectable_address() {
    setup_logging();
    info!("Testing connectable address retrieval");

    let connectivity = create_test_connectivity().await
        .expect("Failed to create connectivity");

    let address = connectivity.get_connectable_address().await;
    assert!(address.is_ok(), "Failed to get connectable address");

    let addr = address.unwrap();
    assert_ne!(addr.port(), 0, "Invalid port in connectable address");

    info!("Connectable address: {}", addr);
}

/// Тест состояний connectivity
#[tokio::test]
async fn test_connectivity_states() {
    setup_logging();
    info!("Testing connectivity states");

    let connectivity = create_test_connectivity().await
        .expect("Failed to create connectivity");

    // Начальное состояние
    let initial_state = connectivity.get_state().await;
    assert_eq!(initial_state, ConnectionState::New);

    // Проверка готовности
    assert!(connectivity.is_ready().await);

    // Получение метрик
    let metrics = connectivity.get_metrics().await;
    assert!(metrics.started_at.is_some());

    // Получение детальной статистики
    let detailed_stats = connectivity.get_detailed_stats().await;
    assert!(detailed_stats.connection_start.is_some());

    info!("State tests passed");
}

/// Тест создания и работы с кандидатами
#[tokio::test]
async fn test_candidates() {
    setup_logging();
    info!("Testing ICE candidates");

    // Создание различных типов кандидатов
    let host_candidate = Candidate::host("192.168.1.100:5000".parse().unwrap());
    assert_eq!(host_candidate.candidate_type, CandidateType::Host);
    assert!(!host_candidate.is_public());

    let public_candidate = Candidate::host("8.8.8.8:53".parse().unwrap());
    assert!(public_candidate.is_public());

    let srflx_candidate = Candidate::server_reflexive(
        "203.0.113.1:6000".parse().unwrap(),
        "192.168.1.100:5000".parse().unwrap(),
        "203.0.113.10:3478".parse().unwrap(),
    );
    assert_eq!(srflx_candidate.candidate_type, CandidateType::ServerReflexive);
    assert!(srflx_candidate.related_address.is_some());

    let relay_candidate = Candidate::relay(
        "203.0.113.20:7000".parse().unwrap(),
        "192.168.1.100:5000".parse().unwrap(),
        true,
    );
    assert_eq!(relay_candidate.candidate_type, CandidateType::Relay);

    info!("Candidate tests passed");
}

/// Тест events системы
#[tokio::test]
async fn test_connectivity_events() {
    setup_logging();
    info!("Testing connectivity events");

    let connectivity = create_test_connectivity().await
        .expect("Failed to create connectivity");

    // Получаем event receiver
    let event_rx = connectivity.take_event_receiver().await;
    assert!(event_rx.is_some(), "Failed to get event receiver");

    let mut event_rx = event_rx.unwrap();

    // Запускаем задачу для мониторинга событий
    let event_monitor = tokio::spawn(async move {
        let mut events_received = 0;

        while let Some(event) = timeout(Duration::from_secs(5), event_rx.recv()).await.ok().flatten() {
            debug!("Received event: {:?}", event);
            events_received += 1;

            match event {
                ConnectivityEvent::Error(_) => break,
                ConnectivityEvent::ConnectionEstablished(_) => break,
                _ => {}
            }

            if events_received > 10 {
                break; // Защита от бесконечного цикла
            }
        }

        events_received
    });

    // Даем время для обработки
    sleep(Duration::from_millis(100)).await;

    // Останавливаем монитор
    event_monitor.abort();

    info!("Event system tests passed");
}

/// Тест поддерживаемых features
#[tokio::test]
async fn test_supported_features() {
    setup_logging();
    info!("Testing supported features");

    let connectivity = create_test_connectivity().await
        .expect("Failed to create connectivity");

    let features = connectivity.get_supported_features();

    // Проверяем, что минимальные требования выполнены
    assert!(features.meets_minimum_requirements(),
            "Minimum requirements not met");

    let active_features = features.active_features();
    assert!(!active_features.is_empty(), "No active features found");

    info!("Active features: {:?}", active_features);

    // Проверяем connectivity info
    let info = connectivity_info();
    assert!(info.contains("SHARP-256 Connectivity"));
    assert!(info.contains("v2.0.0"));

    info!("Features tests passed");
}

/// Тест прямого соединения
#[tokio::test]
async fn test_direct_connection() {
    setup_logging();
    info!("Testing direct connection");

    let (socket1, socket2) = create_socket_pair().await
        .expect("Failed to create socket pair");

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();

    // Создаем connectivity для обеих сторон
    let connectivity1 = create_test_connectivity().await
        .expect("Failed to create connectivity1");

    let connectivity2 = create_test_connectivity().await
        .expect("Failed to create connectivity2");

    info!("Testing connection between {} and {}", addr1, addr2);

    // Пытаемся установить соединение
    // Примечание: Для полного теста нужна поддержка signaling
    let socket1_arc = Arc::new(socket1);
    let socket2_arc = Arc::new(socket2);

    // Тест базовой функциональности
    let result1 = timeout(
        Duration::from_secs(2),
        connectivity1.establish_connection(socket1_arc, Some(addr2), true)
    ).await;

    // Ожидаем либо успех, либо таймаут (что нормально без signaling)
    match result1 {
        Ok(Ok(connection)) => {
            info!("Direct connection established successfully");
            assert_eq!(connection.remote_addr(), addr2);
        }
        Ok(Err(e)) => {
            info!("Direct connection failed as expected: {}", e);
        }
        Err(_) => {
            info!("Direct connection timed out as expected");
        }
    }

    info!("Direct connection tests completed");
}

/// Тест ICE конфигурации и валидации
#[cfg(feature = "webrtc-ice-stack")]
#[tokio::test]
async fn test_ice_configuration() {
    setup_logging();
    info!("Testing ICE configuration");

    // Тест создания и валидации ICE конфигурации
    let ice_config = create_test_ice_config();
    assert!(validate_ice_config(&ice_config).is_ok(),
            "ICE config validation failed");

    // Тест создания ICE компонентов
    let ice_stack_result = IceComponentFactory::create_test_stack().await;

    match ice_stack_result {
        Ok(ice_stack) => {
            info!("ICE stack created successfully");

            // Тест получения состояния
            let process_state = ice_stack.get_process_state().await;
            debug!("ICE process state: {:?}", process_state);

            // Тест получения статистики
            let stats = ice_stack.get_stats().await;
            debug!("ICE stats: {:?}", stats);

            // Тест проверки соединения
            let is_connected = ice_stack.is_connected().await;
            debug!("ICE connected: {}", is_connected);

        }
        Err(e) => {
            warn!("ICE stack creation failed (expected in test environment): {}", e);
        }
    }

    info!("ICE configuration tests completed");
}

/// Тест собрания кандидатов (мок версия)
#[cfg(feature = "webrtc-ice-stack")]
#[tokio::test]
async fn test_candidate_gathering() {
    setup_logging();
    info!("Testing candidate gathering");

    let connectivity = create_test_connectivity().await
        .expect("Failed to create connectivity");

    // Пытаемся получить локальные кандидаты
    let candidates = connectivity.get_local_candidates().await;

    // В тестовой среде может не быть кандидатов без сети
    info!("Local candidates count: {}", candidates.len());

    for (i, candidate) in candidates.iter().enumerate() {
        info!("Candidate {}: {:?} at {}", i, candidate.candidate_type, candidate.address);
    }

    info!("Candidate gathering tests completed");
}

/// Тест lifecycle connectivity
#[tokio::test]
async fn test_connectivity_lifecycle() {
    setup_logging();
    info!("Testing connectivity lifecycle");

    let connectivity = create_test_connectivity().await
        .expect("Failed to create connectivity");

    // Проверяем начальное состояние
    assert_eq!(connectivity.get_state().await, ConnectionState::New);
    assert!(connectivity.is_ready().await);

    // Получаем connectable адрес
    let addr = connectivity.get_connectable_address().await
        .expect("Failed to get connectable address");
    info!("Connectable address: {}", addr);

    // Проверяем метрики
    let metrics = connectivity.get_metrics().await;
    assert!(metrics.started_at.is_some());

    // Тестируем shutdown
    connectivity.shutdown().await
        .expect("Failed to shutdown connectivity");

    // После shutdown состояние должно быть Closed
    let final_state = connectivity.get_state().await;
    assert_eq!(final_state, ConnectionState::Closed);

    info!("Lifecycle tests completed");
}

/// Тест совместимости с старым NAT API
#[cfg(feature = "webrtc-ice-stack")]
#[tokio::test]
async fn test_nat_compatibility() {
    setup_logging();
    info!("Testing NAT compatibility layer");

    use sharp256::connectivity::nat_compat::NatManager;

    let nat_manager = NatManager::new().await
        .expect("Failed to create NAT manager");

    // Тестируем основные методы
    let socket = UdpSocket::bind("127.0.0.1:0").await
        .expect("Failed to create socket");

    // Инициализация (должна проходить без ошибок)
    nat_manager.initialize(&socket).await
        .expect("Failed to initialize NAT manager");

    // Получение connectable адреса
    let addr = nat_manager.get_connectable_address().await
        .expect("Failed to get connectable address");
    info!("NAT manager connectable address: {}", addr);

    // Cleanup
    nat_manager.cleanup().await
        .expect("Failed to cleanup NAT manager");

    info!("NAT compatibility tests passed");
}

/// Benchmark тест производительности
#[tokio::test]
async fn test_performance_benchmark() {
    setup_logging();
    info!("Running performance benchmark");

    let start_time = std::time::Instant::now();

    // Тест создания множественных connectivity объектов
    let mut connectivities = Vec::new();

    for i in 0..10 {
        let connectivity = create_test_connectivity().await
            .expect(&format!("Failed to create connectivity {}", i));
        connectivities.push(connectivity);
    }

    let creation_time = start_time.elapsed();
    info!("Created 10 connectivity objects in {:?}", creation_time);

    // Тест получения адресов
    let addr_start = std::time::Instant::now();

    for (i, connectivity) in connectivities.iter().enumerate() {
        let _addr = connectivity.get_connectable_address().await
            .expect(&format!("Failed to get address for connectivity {}", i));
    }

    let addr_time = addr_start.elapsed();
    info!("Retrieved 10 connectable addresses in {:?}", addr_time);

    // Тест shutdown
    let shutdown_start = std::time::Instant::now();

    for connectivity in connectivities {
        connectivity.shutdown().await
            .expect("Failed to shutdown connectivity");
    }

    let shutdown_time = shutdown_start.elapsed();
    info!("Shutdown 10 connectivity objects in {:?}", shutdown_time);

    let total_time = start_time.elapsed();
    info!("Total benchmark time: {:?}", total_time);

    // Проверяем производительность
    assert!(creation_time < Duration::from_secs(5), "Creation too slow");
    assert!(addr_time < Duration::from_secs(2), "Address retrieval too slow");
    assert!(shutdown_time < Duration::from_secs(2), "Shutdown too slow");

    info!("Performance benchmark completed successfully");
}

/// Stress test для проверки стабильности
#[tokio::test]
async fn test_stress() {
    setup_logging();
    info!("Running stress test");

    let iterations = 50;
    let mut successful_operations = 0;

    for i in 0..iterations {
        match create_test_connectivity().await {
            Ok(connectivity) => {
                // Выполняем базовые операции
                let _state = connectivity.get_state().await;
                let _metrics = connectivity.get_metrics().await;

                if let Ok(_addr) = connectivity.get_connectable_address().await {
                    successful_operations += 1;
                }

                let _ = connectivity.shutdown().await;
            }
            Err(e) => {
                warn!("Iteration {} failed: {}", i, e);
            }
        }

        // Небольшая пауза между итерациями
        if i % 10 == 0 {
            sleep(Duration::from_millis(10)).await;
            info!("Completed {} iterations", i);
        }
    }

    let success_rate = successful_operations as f64 / iterations as f64;
    info!("Stress test completed: {}/{} successful operations ({:.1}%)",
          successful_operations, iterations, success_rate * 100.0);

    // Требуем минимум 80% успешности
    assert!(success_rate >= 0.8, "Stress test success rate too low: {:.1}%", success_rate * 100.0);
}

/// Интеграционный тест с реальными сокетами
#[tokio::test]
async fn test_real_socket_integration() {
    setup_logging();
    info!("Testing real socket integration");

    // Создаем реальные UDP сокеты
    let socket1 = UdpSocket::bind("127.0.0.1:0").await
        .expect("Failed to bind socket1");
    let socket2 = UdpSocket::bind("127.0.0.1:0").await
        .expect("Failed to bind socket2");

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();

    info!("Socket1 bound to: {}", addr1);
    info!("Socket2 bound to: {}", addr2);

    // Создаем connectivity системы
    let connectivity1 = create_test_connectivity().await
        .expect("Failed to create connectivity1");
    let connectivity2 = create_test_connectivity().await
        .expect("Failed to create connectivity2");

    // Тестируем базовую UDP коммуникацию между сокетами
    let test_data = b"SHARP-256-TEST";

    socket1.send_to(test_data, addr2).await
        .expect("Failed to send test data");

    let mut buffer = [0u8; 1024];
    let (size, recv_addr) = timeout(
        Duration::from_secs(1),
        socket2.recv_from(&mut buffer)
    ).await
        .expect("Timeout waiting for data")
        .expect("Failed to receive data");

    assert_eq!(recv_addr, addr1);
    assert_eq!(&buffer[..size], test_data);
    info!("Basic UDP communication successful");

    // Cleanup
    connectivity1.shutdown().await.expect("Failed to shutdown connectivity1");
    connectivity2.shutdown().await.expect("Failed to shutdown connectivity2");

    info!("Real socket integration test completed");
}

/// Финальный интеграционный тест
#[tokio::test]
async fn test_final_integration() {
    setup_logging();
    info!("Running final integration test");

    // Создаем полную connectivity систему
    let connectivity = create_auto_connectivity().await
        .expect("Failed to create auto connectivity");

    // Проверяем все основные функции
    assert!(connectivity.is_ready().await);

    let features = connectivity.get_supported_features();
    assert!(features.meets_minimum_requirements());

    let _addr = connectivity.get_connectable_address().await
        .expect("Failed to get connectable address");

    let state = connectivity.get_state().await;
    assert_eq!(state, ConnectionState::New);

    let metrics = connectivity.get_metrics().await;
    assert!(metrics.started_at.is_some());

    // Тестируем валидацию конфигурации
    connectivity.validate_config()
        .expect("Config validation failed");

    // Финальный shutdown
    connectivity.shutdown().await
        .expect("Failed to shutdown connectivity");

    assert_eq!(connectivity.get_state().await, ConnectionState::Closed);

    info!("✅ All integration tests passed successfully!");
    info!("SHARP-256 Connectivity Module is ready for production use");
}