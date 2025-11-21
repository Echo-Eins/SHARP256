// examples/nat_system_usage.rs
//! Пример использования исправленной NAT системы SHARP3
//!
//! Этот пример демонстрирует, как использовать исправленную NAT систему
//! для установления P2P соединений между двумя узлами.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use SHARP3::nat::{
    create_controlled_session_config,
    create_controlling_session_config,
    create_ice_session_with_sharp,

    create_p2p_nat_system,

    // Менеджеры
    create_stun_turn_manager,
    // Утилиты
    default_stun_servers,
    parse_turn_server_url,
    IceIntegrationEvent,

    IceRole,

    NatError,
    // Ошибки
    NatResult,
    NatSessionConfig,

    NatSessionEvent,
    // Основные типы системы
    NatSystem,
    NatSystemConfig,
    // События
    NatSystemEvent,
    // Конфигурации
    TurnServerInfo,
    TurnTransport,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Инициализация логирования
    SHARP3::init_logging("debug");

    info!("🚀 Запуск примера использования NAT системы SHARP3");

    // Демонстрация различных сценариев
    demo_basic_nat_system().await?;
    demo_stun_turn_manager().await?;
    demo_ice_integration().await?;
    demo_full_p2p_connection().await?;

    info!("✅ Все примеры завершены успешно");
    Ok(())
}

/// Демонстрация базовой NAT системы
async fn demo_basic_nat_system() -> NatResult<()> {
    info!("📡 Демонстрация базовой NAT системы");

    // Создать конфигурацию системы
    let mut config = NatSystemConfig::default();
    config.stun_config.servers = default_stun_servers();

    // Добавить TURN серверы (пример)
    config.turn_servers = vec![parse_turn_server_url(
        "turn:turn.example.com:3478",
        "username",
        "password",
    )?];

    // Создать NAT систему
    let nat_system = Arc::new(NatSystem::new(config).await?);

    // Подписаться на события системы
    let mut system_events = nat_system.subscribe();

    // Создать сессию для controlling агента
    let session_config = create_controlling_session_config(vec![1]); // RTP компонент
    let session = nat_system.create_session(session_config).await?;

    info!("Создана NAT сессия: {}", session.session_id);

    // Подписаться на события сессии
    let mut session_events = session.subscribe();

    // Создать сокет для демонстрации
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    info!("Создан сокет: {}", socket.local_addr()?);

    // Запустить соединение
    nat_system.start_connection(session.clone(), socket).await?;

    // Обработать события в течение некоторого времени
    let events_task = tokio::spawn(async move {
        let mut timeout_count = 0;

        loop {
            tokio::select! {
                event = system_events.recv() => {
                    match event {
                        Ok(NatSystemEvent::SessionCreated { session_id }) => {
                            info!("🎯 Система: Сессия создана - {}", session_id);
                        }
                        Ok(NatSystemEvent::SessionConnected { session_id, result }) => {
                            info!("🎉 Система: Сессия соединена - {} ({:?})",
                                  session_id, result.connection_strategy);
                            break;
                        }
                        Ok(NatSystemEvent::SessionFailed { session_id, error }) => {
                            warn!("❌ Система: Сессия неудачна - {} ({})", session_id, error);
                            break;
                        }
                        Ok(event) => {
                            debug!("📨 Система: {:?}", event);
                        }
                        Err(_) => {
                            timeout_count += 1;
                            if timeout_count > 10 {
                                warn!("⏰ Таймаут ожидания событий системы");
                                break;
                            }
                        }
                    }
                }

                event = session_events.recv() => {
                    match event {
                        Ok(NatSessionEvent::StateChanged { old_state, new_state }) => {
                            info!("🔄 Сессия: Состояние изменилось {:?} -> {:?}", old_state, new_state);
                        }
                        Ok(NatSessionEvent::CandidateGathered { component_id, candidate }) => {
                            info!("🎯 Сессия: Кандидат собран для компонента {} - {:?}",
                                  component_id, candidate.candidate_type);
                        }
                        Ok(event) => {
                            debug!("📨 Сессия: {:?}", event);
                        }
                        Err(_) => {
                            // Продолжить
                        }
                    }
                }

                _ = sleep(Duration::from_secs(10)) => {
                    info!("⏰ Демонстрация завершена по таймауту");
                    break;
                }
            }
        }
    });

    // Дождаться завершения обработки событий
    let _ = timeout(Duration::from_secs(15), events_task).await;

    // Получить статистику
    let stats = nat_system.get_stats();
    info!("📊 Статистика NAT системы:");
    info!(
        "  - Общие сессии: {}",
        stats
            .total_sessions
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Активные сессии: {}",
        stats
            .active_sessions
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Успешные соединения: {}",
        stats
            .successful_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    // Завершить систему
    nat_system.shutdown().await?;
    info!("✅ Базовая NAT система демонстрация завершена");

    Ok(())
}

/// Демонстрация STUN/TURN менеджера
async fn demo_stun_turn_manager() -> NatResult<()> {
    info!("🌐 Демонстрация STUN/TURN менеджера");

    // Создать STUN/TURN менеджер
    let stun_servers = default_stun_servers();
    let turn_servers = vec![]; // Пустой список для демонстрации

    let manager = Arc::new(create_stun_turn_manager(stun_servers, turn_servers, false).await?);

    // Подписаться на события
    let mut events = manager.subscribe();

    // Создать тестовый сокет
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let component_id = 1;

    info!("Тестирование сбора кандидатов...");

    // Попробовать получить server reflexive кандидат
    match manager
        .get_server_reflexive_candidate(socket.clone(), component_id)
        .await
    {
        Ok(Some(candidate)) => {
            info!(
                "🎯 Получен server reflexive кандидат: {}:{} ({})",
                candidate.address.ip, candidate.address.port, candidate.foundation
            );
        }
        Ok(None) => {
            info!("ℹ️ Server reflexive кандидат не получен");
        }
        Err(e) => {
            warn!("❌ Ошибка получения server reflexive кандидата: {}", e);
        }
    }

    // Попробовать получить relay кандидат (ожидается неудача без TURN серверов)
    match manager.get_relay_candidate(socket, component_id).await {
        Ok(Some(candidate)) => {
            info!(
                "🎯 Получен relay кандидат: {}:{} ({})",
                candidate.address.ip, candidate.address.port, candidate.foundation
            );
        }
        Ok(None) => {
            info!("ℹ️ Relay кандидат не получен (ожидается без TURN серверов)");
        }
        Err(e) => {
            warn!("❌ Ошибка получения relay кандидата: {}", e);
        }
    }

    // Обработать события в течение короткого времени
    tokio::spawn(async move {
        for _ in 0..5 {
            match timeout(Duration::from_secs(1), events.recv()).await {
                Ok(Ok(event)) => {
                    debug!("📨 STUN/TURN событие: {:?}", event);
                }
                _ => break,
            }
        }
    });

    // Получить статистику
    let stats = manager.get_stats();
    info!("📊 Статистика STUN/TURN:");
    info!(
        "  - STUN запросы: {}",
        stats
            .stun_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - STUN успехи: {}",
        stats
            .stun_successes
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - TURN запросы: {}",
        stats
            .turn_allocation_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    // Завершить менеджер
    manager.shutdown().await?;
    info!("✅ STUN/TURN менеджер демонстрация завершена");

    Ok(())
}

/// Демонстрация ICE интеграции
async fn demo_ice_integration() -> NatResult<()> {
    info!("🧊 Демонстрация ICE интеграции");

    // Создать ICE сессию с интеграцией
    let ice_config = SHARP3::nat::ice::create_p2p_ice_config();
    let stun_servers = default_stun_servers();
    let turn_servers = vec![];

    let ice_session =
        Arc::new(create_ice_session_with_sharp(ice_config, stun_servers, turn_servers).await?);

    // Подписаться на события ICE
    let mut ice_events = ice_session.subscribe_ice_events();

    // Подписаться на события интеграции
    let mut integration_events = ice_session.subscribe_integration_events().await;

    // Создать сокет для сбора кандидатов
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    info!("Запуск ICE сессии...");

    // Запустить ICE как controlling агент
    ice_session.start(IceRole::Controlling).await?;

    // Начать сбор кандидатов
    ice_session.start_gathering(socket).await?;

    // Обработать события
    let events_task = tokio::spawn(async move {
        let mut ice_candidates = 0;
        let mut integration_events_count = 0;

        loop {
            tokio::select! {
                event = ice_events.recv() => {
                    match event {
                        Ok(event) => {
                            match event {
                                SHARP3::nat::ice::IceEvent::CandidateAdded { candidate, component_id } => {
                                    ice_candidates += 1;
                                    info!("🎯 ICE: Кандидат добавлен для компонента {} - {:?} ({}:{})",
                                          component_id, candidate.candidate_type,
                                          candidate.address.ip, candidate.address.port);
                                }
                                SHARP3::nat::ice::IceEvent::GatheringCompleted { component_id, candidate_count } => {
                                    info!("✅ ICE: Сбор завершен для компонента {} - {} кандидатов",
                                          component_id, candidate_count);
                                }
                                SHARP3::nat::ice::IceEvent::StateChanged { old_state, new_state } => {
                                    info!("🔄 ICE: Состояние изменилось {:?} -> {:?}", old_state, new_state);
                                }
                                _ => {
                                    debug!("📨 ICE событие: {:?}", event);
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                event = integration_events.recv() => {
                    match event {
                        Ok(event) => {
                            integration_events_count += 1;
                            match event {
                                IceIntegrationEvent::GatheringSessionStarted { session_id, component_id } => {
                                    info!("🚀 Интеграция: Начата сессия сбора {} для компонента {}",
                                          session_id, component_id);
                                }
                                IceIntegrationEvent::GatheringSessionCompleted { session_id, component_id, candidates_count, duration } => {
                                    info!("✅ Интеграция: Завершена сессия {} для компонента {} - {} кандидатов за {}ms",
                                          session_id, component_id, candidates_count, duration.as_millis());
                                }
                                IceIntegrationEvent::CandidateGathered { candidate, candidate_type, .. } => {
                                    info!("🎯 Интеграция: Собран кандидат {:?} ({}:{})",
                                          candidate_type, candidate.address.ip, candidate.address.port);
                                }
                                _ => {
                                    debug!("📨 Интеграция событие: {:?}", event);
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                _ = sleep(Duration::from_secs(8)) => {
                    info!("⏰ Демонстрация ICE завершена по таймауту");
                    info!("📊 Обработано {} ICE событий и {} событий интеграции",
                          ice_candidates, integration_events_count);
                    break;
                }
            }
        }
    });

    // Дождаться завершения
    let _ = timeout(Duration::from_secs(10), events_task).await;

    // Получить статистику
    let ice_stats = ice_session.get_integration_stats();
    info!("📊 Статистика ICE интеграции:");
    info!(
        "  - Общие сессии: {}",
        ice_stats
            .total_sessions
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Общие кандидаты: {}",
        ice_stats
            .total_candidates
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Host кандидаты: {}",
        ice_stats
            .host_candidates
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Server reflexive: {}",
        ice_stats
            .server_reflexive_candidates
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Relay кандидаты: {}",
        ice_stats
            .relay_candidates
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    // Получить кандидаты
    let candidates = ice_session.get_candidates(1).await;
    info!("📋 Собранные кандидаты для компонента 1:");
    for (i, candidate) in candidates.iter().enumerate() {
        info!(
            "  {}. {:?} - {}:{} (приоритет: {})",
            i + 1,
            candidate.candidate_type,
            candidate.address.ip,
            candidate.address.port,
            candidate.priority
        );
    }

    // Завершить сессию
    ice_session.shutdown().await?;
    info!("✅ ICE интеграция демонстрация завершена");

    Ok(())
}

/// Демонстрация полного P2P соединения
async fn demo_full_p2p_connection() -> NatResult<()> {
    info!("🤝 Демонстрация полного P2P соединения");

    // Создать P2P оптимизированную NAT систему
    let stun_servers = default_stun_servers();
    let turn_servers = vec![]; // Для демонстрации без TURN

    // Создать две NAT системы (имитация двух узлов)
    let nat_system_a =
        Arc::new(create_p2p_nat_system(stun_servers.clone(), turn_servers.clone()).await?);
    let nat_system_b = Arc::new(create_p2p_nat_system(stun_servers, turn_servers).await?);

    info!("Созданы две NAT системы для имитации P2P соединения");

    // Создать сессии
    let session_config_a = create_controlling_session_config(vec![1]);
    let session_config_b = create_controlled_session_config(vec![1]);

    let session_a = nat_system_a.create_session(session_config_a).await?;
    let session_b = nat_system_b.create_session(session_config_b).await?;

    info!(
        "Созданы сессии: A={}, B={}",
        session_a.session_id, session_b.session_id
    );

    // Создать сокеты
    let socket_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let socket_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    info!(
        "Созданы сокеты: A={}, B={}",
        socket_a.local_addr()?,
        socket_b.local_addr()?
    );

    // Подписаться на события
    let mut events_a = session_a.subscribe();
    let mut events_b = session_b.subscribe();

    // Запустить соединения
    nat_system_a
        .start_connection(session_a.clone(), socket_a)
        .await?;
    nat_system_b
        .start_connection(session_b.clone(), socket_b)
        .await?;

    info!("Запущены процессы соединения для обеих сессий");

    // Обработать события обеих сессий
    let connection_task = tokio::spawn(async move {
        let mut session_a_connected = false;
        let mut session_b_connected = false;
        let mut timeout_count = 0;

        loop {
            tokio::select! {
                event_a = events_a.recv() => {
                    match event_a {
                        Ok(NatSessionEvent::StateChanged { new_state, .. }) => {
                            info!("🔄 Сессия A: Новое состояние {:?}", new_state);
                            if new_state == SHARP3::nat::NatSessionState::Connected {
                                session_a_connected = true;
                            }
                        }
                        Ok(NatSessionEvent::CandidateGathered { component_id, candidate }) => {
                            info!("🎯 Сессия A: Кандидат для компонента {} - {:?}",
                                  component_id, candidate.candidate_type);
                        }
                        Ok(event) => {
                            debug!("📨 Сессия A: {:?}", event);
                        }
                        Err(_) => {
                            timeout_count += 1;
                        }
                    }
                }

                event_b = events_b.recv() => {
                    match event_b {
                        Ok(NatSessionEvent::StateChanged { new_state, .. }) => {
                            info!("🔄 Сессия B: Новое состояние {:?}", new_state);
                            if new_state == SHARP3::nat::NatSessionState::Connected {
                                session_b_connected = true;
                            }
                        }
                        Ok(NatSessionEvent::CandidateGathered { component_id, candidate }) => {
                            info!("🎯 Сессия B: Кандидат для компонента {} - {:?}",
                                  component_id, candidate.candidate_type);
                        }
                        Ok(event) => {
                            debug!("📨 Сессия B: {:?}", event);
                        }
                        Err(_) => {
                            timeout_count += 1;
                        }
                    }
                }

                _ = sleep(Duration::from_secs(1)) => {
                    timeout_count += 1;
                    if timeout_count > 15 {
                        info!("⏰ Демонстрация P2P завершена по таймауту");
                        break;
                    }
                }
            }

            if session_a_connected && session_b_connected {
                info!("🎉 Обе сессии соединены успешно!");
                break;
            }
        }

        (session_a_connected, session_b_connected)
    });

    // Дождаться результата
    let (connected_a, connected_b) = timeout(Duration::from_secs(20), connection_task)
        .await
        .unwrap_or((false, false));

    // Получить итоговое состояние сессий
    let state_a = session_a.get_state().await;
    let state_b = session_b.get_state().await;

    info!("📊 Результаты P2P соединения:");
    info!(
        "  - Сессия A: состояние={:?}, соединена={}",
        state_a, connected_a
    );
    info!(
        "  - Сессия B: состояние={:?}, соединена={}",
        state_b, connected_b
    );

    // Получить статистику обеих систем
    let stats_a = nat_system_a.get_stats();
    let stats_b = nat_system_b.get_stats();

    info!("📊 Статистика системы A:");
    info!(
        "  - Успешные соединения: {}",
        stats_a
            .successful_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Неудачные соединения: {}",
        stats_a
            .failed_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    info!("📊 Статистика системы B:");
    info!(
        "  - Успешные соединения: {}",
        stats_b
            .successful_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Неудачные соединения: {}",
        stats_b
            .failed_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    // Завершить системы
    nat_system_a.shutdown().await?;
    nat_system_b.shutdown().await?;

    info!("✅ Полная P2P демонстрация завершена");

    Ok(())
}

/// Демонстрация обработки ошибок
#[allow(dead_code)]
async fn demo_error_handling() -> NatResult<()> {
    info!("⚠️ Демонстрация обработки ошибок");

    // Попытка создать NAT систему с неверной конфигурацией
    let mut bad_config = NatSystemConfig::default();
    bad_config.timeouts.connection_timeout = Duration::ZERO; // Неверный таймаут

    match NatSystem::new(bad_config).await {
        Ok(_) => {
            warn!("Неожиданно: система создана с неверной конфигурацией");
        }
        Err(NatError::Configuration(msg)) => {
            info!("✅ Правильно обработана ошибка конфигурации: {}", msg);
        }
        Err(e) => {
            warn!("Неожиданный тип ошибки: {:?}", e);
        }
    }

    // Попытка использовать неверный TURN URL
    match parse_turn_server_url("invalid-url", "user", "pass") {
        Ok(_) => {
            warn!("Неожиданно: неверный URL принят");
        }
        Err(NatError::Configuration(msg)) => {
            info!("✅ Правильно обработана ошибка неверного URL: {}", msg);
        }
        Err(e) => {
            warn!("Неожиданный тип ошибки: {:?}", e);
        }
    }

    info!("✅ Демонстрация обработки ошибок завершена");
    Ok(())
}

/// Утилитарная функция для красивого вывода состояния
#[allow(dead_code)]
fn format_session_state(state: &SHARP3::nat::NatSessionState) -> &'static str {
    match state {
        SHARP3::nat::NatSessionState::Initializing => "🔄 Инициализация",
        SHARP3::nat::NatSessionState::GatheringCandidates => "🎯 Сбор кандидатов",
        SHARP3::nat::NatSessionState::Connecting => "🔗 Соединение",
        SHARP3::nat::NatSessionState::Connected => "✅ Соединено",
        SHARP3::nat::NatSessionState::Reconnecting => "🔄 Переподключение",
        SHARP3::nat::NatSessionState::Failed(_) => "❌ Неудачно",
        SHARP3::nat::NatSessionState::Closed => "🔒 Закрыто",
    }
}
