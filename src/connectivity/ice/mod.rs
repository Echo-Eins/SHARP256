// src/connectivity/ice/mod.rs
//! ICE (Interactive Connectivity Establishment) реализация на основе webrtc-rs

#[cfg(feature = "webrtc-ice-stack")]
use anyhow::Result;
#[cfg(feature = "webrtc-ice-stack")]
use std::sync::Arc;
#[cfg(feature = "webrtc-ice-stack")]
use std::time::Duration;
#[cfg(feature = "webrtc-ice-stack")]
use tokio::sync::mpsc;

// Submodules (только если webrtc-ice-stack включен)
#[cfg(feature = "webrtc-ice-stack")]
pub mod agent;
#[cfg(feature = "webrtc-ice-stack")]
pub mod gathering;
#[cfg(feature = "webrtc-ice-stack")]
pub mod connectivity;
#[cfg(feature = "webrtc-ice-stack")]
pub mod nomination;

// Re-exports
#[cfg(feature = "webrtc-ice-stack")]
pub use agent::{IceAgent, IceAgentConfig};
#[cfg(feature = "webrtc-ice-stack")]
pub use gathering::{CandidateGatherer, GatheringProgress};
#[cfg(feature = "webrtc-ice-stack")]
pub use connectivity::{ConnectivityChecker, CheckResult};
#[cfg(feature = "webrtc-ice-stack")]
pub use nomination::{CandidateNominator, NominationResult};

#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::{Candidate, CandidatePair, ConnectivityCheckResult};
#[cfg(feature = "webrtc-ice-stack")]
use crate::connectivity::config::IceConfig;

/// ICE Connection wrapper для Transport trait
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug)]
pub struct IceConnection {
    conn: Arc<dyn webrtc::ice::conn::Conn + Send + Sync>,
    selected_pair: CandidatePair,
}

#[cfg(feature = "webrtc-ice-stack")]
impl IceConnection {
    pub fn new(
        conn: Arc<dyn webrtc::ice::conn::Conn + Send + Sync>,
        selected_pair: CandidatePair,
    ) -> Self {
        Self { conn, selected_pair }
    }

    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        self.conn.send(data).await.map_err(Into::into)
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.conn.recv(buf).await.map_err(Into::into)
    }

    pub fn selected_pair(&self) -> &CandidatePair {
        &self.selected_pair
    }

    pub async fn close(&self) -> Result<()> {
        self.conn.close().await.map_err(Into::into)
    }
}

/// События ICE процесса
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone)]
pub enum IceEvent {
    /// Новый кандидат собран
    CandidateGathered(Candidate),
    /// Сбор кандидатов завершен
    GatheringComplete,
    /// Начались connectivity checks
    ConnectivityChecksStarted,
    /// Результат connectivity check
    ConnectivityCheckCompleted(ConnectivityCheckResult),
    /// Пара кандидатов номинирована
    CandidatePairNominated(CandidatePair),
    /// ICE соединение установлено
    ConnectionEstablished(IceConnection),
    /// ICE ошибка
    Error(String),
}

/// Состояние ICE агента
#[cfg(feature = "webrtc-ice-stack")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceAgentState {
    /// Начальное состояние
    New,
    /// Сбор кандидатов
    Gathering,
    /// Connectivity checks
    Connecting,
    /// Соединение установлено
    Connected,
    /// Соединение отключено
    Disconnected,
    /// Ошибка
    Failed,
    /// Закрыто
    Closed,
}

/// Utilities для работы с ICE
#[cfg(feature = "webrtc-ice-stack")]
pub mod utils {
    use super::*;
    use webrtc::ice::candidate::*;

    /// Конвертация webrtc кандидата в наш Candidate
    pub fn webrtc_candidate_to_candidate(
        webrtc_candidate: &dyn webrtc::ice::candidate::Candidate,
    ) -> Result<Candidate> {
        let candidate_type = match webrtc_candidate.candidate_type() {
            CandidateType::Host => crate::connectivity::CandidateType::Host,
            CandidateType::ServerReflexive => crate::connectivity::CandidateType::ServerReflexive,
            CandidateType::PeerReflexive => crate::connectivity::CandidateType::PeerReflexive,
            CandidateType::Relay => crate::connectivity::CandidateType::Relay,
        };

        Ok(Candidate {
            foundation: webrtc_candidate.foundation().to_string(),
            priority: webrtc_candidate.priority(),
            address: webrtc_candidate.address(),
            candidate_type,
            related_address: webrtc_candidate.related_address(),
            attributes: crate::connectivity::CandidateAttributes {
                transport: webrtc_candidate.network_type().to_string(),
                component: webrtc_candidate.component(),
                network_cost: calculate_network_cost(&webrtc_candidate.address()),
                hairpin_capable: false, // Определяется отдельно
                encryption_capable: candidate_type == crate::connectivity::CandidateType::Relay,
            },
        })
    }

    /// Конвертация нашего кандидата в webrtc кандидат
    pub fn candidate_to_webrtc_candidate(
        candidate: &Candidate,
    ) -> Result<Box<dyn webrtc::ice::candidate::Candidate + Send + Sync>> {
        let candidate_type = match candidate.candidate_type {
            crate::connectivity::CandidateType::Host => CandidateType::Host,
            crate::connectivity::CandidateType::ServerReflexive => CandidateType::ServerReflexive,
            crate::connectivity::CandidateType::PeerReflexive => CandidateType::PeerReflexive,
            crate::connectivity::CandidateType::Relay => CandidateType::Relay,
            crate::connectivity::CandidateType::RouterPool => CandidateType::Host, // Маппим как host
        };

        let webrtc_candidate = webrtc::ice::candidate::candidate_host::CandidateHostConfig {
            base_config: webrtc::ice::candidate::CandidateConfig {
                candidate_type,
                network: candidate.attributes.transport.clone(),
                address: candidate.address,
                component: candidate.attributes.component,
                priority: candidate.priority,
                foundation: candidate.foundation.clone(),
                related_address: candidate.related_address,
            },
        };

        Ok(Box::new(webrtc::ice::candidate::candidate_host::CandidateHost::new(&webrtc_candidate)?))
    }

    /// Расчет сетевой стоимости
    fn calculate_network_cost(addr: &std::net::SocketAddr) -> u16 {
        crate::connectivity::utils::calculate_network_distance(
            &"127.0.0.1:0".parse().unwrap(), // Dummy local
            addr
        ) as u16
    }

    /// Проверка совместимости ICE кандидатов
    pub fn are_ice_candidates_compatible(
        local: &dyn webrtc::ice::candidate::Candidate,
        remote: &dyn webrtc::ice::candidate::Candidate,
    ) -> bool {
        // Проверяем совместимость IP версий
        match (local.address(), remote.address()) {
            (std::net::SocketAddr::V4(_), std::net::SocketAddr::V4(_)) => true,
            (std::net::SocketAddr::V6(_), std::net::SocketAddr::V6(_)) => true,
            _ => false,
        }
    }

    /// Приоритизация кандидатов для оптимального порядка проверки
    pub fn prioritize_candidate_pairs(pairs: &mut [CandidatePair]) {
        pairs.sort_by(|a, b| {
            // Сортируем по убыванию приоритета
            b.priority.cmp(&a.priority)
                // При равном приоритете предпочитаем host кандидаты
                .then_with(|| {
                    let a_host_score = if a.local.candidate_type == crate::connectivity::CandidateType::Host { 1 } else { 0 };
                    let b_host_score = if b.local.candidate_type == crate::connectivity::CandidateType::Host { 1 } else { 0 };
                    b_host_score.cmp(&a_host_score)
                })
                // При прочих равных предпочитаем пары с меньшим network cost
                .then_with(|| {
                    let a_cost = a.local.attributes.network_cost + a.remote.attributes.network_cost;
                    let b_cost = b.local.attributes.network_cost + b.remote.attributes.network_cost;
                    a_cost.cmp(&b_cost)
                })
        });
    }
}

/// Фабрика для создания ICE агентов
#[cfg(feature = "webrtc-ice-stack")]
pub struct IceAgentFactory;

#[cfg(feature = "webrtc-ice-stack")]
impl IceAgentFactory {
    /// Создание ICE агента с конфигурацией по умолчанию
    pub async fn create_agent(config: IceConfig, controlling: bool) -> Result<IceAgent> {
        IceAgent::new(config, controlling).await
    }

    /// Создание lite ICE агента (упрощенный)
    pub async fn create_lite_agent(config: IceConfig) -> Result<IceAgent> {
        let mut ice_config = config;
        ice_config.enable_host_candidates = true;
        ice_config.enable_srflx_candidates = false;
        ice_config.enable_relay_candidates = false;

        IceAgent::new(ice_config, false).await
    }

    /// Создание агента только для тестирования
    pub async fn create_test_agent() -> Result<IceAgent> {
        let config = IceConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            gathering_timeout: Duration::from_secs(5),
            connectivity_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        IceAgent::new(config, true).await
    }
}

/// Mock реализация для тестирования без webrtc-ice-stack
#[cfg(not(feature = "webrtc-ice-stack"))]
pub mod mock {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Mock ICE Agent для сборки без webrtc-ice-stack
    #[derive(Debug)]
    pub struct MockIceAgent;

    impl MockIceAgent {
        pub async fn new(_config: crate::connectivity::config::IceConfig, _controlling: bool) -> Result<Self> {
            Ok(Self)
        }

        pub async fn gather_candidates_with_progress(
            &self,
            _progress_tx: mpsc::UnboundedSender<crate::connectivity::ConnectivityEvent>,
        ) -> Result<Vec<crate::connectivity::Candidate>> {
            Ok(vec![])
        }

        pub async fn add_remote_candidate(&self, _candidate: crate::connectivity::Candidate) -> Result<()> {
            Ok(())
        }

        pub async fn perform_connectivity_checks(&self) -> Result<Vec<crate::connectivity::ConnectivityCheckResult>> {
            Ok(vec![])
        }

        pub async fn nominate_pair(&self, _pair: crate::connectivity::CandidatePair) -> Result<Option<crate::connectivity::CandidatePair>> {
            Ok(None)
        }

        pub async fn get_connection(&self) -> Result<Arc<dyn std::fmt::Debug + Send + Sync>> {
            Err(anyhow::anyhow!("WebRTC ICE not available"))
        }
    }
}

// Условные re-exports
#[cfg(feature = "webrtc-ice-stack")]
pub use agent::IceAgent;

#[cfg(not(feature = "webrtc-ice-stack"))]
pub use mock::MockIceAgent as IceAgent;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "webrtc-ice-stack")]
    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = crate::connectivity::config::IceConfig::default();
        let agent = IceAgentFactory::create_test_agent().await;
        assert!(agent.is_ok());
    }

    #[cfg(not(feature = "webrtc-ice-stack"))]
    #[tokio::test]
    async fn test_mock_ice_agent() {
        let config = crate::connectivity::config::IceConfig::default();
        let agent = mock::MockIceAgent::new(config, true).await;
        assert!(agent.is_ok());
    }

    #[cfg(feature = "webrtc-ice-stack")]
    #[test]
    fn test_candidate_prioritization() {
        let host_candidate = crate::connectivity::Candidate::host(
            "192.168.1.100:5000".parse().unwrap()
        );
        let relay_candidate = crate::connectivity::Candidate::relay(
            "1.2.3.4:3478".parse().unwrap(),
            "192.168.1.100:5000".parse().unwrap(),
            true,
        );

        let mut pairs = vec![
            crate::connectivity::CandidatePair::new(host_candidate.clone(), relay_candidate.clone()),
            crate::connectivity::CandidatePair::new(relay_candidate, host_candidate),
        ];

        utils::prioritize_candidate_pairs(&mut pairs);

        // Host кандидаты должны иметь более высокий приоритет
        assert!(pairs[0].priority >= pairs[1].priority);
    }
}