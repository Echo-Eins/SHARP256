// src/connectivity/ice/utils.rs
//! ICE Utility Functions and Type Conversions
//! Конвертация между webrtc-rs типами и нашими типами

use anyhow::Result;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

use std::sync::Arc;
use webrtc::ice::candidate::{
    candidate_host::CandidateHostConfig, candidate_peer_reflexive::CandidatePeerReflexiveConfig,
    candidate_relay::CandidateRelayConfig,
    candidate_server_reflexive::CandidateServerReflexiveConfig, Candidate as WebRtcCandidate,
    CandidateType as WebRtcCandidateType,
};

use crate::connectivity::{
    Candidate, CandidateAttributes, CandidatePair, CandidatePairState, CandidateType,
};

/// Конвертация WebRTC кандидата в наш формат
pub fn webrtc_candidate_to_candidate(webrtc_candidate: &dyn WebRtcCandidate) -> Result<Candidate> {
    use anyhow::Context;
    use std::net::IpAddr;

    // Получаем базовую информацию
    let foundation = webrtc_candidate.foundation().to_string();
    let priority = webrtc_candidate.priority();
    let candidate_type = webrtc_candidate_type_to_candidate_type(webrtc_candidate.candidate_type());

    // Parse address string to SocketAddr
    let ip_addr: IpAddr = webrtc_candidate
        .address()
        .parse()
        .context("Failed to parse candidate IP address")?;
    let address = SocketAddr::new(ip_addr, webrtc_candidate.port());

    // Handle related address
    let related_address = if !webrtc_candidate.related_address().is_empty() {
        let rel_ip: IpAddr = webrtc_candidate
            .related_address()
            .parse()
            .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
        let rel_port = webrtc_candidate.related_port();
        Some(SocketAddr::new(rel_ip, rel_port))
    } else {
        None
    };

    // Создаем атрибуты кандидата
    let attributes = CandidateAttributes {
        transport: "udp".to_string(), // webrtc_candidate.network_type().to_string() for actual
        component: webrtc_candidate.component() as u16,
        network_cost: calculate_network_cost(&candidate_type, &address),
        generation: 0, // WebRTC-rs не предоставляет это напрямую
        network_id: 1, // По умолчанию
        extensions: extract_candidate_extensions(webrtc_candidate),
    };

    Ok(Candidate {
        foundation,
        priority,
        address,
        candidate_type,
        base_address: address, // For simplicity use same as address
        related_address,
        attributes,
    })
}

/// Конвертация нашего кандидата в WebRTC формат
///
/// Создает реальные webrtc-rs кандидаты на основе типа кандидата.
/// RFC 8445 compliant implementation.
pub fn candidate_to_webrtc_candidate(
    candidate: &Candidate,
) -> Result<Arc<dyn WebRtcCandidate + Send + Sync>> {
    use anyhow::Context;
    // Import directly from webrtc_ice as it's not re-exported
    use webrtc_ice::candidate::candidate_base::CandidateBaseConfig;

    let base_config = CandidateBaseConfig {
        network: "udp".to_string(),
        address: candidate.address.ip().to_string(),
        port: candidate.address.port(),
        component: candidate.attributes.component as u16,
        priority: candidate.priority,
        foundation: candidate.foundation.clone(),
        ..Default::default()
    };

    match candidate.candidate_type {
        CandidateType::Host => {
            let config = CandidateHostConfig {
                base_config,
                ..Default::default()
            };
            let webrtc_candidate = config
                .new_candidate_host()
                .context("Failed to create host candidate")?;
            Ok(Arc::new(webrtc_candidate))
        }
        CandidateType::ServerReflexive => {
            let config = CandidateServerReflexiveConfig {
                base_config,
                rel_addr: candidate
                    .related_address
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
                rel_port: candidate
                    .related_address
                    .map(|addr| addr.port())
                    .unwrap_or(0),
            };
            let webrtc_candidate = config
                .new_candidate_server_reflexive()
                .context("Failed to create server reflexive candidate")?;
            Ok(Arc::new(webrtc_candidate))
        }
        CandidateType::PeerReflexive => {
            let config = CandidatePeerReflexiveConfig {
                base_config,
                rel_addr: candidate
                    .related_address
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
                rel_port: candidate
                    .related_address
                    .map(|addr| addr.port())
                    .unwrap_or(0),
            };
            let webrtc_candidate = config
                .new_candidate_peer_reflexive()
                .context("Failed to create peer reflexive candidate")?;
            Ok(Arc::new(webrtc_candidate))
        }
        CandidateType::Relay => {
            let config = CandidateRelayConfig {
                base_config,
                rel_addr: candidate
                    .related_address
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
                rel_port: candidate
                    .related_address
                    .map(|addr| addr.port())
                    .unwrap_or(0),
                ..Default::default()
            };
            let webrtc_candidate = config
                .new_candidate_relay()
                .context("Failed to create relay candidate")?;
            Ok(Arc::new(webrtc_candidate))
        }
        // For custom types (RouterPool, Hairpin), map to closest webrtc-rs types
        CandidateType::RouterPool => {
            // Map to ServerReflexive
            let config = CandidateServerReflexiveConfig {
                base_config,
                rel_addr: candidate
                    .related_address
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
                rel_port: candidate
                    .related_address
                    .map(|addr| addr.port())
                    .unwrap_or(0),
            };
            let webrtc_candidate = config
                .new_candidate_server_reflexive()
                .context("Failed to create router pool candidate")?;
            Ok(Arc::new(webrtc_candidate))
        }
        CandidateType::Hairpin => {
            // Map to Host
            let config = CandidateHostConfig {
                base_config,
                ..Default::default()
            };
            let webrtc_candidate = config
                .new_candidate_host()
                .context("Failed to create hairpin candidate")?;
            Ok(Arc::new(webrtc_candidate))
        }
    }
}

/// Конвертация типа кандидата WebRTC в наш тип
pub fn webrtc_candidate_type_to_candidate_type(webrtc_type: WebRtcCandidateType) -> CandidateType {
    match webrtc_type {
        WebRtcCandidateType::Host => CandidateType::Host,
        WebRtcCandidateType::ServerReflexive => CandidateType::ServerReflexive,
        WebRtcCandidateType::PeerReflexive => CandidateType::PeerReflexive,
        WebRtcCandidateType::Relay => CandidateType::Relay,
    }
}

/// Конвертация нашего типа кандидата в WebRTC тип
pub fn candidate_type_to_webrtc_candidate_type(
    candidate_type: CandidateType,
) -> WebRtcCandidateType {
    match candidate_type {
        CandidateType::Host => WebRtcCandidateType::Host,
        CandidateType::ServerReflexive => WebRtcCandidateType::ServerReflexive,
        CandidateType::PeerReflexive => WebRtcCandidateType::PeerReflexive,
        CandidateType::Relay => WebRtcCandidateType::Relay,
        // Наши дополнительные типы мапим на ближайшие WebRTC типы
        CandidateType::RouterPool => WebRtcCandidateType::ServerReflexive,
        CandidateType::Hairpin => WebRtcCandidateType::Host,
    }
}

/// Конвертация WebRTC пары кандидатов в нашу пару
///
/// Note: webrtc-rs 0.13 handles CandidatePair internally.
/// Use the on_selected_candidate_pair_change callback to get the selected pair.
/// This function creates a CandidatePair from two candidates directly.
pub fn create_candidate_pair_from_webrtc(
    local: &Arc<dyn WebRtcCandidate + Send + Sync>,
    remote: &Arc<dyn WebRtcCandidate + Send + Sync>,
) -> Result<CandidatePair> {
    let local_candidate = webrtc_candidate_to_candidate(local.as_ref())?;
    let remote_candidate = webrtc_candidate_to_candidate(remote.as_ref())?;

    let mut pair = CandidatePair::new(local_candidate, remote_candidate);
    pair.state = CandidatePairState::Waiting;

    Ok(pair)
}

/// Расчет стоимости сети для кандидата
fn calculate_network_cost(candidate_type: &CandidateType, address: &SocketAddr) -> u16 {
    let base_cost = match candidate_type {
        CandidateType::Host => 0, // Наименьшая стоимость
        CandidateType::PeerReflexive => 10,
        CandidateType::ServerReflexive => 20,
        CandidateType::RouterPool => 30,
        CandidateType::Relay => 50, // Наибольшая стоимость
        CandidateType::Hairpin => 5,
    };

    // Добавляем стоимость для IPv6 (если нужно предпочитать IPv4)
    let ipv6_penalty = if address.is_ipv6() { 5 } else { 0 };

    base_cost + ipv6_penalty
}

/// Извлечение расширений кандидата
fn extract_candidate_extensions(webrtc_candidate: &dyn WebRtcCandidate) -> HashMap<String, String> {
    let mut extensions = HashMap::new();

    // Добавляем дополнительную информацию из WebRTC кандидата
    extensions.insert(
        "webrtc_type".to_string(),
        format!("{:?}", webrtc_candidate.candidate_type()),
    );
    extensions.insert(
        "webrtc_protocol".to_string(),
        webrtc_candidate.transport_type().to_string(),
    );

    // TCP тип (если применимо)
    if let Some(tcp_type) = webrtc_candidate.tcp_type() {
        extensions.insert("tcp_type".to_string(), format!("{:?}", tcp_type));
    }

    extensions
}

/// Генерация foundation для кандидата
pub fn generate_foundation(
    candidate_type: CandidateType,
    base_address: SocketAddr,
    server_address: Option<SocketAddr>,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    candidate_type.hash(&mut hasher);
    base_address.hash(&mut hasher);
    if let Some(server) = server_address {
        server.hash(&mut hasher);
    }

    format!("{:x}", hasher.finish()).chars().take(8).collect()
}

/// Расчет приоритета кандидата по RFC 8445
pub fn calculate_candidate_priority(
    candidate_type: CandidateType,
    local_preference: u16,
    component_id: u16,
) -> u32 {
    let type_preference = match candidate_type {
        CandidateType::Host => 126,
        CandidateType::PeerReflexive => 110,
        CandidateType::ServerReflexive => 100,
        CandidateType::RouterPool => 90,
        CandidateType::Relay => 0,
        CandidateType::Hairpin => 120,
    };

    // Priority = (2^24) * type_preference + (2^8) * local_preference + (2^0) * (256 - component_id)
    (1 << 24) * type_preference as u32
        + (1 << 8) * local_preference as u32
        + (256 - component_id as u32)
}

/// Расчет приоритета пары кандидатов по RFC 8445
pub fn calculate_pair_priority(
    controlling: bool,
    local_priority: u32,
    remote_priority: u32,
) -> u64 {
    let (g, d) = if controlling {
        if local_priority > remote_priority {
            (1, local_priority as u64)
        } else {
            (0, remote_priority as u64)
        }
    } else {
        if local_priority > remote_priority {
            (0, remote_priority as u64)
        } else {
            (1, local_priority as u64)
        }
    };

    let min_priority = std::cmp::min(local_priority, remote_priority) as u64;
    let max_priority = std::cmp::max(local_priority, remote_priority) as u64;

    (1u64 << 32) * min_priority + 2 * max_priority + g
}

/// Проверка валидности адреса кандидата
pub fn is_valid_candidate_address(address: &SocketAddr) -> bool {
    // Проверки по RFC 8445

    // Исключаем multicast адреса
    if address.ip().is_multicast() {
        return false;
    }

    // Исключаем loopback (кроме тестирования)
    if address.ip().is_loopback() {
        return cfg!(test);
    }

    // Проверяем диапазон портов
    if address.port() == 0 {
        return false;
    }

    true
}

/// Определение типа NAT на основе кандидатов
pub fn determine_nat_type(
    host_candidates: &[Candidate],
    srflx_candidates: &[Candidate],
) -> NatType {
    if srflx_candidates.is_empty() {
        if host_candidates
            .iter()
            .any(|c| is_public_address(&c.address))
        {
            return NatType::OpenInternet;
        } else {
            return NatType::SymmetricUdpFirewall;
        }
    }

    // Проверяем, одинаковые ли внешние адреса для разных локальных
    let external_addresses: std::collections::HashSet<_> =
        srflx_candidates.iter().map(|c| c.address.ip()).collect();

    if external_addresses.len() == 1 {
        // Проверяем порты
        let external_ports: std::collections::HashSet<_> =
            srflx_candidates.iter().map(|c| c.address.port()).collect();

        if external_ports.len() == srflx_candidates.len() {
            NatType::FullCone
        } else {
            NatType::AddressRestrictedCone
        }
    } else {
        NatType::Symmetric
    }
}

/// Тип NAT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// Открытый интернет (без NAT)
    OpenInternet,
    /// Full cone NAT
    FullCone,
    /// Address-restricted cone NAT
    AddressRestrictedCone,
    /// Port-restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT
    Symmetric,
    /// UDP Firewall
    SymmetricUdpFirewall,
}

/// Проверка, является ли адрес публичным
pub fn is_public_address(address: &SocketAddr) -> bool {
    let ip = address.ip();

    // IPv4 частные диапазоны
    if let std::net::IpAddr::V4(ipv4) = ip {
        let octets = ipv4.octets();

        // 10.0.0.0/8
        if octets[0] == 10 {
            return false;
        }

        // 172.16.0.0/12
        if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
            return false;
        }

        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return false;
        }

        // 169.254.0.0/16 (link-local)
        if octets[0] == 169 && octets[1] == 254 {
            return false;
        }
    }

    // IPv6 частные диапазоны
    if let std::net::IpAddr::V6(ipv6) = ip {
        let segments = ipv6.segments();

        // fc00::/7 (unique local)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return false;
        }

        // fe80::/10 (link-local)
        if (segments[0] & 0xffc0) == 0xfe80 {
            return false;
        }
    }

    // Исключаем зарезервированные и multicast
    !ip.is_loopback() && !ip.is_multicast() && !ip.is_unspecified()
}

/// Фильтрация кандидатов по критериям
pub fn filter_candidates(candidates: &[Candidate], filter: &CandidateFilter) -> Vec<Candidate> {
    candidates
        .iter()
        .filter(|candidate| {
            // Фильтр по типу
            if let Some(ref types) = filter.candidate_types {
                if !types.contains(&candidate.candidate_type) {
                    return false;
                }
            }

            // Фильтр по IP версии
            match filter.ip_version {
                Some(IpVersion::V4) if candidate.address.is_ipv6() => return false,
                Some(IpVersion::V6) if candidate.address.is_ipv4() => return false,
                _ => {}
            }

            // Фильтр по транспорту
            if let Some(ref transport) = filter.transport {
                if candidate.attributes.transport != *transport {
                    return false;
                }
            }

            // Фильтр по компоненту
            if let Some(component) = filter.component {
                if candidate.attributes.component != component {
                    return false;
                }
            }

            true
        })
        .cloned()
        .collect()
}

/// Фильтр для кандидатов
#[derive(Debug, Clone, Default)]
pub struct CandidateFilter {
    pub candidate_types: Option<Vec<CandidateType>>,
    pub ip_version: Option<IpVersion>,
    pub transport: Option<String>,
    pub component: Option<u16>,
}

/// Версия IP протокола
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Сортировка кандидатов по приоритету
pub fn sort_candidates_by_priority(candidates: &mut [Candidate]) {
    candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
}

/// Сортировка пар кандидатов по приоритету
pub fn sort_pairs_by_priority(pairs: &mut [CandidatePair]) {
    pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
}

/// Получение локального IP адреса по умолчанию
pub fn get_default_local_address() -> Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr};

    // Пытаемся получить локальный IP через временное соединение
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?; // Google DNS для определения маршрута
    let local_addr = socket.local_addr()?;

    Ok(SocketAddr::new(local_addr.ip(), 0))
}

/// Создание test кандидата для unit тестов
#[cfg(test)]
pub fn create_test_candidate(
    candidate_type: CandidateType,
    address: SocketAddr,
    component: u16,
) -> Candidate {
    let foundation = generate_foundation(candidate_type, address, None);
    let priority = calculate_candidate_priority(candidate_type, 65535, component);

    Candidate {
        foundation,
        priority,
        address,
        candidate_type,
        related_address: None,
        attributes: CandidateAttributes {
            transport: "udp".to_string(),
            component,
            network_cost: calculate_network_cost(&candidate_type, &address),
            generation: 0,
            network_id: 1,
            extensions: HashMap::new(),
        },
    }
}

/// Создание test пары кандидатов для unit тестов
#[cfg(test)]
pub fn create_test_candidate_pair(
    local_type: CandidateType,
    local_addr: SocketAddr,
    remote_type: CandidateType,
    remote_addr: SocketAddr,
) -> CandidatePair {
    let local = create_test_candidate(local_type, local_addr, 1);
    let remote = create_test_candidate(remote_type, remote_addr, 1);

    CandidatePair::new(local, remote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_priority_calculation() {
        let priority = calculate_candidate_priority(CandidateType::Host, 65535, 1);
        assert!(priority > 0);

        let host_priority = calculate_candidate_priority(CandidateType::Host, 65535, 1);
        let relay_priority = calculate_candidate_priority(CandidateType::Relay, 65535, 1);
        assert!(host_priority > relay_priority);
    }

    #[test]
    fn test_pair_priority_calculation() {
        let controlling_priority = calculate_pair_priority(true, 1000, 2000);
        let controlled_priority = calculate_pair_priority(false, 1000, 2000);

        // При одинаковых приоритетах кандидатов, роли влияют на итоговый приоритет
        assert_ne!(controlling_priority, controlled_priority);
    }

    #[test]
    fn test_foundation_generation() {
        let foundation1 = generate_foundation(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            None,
        );

        let foundation2 = generate_foundation(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            None,
        );

        // Одинаковые параметры должны давать одинаковый foundation
        assert_eq!(foundation1, foundation2);

        let foundation3 = generate_foundation(
            CandidateType::ServerReflexive,
            "192.168.1.1:5000".parse().unwrap(),
            None,
        );

        // Разные типы должны давать разные foundation
        assert_ne!(foundation1, foundation3);
    }

    #[test]
    fn test_public_address_detection() {
        assert!(is_public_address(&"8.8.8.8:53".parse().unwrap()));
        assert!(!is_public_address(&"192.168.1.1:5000".parse().unwrap()));
        assert!(!is_public_address(&"10.0.0.1:5000".parse().unwrap()));
        assert!(!is_public_address(&"172.16.0.1:5000".parse().unwrap()));
    }

    #[test]
    fn test_nat_type_determination() {
        let host_candidates = vec![create_test_candidate(
            CandidateType::Host,
            "192.168.1.100:5000".parse().unwrap(),
            1,
        )];

        let srflx_candidates = vec![create_test_candidate(
            CandidateType::ServerReflexive,
            "203.0.113.1:6000".parse().unwrap(),
            1,
        )];

        let nat_type = determine_nat_type(&host_candidates, &srflx_candidates);
        assert_eq!(nat_type, NatType::FullCone);
    }

    #[test]
    fn test_candidate_filtering() {
        let candidates = vec![
            create_test_candidate(CandidateType::Host, "192.168.1.1:5000".parse().unwrap(), 1),
            create_test_candidate(CandidateType::Relay, "203.0.113.1:3478".parse().unwrap(), 1),
            create_test_candidate(CandidateType::Host, "[::1]:5000".parse().unwrap(), 1),
        ];

        let filter = CandidateFilter {
            candidate_types: Some(vec![CandidateType::Host]),
            ip_version: Some(IpVersion::V4),
            ..Default::default()
        };

        let filtered = filter_candidates(&candidates, &filter);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].candidate_type, CandidateType::Host);
        assert!(filtered[0].address.is_ipv4());
    }

    #[test]
    fn test_test_helpers() {
        let pair = create_test_candidate_pair(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            CandidateType::Host,
            "192.168.1.2:5000".parse().unwrap(),
        );

        assert_eq!(pair.local.candidate_type, CandidateType::Host);
        assert_eq!(pair.remote.candidate_type, CandidateType::Host);
        assert!(pair.priority > 0);
    }
}
