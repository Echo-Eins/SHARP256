# ДЕТАЛЬНЫЙ ПЛАН ИСПРАВЛЕНИЯ CONNECTIVITY MODULE

**Дата**: 2025-11-18
**Цель**: Привести connectivity в полное соответствие с RFC и заменить симуляции на библиотечный код
**Статус**: READY FOR IMPLEMENTATION

---

## 📊 ТЕКУЩЕЕ СОСТОЯНИЕ

**Всего файлов**: 27
**Статус**:
- ✅ Библиотечные (корректные): 15 файлов (55%)
- ⚠️ Симуляции/смешанные: 3 файла (11%)
- ❌ Пустые/критичные: 9 файлов (34%)

**Общая оценка**: 53% - ТРЕБУЕТСЯ ЗНАЧИТЕЛЬНАЯ ДОРАБОТКА

---

## 🎯 СТРАТЕГИЯ ИСПРАВЛЕНИЯ

### Принципы:
1. **ТОЛЬКО сертифицированные библиотеки** - webrtc-rs, libp2p, igd
2. **НИКАКИХ симуляций** - удалить все `simulate_*()` функции
3. **ПОЛНОЕ RFC соответствие** - RFC 8445, 8489, 8656
4. **Модульность** - каждый модуль независим и тестируем
5. **Чистота API** - простой и понятный интерфейс для sender/receiver

---

## 📋 ФАЗЫ ИСПРАВЛЕНИЯ

### ФАЗА 0: ПОДГОТОВКА (30 минут)

#### ШАГ 0.1: Разрешить git merge conflict в lib.rs
**Файл**: `src/lib.rs`
**Строки**: 20-439

**Действия**:
1. Открыть `src/lib.rs`
2. Найти маркеры `<<<<<<< Updated upstream`
3. Удалить ВСЕ старые импорты nat модуля
4. Оставить ТОЛЬКО connectivity импорты
5. Удалить дублированные функции:
   - Оставить одну `init_logging()` (новую, строки 107-122)
   - Удалить старую `init_logging()` (строки 70-81)
6. Исправить `has_tls()`:
   ```rust
   pub const fn has_tls() -> bool {
       cfg!(feature = "tls")
   }
   ```
7. Удалить все re-export'ы из nat модуля
8. Проверить компиляцию: `cargo check --no-default-features --features connectivity`

**Ожидаемый результат**: lib.rs компилируется без ошибок

**Критерии успеха**:
- [ ] Нет маркеров merge conflict
- [ ] Нет импортов `use nat::`
- [ ] `has_tls()` корректна
- [ ] `cargo check` проходит

---

### ФАЗА 1: КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ ICE (4-6 часов)

#### ШАГ 1.1: Исправить ICE Connectivity Checks
**Файл**: `src/connectivity/ice/connectivity.rs`
**Приоритет**: 🔴 КРИТИЧЕСКИЙ
**RFC**: RFC 8445 Section 7.2 (STUN Connectivity Checks)

**Текущая проблема**:
```rust
// ПЛОХО - симуляция!
async fn simulate_check_result(&self, pair: &CandidatePair) -> bool {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen::<f64>() < success_probability
}
```

**Правильная реализация**:
```rust
// ХОРОШО - использование webrtc-rs
async fn perform_connectivity_check(&self, pair: &CandidatePair) -> Result<bool> {
    // 1. Получить WebRTC Agent
    let agent = self.webrtc_agent.read().await;

    // 2. Создать STUN Binding Request (webrtc-rs делает автоматически)
    let local_cand = pair.local.to_webrtc_candidate()?;
    let remote_cand = pair.remote.to_webrtc_candidate()?;

    // 3. Выполнить настоящую connectivity check через webrtc-rs
    let result = agent.check_connectivity(&local_cand, &remote_cand).await?;

    Ok(result.is_successful())
}
```

**Детальные шаги**:
1. Удалить всю функцию `simulate_check_result()`
2. Удалить импорт `use rand::Rng;`
3. Заменить все вызовы `simulate_check_result()` на реальные STUN checks через webrtc-rs
4. Использовать `webrtc::ice::agent::Agent::check_candidate_pair()`
5. Обработать реальные STUN response codes (RFC 8445)
6. Добавить обработку ошибок (timeout, unreachable, etc.)

**Методы webrtc-rs для использования**:
- `Agent::check_candidate_pair(local, remote)` - выполняет STUN Binding Request
- `Agent::get_selected_candidate_pair()` - получает выбранную пару
- `Agent::on_connection_state_change()` - отслеживает изменения состояния

**Критерии успеха**:
- [ ] Нет функций `simulate_*()`
- [ ] Используется `webrtc::ice::agent::Agent`
- [ ] STUN Binding Request/Response обрабатываются корректно
- [ ] Тайм-ауты соответствуют RFC 8445 (39.5s для RTO)
- [ ] Логирование STUN транзакций

**Тестирование**:
```rust
#[tokio::test]
async fn test_real_connectivity_check() {
    let agent = create_test_ice_agent().await;
    let pair = create_test_pair();
    let result = agent.perform_connectivity_check(&pair).await;
    assert!(result.is_ok());
}
```

---

#### ШАГ 1.2: Удалить Mock Connection из IceAgent
**Файл**: `src/connectivity/ice/agent.rs`
**Приоритет**: 🔴 КРИТИЧЕСКИЙ
**RFC**: RFC 8445 Section 8 (Concluding ICE)

**Текущая проблема**:
```rust
// ПЛОХО - mock реализация!
struct MockWebRtcConn;
impl webrtc::ice::conn::Conn for MockWebRtcConn {
    fn send(&self, _data: &[u8]) -> Result<usize, webrtc::Error> {
        Ok(0) // НИЧЕГО НЕ ДЕЛАЕТ!
    }
    fn recv(&self, _buf: &mut [u8]) -> Result<usize, webrtc::Error> {
        Ok(0) // НИЧЕГО НЕ ДЕЛАЕТ!
    }
}
```

**Правильная реализация**:
```rust
// ХОРОШО - использование реального Connection от webrtc-rs
async fn establish_connection(&self, pair: &CandidatePair) -> Result<IceConnection> {
    let agent = self.webrtc_agent.read().await;

    // 1. Дождаться завершения ICE
    agent.wait_for_connection().await?;

    // 2. Получить РЕАЛЬНОЕ соединение
    let webrtc_conn = agent.get_connection()?;

    // 3. Обернуть в наш тип
    Ok(IceConnection {
        pair: pair.clone(),
        webrtc_conn: Arc::new(webrtc_conn),
        state: ConnectionState::Connected,
        established_at: Instant::now(),
    })
}
```

**Детальные шаги**:
1. Удалить весь struct `MockWebRtcConn` (строки 624-650)
2. Удалить функцию `create_mock_connection()`
3. Заменить на `establish_connection()` с использованием `Agent::get_connection()`
4. Использовать реальный `Arc<dyn webrtc::ice::conn::Conn>`
5. Добавить обработку состояний: Connecting, Connected, Failed, Closed
6. Реализовать graceful shutdown соединения

**Методы webrtc-rs**:
- `Agent::get_connection()` - получить установленное соединение
- `Conn::send(data)` - отправить данные
- `Conn::recv(buf)` - получить данные
- `Conn::close()` - закрыть соединение

**Критерии успеха**:
- [ ] Нет `MockWebRtcConn`
- [ ] Используется `webrtc::ice::conn::Conn` из библиотеки
- [ ] Соединение функционально (send/recv работают)
- [ ] Правильная обработка закрытия соединения

---

#### ШАГ 1.3: Исправить ICE Nomination
**Файл**: `src/connectivity/ice/nomination.rs`
**Приоритет**: 🟡 ВЫСОКИЙ
**RFC**: RFC 8445 Section 8.1 (Nominating Pairs)

**Текущая проблема**:
```rust
// ПЛОХО - симуляция!
async fn simulate_nomination_success(&self, pair: &CandidatePair) -> bool {
    use rand::Rng;
    rand::thread_rng().gen::<f64>() < 0.9
}
```

**Правильная реализация**:
```rust
// ХОРОШО - реальная nomination через webrtc-rs
async fn nominate_pair(&self, pair: &CandidatePair) -> Result<()> {
    let agent = self.webrtc_agent.read().await;

    // RFC 8445: Controlling agent отправляет STUN request с USE-CANDIDATE
    if self.is_controlling {
        agent.nominate_candidate_pair(
            &pair.local.to_webrtc_candidate()?,
            &pair.remote.to_webrtc_candidate()?
        ).await?;
    }

    Ok(())
}
```

**Детальные шаги**:
1. Удалить `simulate_nomination_success()`
2. Реализовать `nominate_pair()` используя webrtc-rs
3. Различать Controlling vs Controlled роли (RFC 8445)
4. Отправлять STUN Binding Request с атрибутом USE-CANDIDATE
5. Обрабатывать response от controlled agent

**Методы webrtc-rs**:
- `Agent::nominate_candidate_pair()` - номинация пары
- `Agent::is_controlling()` - проверка роли
- `Agent::on_selected_candidate_pair_change()` - callback при выборе пары

**Критерии успеха**:
- [ ] Нет симуляций
- [ ] Правильная роль (controlling/controlled)
- [ ] USE-CANDIDATE атрибут в STUN запросах
- [ ] Обработка успешной и неуспешной nomination

---

#### ШАГ 1.4: Добавить TransportProtocol::Tcp
**Файл**: `src/connectivity/mod.rs`
**Приоритет**: 🟡 ВЫСОКИЙ

**Текущая проблема**:
```rust
// В webrtc_integration.rs:233
transport: if webrtc_candidate.protocol() == "tcp" {
    TransportProtocol::Tcp  // ← НЕ СУЩЕСТВУЕТ!
} else {
    TransportProtocol::Udp
}
```

**Исправление**:
В `src/connectivity/mod.rs` найти enum TransportProtocol и добавить:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Udp,
    Tcp,  // ← ДОБАВИТЬ
    #[cfg(feature = "tls")]
    Tls,
}
```

**Критерии успеха**:
- [ ] `TransportProtocol::Tcp` определен
- [ ] `webrtc_integration.rs` компилируется
- [ ] TCP кандидаты обрабатываются корректно

---

#### ШАГ 1.5: Очистить legacy код
**Файл**: `src/connectivity/ice/mod.rs`
**Приоритет**: 🟢 СРЕДНИЙ

**Действия**:
1. Удалить комментарии TODO (строки 40-41):
   ```rust
   // DELETE: agent.rs (old mock version)
   // DELETE: create_mock_connection function
   ```
2. Проверить что `agent.rs` использует только webrtc-rs (не mock)
3. Убедиться что все type alias актуальны:
   ```rust
   pub type IceAgent = ProductionIceAgent;  // Проверить что это правильный тип
   ```

**Критерии успеха**:
- [ ] Нет TODO комментариев о удалении
- [ ] Нет legacy mock кода
- [ ] Все импорты актуальны

---

### ФАЗА 2: РЕАЛИЗАЦИЯ ENCRYPTION (2-3 часа)

#### ШАГ 2.1: Реализовать encryption/mod.rs
**Файл**: `src/connectivity/encryption/mod.rs`
**Приоритет**: 🔴 КРИТИЧЕСКИЙ
**Стандарты**: AEAD (RFC 5116), ChaCha20-Poly1305 (RFC 8439)

**Текущая проблема**:
```rust
// Объявлено но НЕ реализовано!
pub enum EncryptionAlgorithm {
    ChaCha20Poly1305,
    AesGcm256,
    AesGcm128,
}
// НЕТ ИМПОРТОВ aes-gcm, chacha20poly1305!
```

**Правильная реализация**:
```rust
#[cfg(feature = "relay-encryption")]
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
#[cfg(feature = "relay-encryption")]
use aes_gcm::{Aes256Gcm, Aes128Gcm};
#[cfg(feature = "relay-encryption")]
use aes_gcm::aead::{Aead, KeyInit, OsRng};

pub struct EncryptionContext {
    algorithm: EncryptionAlgorithm,
    cipher: Box<dyn Cipher>,
    nonce_counter: AtomicU64,
}

impl EncryptionContext {
    pub fn new_chacha20poly1305(key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            cipher: Box::new(cipher),
            nonce_counter: AtomicU64::new(0),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.generate_nonce();
        let ciphertext = self.cipher.encrypt(&nonce, plaintext)?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.extract_nonce(ciphertext)?;
        let plaintext = self.cipher.decrypt(&nonce, &ciphertext[12..])?;
        Ok(plaintext)
    }
}
```

**Детальные шаги**:
1. Добавить импорты:
   ```rust
   #[cfg(feature = "relay-encryption")]
   use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};
   #[cfg(feature = "relay-encryption")]
   use aes_gcm::{Aes256Gcm, Aes128Gcm, Key as AesKey};
   #[cfg(feature = "relay-encryption")]
   use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
   ```

2. Реализовать trait `Cipher`:
   ```rust
   pub trait Cipher: Send + Sync {
       fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
       fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
   }
   ```

3. Реализовать для ChaCha20Poly1305:
   ```rust
   impl Cipher for ChaCha20Poly1305 {
       fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
           let nonce = Nonce::from_slice(nonce);
           self.encrypt(nonce, plaintext)
               .map_err(|e| anyhow!("ChaCha20 encryption failed: {}", e))
       }
   }
   ```

4. Реализовать для AesGcm:
   ```rust
   impl Cipher for Aes256Gcm { /* аналогично */ }
   impl Cipher for Aes128Gcm { /* аналогично */ }
   ```

5. Добавить генерацию nonce (RFC 8439 - 96 bit nonce):
   ```rust
   fn generate_nonce(&self) -> Vec<u8> {
       let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
       let mut nonce = vec![0u8; 12]; // 96 bits
       nonce[4..12].copy_from_slice(&counter.to_le_bytes());
       nonce
   }
   ```

6. Добавить тесты:
   ```rust
   #[cfg(test)]
   mod tests {
       #[test]
       fn test_chacha20_encrypt_decrypt() {
           let key = [0u8; 32];
           let ctx = EncryptionContext::new_chacha20poly1305(&key).unwrap();
           let plaintext = b"Hello, World!";
           let ciphertext = ctx.encrypt(plaintext).unwrap();
           let decrypted = ctx.decrypt(&ciphertext).unwrap();
           assert_eq!(plaintext, &decrypted[..]);
       }
   }
   ```

**Критерии успеха**:
- [ ] Импорты `chacha20poly1305` и `aes-gcm` присутствуют
- [ ] Все три алгоритма реализованы
- [ ] Encrypt/decrypt работают
- [ ] Nonce генерируется корректно (уникальный для каждого сообщения)
- [ ] Тесты проходят

---

#### ШАГ 2.2: Проверить header_crypto.rs и turn_crypto.rs
**Файлы**:
- `src/connectivity/encryption/header_crypto.rs`
- `src/connectivity/encryption/turn_crypto.rs`

**Приоритет**: 🟡 ВЫСОКИЙ

**Действия**:
1. Прочитать оба файла
2. Проверить что используют EncryptionContext из mod.rs
3. Убедиться что нет самописного шифрования
4. Проверить что header encryption использует ChaCha20Poly1305
5. Проверить что TURN encryption соответствует RFC 8656

**Критерии успеха**:
- [ ] Используется EncryptionContext
- [ ] Нет самописной криптографии
- [ ] Соответствие RFC

---

### ФАЗА 3: РЕАЛИЗАЦИЯ FALLBACK MODULE (3-4 часа)

#### ШАГ 3.1: Реализовать fallback/mod.rs
**Файл**: `src/connectivity/fallback/mod.rs`
**Приоритет**: 🔴 КРИТИЧЕСКИЙ
**Библиотека**: libp2p 0.53

**Текущее состояние**: ПУСТОЙ (1 строка)

**Правильная реализация**:
```rust
#[cfg(feature = "libp2p-fallback")]
use libp2p::{
    autonat,
    identify,
    ping,
    swarm::{Swarm, SwarmEvent},
    Multiaddr,
    PeerId,
};

#[cfg(feature = "libp2p-fallback")]
pub struct LibP2pClient {
    swarm: Swarm<LibP2pBehaviour>,
    peer_id: PeerId,
}

#[cfg(feature = "libp2p-fallback")]
impl LibP2pClient {
    pub async fn new() -> Result<Self> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        let transport = libp2p::tcp::tokio::Transport::default();
        let behaviour = LibP2pBehaviour::new(&local_key);
        let swarm = Swarm::new(transport, behaviour, peer_id);

        Ok(Self { swarm, peer_id })
    }

    pub async fn detect_nat_type(&mut self) -> Result<NatType> {
        // Используем libp2p autonat для определения типа NAT
        self.swarm.behaviour_mut().autonat.probe_nat().await?;
        // ... обработка результатов
    }
}
```

**Детальные шаги**:
1. Добавить импорты libp2p
2. Создать struct LibP2pClient
3. Реализовать создание Swarm
4. Настроить поведения (autonat, identify, ping)
5. Добавить методы:
   - `new()` - создание клиента
   - `detect_nat_type()` - определение NAT
   - `dial_peer()` - подключение к peer
   - `listen_on()` - прослушивание адреса

**Критерии успеха**:
- [ ] LibP2pClient определен
- [ ] Используется libp2p 0.53
- [ ] Swarm настроен корректно
- [ ] Базовые методы реализованы

---

#### ШАГ 3.2: Реализовать autonat.rs
**Файл**: `src/connectivity/fallback/autonat.rs`
**Приоритет**: 🔴 КРИТИЧЕСКИЙ
**RFC**: libp2p AutoNAT (не RFC, но стандартный протокол)

**Текущее состояние**: ПУСТОЙ

**Правильная реализация**:
```rust
use libp2p::autonat::{Behaviour as AutonatBehaviour, Event, NatStatus};

pub struct AutoNatDetector {
    behaviour: AutonatBehaviour,
}

impl AutoNatDetector {
    pub fn new() -> Self {
        let config = libp2p::autonat::Config::default();
        let behaviour = AutonatBehaviour::new(peer_id, config);
        Self { behaviour }
    }

    pub async fn detect(&mut self) -> Result<NatType> {
        match self.behaviour.nat_status() {
            NatStatus::Public(addr) => Ok(NatType::None),
            NatStatus::Private => Ok(NatType::Symmetric), // упрощение
            NatStatus::Unknown => Ok(NatType::Unknown),
        }
    }
}
```

**Критерии успеха**:
- [ ] Используется libp2p::autonat
- [ ] Определяет публичные/приватные адреса
- [ ] Возвращает правильный NatType

---

#### ШАГ 3.3: Реализовать hole_punch.rs
**Файл**: `src/connectivity/fallback/hole_punch.rs`
**Приоритет**: 🟡 ВЫСОКИЙ
**RFC**: RFC 8445 (Aggressive Nomination for symmetric NAT)

**Текущее состояние**: ПУСТОЙ

**Правильная реализация**:
```rust
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct HolePuncher {
    socket: UdpSocket,
}

impl HolePuncher {
    pub async fn new(local_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        Ok(Self { socket })
    }

    pub async fn punch_hole(&self, remote_addr: SocketAddr) -> Result<()> {
        // Отправляем несколько пакетов для создания отверстия в NAT
        for _ in 0..5 {
            self.socket.send_to(b"PUNCH", remote_addr).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    pub async fn simultaneous_open(
        &self,
        remote_addr: SocketAddr
    ) -> Result<()> {
        // RFC 8445: одновременная отправка с обеих сторон
        tokio::select! {
            _ = self.punch_hole(remote_addr) => {},
            _ = self.listen_for_punch() => {},
        }
        Ok(())
    }
}
```

**Критерии успеха**:
- [ ] UDP hole punching реализован
- [ ] Simultaneous open поддерживается
- [ ] Работает для symmetric NAT (с ограничениями)

---

#### ШАГ 3.4: Реализовать relay_detect.rs
**Файл**: `src/connectivity/fallback/relay_detect.rs`
**Приоритет**: 🟢 СРЕДНИЙ

**Действия**:
1. Реализовать обнаружение необходимости TURN relay
2. Проверка доступности TURN серверов
3. Автоматический выбор relay при symmetric NAT

**Критерии успеха**:
- [ ] Определяет когда нужен relay
- [ ] Проверяет доступность TURN
- [ ] Автоматически переключается на relay

---

### ФАЗА 4: РЕАЛИЗАЦИЯ НЕДОСТАЮЩИХ МОДУЛЕЙ (2-3 часа)

#### ШАГ 4.1: Реализовать http_signaling.rs
**Файл**: `src/connectivity/signaling/http_signaling.rs`
**Приоритет**: 🟡 ВЫСОКИЙ

**Текущее состояние**: ПУСТОЙ

**Правильная реализация**:
```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct HttpSignalingClient {
    client: Client,
    server_url: String,
}

impl HttpSignalingClient {
    pub fn new(server_url: String) -> Self {
        Self {
            client: Client::new(),
            server_url,
        }
    }

    pub async fn send_offer(&self, offer: SignalingMessage) -> Result<()> {
        self.client
            .post(&format!("{}/offer", self.server_url))
            .json(&offer)
            .send()
            .await?;
        Ok(())
    }

    pub async fn poll_answer(&self) -> Result<Option<SignalingMessage>> {
        let response = self.client
            .get(&format!("{}/answer", self.server_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(Some(response.json().await?))
        } else {
            Ok(None)
        }
    }
}
```

**Критерии успеха**:
- [ ] HTTP клиент реализован
- [ ] Отправка/получение signaling сообщений
- [ ] Обработка ошибок сети

---

#### ШАГ 4.2: Реализовать relay_signaling.rs
**Файл**: `src/connectivity/signaling/relay_signaling.rs`
**Приоритет**: 🟡 ВЫСОКИЙ

**Действия**:
1. Реализовать signaling через TURN relay
2. Использовать TURN Send/Data indications
3. Шифрование signaling сообщений

**Критерии успеха**:
- [ ] Signaling через TURN работает
- [ ] Сообщения шифруются
- [ ] Совместимо с relay.rs

---

#### ШАГ 4.3: Реализовать hairpin.rs
**Файл**: `src/connectivity/transport/hairpin.rs`
**Приоритет**: 🟡 ВЫСОКИЙ
**RFC**: RFC 8445 Section 7.2.1.1 (Hairpin detection)

**Текущее состояние**: ПУСТОЙ

**Правильная реализация**:
```rust
use std::net::SocketAddr;

pub struct HairpinDetector;

impl HairpinDetector {
    pub async fn detect(
        local_addr: SocketAddr,
        reflexive_addr: SocketAddr
    ) -> Result<bool> {
        // RFC 8445: Если локальный адрес может достичь рефлексивного,
        // значит NAT поддерживает hairpinning

        let socket = tokio::net::UdpSocket::bind(local_addr).await?;

        // Отправляем пакет на свой рефлексивный адрес
        socket.send_to(b"HAIRPIN_TEST", reflexive_addr).await?;

        // Пытаемся получить ответ
        let mut buf = [0u8; 1024];
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                Ok(result.is_ok())
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                Ok(false)
            }
        }
    }
}
```

**Критерии успеха**:
- [ ] Определяет hairpin NAT
- [ ] Тест корректный (RFC 8445)
- [ ] Интегрировано с ICE

---

### ФАЗА 5: ИСПРАВЛЕНИЕ lib.rs И API (1-2 часа)

#### ШАГ 5.1: Очистить lib.rs от старых импортов
**Файл**: `src/lib.rs`
**Приоритет**: 🔴 КРИТИЧЕСКИЙ

**Действия**:
1. Удалить все `pub use nat::*`
2. Оставить только `pub use connectivity::*`
3. Убрать re-export'ы NatManager, NatConfig, etc.
4. Проверить что все функции используют connectivity API

**Что оставить**:
```rust
#[cfg(feature = "connectivity")]
pub use connectivity::{
    Connectivity,
    ConnectivityManager,
    ConnectivityEvent,
    ConnectivityConfig,
    Candidate,
    CandidatePair,
    ConnectionState,
    EstablishedConnection,
    Transport,
    TransportType,
    TransportProtocol, // ДОБАВИТЬ если нет
};
```

**Что удалить**:
```rust
// УДАЛИТЬ:
pub use nat::{
    NatManager,
    NatConfig,
    NatType,
    // ... все импорты из nat
};
```

**Критерии успеха**:
- [ ] Нет импортов из `nat::`
- [ ] Только connectivity импорты
- [ ] Публичный API понятен и чист

---

#### ШАГ 5.2: Добавить недостающие методы в ConnectivityManager
**Файл**: `src/connectivity/manager.rs`
**Приоритет**: 🟡 ВЫСОКИЙ

**Добавить методы**:
```rust
impl ConnectivityManager {
    pub async fn get_detailed_stats(&self) -> DetailedConnectivityStats {
        DetailedConnectivityStats {
            metrics: self.metrics.read().await.clone(),
            active_pairs: self.get_active_pairs().await,
            selected_pair: self.get_selected_pair().await,
            uptime: self.get_uptime().await,
        }
    }

    pub async fn restart_ice(&self) -> Result<()> {
        self.ice_agent.restart().await?;
        self.start_gathering().await?;
        Ok(())
    }
}
```

**Добавить в ConnectivityMetrics**:
```rust
pub struct ConnectivityMetrics {
    // ... существующие поля
    pub connection_method: Option<String>, // ДОБАВИТЬ
}

impl ConnectivityMetrics {
    pub fn mark_connected(&mut self) { // ДОБАВИТЬ
        self.completed_at = Some(Instant::now());
    }
}
```

**Добавить в Candidate**:
```rust
impl Candidate {
    pub fn is_compatible_with(&self, other: &Candidate) -> bool { // ДОБАВИТЬ
        // IP версии должны совпадать
        self.address.is_ipv4() == other.address.is_ipv4()
    }
}
```

**Добавить в ConnectivityConfig**:
```rust
impl ConnectivityConfig {
    pub fn optimize_for_symmetric_nat(&mut self) { // ДОБАВИТЬ
        self.ice.aggressive_nomination = true;
        self.ice.max_candidate_pairs = 100;
        self.enable_hole_punching = true;
        self.prefer_relay_for_symmetric = true;
    }
}
```

**Критерии успеха**:
- [ ] Все методы из CRITICAL_AUDIT_REPORT реализованы
- [ ] Нет ошибок "method not found"
- [ ] API полный и функциональный

---

#### ШАГ 5.3: Добавить недостающие поля в структуры
**Файл**: `src/connectivity/mod.rs`
**Приоритет**: 🟡 ВЫСОКИЙ

**Добавить в CandidateAttributes**:
```rust
pub struct CandidateAttributes {
    // ... существующие поля
    pub encryption_capable: bool, // ДОБАВИТЬ
}
```

**Добавить в DetailedConnectivityStats** (создать если нет):
```rust
#[derive(Debug, Clone, Serialize)]
pub struct DetailedConnectivityStats {
    pub metrics: ConnectivityMetrics,
    pub active_pairs: Vec<CandidatePair>,
    pub selected_pair: Option<CandidatePair>,
    pub uptime: Duration,
}
```

**Критерии успеха**:
- [ ] Все поля существуют
- [ ] Нет ошибок "field not found"

---

### ФАЗА 6: ИНТЕГРАЦИЯ С SENDER/RECEIVER (1-2 часа)

#### ШАГ 6.1: Обновить sender.rs
**Файл**: `src/sender.rs` (или `src/bin/sender.rs`)
**Приоритет**: 🟡 ВЫСОКИЙ

**Действия**:
1. Найти все использования старого `nat::` API
2. Заменить на `connectivity::` API
3. Пример:
   ```rust
   // СТАРЫЙ КОД:
   use crate::nat::{NatManager, NatConfig};
   let nat_manager = NatManager::new(config).await?;

   // НОВЫЙ КОД:
   use crate::connectivity::{Connectivity, ConnectivityConfig};
   let connectivity = Connectivity::new(config).await?;
   let connection = connectivity.establish(remote_addr).await?;
   ```

**Критерии успеха**:
- [ ] Нет импортов `nat::`
- [ ] Используется `Connectivity` API
- [ ] Sender компилируется

---

#### ШАГ 6.2: Обновить receiver.rs
**Файл**: `src/receiver.rs` (или `src/bin/receiver.rs`)
**Приоритет**: 🟡 ВЫСОКИЙ

**Действия**: Аналогично sender.rs

**Критерии успеха**:
- [ ] Нет импортов `nat::`
- [ ] Используется `Connectivity` API
- [ ] Receiver компилируется

---

#### ШАГ 6.3: Обновить relay.rs (bin)
**Файл**: `src/bin/relay.rs`
**Приоритет**: 🟢 СРЕДНИЙ

**Действия**: Проверить что relay использует connectivity encryption

---

### ФАЗА 7: ТЕСТИРОВАНИЕ И ПРОВЕРКА (2-3 часа)

#### ШАГ 7.1: Компиляция
**Приоритет**: 🔴 КРИТИЧЕСКИЙ

**Команды**:
```bash
# Базовая компиляция
cargo check --no-default-features --features connectivity

# Со всеми features
cargo check --all-features

# Release сборка
cargo build --release --all-features
```

**Критерии успеха**:
- [ ] `cargo check` проходит без ошибок
- [ ] `cargo build --release` успешна
- [ ] Нет warnings о неиспользуемых импортах

---

#### ШАГ 7.2: Unit тесты
**Приоритет**: 🟡 ВЫСОКИЙ

**Команды**:
```bash
cargo test --lib --features connectivity
```

**Добавить тесты для**:
1. ICE gathering
2. Connectivity checks
3. Nomination
4. Encryption
5. Fallback

**Критерии успеха**:
- [ ] Минимум 50% покрытие кода
- [ ] Все critical пути протестированы

---

#### ШАГ 7.3: Интеграционные тесты
**Приоритет**: 🟡 ВЫСОКИЙ

**Создать тесты**:
```rust
// tests/integration_test.rs
#[tokio::test]
async fn test_full_ice_flow() {
    // 1. Создать два агента
    let agent1 = create_test_agent().await;
    let agent2 = create_test_agent().await;

    // 2. Обменяться кандидатами
    exchange_candidates(&agent1, &agent2).await;

    // 3. Выполнить connectivity checks
    let connection = agent1.establish_connection().await.unwrap();

    // 4. Отправить данные
    connection.send(b"Hello").await.unwrap();

    // 5. Проверить получение
    assert_eq!(agent2.recv().await.unwrap(), b"Hello");
}
```

**Критерии успеха**:
- [ ] Тест полного ICE flow проходит
- [ ] Тест с TURN relay проходит
- [ ] Тест с encryption проходит

---

#### ШАГ 7.4: RFC Compliance проверка
**Приоритет**: 🟢 СРЕДНИЙ

**Проверить**:
1. ✅ RFC 8445 (ICE) - все обязательные секции реализованы
2. ✅ RFC 8489 (STUN) - webrtc-stun используется
3. ✅ RFC 8656 (TURN) - webrtc-turn используется
4. ✅ RFC 8838 (Trickle ICE) - поддерживается

**Инструменты**:
- Wireshark для проверки STUN пакетов
- Логи для проверки состояний ICE

**Критерии успеха**:
- [ ] STUN Binding Request/Response корректны
- [ ] ICE state transitions соответствуют RFC
- [ ] Nomination происходит правильно

---

## 📊 ФИНАЛЬНАЯ ПРОВЕРКА

### Чек-лист завершения:

**Код**:
- [ ] Нет симуляций (`simulate_*`)
- [ ] Нет mock объектов (MockWebRtcConn)
- [ ] Все пустые файлы реализованы
- [ ] Все методы из audit report существуют
- [ ] Все поля из audit report существуют

**Библиотеки**:
- [ ] webrtc-rs используется для ICE
- [ ] libp2p используется для fallback
- [ ] chacha20poly1305/aes-gcm используются для encryption
- [ ] igd используется для UPnP (если реализовано)

**RFC**:
- [ ] RFC 8445 (ICE) - полностью соблюдается
- [ ] RFC 8489 (STUN) - через webrtc-stun
- [ ] RFC 8656 (TURN) - через webrtc-turn
- [ ] RFC 8838 (Trickle ICE) - поддерживается

**Компиляция**:
- [ ] `cargo check` - OK
- [ ] `cargo build --release` - OK
- [ ] `cargo test` - OK
- [ ] Нет warnings

**API**:
- [ ] lib.rs экспортирует только connectivity
- [ ] sender.rs использует connectivity
- [ ] receiver.rs использует connectivity
- [ ] Публичный API чист и понятен

---

## ⏱️ ОЦЕНКА ВРЕМЕНИ

| Фаза | Время | Приоритет |
|------|-------|-----------|
| Фаза 0: Подготовка | 30 мин | 🔴 |
| Фаза 1: ICE исправления | 4-6 часов | 🔴 |
| Фаза 2: Encryption | 2-3 часа | 🔴 |
| Фаза 3: Fallback | 3-4 часа | 🔴 |
| Фаза 4: Недостающие модули | 2-3 часа | 🟡 |
| Фаза 5: lib.rs и API | 1-2 часа | 🟡 |
| Фаза 6: Интеграция | 1-2 часа | 🟡 |
| Фаза 7: Тестирование | 2-3 часа | 🟡 |
| **ИТОГО** | **16-24 часа** | |

---

## 🎯 ПРИОРИТЕТЫ

**День 1 (8 часов)**: Фаза 0, 1, 2
- Разрешить merge conflict
- Исправить ICE (убрать симуляции)
- Реализовать encryption

**День 2 (8 часов)**: Фаза 3, 4
- Реализовать fallback (libp2p)
- Реализовать недостающие модули

**День 3 (8 часов)**: Фаза 5, 6, 7
- Очистить API
- Интегрировать с sender/receiver
- Тестирование

---

## 📝 ПРИМЕЧАНИЯ

1. **Параллелизация**: Фазы 2 и 3 можно делать параллельно
2. **Тестирование**: Тестировать после каждой фазы, не ждать конца
3. **Коммиты**: Коммитить после каждой завершенной фазы
4. **Документация**: Обновлять README после завершения

---

**ПЛАН ГОТОВ К ИСПОЛНЕНИЮ**
**Следующий шаг**: Начать с Фазы 0 - разрешение merge conflict
