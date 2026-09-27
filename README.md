# SHARP-256 Protocol

**S**wift **H**ash **A**ssurance **R**ust **P**rotocol

Высокопроизводительный протокол передачи файлов с проверкой целостности на основе BLAKE3.

## Особенности

- 🚀 Высокая скорость передачи (80-90% от пропускной способности канала)
- 🔒 Проверка целостности данных с помощью BLAKE3
- 📊 Система автоматической оптимизации (SAO)
- 💾 Поддержка возобновления передачи после разрыва
- 🖥️ GUI и headless режимы работы
- 🔐 Опциональное шифрование TLS 1.3
- 📈 Адаптивная настройка под условия сети
- 🌐 **NAT traversal** (STUN, UPnP, UDP hole punching)
- 🔄 **Relay сервер** для сложных сетевых конфигураций

## Архитектура

- Блоки данных: 256 КБ
- Партии: 5-50 пакетов (динамически)
- Хеширование: BLAKE3
- Транспорт: UDP с собственной надежностью
- Поддержка GSO/GRO для пакетов до 64 КБ
- NAT traversal: STUN для определения публичного IP, UPnP для автоматического проброса портов, UDP hole punching для P2P

## Установка

### Требования

- Rust 1.70+
- Cargo

### Сборка

```bash
# Клонирование репозитория
git clone https://github.com/your-repo/sharp-256
cd sharp-256

# Сборка с GUI и NAT traversal (по умолчанию)
cargo build --release

# Сборка без GUI
cargo build --release --no-default-features --features nat-traversal

# Сборка с поддержкой TLS
cargo build --release --features tls

# Полная сборка со всеми возможностями
cargo build --release --features "gui,tls,nat-traversal"
```

## Использование

### Отправитель

```bash
# GUI режим с автоматическим NAT traversal
./target/release/sharp-sender /path/to/file.bin 192.168.1.100:5555

# Headless режим
./target/release/sharp-sender /path/to/file.bin 192.168.1.100:5555 --headless

# С шифрованием
./target/release/sharp-sender /path/to/file.bin 192.168.1.100:5555 --encrypt

# Отключить NAT traversal (только прямое соединение)
./target/release/sharp-sender /path/to/file.bin 192.168.1.100:5555 --no-nat

# Указание локального адреса
./target/release/sharp-sender /path/to/file.bin 192.168.1.100:5555 --bind 0.0.0.0:5556
```

### Получатель

```bash
# GUI режим с автоматическим NAT traversal
./target/release/sharp-receiver

# Headless режим
./target/release/sharp-receiver --headless

# Указание директории для сохранения
./target/release/sharp-receiver --output /path/to/downloads

# Указание адреса прослушивания
./target/release/sharp-receiver --bind 0.0.0.0:5555

# Отключить NAT traversal
./target/release/sharp-receiver --no-nat
```

### Relay сервер

Для случаев, когда прямое P2P соединение невозможно:

```bash
# Запуск relay сервера
./target/release/sharp-relay --bind 0.0.0.0:5556

# Клиенты могут использовать relay через API
```

## NAT Traversal

Протокол автоматически пытается установить прямое соединение между клиентами используя:

1. **STUN** - определение публичного IP адреса через серверы:
   - stun.l.google.com:19302
   - stun.cloudflare.com:3478

2. **UPnP** - автоматический проброс портов на роутере

3. **UDP Hole Punching** - пробивание NAT для P2P соединения

4. **Relay** - пересылка через промежуточный сервер (последний вариант)

### Сценарии подключения

| Отправитель | Получатель | Метод соединения |
|-------------|------------|------------------|
| Публичный IP | Публичный IP | Прямое |
| За NAT | Публичный IP | Прямое |
| Публичный IP | За NAT | UPnP или Relay |
| За NAT | За NAT | Hole Punching или Relay |
| За Symmetric NAT | За NAT | Relay |

## Параметры командной строки

### sharp-sender

- `file` - Путь к файлу для отправки
- `receiver` - IP:порт получателя
- `--bind` - Локальный адрес (по умолчанию 0.0.0.0:0)
- `--encrypt` - Включить шифрование TLS 1.3
- `--no-nat` - Отключить NAT traversal
- `--log-level` - Уровень логирования (trace/debug/info/warn/error)
- `--headless` - Запуск без GUI

### sharp-receiver

- `--output` - Директория для сохранения файлов (по умолчанию ./received)
- `--bind` - Адрес прослушивания (по умолчанию 0.0.0.0:5555)
- `--no-nat` - Отключить NAT traversal
- `--log-level` - Уровень логирования
- `--headless` - Запуск без GUI

### sharp-relay

- `--bind` - Адрес прослушивания (по умолчанию 0.0.0.0:5556)
- `--log-level` - Уровень логирования

## API для интеграции

```rust
use sharp_256::{Sender, Receiver};
use std::net::SocketAddr;
use std::path::Path;

// Отправка файла
async fn send_file() -> Result<()> {
    let sender = Sender::new(
        "0.0.0.0:0".parse()?,
        "192.168.1.100:5555".parse()?,
        Path::new("/path/to/file.bin"),
        false, // без шифрования
    ).await?;
    
    sender.start_transfer().await?;
    Ok(())
}

// Прием файлов
async fn receive_files() -> Result<()> {
    let receiver = Receiver::new(
        "0.0.0.0:5555".parse()?,
        PathBuf::from("./downloads"),
    ).await?;
    
    receiver.start().await?;
    Ok(())
}
```

## Производительность

На канале 1 Гбит/с:
- Без шифрования: ~850-900 Мбит/с
- С TLS 1.3: ~700-800 Мбит/с

## Система автоматической оптимизации (SAO)

SAO автоматически регулирует размер партии (5-50 пакетов) на основе:
- RTT (Round Trip Time)
- Процента потерь пакетов
- Пропускной способности канала

Формула расчета:
```
score = (1 - loss_rate) * bandwidth_utilization * (1 / (1 + rtt/100))
```

## Возобновление передачи

При разрыве соединения создается файл состояния в:
- Windows: `%APPDATA%\sharp-256\states\`
- Linux: `~/.local/share/sharp-256/states/`
- macOS: `~/Library/Application Support/sharp-256/states/`

При повторном запуске передача автоматически возобновляется с места разрыва.

## Лицензия

MIT, см. файл [LICENSE](LICENSE).

## Автор

Echo_1