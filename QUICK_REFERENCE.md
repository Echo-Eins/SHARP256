# SHARP-256 - Быстрая Справка

## Что это?
**SHARP-256** - высокопроизводительный протокол передачи файлов с:
- 80-90% пропускной способности сети
- Поддержкой **всех типов NAT** (включая symmetric)
- WebRTC ICE интеграцией (RFC 8445)
- Верификацией целостности BLAKE3

## Основные Компоненты

```
Sender ─────────► [Protocol Layer + SAO] ─────────► Network
                         ▲
                         │
                  [Connectivity Manager]
                  • ICE (primary)
                  • Fallback systems
                  • Transport selection
                         │
                         ▼
                    UDP Socket
                         │
                         ▼
                    Receiver
```

## Ключевые Цифры

| Метрика | Значение |
|---------|----------|
| Размер блока | 256 KB |
| Размер заголовка пакета | 30 байт |
| Размер батча | 5-50 пакетов (динамический) |
| Хеширование | BLAKE3 (32 байта) |
| Макс пакет (GSO) | 64 KB |
| Производительность | 80-90% от пропускной способности |
| Покрытие NAT | ~95% всех сценариев |

## Недавние Изменения

### Коммит "New NAT 1" (6d0bf8c) - ГЛАВНЫЙ РЕФАКТОРИНГ
- **Добавлено**: 17,167 строк кода
- **Удалено**: 1,123 строк
- **Измененно**: 60 файлов

**Что добавлено:**
```
connectivity/                    # НОВАЯ система
├── ice/                        # WebRTC ICE
├── manager.rs                  # Менеджер соединений
├── config.rs                   # Полная конфиг
├── transport/                  # Абстракция
├── signaling/                  # Сигнализация
├── encryption/                 # Шифрование
└── fallback/                   # Fallback системы
```

### Коммиты ICE Integration (11 коммитов)
- Интеграция WebRTC ICE
- Исправления STUN
- Отладка connectivity checks
- Улучшение nomination

### Коммиты New Relay (4 коммита)
- SHARP relay сервер
- TURN поддержка
- Header encryption

## Архитектура NAT Traversal

### Многоуровневая Цепочка (5 уровней)

```
1. СТУК (STUN) - RFC 8489
   └─ MESSAGE-INTEGRITY-SHA256

2. UPnP/NAT-PMP/PCP
   └─ Автоматический проброс портов

3. WebRTC ICE - RFC 8445
   ├─ Host кандидаты
   ├─ Server reflexive (STUN)
   ├─ Peer reflexive
   └─ Relayed (TURN)

4. Hole Punching
   └─ Birthday paradox для портов

5. TURN Relay - RFC 8656
   └─ Гарантированное резервирование
```

## RFC Стандарты

✓ **RFC 8489** (STUN) - NAT обнаружение
✓ **RFC 8445** (ICE) - Интерактивный обход соединения  
✓ **RFC 8838** (Trickle ICE) - Инкрементальная доставка кандидатов
✓ **RFC 5768** (mDNS) - Приватность имен
✓ **RFC 8656** (TURN) - Relay протокол
✓ **RFC 6887** (PCP) - Управление NAT
✓ **RFC 6886** (NAT-PMP) - Проброс портов (Apple)
✓ **UPnP IGD v2.0** - Управление роутером

## SAO (System of Automatic Optimization)

**Динамическая подстройка параметров:**

```
Score = (1 - loss_rate) * bandwidth * (1 / (1 + rtt/100))

Адаптация:
• score > 0.8  → batch_size +5 (макс 50)
• score < 0.4  → batch_size -5 (мин 5)
• иначе → сохранить
```

## Структура Пакета (30 байт заголовок)

```
┌─────────────────────────────────────────────┐
│ Magic (0x5348) │ Ver │ Type │ Flags        │ 2+1+1+1
├─────────────────────────────────────────────┤
│ Batch # │ Packet # │ Total Packets │ Len   │ 4+2+2+4
├─────────────────────────────────────────────┤
│ Sequence │ Reserved (9 bytes)               │ 4+9
└─────────────────────────────────────────────┘
```

## Типы Пакетов

- **0x01 - Data** - данные файла
- **0x02 - Hash** - BLAKE3 хеш партии
- **0x03 - Ack** - подтверждение
- **0x04 - Control** - контрольные параметры
- **0x05 - Resume** - возобновление

## Зависимости (Ключевые)

### WebRTC Stack
- webrtc 0.13.0
- webrtc-ice 0.13.0
- webrtc-stun 0.1.13
- webrtc-turn 0.1.3
- webrtc-srtp 0.15.0

### Криптография
- blake3 1.5 (хеширование)
- x25519-dalek 2.0 (ECDH)
- aes-gcm 0.10 (шифрование)
- rustls 0.22 (TLS 1.3)

### P2P & Network
- tokio 1.35 (async runtime)
- libp2p 0.53 (fallback система)
- igd 0.12 (UPnP)
- socket2 0.5 (socket options)

## Исполняемые Файлы

```bash
./sharp-sender   # Отправитель (GUI или CLI)
./sharp-receiver # Получатель (GUI или CLI)  
./sharp-relay    # TURN relay сервер
```

## Команды Примеры

```bash
# Отправить файл
./sharp-sender file.zip 192.168.1.100:5555

# Запустить получатель
./sharp-receiver --bind 0.0.0.0:5555 --output ~/Downloads

# Запустить relay сервер
./sharp-relay --bind 0.0.0.0:5556

# С шифрованием TLS
./sharp-sender file.zip 192.168.1.100:5555 --encrypt
```

## Статистика Кода

| Метрика | Значение |
|---------|----------|
| Rust файлов | 53 |
| Размер src/ | 813 KB |
| Самый большой файл | ice/agent.rs (1116 строк) |
| Строк документации | 19K (Rec after commit 12.txt) |
| PDF документов | 2 (173K + 6.9M) |

## Производительность

| Сетевой тип | Скорость | SHARP-256 |
|------------|----------|-----------|
| LAN 1Gbps | 1000 Mbps | 850-900 Mbps |
| WAN 1Gbps | 1000 Mbps | 800-850 Mbps |
| Internet 100Mbps | 100 Mbps | 85-90 Mbps |
| 4G LTE | 50 Mbps | 42-45 Mbps |

С TLS: ~10-15% overhead

## Сильные Стороны

✓ Комплексная система NAT traversal  
✓ Высокая производительность (80-90%)  
✓ Multi-layered fallback архитектура  
✓ RFC-совместимость  
✓ Production-ready код  
✓ Отличная документация  
✓ Модульная архитектура  
✓ BLAKE3 верификация  
✓ Адаптивная оптимизация (SAO)  

## Развертывание

Готов для:
- Быстрой передачи файлов между машинами
- P2P приложений
- Резервного копирования
- Real-time систем (низкая латентность)
- Систем требующих обхода NAT

## Документация

- `/home/user/SHARP256/README.md` - Основное описание
- `/home/user/SHARP256/Connectivity.md` - Система connectivity
- `/home/user/SHARP256/RESEARCH_REPORT_RU.txt` - Полный отчет (765 строк)
- `/home/user/SHARP256/Rec after commit 12.txt` - Современный NAT traversal (19K)

---
**Версия**: 0.4.0 | **Язык**: Rust 1.70+ | **Лицензия**: MIT
