Модуль connectivity/mod.rs. Фундамент для всей системы. Ключевые компоненты:
1) Публичный API через структуру Connectivity - простой интерфейс для использования
2) Универсальные структуры - Candidate, CandidatePair, ConnectionState и т.д.
3) Модульная архитектура - условная компиляция для разных features
4) Метрики и мониторинг - ConnectivityMetrics для отладки
5) Utilities - полезные функции для работы с адресами
6) Тесты - основные unit тесты

Модуль connectivity/config.rs. Полная структура конфигурации для всех компонентов connectivity систем:
1) IceConfig - WebRTC ICE конфигурация с STUN/TURN серверами
2) LibP2pConfig - fallback система на libp2p
3) RelayConfig - конфигурация для SHARP relay серверов с шифрованием заголовков
4) RouterPoolsConfig - пулы NAT роутеров из файлов
5) UpnpConfig - legacy UPnP поддержка
6) GeneralConfig - общие настройки

Особенности:
1. Модульность через conditional compilation
2. Различные профили (testing, production)
3. Специальная оптимизация для symmetric NAT
4. Валидация конфигурации
5. Поддержка TOML файлов для пулов роутеров\

