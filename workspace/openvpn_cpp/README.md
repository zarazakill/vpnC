# OpenVPN Client in C++

Реализация OpenVPN клиента на C++ с поддержкой TUN/TAP интерфейсов и SSL/TLS.

## Особенности

- Поддержка TUN/TAP интерфейсов
- SSL/TLS шифрование через OpenSSL
- Асинхронная обработка пакетов
- Поддержка аутентификации по сертификатам
- Автоматическое переподключение
- Подробное логирование
- Статистика трафика
- Конфигурирование через файлы

## Сборка

### Требования

- CMake 3.14+
- C++17 компилятор
- OpenSSL 1.1.1+
- Linux/Unix система (для TUN/TAP)

### Сборка из исходников

```bash
# Клонирование репозитория
git clone <repository-url>
cd openvpn-cpp-client

# Создание директории сборки
mkdir build && cd build

# Конфигурация
cmake .. -DCMAKE_BUILD_TYPE=Release

# Сборка
cmake --build . --config Release

# Установка (опционально)
sudo cmake --install .
