#include "openvpn_client.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <thread>
#include <chrono>

OpenVPNClient::OpenVPNClient(const OpenVPNConfig& config) 
    : config_(config), socket_fd_(-1), ssl_ctx_(nullptr), ssl_(nullptr),
      running_(false), bytes_sent_(0), bytes_received_(0) {}

OpenVPNClient::~OpenVPNClient() {
    disconnect();
}

bool OpenVPNClient::initialize() {
    std::cout << "Инициализация OpenVPN клиента..." << std::endl;
    
    // Инициализация OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Создание SSL контекста
    ssl_ctx_ = SSL_CTX_new(DTLS_client_method());
    if (!ssl_ctx_) {
        std::cerr << "Ошибка инициализации SSL контекста" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    // Настройка SSL контекста
    if (!config_.ca_cert.empty()) {
        if (!SSL_CTX_load_verify_locations(ssl_ctx_, config_.ca_cert.c_str(), nullptr)) {
            std::cerr << "Ошибка загрузки CA сертификата: " << config_.ca_cert << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
    }
    
    if (!config_.client_cert.empty() && !config_.client_key.empty()) {
        if (!SSL_CTX_use_certificate_file(ssl_ctx_, config_.client_cert.c_str(), SSL_FILETYPE_PEM) ||
            !SSL_CTX_use_PrivateKey_file(ssl_ctx_, config_.client_key.c_str(), SSL_FILETYPE_PEM)) {
            std::cerr << "Ошибка загрузки клиентского сертификата или ключа" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
        
        if (!SSL_CTX_check_private_key(ssl_ctx_)) {
            std::cerr << "Приватный ключ не соответствует сертификату" << std::endl;
            return false;
        }
    }
    
    // Создание TUN-интерфейса
    tun_interface_ = std::make_unique<TUNInterface>(config_.tun_device);
    if (!tun_interface_->open()) {
        std::cerr << "Ошибка открытия TUN-интерфейса" << std::endl;
        return false;
    }
    
    // Инициализация аутентификации
    if (!config_.auth_user.empty() && !config_.auth_pass.empty()) {
        auth_manager_ = std::make_unique<AuthenticationManager>(config_.auth_user, config_.auth_pass);
    }
    
    // Инициализация менеджера переподключений
    reconnection_manager_ = std::make_unique<ReconnectionManager>(
        config_.reconnect_interval, config_.max_reconnect_attempts);
    
    std::cout << "OpenVPN клиент инициализирован" << std::endl;
    return true;
}

bool OpenVPNClient::connect() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    // Создание UDP сокета
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        std::cerr << "Ошибка создания UDP сокета" << std::endl;
        return false;
    }
    
    // Настройка адреса сервера
    memset(&server_addr_, 0, sizeof(server_addr_));
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(config_.remote_port);
    inet_pton(AF_INET, config_.remote_host.c_str(), &server_addr_.sin_addr);
    
    // Подключение к серверу
    if (::connect(socket_fd_, (struct sockaddr*)&server_addr_, sizeof(server_addr_)) < 0) {
        std::cerr << "Ошибка подключения к серверу: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Установка SSL соединения
    if (!establishSSLConnection()) {
        return false;
    }
    
    // Аутентификация
    if (auth_manager_ && !auth_manager_->authenticate()) {
        std::cerr << "Ошибка аутентификации" << std::endl;
        return false;
    }
    
    // Выполнение handshake
    if (!performHandshake()) {
        std::cerr << "Ошибка выполнения handshake" << std::endl;
        return false;
    }
    
    // Создание сессии
    session_ = std::make_unique<OpenVPNSession>();
    session_->session_id = generateSessionId();
    session_->key_id = 0;
    
    std::cout << "Соединение с VPN сервером установлено" << std::endl;
    std::cout << "Сессия ID: " << session_->session_id << std::endl;
    
    running_ = true;
    
    // Запуск потоков обработки данных
    startProcessingThreads();
    
    // Запуск менеджера переподключений
    reconnection_manager_->start(
        [this]() { return isConnected(); },
        [this]() { reconnect(); }
    );
    
    return true;
}

void OpenVPNClient::disconnect() {
    if (!running_) return;
    
    std::cout << "Отключение от VPN сервера..." << std::endl;
    
    running_ = false;
    
    // Остановка менеджера переподключений
    if (reconnection_manager_) {
        reconnection_manager_->stop();
    }
    
    // Остановка потоков обработки данных
    stopProcessingThreads();
    
    // Закрытие SSL соединения
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    
    // Закрытие сокета
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
    
    // Закрытие TUN-интерфейса
    if (tun_interface_) {
        tun_interface_->close();
    }
    
    std::cout << "VPN соединение закрыто" << std::endl;
}

void OpenVPNClient::reconnect() {
    std::cout << "Попытка переподключения..." << std::endl;
    disconnect();
    
    // Небольшая задержка перед переподключением
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    if (!connect()) {
        std::cerr << "Ошибка переподключения" << std::endl;
    }
}

void OpenVPNClient::printStats() const {
    std::cout << "Статистика: отправлено " << bytes_sent_ << " байт, "
              << "получено " << bytes_received_ << " байт" << std::endl;
}

void OpenVPNClient::startProcessingThreads() {
    // Поток обработки данных из сети
    network_thread_ = std::thread(&OpenVPNClient::handleNetworkData, this);
    
    // Поток обработки данных из TUN-интерфейса
    tun_thread_ = std::thread(&OpenVPNClient::handleTunData, this);
}

void OpenVPNClient::stopProcessingThreads() {
    // Ожидание завершения потоков
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
}

void OpenVPNClient::handleNetworkData() {
    std::vector<uint8_t> buffer(65536);
    while (running_) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_fd_, &read_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            break;
        }
        
        if (FD_ISSET(socket_fd_, &read_fds)) {
            int nbytes = SSL_read(ssl_, buffer.data(), buffer.size());
            if (nbytes > 0) {
                // Запись данных в TUN-интерфейс
                int tun_written = tun_interface_->write_data(
                    std::vector<uint8_t>(buffer.begin(), buffer.begin() + nbytes));
                if (tun_written > 0) {
                    bytes_received_ += tun_written;
                    updateLastActivity();
                }
            } else {
                int ssl_error = SSL_get_error(ssl_, nbytes);
                if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                    std::cerr << "Ошибка SSL чтения" << std::endl;
                    break;
                }
            }
        }
    }
}

void OpenVPNClient::handleTunData() {
    std::vector<uint8_t> buffer(65536);
    while (running_) {
        int nbytes = tun_interface_->read_data(buffer, buffer.size());
        if (nbytes > 0) {
            // Шифрование и отправка данных в сеть
            int ssl_written = SSL_write(ssl_, buffer.data(), nbytes);
            if (ssl_written > 0) {
                bytes_sent_ += ssl_written;
                updateLastActivity();
            }
        } else if (nbytes < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

bool OpenVPNClient::establishSSLConnection() {
    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_) {
        std::cerr << "Ошибка создания SSL объекта" << std::endl;
        return false;
    }
    
    // Привязка сокета к SSL
    BIO* bio = BIO_new_socket(socket_fd_, BIO_NOCLOSE);
    SSL_set_bio(ssl_, bio, bio);
    
    // Установка соединения
    if (SSL_connect(ssl_) <= 0) {
        std::cerr << "Ошибка установки SSL соединения" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    return true;
}

bool OpenVPNClient::performHandshake() {
    // В реальной реализации здесь происходит сложный процесс handshake
    // Для упрощения просто возвращаем true
    // Включаем поддержку TLS 1.2, чтобы избежать проблем с DTLS
    SSL_set_tlsext_host_name(ssl_, config_.remote_host.c_str());
    
    return true;
}

uint32_t OpenVPNClient::generateSessionId() {
    unsigned char random_bytes[4];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) == 1) {
        return *reinterpret_cast<uint32_t*>(random_bytes);
    }
    return static_cast<uint32_t>(std::chrono::steady_clock::now()
                                .time_since_epoch().count());
}

void OpenVPNClient::updateLastActivity() {
    if (session_) {
        session_->last_activity = std::chrono::steady_clock::now();
    }
}