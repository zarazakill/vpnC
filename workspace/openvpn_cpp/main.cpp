#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <chrono>
#include <queue>

// Структура для хранения конфигурации OpenVPN
struct OpenVPNConfig {
    std::string remote_host;
    int remote_port;
    std::string auth_user;
    std::string auth_pass;
    std::string ca_cert;
    std::string client_cert;
    std::string client_key;
    std::string cipher;
    std::string auth;
    bool use_tun = true;
    std::string tun_device = "tun0";
    int reconnect_interval = 5;
    int max_reconnect_attempts = 10;
    std::string config_file;
    
    OpenVPNConfig() : remote_port(1194), cipher("AES-256-CBC"), auth("SHA256") {}
};

// Структура для управления сессией OpenVPN
struct OpenVPNSession {
    uint32_t session_id;
    uint32_t key_id;
    std::vector<uint8_t> encrypt_key;
    std::vector<uint8_t> decrypt_key;
    std::vector<uint8_t> hmac_key;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_activity;
    
    OpenVPNSession() : session_id(0), key_id(0) {
        created_at = last_activity = std::chrono::steady_clock::now();
    }
};

// Класс для работы с TUN/TAP интерфейсами
class TUNInterface {
private:
    int tun_fd;
    std::string device_name;
    std::string ip_address;
    std::string netmask;
    bool is_open;

public:
    TUNInterface(const std::string& dev_name = "tun0") 
        : tun_fd(-1), device_name(dev_name), is_open(false) {}
    
    ~TUNInterface() {
        close();
    }
    
    bool open(const std::string& ip = "10.8.0.2", const std::string& mask = "255.255.255.0") {
        ip_address = ip;
        netmask = mask;
        
        // Открытие устройства TUN
        tun_fd = ::open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            std::cerr << "Ошибка открытия /dev/net/tun" << std::endl;
            return false;
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        
        // Установка имени устройства
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN-устройство без заголовка пакета
        strncpy(ifr.ifr_name, device_name.c_str(), IFNAMSIZ);
        
        // Создание TUN-устройства
        if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
            std::cerr << "Ошибка создания TUN-устройства: " << strerror(errno) << std::endl;
            ::close(tun_fd);
            return false;
        }
        
        std::cout << "TUN-устройство " << device_name << " создано" << std::endl;
        is_open = true;
        
        // Настройка IP-адреса (требует root прав)
        std::string cmd = "ip addr add " + ip_address + "/" + 
                         std::to_string(countSubnetBits(netmask)) + " dev " + device_name;
        system(cmd.c_str());
        
        cmd = "ip link set " + device_name + " up";
        system(cmd.c_str());
        
        return true;
    }
    
    int read_data(std::vector<uint8_t>& buffer, size_t max_size) {
        if (!is_open || tun_fd < 0) return -1;
        
        buffer.resize(max_size);
        int nbytes = ::read(tun_fd, buffer.data(), max_size);
        if (nbytes > 0) {
            buffer.resize(nbytes);
        } else if (nbytes < 0) {
            std::cerr << "Ошибка чтения из TUN-устройства: " << strerror(errno) << std::endl;
        }
        return nbytes;
    }
    
    int write_data(const std::vector<uint8_t>& data) {
        if (!is_open || tun_fd < 0) return -1;
        
        return ::write(tun_fd, data.data(), data.size());
    }
    
    void close() {
        if (is_open && tun_fd >= 0) {
            ::close(tun_fd);
            is_open = false;
            tun_fd = -1;
            
            // Отключение интерфейса
            std::string cmd = "ip link set " + device_name + " down";
            system(cmd.c_str());
        }
    }
    
private:
    int countSubnetBits(const std::string& netmask) {
        unsigned int mask = inet_addr(netmask.c_str());
        int count = 0;
        while (mask) {
            count += mask & 1;
            mask >>= 1;
        }
        return count;
    }
};

// Класс для управления аутентификацией
class AuthenticationManager {
private:
    std::string username;
    std::string password;
    std::string token;
    
public:
    AuthenticationManager(const std::string& user, const std::string& pass) 
        : username(user), password(pass) {}
    
    bool authenticate() {
        // Здесь должна быть реализация аутентификации
        // В реальной реализации это может быть обмен специальными пакетами аутентификации
        std::cout << "Аутентификация пользователя: " << username << std::endl;
        
        // Генерация токена (в реальной реализации будет более сложной)
        generateToken();
        return !token.empty();
    }
    
    const std::string& getToken() const { return token; }
    
private:
    void generateToken() {
        // Генерация случайного токена
        unsigned char random_bytes[16];
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) == 1) {
            std::stringstream ss;
            for (size_t i = 0; i < sizeof(random_bytes); ++i) {
                ss << std::hex << static_cast<int>(random_bytes[i]);
            }
            token = ss.str();
        }
    }
};

// Класс для обработки конфигурационных файлов
class ConfigParser {
public:
    static OpenVPNConfig parseConfigFile(const std::string& filename) {
        OpenVPNConfig config;
        
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Не удалось открыть конфигурационный файл: " << filename << std::endl;
            return config;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // Удаление комментариев и пробелов
            if (line.find('#') != std::string::npos) {
                line = line.substr(0, line.find('#'));
            }
            
            // Удаление ведущих и завершающих пробелов
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            
            if (line.empty()) continue;
            
            // Парсинг параметров
            std::istringstream iss(line);
            std::string key;
            iss >> key;
            
            if (key == "remote") {
                std::string host, port_str;
                iss >> host >> port_str;
                config.remote_host = host;
                config.remote_port = std::stoi(port_str);
            } else if (key == "auth-user-pass") {
                std::string auth_file;
                iss >> auth_file;
                // Загрузка данных аутентификации из файла
                loadAuthFile(config, auth_file);
            } else if (key == "ca") {
                iss >> config.ca_cert;
            } else if (key == "cert") {
                iss >> config.client_cert;
            } else if (key == "key") {
                iss >> config.client_key;
            } else if (key == "cipher") {
                iss >> config.cipher;
            } else if (key == "auth") {
                iss >> config.auth;
            } else if (key == "dev") {
                std::string dev_type;
                iss >> dev_type;
                config.use_tun = (dev_type == "tun");
            } else if (key == "dev-node") {
                iss >> config.tun_device;
            }
        }
        
        file.close();
        return config;
    }
    
private:
    static void loadAuthFile(OpenVPNConfig& config, const std::string& filename) {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::getline(file, config.auth_user);
            std::getline(file, config.auth_pass);
            file.close();
        }
    }
};

// Основной класс OpenVPN клиента
class OpenVPNClient {
private:
    OpenVPNConfig config_;
    std::unique_ptr<TUNInterface> tun_interface_;
    std::unique_ptr<AuthenticationManager> auth_manager_;
    std::unique_ptr<OpenVPNSession> session_;
    
    // Сокет для связи с сервером
    int socket_fd_;
    struct sockaddr_in server_addr_;
    
    // SSL контекст и соединение
    SSL_CTX* ssl_ctx_;
    SSL* ssl_;
    
    // Потоки для обработки данных
    std::thread network_thread_;
    std::thread tun_thread_;
    std::thread reconnection_thread_;
    
    // Синхронизация
    std::atomic<bool> running_;
    std::mutex connection_mutex_;
    std::condition_variable connection_cv_;
    
    // Статистика
    std::atomic<uint64_t> bytes_sent_;
    std::atomic<uint64_t> bytes_received_;

public:
    OpenVPNClient(const OpenVPNConfig& config) 
        : config_(config), socket_fd_(-1), ssl_ctx_(nullptr), ssl_(nullptr),
          running_(false), bytes_sent_(0), bytes_received_(0) {}
    
    ~OpenVPNClient() {
        disconnect();
    }
    
    bool initialize() {
        std::cout << "Инициализация OpenVPN клиента..." << std::endl;
        
        // Инициализация OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        
        // Создание SSL контекста
        ssl_ctx_ = SSL_CTX_new(DTLS_client_method());
        if (!ssl_ctx_) {
            std::cerr << "Ошибка инициализации SSL контекста" << std::endl;
            return false;
        }
        
        // Настройка SSL контекста
        if (!config_.ca_cert.empty()) {
            if (!SSL_CTX_load_verify_locations(ssl_ctx_, config_.ca_cert.c_str(), nullptr)) {
                std::cerr << "Ошибка загрузки CA сертификата: " << config_.ca_cert << std::endl;
                return false;
            }
        }
        
        if (!config_.client_cert.empty() && !config_.client_key.empty()) {
            if (!SSL_CTX_use_certificate_file(ssl_ctx_, config_.client_cert.c_str(), SSL_FILETYPE_PEM) ||
                !SSL_CTX_use_PrivateKey_file(ssl_ctx_, config_.client_key.c_str(), SSL_FILETYPE_PEM)) {
                std::cerr << "Ошибка загрузки клиентского сертификата или ключа" << std::endl;
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
        
        std::cout << "OpenVPN клиент инициализирован" << std::endl;
        return true;
    }
    
    bool connect() {
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
        
        // Создание SSL соединения
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
        
        // Аутентификация
        if (auth_manager_ && !auth_manager_->authenticate()) {
            std::cerr << "Ошибка аутентификации" << std::endl;
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
        
        return true;
    }
    
    void disconnect() {
        if (!running_) return;
        
        std::cout << "Отключение от VPN сервера..." << std::endl;
        
        running_ = false;
        
        // Ожидание завершения потоков
        if (network_thread_.joinable()) {
            network_thread_.join();
        }
        if (tun_thread_.joinable()) {
            tun_thread_.join();
        }
        if (reconnection_thread_.joinable()) {
            reconnection_thread_.join();
        }
        
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
    
    void reconnect() {
        disconnect();
        connect();
    }
    
    void printStats() const {
        std::cout << "Статистика: отправлено " << bytes_sent_ << " байт, "
                  << "получено " << bytes_received_ << " байт" << std::endl;
    }
    
private:
    void startProcessingThreads() {
        // Поток обработки данных из сети
        network_thread_ = std::thread([this]() {
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
        });
        
        // Поток обработки данных из TUN-интерфейса
        tun_thread_ = std::thread([this]() {
            std::vector<uint8_t> buffer(65536);
            while (running_) {
                int nbytes = tun_interface_->read_data(buffer, buffer.size());
                if (nbytes > 0) {
                    // Шифрование и отправка данных в сеть
                    int ssl_written = SSL_write(ssl_, buffer.data(), nbytes);
                    if (ssl_written > 0) {
                        bytes_sent_ += ssl_written;
                    }
                } else if (nbytes < 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
        });
        
        // Поток управления переподключением
        reconnection_thread_ = std::thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                
                // Проверка активности соединения
                if (session_) {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - session_->last_activity).count();
                    
                    if (elapsed > 30) { // Если нет активности более 30 секунд
                        std::cout << "Нет активности в течение " << elapsed << " секунд, проверка соединения..." << std::endl;
                        // Здесь можно добавить ping/pong для проверки соединения
                    }
                }
            }
        });
    }
    
    uint32_t generateSessionId() {
        unsigned char random_bytes[4];
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) == 1) {
            return *reinterpret_cast<uint32_t*>(random_bytes);
        }
        return static_cast<uint32_t>(std::chrono::steady_clock::now()
                                    .time_since_epoch().count());
    }
};

// Глобальная переменная для обработки сигналов
static std::atomic<bool> should_exit(false);

void signalHandler(int signal) {
    std::cout << "\nПолучен сигнал " << signal << ", завершение работы..." << std::endl;
    should_exit = true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: " << argv[0] << " <конфигурационный_файл>" << std::endl;
        return 1;
    }
    
    // Регистрация обработчика сигналов
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Загрузка конфигурации
    OpenVPNConfig config = ConfigParser::parseConfigFile(argv[1]);
    if (config.remote_host.empty()) {
        std::cerr << "Ошибка: не указан удаленный сервер" << std::endl;
        return 1;
    }
    
    OpenVPNClient client(config);
    
    if (!client.initialize()) {
        std::cerr << "Ошибка инициализации OpenVPN клиента" << std::endl;
        return 1;
    }
    
    if (!client.connect()) {
        std::cerr << "Ошибка подключения к VPN серверу" << std::endl;
        return 1;
    }
    
    std::cout << "VPN соединение активно. Нажмите Ctrl+C для отключения." << std::endl;
    
    
    // Основной цикл работы
    while (!should_exit) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Периодический вывод статистики
        static int stats_counter = 0;
        if (++stats_counter % 10 == 0) {
            client.printStats();
        }
    }
    
    client.disconnect();
    return 0;
}
