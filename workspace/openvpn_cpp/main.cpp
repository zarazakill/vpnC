#include <iostream>
#include <string>
#include <thread>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>

class OpenVPNClient {
private:
    std::string server_addr;
    int server_port;
    SSL_CTX* ssl_ctx;
    int socket_fd;

public:
    OpenVPNClient(const std::string& addr, int port)
    : server_addr(addr), server_port(port), ssl_ctx(nullptr), socket_fd(-1) {}

    bool initialize() {
        // Инициализация OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        ssl_ctx = SSL_CTX_new(DTLS_client_method());
        if (!ssl_ctx) {
            std::cerr << "Ошибка инициализации SSL контекста" << std::endl;
            return false;
        }

        // Настройка SSL контекста
        if (!SSL_CTX_load_verify_locations(ssl_ctx, "ca.crt", nullptr)) {
            std::cerr << "Ошибка загрузки CA сертификата" << std::endl;
            return false;
        }

        return true;
    }

    bool connect() {
        // Создание UDP сокета
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            std::cerr << "Ошибка создания сокета" << std::endl;
            return false;
        }

        // Настройка адреса сервера
        struct sockaddr_in server_addr_in;
        memset(&server_addr_in, 0, sizeof(server_addr_in));
        server_addr_in.sin_family = AF_INET;
        server_addr_in.sin_port = htons(server_port);
        inet_pton(AF_INET, server_addr.c_str(), &server_addr_in.sin_addr);

        // Подключение к серверу
        if (::connect(socket_fd, (struct sockaddr*)&server_addr_in, sizeof(server_addr_in)) < 0) {
            std::cerr << "Ошибка подключения к серверу" << std::endl;
            return false;
        }

        // Создание SSL соединения
        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            std::cerr << "Ошибка создания SSL объекта" << std::endl;
            return false;
        }

        // Привязка сокета к SSL
        BIO* bio = BIO_new_socket(socket_fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);

        // Установка соединения
        if (SSL_connect(ssl) <= 0) {
            std::cerr << "Ошибка установки SSL соединения" << std::endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            return false;
        }

        std::cout << "Соединение с VPN сервером установлено" << std::endl;
        return true;
    }

    void disconnect() {
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
        }
        EVP_cleanup();
        ERR_free_strings();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Использование: " << argv[0] << " <адрес_сервера> <порт>" << std::endl;
        return 1;
    }

    OpenVPNClient client(argv[1], std::stoi(argv[2]));

    if (!client.initialize()) {
        std::cerr << "Ошибка инициализации OpenVPN клиента" << std::endl;
        return 1;
    }

    if (!client.connect()) {
        std::cerr << "Ошибка подключения к VPN серверу" << std::endl;
        return 1;
    }

    // Основной цикл работы
    std::cout << "VPN соединение активно. Нажмите Ctrl+C для отключения." << std::endl;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    client.disconnect();
    return 0;
}
