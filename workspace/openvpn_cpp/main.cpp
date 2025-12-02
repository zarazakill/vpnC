#include "core/OpenVPNClient.h"
#include "utils/Logger.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <memory>

std::atomic<bool> running(true);
std::unique_ptr<OpenVPNClient> client;

void signalHandler(int signal) {
    std::cout << "\nПолучен сигнал " << signal << ", завершение работы..." << std::endl;
    running = false;
    if (client) {
        client->disconnect();
    }
}

void onLogMessage(const std::string& message) {
    std::cout << "[LOG] " << message << std::endl;
}

void onStateChange(OpenVPNClient::ClientState state) {
    static const char* state_names[] = {
        "DISCONNECTED",
        "CONNECTING",
        "HANDSHAKE",
        "AUTHENTICATING",
        "CONNECTED",
        "RECONNECTING",
        "ERROR"
    };
    std::cout << "[STATE] " << state_names[static_cast<int>(state)] << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: " << argv[0] << " <конфигурационный_файл>" << std::endl;
        return 1;
    }

    // Настройка обработки сигналов
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    try {
        // Настройка логгера
        Logger::getInstance().setConsoleOutput(true);
        Logger::getInstance().setLogLevel(Logger::LogLevel::INFO);

        // Создание клиента
        client = std::make_unique<OpenVPNClient>();
        client->setLogCallback(onLogMessage);
        client->setStateChangeCallback(onStateChange);

        // Инициализация
        if (!client->initialize(argv[1])) {
            std::cerr << "Ошибка инициализации клиента" << std::endl;
            return 1;
        }

        // Подключение
        std::cout << "Подключение к VPN..." << std::endl;
        if (!client->connect()) {
            std::cerr << "Ошибка подключения" << std::endl;
            return 1;
        }

        // Основной цикл
        std::cout << "VPN подключен. Нажмите Ctrl+C для отключения." << std::endl;

        auto last_stats_time = std::chrono::steady_clock::now();
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // Периодический вывод статистики
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_stats_time).count();

                if (elapsed >= 10) {
                    auto stats = client->getStats();
                    std::cout << "\nСтатистика:" << std::endl;
                    std::cout << "  Отправлено: " << stats.total_bytes_sent << " байт" << std::endl;
                    std::cout << "  Получено: " << stats.total_bytes_received << " байт" << std::endl;
                    std::cout << "  Пакеты: " << stats.packets_sent << " отправлено, "
                    << stats.packets_received << " получено" << std::endl;
                    std::cout << "  Время подключения: " << stats.connection_time << " секунд" << std::endl;
                    last_stats_time = now;
                }
        }

        std::cout << "Завершение работы..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Исключение: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
