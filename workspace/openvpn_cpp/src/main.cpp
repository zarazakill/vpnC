#include "openvpn_client.h"
#include <iostream>
#include <signal.h>
#include <csignal>

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