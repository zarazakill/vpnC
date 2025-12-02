#include "config_parser.h"
#include <iostream>
#include <fstream>
#include <sstream>

OpenVPNConfig ConfigParser::parseConfigFile(const std::string& filename) {
    OpenVPNConfig config;
    config.config_file = filename;
    
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
        } else if (key == "reconnect-interval") {
            iss >> config.reconnect_interval;
        } else if (key == "max-reconnect-attempts") {
            iss >> config.max_reconnect_attempts;
        }
    }
    
    file.close();
    return config;
}

void ConfigParser::loadAuthFile(OpenVPNConfig& config, const std::string& filename) {
    std::ifstream file(filename);
    if (file.is_open()) {
        std::getline(file, config.auth_user);
        std::getline(file, config.auth_pass);
        file.close();
    }
}