#include "config/ConfigParser.h"
#include <fstream>
#include <algorithm>
#include <sstream>

std::string ConfigParser::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> ConfigParser::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

bool ConfigParser::parseFile(const std::string& filename, Config& config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Find the first space or tab to separate command from arguments
        size_t pos = line.find_first_of(" \t");
        if (pos == std::string::npos) {
            // Command without arguments
            std::string command = line;
            if (command == "nobind") {
                config.nobind = true;
            } else if (command == "tun-ipv6") {
                config.tun_ipv6 = true;
            } else if (command == "persist-tun") {
                config.persist_tun = true;
            } else if (command == "persist-key") {
                config.persist_key = true;
            }
            continue;
        }
        
        std::string command = line.substr(0, pos);
        std::string args = trim(line.substr(pos));
        
        if (command == "remote") {
            auto parts = split(args, ' ');
            if (parts.size() >= 2) {
                config.remote_host = parts[0];
                try {
                    config.remote_port = std::stoi(parts[1]);
                } catch (const std::exception&) {
                    return false;
                }
            }
        } else if (command == "proto") {
            config.proto = args;
        } else if (command == "dev-type") {
            config.dev_type = args;
        } else if (command == "ca") {
            config.ca_cert = args;
        } else if (command == "cert") {
            config.client_cert = args;
        } else if (command == "key") {
            config.client_key = args;
        } else if (command == "auth-user-pass") {
            config.auth_user_pass_file = args;
        } else if (command == "cipher") {
            config.cipher = args;
        } else if (command == "auth") {
            config.auth = args;
        } else if (command == "connect-retry") {
            try {
                config.connect_retry = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "connect-retry-max") {
            try {
                config.connect_retry_max = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "comp-lzo") {
            config.comp_lzo = args.empty() ? "yes" : args;
        } else if (command == "verb") {
            try {
                config.verb = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "key-direction") {
            try {
                config.key_direction = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "tls-auth") {
            config.tls_auth = args;
        } else if (command == "tls-cipher") {
            config.tls_cipher = args;
        } else if (command == "remote-cert-tls") {
            config.remote_cert_tls = args;
        }
    }
    
    file.close();
    return true;
}

bool ConfigParser::parseString(const std::string& configStr, Config& config) {
    std::istringstream stream(configStr);
    std::string line;
    
    while (std::getline(stream, line)) {
        line = trim(line);
        
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Find the first space or tab to separate command from arguments
        size_t pos = line.find_first_of(" \t");
        if (pos == std::string::npos) {
            // Command without arguments
            std::string command = line;
            if (command == "nobind") {
                config.nobind = true;
            } else if (command == "tun-ipv6") {
                config.tun_ipv6 = true;
            } else if (command == "persist-tun") {
                config.persist_tun = true;
            } else if (command == "persist-key") {
                config.persist_key = true;
            }
            continue;
        }
        
        std::string command = line.substr(0, pos);
        std::string args = trim(line.substr(pos));
        
        if (command == "remote") {
            auto parts = split(args, ' ');
            if (parts.size() >= 2) {
                config.remote_host = parts[0];
                try {
                    config.remote_port = std::stoi(parts[1]);
                } catch (const std::exception&) {
                    return false;
                }
            }
        } else if (command == "proto") {
            config.proto = args;
        } else if (command == "dev-type") {
            config.dev_type = args;
        } else if (command == "ca") {
            config.ca_cert = args;
        } else if (command == "cert") {
            config.client_cert = args;
        } else if (command == "key") {
            config.client_key = args;
        } else if (command == "auth-user-pass") {
            config.auth_user_pass_file = args;
        } else if (command == "cipher") {
            config.cipher = args;
        } else if (command == "auth") {
            config.auth = args;
        } else if (command == "connect-retry") {
            try {
                config.connect_retry = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "connect-retry-max") {
            try {
                config.connect_retry_max = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "comp-lzo") {
            config.comp_lzo = args.empty() ? "yes" : args;
        } else if (command == "verb") {
            try {
                config.verb = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "key-direction") {
            try {
                config.key_direction = std::stoi(args);
            } catch (const std::exception&) {
                return false;
            }
        } else if (command == "tls-auth") {
            config.tls_auth = args;
        } else if (command == "tls-cipher") {
            config.tls_cipher = args;
        } else if (command == "remote-cert-tls") {
            config.remote_cert_tls = args;
        }
    }
    
    return true;
}