#include "config/OpenVPNConfig.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

// Define the parseConfigLine method that was missing from the header
void OpenVPNConfig::parseConfigLine(const std::string& line) {
    std::istringstream iss(line);
    std::string command;
    iss >> command;
    
    if (command == "remote") {
        std::string host, port_str, protocol = "udp";
        iss >> host >> port_str;
        if (iss >> protocol) {  // Optional protocol
            // protocol already set
        }
        
        ServerEndpoint server;
        server.host = host;
        server.port = std::stoi(port_str);
        server.protocol = protocol;
        server.enabled = true;
        addServer(server);
    }
    else if (command == "ca") {
        iss >> security_.ca_cert;
    }
    else if (command == "cert") {
        iss >> security_.client_cert;
    }
    else if (command == "key") {
        iss >> security_.client_key;
    }
    else if (command == "cipher") {
        iss >> security_.cipher;
    }
    else if (command == "auth") {
        iss >> security_.auth;
    }
    else if (command == "dev") {
        iss >> network_.device_name;
    }
    else if (command == "mtu" || command == "mru") {
        std::string mtu_str;
        iss >> mtu_str;
        network_.mtu = std::stoi(mtu_str);
    }
    else if (command == "keepalive") {
        std::string interval_str, timeout_str;
        iss >> interval_str >> timeout_str;
        connection_.keepalive_interval = std::stoi(interval_str);
        connection_.keepalive_timeout = std::stoi(timeout_str);
    }
    else if (command == "comp-lzo") {
        connection_.compress = true;
        std::string algo;
        iss >> algo;
        if (!algo.empty()) {
            connection_.compression_algorithm = algo;
        } else {
            connection_.compression_algorithm = "yes";
        }
    }
    else if (command == "proto") {
        iss >> network_.device_name;  // Simplified - in real config, this would affect server protocol
    }
    else if (command == "persist-tun") {
        network_.persist_tun = true;
    }
    else {
        // Store unknown options
        std::string remainder;
        std::getline(iss, remainder);
        if (!remainder.empty() && remainder[0] == ' ') {
            remainder = remainder.substr(1);  // Remove leading space
        }
        options_[command] = remainder;
    }
}

OpenVPNConfig::OpenVPNConfig() {
    // Initialize default values
    connection_.reconnect_interval = 5;
    connection_.max_reconnect_attempts = 3;
    connection_.keepalive_interval = 10;
    connection_.keepalive_timeout = 60;
    connection_.compress = false;
    connection_.compression_algorithm = "none";
    
    network_.use_tun = true;
    network_.mtu = 1500;
    network_.persist_tun = false;
}

bool OpenVPNConfig::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    std::vector<std::string> lines;
    while (std::getline(file, line)) {
        // Remove comments and trim whitespace
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        
        // Trim leading/trailing whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    
    for (const auto& config_line : lines) {
        parseConfigLine(config_line);
    }
    
    return true;
}

bool OpenVPNConfig::saveToFile(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    // Save server configuration
    for (const auto& server : servers_) {
        file << "remote " << server.host << " " << server.port << " " << server.protocol << std::endl;
    }
    
    // Save security configuration
    if (!security_.ca_cert.empty()) {
        file << "ca " << security_.ca_cert << std::endl;
    }
    if (!security_.client_cert.empty()) {
        file << "cert " << security_.client_cert << std::endl;
    }
    if (!security_.client_key.empty()) {
        file << "key " << security_.client_key << std::endl;
    }
    if (!security_.cipher.empty()) {
        file << "cipher " << security_.cipher << std::endl;
    }
    if (!security_.auth.empty()) {
        file << "auth " << security_.auth << std::endl;
    }
    
    // Save network configuration
    file << "dev " << network_.device_name << std::endl;
    if (network_.mtu != 1500) {
        file << "mru " << network_.mtu << std::endl;
        file << "mtu " << network_.mtu << std::endl;
    }
    
    // Save connection configuration
    file << "keepalive " << connection_.keepalive_interval << " " << connection_.keepalive_timeout << std::endl;
    
    if (connection_.compress) {
        file << "comp-lzo " << connection_.compression_algorithm << std::endl;
    }
    
    // Save additional options
    for (const auto& option : options_) {
        file << option.first << " " << option.second << std::endl;
    }
    
    return true;
}

void OpenVPNConfig::addServer(const ServerEndpoint& server) {
    servers_.push_back(server);
}

void OpenVPNConfig::setSecurityConfig(const SecurityConfig& security) {
    security_ = security;
}

void OpenVPNConfig::setNetworkConfig(const NetworkConfig& network) {
    network_ = network;
}

void OpenVPNConfig::setConnectionConfig(const ConnectionConfig& connection) {
    connection_ = connection;
}

bool OpenVPNConfig::validate() const {
    // Check if at least one server is configured
    if (servers_.empty()) {
        return false;
    }
    
    // Validate security configuration
    if (security_.verify_cert && (security_.ca_cert.empty() || security_.client_cert.empty() || security_.client_key.empty())) {
        return false;
    }
    
    // Validate network configuration
    if (network_.use_tun && network_.device_name.empty()) {
        return false;
    }
    
    return true;
}
