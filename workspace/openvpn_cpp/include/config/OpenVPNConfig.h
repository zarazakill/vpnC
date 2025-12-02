#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>

struct ServerEndpoint {
    std::string host;
    int port;
    std::string protocol;
    bool enabled;
};

struct SecurityConfig {
    std::string ca_cert;
    std::string client_cert;
    std::string client_key;
    std::string cipher;
    std::string auth;
    std::string tls_version;
    std::string tls_cipher;
    bool verify_cert;
    bool verify_name;
};

struct NetworkConfig {
    bool use_tun;
    std::string device_name;
    std::string local_ip;
    std::string remote_ip;
    std::string netmask;
    int mtu;
    bool persist_tun;
    std::vector<std::string> routes;
    std::vector<std::string> dns_servers;
};

struct ConnectionConfig {
    int reconnect_interval;
    int max_reconnect_attempts;
    int keepalive_interval;
    int keepalive_timeout;
    bool compress;
    std::string compression_algorithm;
};

class OpenVPNConfig {
private:
    std::vector<ServerEndpoint> servers_;
    SecurityConfig security_;
    NetworkConfig network_;
    ConnectionConfig connection_;
    std::map<std::string, std::string> options_;

    void parseConfigLine(const std::string& line);

public:
    OpenVPNConfig();
    bool loadFromFile(const std::string& filename);
    bool saveToFile(const std::string& filename);

    // Геттеры/сеттеры
    const std::vector<ServerEndpoint>& getServers() const { return servers_; }
    const SecurityConfig& getSecurityConfig() const { return security_; }
    const NetworkConfig& getNetworkConfig() const { return network_; }
    const ConnectionConfig& getConnectionConfig() const { return connection_; }

    void addServer(const ServerEndpoint& server);
    void setSecurityConfig(const SecurityConfig& security);
    void setNetworkConfig(const NetworkConfig& network);
    void setConnectionConfig(const ConnectionConfig& connection);

    bool validate() const;
};
