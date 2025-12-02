#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <string>
#include <vector>

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

class ConfigParser {
public:
    static OpenVPNConfig parseConfigFile(const std::string& filename);
    
private:
    static void loadAuthFile(OpenVPNConfig& config, const std::string& filename);
};

#endif // CONFIG_PARSER_H