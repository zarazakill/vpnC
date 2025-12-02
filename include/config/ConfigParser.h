#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>

class ConfigParser {
public:
    struct Config {
        std::string remote_host;
        int remote_port;
        std::string proto;
        std::string dev_type;
        std::string ca_cert;
        std::string client_cert;
        std::string client_key;
        std::string auth_user_pass_file;
        std::string cipher;
        std::string auth;
        int connect_retry;
        int connect_retry_max;
        bool nobind;
        bool tun_ipv6;
        std::string comp_lzo;
        int verb;
        int key_direction;
        std::string tls_auth;
        std::string tls_cipher;
        std::string remote_cert_tls;
        bool persist_tun;
        bool persist_key;
        
        Config() : remote_port(0), connect_retry(2), connect_retry_max(0), 
                   nobind(false), tun_ipv6(false), verb(1), key_direction(-1) {}
    };

    static bool parseFile(const std::string& filename, Config& config);
    static bool parseString(const std::string& configStr, Config& config);
    
private:
    static std::string trim(const std::string& str);
    static std::vector<std::string> split(const std::string& str, char delimiter);
};

#endif // CONFIG_PARSER_H