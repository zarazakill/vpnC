#pragma once
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <vector>

class SSLWrapper {
public:
    enum class SSLMode {
        CLIENT,
        SERVER
    };

    SSLWrapper(SSLMode mode);
    ~SSLWrapper();

    bool initialize();
    bool setCertificate(const std::string& cert_file,
                        const std::string& key_file,
                        const std::string& ca_file = "");
    bool setCipherList(const std::string& cipher_list);
    bool setTLSVersion(const std::string& version);

    bool attachSocket(int socket_fd);
    bool handshake();
    void shutdown();

    int read(std::vector<uint8_t>& buffer, int timeout_ms = -1);
    int write(const std::vector<uint8_t>& data);

    bool verifyCertificate() const;
    std::string getPeerCertificateInfo() const;
    std::string getCipherInfo() const;

    bool isHandshakeComplete() const;

private:
    SSL_CTX* ctx_;
    SSL* ssl_;
    SSLMode mode_;
    bool initialized_;

    static bool ssl_initialized_;

    bool initSSL();
    void cleanup();
    static void initSSLGlobal();
    static void cleanupSSLGlobal();
};
