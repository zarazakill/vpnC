#ifndef OPENVPN_CLIENT_H
#define OPENVPN_CLIENT_H

#include "config_parser.h"
#include "tun_interface.h"
#include "authentication_manager.h"
#include "openvpn_session.h"
#include "openvpn_protocol.h"
#include "reconnection_manager.h"

#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include <openssl/ssl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class OpenVPNClient {
private:
    OpenVPNConfig config_;
    std::unique_ptr<TUNInterface> tun_interface_;
    std::unique_ptr<AuthenticationManager> auth_manager_;
    std::unique_ptr<OpenVPNSession> session_;
    
    // Socket for server communication
    int socket_fd_;
    struct sockaddr_in server_addr_;
    
    // SSL context and connection
    SSL_CTX* ssl_ctx_;
    SSL* ssl_;
    
    // Processing threads
    std::thread network_thread_;
    std::thread tun_thread_;
    std::unique_ptr<ReconnectionManager> reconnection_manager_;
    
    // Synchronization
    std::atomic<bool> running_;
    std::mutex connection_mutex_;
    std::condition_variable connection_cv_;
    
    // Statistics
    std::atomic<uint64_t> bytes_sent_;
    std::atomic<uint64_t> bytes_received_;

public:
    OpenVPNClient(const OpenVPNConfig& config);
    ~OpenVPNClient();
    
    bool initialize();
    bool connect();
    void disconnect();
    void reconnect();
    void printStats() const;
    bool isConnected() const { return running_ && ssl_ != nullptr; }

private:
    void startProcessingThreads();
    void stopProcessingThreads();
    void handleNetworkData();
    void handleTunData();
    bool establishSSLConnection();
    bool performHandshake();
    uint32_t generateSessionId();
    void updateLastActivity();
};

#endif // OPENVPN_CLIENT_H