#pragma once
#include "config/OpenVPNConfig.h"
#include "network/UDPClient.h"
#include "network/SSLWrapper.h"
#include "crypto/EncryptionManager.h"
#include "interface/TUNInterface.h"
#include "auth/AuthenticationManager.h"
#include "session/SessionManager.h"
#include "utils/Logger.h"
#include "utils/ThreadPool.h"
#include "core/ConnectionManager.h"
#include "core/StateMachine.h"

class OpenVPNClient {
public:
    enum class ClientState {
        DISCONNECTED,
        CONNECTING,
        HANDSHAKE,
        AUTHENTICATING,
        CONNECTED,
        RECONNECTING,
        ERROR
    };

    struct ClientStats {
        uint64_t total_bytes_sent;
        uint64_t total_bytes_received;
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t connection_time;
        uint64_t reconnects;
    };

    OpenVPNClient();
    ~OpenVPNClient();

    bool initialize(const std::string& config_file);
    bool connect();
    void disconnect();
    void reconnect();

    ClientState getState() const;
    ClientStats getStats() const;

    void setLogCallback(std::function<void(const std::string&)> callback);
    void setStateChangeCallback(std::function<void(ClientState)> callback);

    bool isConnected() const;

private:
    std::unique_ptr<OpenVPNConfig> config_;
    std::unique_ptr<UDPClient> udp_client_;
    std::unique_ptr<SSLWrapper> ssl_wrapper_;
    std::unique_ptr<EncryptionManager> encryption_mgr_;
    std::unique_ptr<TUNInterface> tun_interface_;
    std::unique_ptr<AuthenticationManager> auth_mgr_;
    std::unique_ptr<SessionManager> session_mgr_;
    std::unique_ptr<ConnectionManager> connection_mgr_;
    std::unique_ptr<StateMachine> state_machine_;

    std::unique_ptr<ThreadPool> thread_pool_;
    std::shared_ptr<Logger> logger_;

    ClientStats stats_;
    std::atomic<ClientState> current_state_;

    std::function<void(const std::string&)> log_callback_;
    std::function<void(ClientState)> state_change_callback_;

    bool initializeComponents();
    void setupCallbacks();
    void updateStats(uint64_t sent, uint64_t received);

    void onPacketReceived(const std::vector<uint8_t>& data,
                          const std::string& host, int port);
    void onTUNPacket(const std::vector<uint8_t>& packet);

    void handleControlPacket(const std::vector<uint8_t>& packet);
    void handleDataPacket(const std::vector<uint8_t>& packet);

    void changeState(ClientState new_state);
    void logMessage(const std::string& message, Logger::LogLevel level);
};
