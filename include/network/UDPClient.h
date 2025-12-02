#pragma once
#include <memory>
#include <functional>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

class UDPClient {
public:
    using DataCallback = std::function<void(const std::vector<uint8_t>&, const std::string&, int)>;

    struct ConnectionStats {
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t errors;
    };

    UDPClient();
    ~UDPClient();

    bool connect(const std::string& host, int port);
    bool bind(int port);
    void disconnect();

    bool send(const std::vector<uint8_t>& data);
    bool sendTo(const std::vector<uint8_t>& data, const std::string& host, int port);

    void setDataCallback(DataCallback callback);

    bool isConnected() const { return connected_; }
    ConnectionStats getStats() const { return stats_; }

    void setSocketOptions(int option, int value);
    void setTimeout(int receive_timeout, int send_timeout);

private:
    int socket_fd_;
    std::atomic<bool> connected_;
    std::atomic<bool> running_;

    std::thread receive_thread_;
    std::mutex socket_mutex_;

    DataCallback data_callback_;
    ConnectionStats stats_;

    void receiveLoop();
    bool setupSocket();
    void cleanup();
};
