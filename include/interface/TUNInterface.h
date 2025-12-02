#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

class TUNInterface {
public:
    enum class InterfaceType {
        TUN,
        TAP
    };

    struct InterfaceConfig {
        InterfaceType type;
        std::string name;
        std::string ip_address;
        std::string netmask;
        std::string gateway;
        int mtu;
        bool persist;
        std::vector<std::string> routes;
    };

    using PacketCallback = std::function<void(const std::vector<uint8_t>&)>;

    TUNInterface();
    ~TUNInterface();

    bool open(const InterfaceConfig& config);
    void close();

    bool writePacket(const std::vector<uint8_t>& packet);
    bool readPacket(std::vector<uint8_t>& packet, int timeout_ms = -1);

    void setPacketCallback(PacketCallback callback);
    void startReading();
    void stopReading();

    bool isOpen() const { return fd_ >= 0; }
    const std::string& getName() const { return name_; }
    const std::string& getIPAddress() const { return ip_address_; }

    bool setIPAddress(const std::string& ip, const std::string& netmask);
    bool addRoute(const std::string& network, const std::string& gateway);
    bool setMTU(int mtu);

private:
    int fd_;
    InterfaceType type_;
    std::string name_;
    std::string ip_address_;
    std::string netmask_;
    int mtu_;

    std::atomic<bool> running_;
    std::thread read_thread_;
    std::mutex read_mutex_;
    PacketCallback packet_callback_;

    bool createInterface();
    bool configureInterface();
    void readLoop();
    void executeCommand(const std::string& cmd);
};
