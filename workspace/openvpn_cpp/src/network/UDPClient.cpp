#include "network/UDPClient.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>

UDPClient::UDPClient() : socket_fd_(-1), connected_(false), running_(false) {
    stats_.packets_sent = 0;
    stats_.packets_received = 0;
    stats_.bytes_sent = 0;
    stats_.bytes_received = 0;
    stats_.errors = 0;
}

UDPClient::~UDPClient() {
    disconnect();
    cleanup();
}

bool UDPClient::connect(const std::string& host, int port) {
    if (connected_) {
        disconnect();
    }

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        perror("socket creation failed");
        stats_.errors++;
        return false;
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << host << std::endl;
        close(socket_fd_);
        socket_fd_ = -1;
        stats_.errors++;
        return false;
    }

    if (::connect(socket_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connection failed");
        close(socket_fd_);
        socket_fd_ = -1;
        stats_.errors++;
        return false;
    }

    connected_ = true;
    running_ = true;

    // Start receive thread
    std::thread receive_thread(&UDPClient::receiveLoop, this);
    receive_thread_.swap(receive_thread);

    return true;
}

bool UDPClient::bind(int port) {
    if (socket_fd_ != -1) {
        disconnect();
    }

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        perror("socket creation failed");
        stats_.errors++;
        return false;
    }

    struct sockaddr_in local_addr;
    std::memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(port);

    if (::bind(socket_fd_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind failed");
        close(socket_fd_);
        socket_fd_ = -1;
        stats_.errors++;
        return false;
    }

    connected_ = true;
    running_ = true;

    // Start receive thread
    std::thread receive_thread(&UDPClient::receiveLoop, this);
    receive_thread_.swap(receive_thread);

    return true;
}

void UDPClient::disconnect() {
    if (connected_) {
        running_ = false;
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
        connected_ = false;
        
        if (receive_thread_.joinable()) {
            receive_thread_.join();
        }
    }
}

bool UDPClient::send(const std::vector<uint8_t>& data) {
    if (!connected_ || socket_fd_ < 0 || data.empty()) {
        stats_.errors++;
        return false;
    }

    std::lock_guard<std::mutex> lock(socket_mutex_);
    ssize_t sent = ::send(socket_fd_, data.data(), data.size(), 0);

    if (sent == static_cast<ssize_t>(data.size())) {
        stats_.packets_sent++;
        stats_.bytes_sent += sent;
        return true;
    } else {
        stats_.errors++;
        return false;
    }
}

bool UDPClient::sendTo(const std::vector<uint8_t>& data, const std::string& host, int port) {
    if (socket_fd_ < 0 || data.empty()) {
        stats_.errors++;
        return false;
    }

    struct sockaddr_in dest_addr;
    std::memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << host << std::endl;
        stats_.errors++;
        return false;
    }

    std::lock_guard<std::mutex> lock(socket_mutex_);
    ssize_t sent = sendto(socket_fd_, data.data(), data.size(), 0,
                         (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent == static_cast<ssize_t>(data.size())) {
        stats_.packets_sent++;
        stats_.bytes_sent += sent;
        return true;
    } else {
        stats_.errors++;
        return false;
    }
}

void UDPClient::setDataCallback(DataCallback callback) {
    data_callback_ = callback;
}

void UDPClient::receiveLoop() {
    while (running_) {
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        std::vector<uint8_t> buffer(8192);

        ssize_t received = recvfrom(socket_fd_, buffer.data(), buffer.size(), MSG_DONTWAIT,
                                   (struct sockaddr*)&sender_addr, &addr_len);

        if (received > 0) {
            buffer.resize(received);
            stats_.packets_received++;
            stats_.bytes_received += received;

            if (data_callback_) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sender_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                int sender_port = ntohs(sender_addr.sin_port);
                data_callback_(buffer, std::string(ip_str), sender_port);
            }
        } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            stats_.errors++;
        }

        // Small sleep to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool UDPClient::setupSocket() {
    return true; // Already handled in connect/bind
}

void UDPClient::cleanup() {
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

void UDPClient::setSocketOptions(int option, int value) {
    if (socket_fd_ >= 0) {
        setsockopt(socket_fd_, SOL_SOCKET, option, &value, sizeof(value));
    }
}

void UDPClient::setTimeout(int receive_timeout, int send_timeout) {
    if (socket_fd_ >= 0) {
        struct timeval timeout;
        timeout.tv_sec = receive_timeout / 1000;
        timeout.tv_usec = (receive_timeout % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        timeout.tv_sec = send_timeout / 1000;
        timeout.tv_usec = (send_timeout % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
}