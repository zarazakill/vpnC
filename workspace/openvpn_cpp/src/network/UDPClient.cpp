#include "network/UDPClient.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

UDPClient::UDPClient() : socket_fd_(-1), connected_(false) {
    std::memset(&server_addr_, 0, sizeof(server_addr_));
}

UDPClient::~UDPClient() {
    disconnect();
}

bool UDPClient::connect(const std::string& host, int port) {
    if (connected_) {
        disconnect();
    }

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        perror("socket creation failed");
        return false;
    }

    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &server_addr_.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << host << std::endl;
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    connected_ = true;
    return true;
}

bool UDPClient::disconnect() {
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
    connected_ = false;
    return true;
}

bool UDPClient::sendData(const std::vector<unsigned char>& data) {
    if (!connected_ || socket_fd_ < 0 || data.empty()) {
        return false;
    }

    ssize_t sent = sendto(socket_fd_, data.data(), data.size(), 0,
                         (struct sockaddr*)&server_addr_, sizeof(server_addr_));
    
    return (sent == static_cast<ssize_t>(data.size()));
}

bool UDPClient::receiveData(std::vector<unsigned char>& data, int timeout_ms) {
    if (!connected_ || socket_fd_ < 0) {
        return false;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        return false;
    }

    data.resize(8192); // Max UDP packet size
    socklen_t addr_len = sizeof(server_addr_);
    
    ssize_t received = recvfrom(socket_fd_, data.data(), data.size(), 0,
                               (struct sockaddr*)&server_addr_, &addr_len);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cerr << "Receive timeout" << std::endl;
        } else {
            perror("recvfrom failed");
        }
        return false;
    }
    
    data.resize(received);
    return true;
}

bool UDPClient::isConnected() const {
    return connected_;
}

std::string UDPClient::getRemoteAddress() const {
    if (!connected_) {
        return "";
    }
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server_addr_.sin_addr, ip_str, INET_ADDRSTRLEN);
    return std::string(ip_str);
}

int UDPClient::getRemotePort() const {
    if (!connected_) {
        return -1;
    }
    
    return ntohs(server_addr_.sin_port);
}