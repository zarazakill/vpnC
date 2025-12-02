#include "interface/TUNInterface.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

TUNInterface::TUNInterface() : fd_(-1), initialized_(false) {
    std::memset(&ifr_, 0, sizeof(ifr_));
    std::strcpy(ifr_.ifr_name, "tun0");
}

TUNInterface::~TUNInterface() {
    close();
}

bool TUNInterface::open() {
    if (initialized_) {
        close();
    }

    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        perror("open /dev/net/tun");
        return false;
    }

    // Configure TUN interface
    ifr_.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet info
    ifr_.ifr_flags |= IFF_MULTI_QUEUE; // Allow multiple queues

    if (ioctl(fd_, TUNSETIFF, &ifr_) < 0) {
        perror("ioctl TUNSETIFF");
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    initialized_ = true;
    return true;
}

bool TUNInterface::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    initialized_ = false;
    return true;
}

bool TUNInterface::write(const std::vector<unsigned char>& data) {
    if (!initialized_ || fd_ < 0 || data.empty()) {
        return false;
    }

    ssize_t written = ::write(fd_, data.data(), data.size());
    return (written == static_cast<ssize_t>(data.size()));
}

bool TUNInterface::read(std::vector<unsigned char>& data, int timeout_ms) {
    if (!initialized_ || fd_ < 0) {
        return false;
    }

    // Set file descriptor timeout
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd_, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(fd_ + 1, &read_fds, NULL, NULL, &timeout);
    if (result <= 0) {
        if (result == 0) {
            std::cerr << "Read timeout" << std::endl;
        } else {
            perror("select");
        }
        return false;
    }

    data.resize(8192); // Max frame size
    ssize_t read_bytes = ::read(fd_, data.data(), data.size());
    if (read_bytes < 0) {
        perror("read");
        return false;
    }

    data.resize(read_bytes);
    return true;
}

bool TUNInterface::isOpened() const {
    return initialized_;
}

std::string TUNInterface::getName() const {
    if (!initialized_) {
        return "";
    }
    return std::string(ifr_.ifr_name);
}

bool TUNInterface::configure(const std::string& ipAddress, const std::string& netmask) {
    if (!initialized_) {
        return false;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifr_.ifr_name, IFNAMSIZ - 1);

    // Set IP address
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr);
    std::memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("SIOCSIFADDR");
        close(sock);
        return false;
    }

    // Set netmask
    inet_pton(AF_INET, netmask.c_str(), &addr.sin_addr);
    std::memcpy(&ifr.ifr_netmask, &addr, sizeof(struct sockaddr));

    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        perror("SIOCSIFNETMASK");
        close(sock);
        return false;
    }

    // Bring interface up
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        close(sock);
        return false;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(sock);
        return false;
    }

    close(sock);
    return true;
}