#include "tun_interface.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>

TUNInterface::TUNInterface(const std::string& dev_name) 
    : tun_fd(-1), device_name(dev_name), is_open(false) {}

TUNInterface::~TUNInterface() {
    close();
}

bool TUNInterface::open(const std::string& ip, const std::string& mask) {
    ip_address = ip;
    netmask = mask;
    
    // Открытие устройства TUN
    tun_fd = ::open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        std::cerr << "Ошибка открытия /dev/net/tun: " << strerror(errno) << std::endl;
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    // Установка имени устройства
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN-устройство без заголовка пакета
    strncpy(ifr.ifr_name, device_name.c_str(), IFNAMSIZ);
    
    // Создание TUN-устройства
    if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
        std::cerr << "Ошибка создания TUN-устройства: " << strerror(errno) << std::endl;
        ::close(tun_fd);
        return false;
    }
    
    std::cout << "TUN-устройство " << device_name << " создано" << std::endl;
    is_open = true;
    
    // Настройка IP-адреса (требует root прав)
    std::string cmd = "ip addr add " + ip_address + "/" + 
                     std::to_string(countSubnetBits(netmask)) + " dev " + device_name;
    system(cmd.c_str());
    
    cmd = "ip link set " + device_name + " up";
    system(cmd.c_str());
    
    return true;
}

int TUNInterface::read_data(std::vector<uint8_t>& buffer, size_t max_size) {
    if (!is_open || tun_fd < 0) return -1;
    
    buffer.resize(max_size);
    int nbytes = ::read(tun_fd, buffer.data(), max_size);
    if (nbytes > 0) {
        buffer.resize(nbytes);
    } else if (nbytes < 0) {
        std::cerr << "Ошибка чтения из TUN-устройства: " << strerror(errno) << std::endl;
    }
    return nbytes;
}

int TUNInterface::write_data(const std::vector<uint8_t>& data) {
    if (!is_open || tun_fd < 0) return -1;
    
    return ::write(tun_fd, data.data(), data.size());
}

void TUNInterface::close() {
    if (is_open && tun_fd >= 0) {
        ::close(tun_fd);
        is_open = false;
        tun_fd = -1;
        
        // Отключение интерфейса
        std::string cmd = "ip link set " + device_name + " down";
        system(cmd.c_str());
    }
}

int TUNInterface::countSubnetBits(const std::string& netmask) {
    unsigned int mask = inet_addr(netmask.c_str());
    int count = 0;
    while (mask) {
        count += mask & 1;
        mask >>= 1;
    }
    return count;
}