#include "interface/NetworkManager.h"
#include "interface/TUNInterface.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <iostream>
#include <sstream>

NetworkManager::NetworkManager() 
    : interfaceName_("tun0"), isInitialized_(false), routeSet_(false) {
}

NetworkManager::~NetworkManager() {
    cleanup();
}

bool NetworkManager::initialize() {
    try {
        tunInterface_ = std::make_unique<TUNInterface>();
        if (!tunInterface_->open()) {
            std::cerr << "Failed to open TUN interface" << std::endl;
            return false;
        }
        
        isInitialized_ = true;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing NetworkManager: " << e.what() << std::endl;
        return false;
    }
}

void NetworkManager::cleanup() {
    if (routeSet_) {
        removeDefaultRoute();
    }
    
    if (tunInterface_) {
        tunInterface_->close();
    }
    
    isInitialized_ = false;
}

bool NetworkManager::configureInterface(const std::string& interfaceName, 
                                       const std::string& ipAddress, 
                                       const std::string& netmask) {
    if (!isInitialized_) {
        std::cerr << "NetworkManager not initialized" << std::endl;
        return false;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    
    // Set IP address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr);
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
    
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("SIOCSIFADDR");
        close(sock);
        return false;
    }
    
    // Set netmask
    inet_pton(AF_INET, netmask.c_str(), &addr.sin_addr);
    memcpy(&ifr.ifr_netmask, &addr, sizeof(struct sockaddr));
    
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        perror("SIOCSIFNETMASK");
        close(sock);
        return false;
    }
    
    interfaceName_ = interfaceName;
    close(sock);
    return true;
}

bool NetworkManager::bringInterfaceUp(const std::string& interfaceName) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    
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

bool NetworkManager::bringInterfaceDown(const std::string& interfaceName) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        close(sock);
        return false;
    }
    
    ifr.ifr_flags &= ~IFF_UP;
    
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(sock);
        return false;
    }
    
    close(sock);
    return true;
}

bool NetworkManager::setDefaultRoute(const std::string& gateway) {
    // Implementation would use route manipulation commands
    // For now, we'll simulate the functionality
    std::string cmd = "ip route add default via " + gateway;
    int result = system(cmd.c_str());
    
    if (result == 0) {
        routeSet_ = true;
        return true;
    }
    
    return false;
}

bool NetworkManager::removeDefaultRoute() {
    // Remove default route
    std::string cmd = "ip route del default";
    int result = system(cmd.c_str());
    
    if (result == 0) {
        routeSet_ = false;
        return true;
    }
    
    return false;
}

bool NetworkManager::flushDNS() {
    // Flush DNS cache - implementation depends on the system
    // This is a simplified approach
    int result = system("systemctl restart systemd-resolved 2>/dev/null || true");
    return (result == 0);
}

bool NetworkManager::setDNSServers(const std::vector<std::string>& dnsServers) {
    if (dnsServers.empty()) {
        return false;
    }
    
    // Create a resolv.conf file with new DNS servers
    std::ostringstream dnsList;
    for (const auto& dns : dnsServers) {
        dnsList << "nameserver " << dns << "\n";
    }
    
    // This would typically write to /etc/resolv.conf or use systemd-resolved
    // For now, we'll use a system command approach
    std::string cmd = "echo -e \"" + dnsList.str() + "\" > /tmp/resolv.conf.tmp && "
                      "sudo cp /tmp/resolv.conf.tmp /etc/resolv.conf";
    int result = system(cmd.c_str());
    
    return (result == 0);
}