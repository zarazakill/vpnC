#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <string>
#include <memory>

class TUNInterface;

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();

    bool initialize();
    void cleanup();

    bool configureInterface(const std::string& interfaceName, 
                           const std::string& ipAddress, 
                           const std::string& netmask);
    bool bringInterfaceUp(const std::string& interfaceName);
    bool bringInterfaceDown(const std::string& interfaceName);
    
    bool setDefaultRoute(const std::string& gateway);
    bool removeDefaultRoute();
    
    bool flushDNS();
    bool setDNSServers(const std::vector<std::string>& dnsServers);
    
    std::string getInterfaceName() const { return interfaceName_; }

private:
    std::string interfaceName_;
    std::unique_ptr<TUNInterface> tunInterface_;
    bool isInitialized_;
    bool routeSet_;
};

#endif // NETWORK_MANAGER_H