#ifndef TUN_INTERFACE_H
#define TUN_INTERFACE_H

#include <string>
#include <vector>

class TUNInterface {
private:
    int tun_fd;
    std::string device_name;
    std::string ip_address;
    std::string netmask;
    bool is_open;

public:
    TUNInterface(const std::string& dev_name = "tun0");
    ~TUNInterface();
    
    bool open(const std::string& ip = "10.8.0.2", const std::string& mask = "255.255.255.0");
    int read_data(std::vector<uint8_t>& buffer, size_t max_size);
    int write_data(const std::vector<uint8_t>& data);
    void close();
    bool isOpen() const { return is_open; }
    
private:
    int countSubnetBits(const std::string& netmask);
};

#endif // TUN_INTERFACE_H