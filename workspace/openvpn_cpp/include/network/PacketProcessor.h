#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <vector>
#include <functional>
#include <mutex>
#include <thread>
#include <queue>
#include <memory>

class EncryptionManager;
class HMACGenerator;

class PacketProcessor {
public:
    enum class PacketType {
        CONTROL = 0,
        DATA = 1,
        ACK = 2,
        HARD_RESET_CLIENT = 3,
        HARD_RESET_SERVER = 4,
        SOFT_RESET = 5,
        ACK_V1 = 6
    };

    struct PacketHeader {
        unsigned char opcode : 5;
        unsigned char key_id : 3;
        unsigned short ack_length;
        unsigned int packet_id;
        // Optional acknowledgment packets if ack_length > 0
    };

    PacketProcessor();
    ~PacketProcessor();

    bool initialize(std::shared_ptr<EncryptionManager> encManager, 
                   std::shared_ptr<HMACGenerator> hmacGen);
    
    // Process incoming packets
    bool processIncomingPacket(const std::vector<unsigned char>& packet, 
                              std::vector<unsigned char>& processedData);
    
    // Prepare outgoing packets
    std::vector<unsigned char> prepareOutgoingPacket(const std::vector<unsigned char>& data, 
                                                    PacketType type);
    
    // Packet encryption/decryption
    bool encryptPacket(std::vector<unsigned char>& packet);
    bool decryptPacket(std::vector<unsigned char>& packet);
    
    // HMAC verification
    bool verifyPacketHMAC(const std::vector<unsigned char>& packet);
    bool addPacketHMAC(std::vector<unsigned char>& packet);
    
    // Sequence number management
    unsigned int getNextPacketId();
    void acknowledgePacket(unsigned int packetId);

private:
    std::shared_ptr<EncryptionManager> encryptionManager_;
    std::shared_ptr<HMACGenerator> hmacGenerator_;
    std::mutex packetMutex_;
    unsigned int nextPacketId_;
    std::queue<unsigned int> pendingAcks_;
};

#endif // PACKET_PROCESSOR_H