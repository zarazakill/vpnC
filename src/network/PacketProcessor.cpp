#include "network/PacketProcessor.h"
#include "crypto/EncryptionManager.h"
#include "crypto/HMACGenerator.h"
#include <cstring>
#include <algorithm>

PacketProcessor::PacketProcessor() : nextPacketId_(1) {
}

PacketProcessor::~PacketProcessor() {
}

bool PacketProcessor::initialize(std::shared_ptr<EncryptionManager> encManager, 
                                std::shared_ptr<HMACGenerator> hmacGen) {
    if (!encManager || !hmacGen) {
        return false;
    }
    
    encryptionManager_ = encManager;
    hmacGenerator_ = hmacGen;
    return true;
}

bool PacketProcessor::processIncomingPacket(const std::vector<unsigned char>& packet, 
                                           std::vector<unsigned char>& processedData) {
    if (packet.size() < sizeof(PacketHeader)) {
        return false;
    }
    
    // Verify HMAC before processing
    if (!verifyPacketHMAC(packet)) {
        return false;
    }
    
    // Decrypt the packet
    std::vector<unsigned char> decryptedPacket = packet;
    if (!decryptPacket(decryptedPacket)) {
        return false;
    }
    
    // Extract data payload (skip header)
    PacketHeader* header = reinterpret_cast<PacketHeader*>(decryptedPacket.data());
    size_t headerSize = sizeof(PacketHeader) + (header->ack_length * sizeof(unsigned int));
    if (decryptedPacket.size() < headerSize) {
        return false;
    }
    
    // Copy payload data
    size_t payloadSize = decryptedPacket.size() - headerSize;
    processedData.resize(payloadSize);
    std::copy(decryptedPacket.begin() + headerSize, decryptedPacket.end(), processedData.begin());
    
    // Acknowledge the received packet
    acknowledgePacket(header->packet_id);
    
    return true;
}

std::vector<unsigned char> PacketProcessor::prepareOutgoingPacket(const std::vector<unsigned char>& data, 
                                                                PacketType type) {
    std::vector<unsigned char> packet;
    
    // Create header
    PacketHeader header;
    header.opcode = static_cast<unsigned char>(type);
    header.key_id = 0;  // Use key ID 0 for now
    header.ack_length = 0;  // No acknowledgments for now
    header.packet_id = getNextPacketId();
    
    // Calculate total packet size
    size_t headerSize = sizeof(PacketHeader);
    packet.resize(headerSize + data.size());
    
    // Copy header to packet
    std::memcpy(packet.data(), &header, headerSize);
    
    // Copy data to packet
    std::copy(data.begin(), data.end(), packet.begin() + headerSize);
    
    // Add HMAC to the packet
    addPacketHMAC(packet);
    
    // Encrypt the packet
    encryptPacket(packet);
    
    return packet;
}

bool PacketProcessor::encryptPacket(std::vector<unsigned char>& packet) {
    if (!encryptionManager_) {
        return false;
    }
    
    return encryptionManager_->encrypt(packet);
}

bool PacketProcessor::decryptPacket(std::vector<unsigned char>& packet) {
    if (!encryptionManager_) {
        return false;
    }
    
    return encryptionManager_->decrypt(packet);
}

bool PacketProcessor::verifyPacketHMAC(const std::vector<unsigned char>& packet) {
    if (!hmacGenerator_ || packet.size() < 32) {  // Minimum HMAC size
        return false;
    }
    
    // For simplicity, assume HMAC is at the end of the packet
    // In real OpenVPN, HMAC position depends on configuration
    size_t hmacSize = 32; // Assuming SHA256 HMAC
    if (packet.size() < hmacSize) {
        return false;
    }
    
    // Extract the HMAC from the end
    std::vector<unsigned char> receivedHMAC(packet.end() - hmacSize, packet.end());
    
    // Create data without the HMAC
    std::vector<unsigned char> dataWithoutHMAC(packet.begin(), packet.end() - hmacSize);
    
    // TODO: Use proper key for HMAC verification
    std::vector<unsigned char> dummyKey = {0x01, 0x02, 0x03, 0x04};
    
    return hmacGenerator_->verifyHMAC(dummyKey, dataWithoutHMAC, receivedHMAC);
}

bool PacketProcessor::addPacketHMAC(std::vector<unsigned char>& packet) {
    if (!hmacGenerator_) {
        return false;
    }
    
    // TODO: Use proper key for HMAC generation
    std::vector<unsigned char> dummyKey = {0x01, 0x02, 0x03, 0x04};
    std::vector<unsigned char> hmac;
    
    if (!hmacGenerator_->generateHMAC(dummyKey, packet, hmac)) {
        return false;
    }
    
    // Append HMAC to the packet
    packet.insert(packet.end(), hmac.begin(), hmac.end());
    
    return true;
}

unsigned int PacketProcessor::getNextPacketId() {
    std::lock_guard<std::mutex> lock(packetMutex_);
    return nextPacketId_++;
}

void PacketProcessor::acknowledgePacket(unsigned int packetId) {
    std::lock_guard<std::mutex> lock(packetMutex_);
    pendingAcks_.push(packetId);
    
    // In a real implementation, we would send an acknowledgment
    // For now, just keep track of received packets
}