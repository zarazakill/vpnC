#ifndef OPENVPN_PROTOCOL_H
#define OPENVPN_PROTOCOL_H

#include <vector>
#include <cstdint>
#include <string>
#include "openvpn_session.h"  // Include the session header
#include <netinet/in.h>       // For htonl

// OpenVPN Protocol Constants
enum OpenVPNPacketType {
    P_CONTROL_HARD_RESET_CLIENT_V1 = 1,
    P_CONTROL_HARD_RESET_SERVER_V1 = 2,
    P_CONTROL_SOFT_RESET_V1 = 3,
    P_CONTROL_V1 = 4,
    P_ACK_V1 = 5,
    P_DATA_V1 = 6,
    P_DATA_V2 = 7,
    P_CONTROL_HARD_RESET_CLIENT_V2 = 8,
    P_CONTROL_HARD_RESET_SERVER_V2 = 9
};

enum OpenVPNOpCode {
    OP_REPLY = 0x01,
    OP_PING = 0x02,
    OP_KILL = 0x03,
    OP_IPXY = 0x04,
    OP_UNDEF = 0x05,
    OP_AUTH = 0x06,
    OP_INFO = 0x07,
    OP_ACK_V1 = 0x08,
    OP_DATA_V1 = 0x09,
    OP_DATA_V2 = 0x0A
};

#pragma pack(push, 1)
struct OpenVPNPacketHeader {
    uint8_t opcode;
    uint8_t key_id;
    uint16_t ack_length;
    uint32_t session_id[3]; // 96 bits
    uint32_t ack_session_id[3]; // 96 bits for acknowledgment
    uint32_t packet_id;
};
#pragma pack(pop)

class OpenVPNProtocol {
public:
    static std::vector<uint8_t> createControlPacket(uint8_t opcode, uint8_t key_id, 
                                                   uint32_t session_id, uint32_t packet_id,
                                                   const std::vector<uint8_t>& payload);
    static std::vector<uint8_t> createDataPacket(uint32_t session_id, uint32_t packet_id,
                                                const std::vector<uint8_t>& data, uint8_t key_id);
    static bool parsePacket(const std::vector<uint8_t>& packet, OpenVPNPacketHeader& header);
    static std::vector<uint8_t> extractPayload(const std::vector<uint8_t>& packet);
    
    // Key generation and management
    static void generateKeys(const std::string& master_key, const std::string& client_random,
                            const std::string& server_random, OpenVPNSession& session);
};

#endif // OPENVPN_PROTOCOL_H