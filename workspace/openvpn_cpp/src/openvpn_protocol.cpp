#include "openvpn_protocol.h"
#include "openvpn_session.h"
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <iostream>

std::vector<uint8_t> OpenVPNProtocol::createControlPacket(uint8_t opcode, uint8_t key_id, 
                                                         uint32_t session_id, uint32_t packet_id,
                                                         const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> packet;
    
    // Добавляем заголовок
    OpenVPNPacketHeader header;
    header.opcode = opcode;
    header.key_id = key_id;
    header.ack_length = 0; // No acknowledgments for this example
    header.session_id[0] = session_id;
    header.session_id[1] = 0;
    header.session_id[2] = 0;
    header.ack_session_id[0] = 0;
    header.ack_session_id[1] = 0;
    header.ack_session_id[2] = 0;
    header.packet_id = packet_id;
    
    // Преобразуем заголовок в байты
    uint8_t* header_bytes = reinterpret_cast<uint8_t*>(&header);
    packet.insert(packet.end(), header_bytes, header_bytes + sizeof(OpenVPNPacketHeader));
    
    // Добавляем полезную нагрузку
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    return packet;
}

std::vector<uint8_t> OpenVPNProtocol::createDataPacket(uint32_t session_id, uint32_t packet_id,
                                                      const std::vector<uint8_t>& data, uint8_t key_id) {
    std::vector<uint8_t> packet;
    
    // Для упрощения используем формат P_DATA_V1
    uint8_t opcode = (P_DATA_V1 << 3) | (key_id & 0x07);
    
    // Добавляем opcode
    packet.push_back(opcode);
    
    // Добавляем session_id и packet_id (упрощённо)
    uint32_t sid = htonl(session_id);
    uint32_t pid = htonl(packet_id);
    
    uint8_t* sid_bytes = reinterpret_cast<uint8_t*>(&sid);
    uint8_t* pid_bytes = reinterpret_cast<uint8_t*>(&pid);
    
    packet.insert(packet.end(), sid_bytes, sid_bytes + 4);
    packet.insert(packet.end(), pid_bytes, pid_bytes + 4);
    
    // Добавляем данные
    packet.insert(packet.end(), data.begin(), data.end());
    
    return packet;
}

bool OpenVPNProtocol::parsePacket(const std::vector<uint8_t>& packet, OpenVPNPacketHeader& header) {
    if (packet.size() < sizeof(OpenVPNPacketHeader)) {
        return false;
    }
    
    memcpy(&header, packet.data(), sizeof(OpenVPNPacketHeader));
    return true;
}

std::vector<uint8_t> OpenVPNProtocol::extractPayload(const std::vector<uint8_t>& packet) {
    if (packet.size() < sizeof(OpenVPNPacketHeader)) {
        return std::vector<uint8_t>();
    }
    
    return std::vector<uint8_t>(packet.begin() + sizeof(OpenVPNPacketHeader), packet.end());
}

void OpenVPNProtocol::generateKeys(const std::string& master_key, const std::string& client_random,
                                  const std::string& server_random, OpenVPNSession& session) {
    // В реальной реализации используется сложный процесс генерации ключей
    // Для упрощения просто используем фиксированные значения
    
    // Генерация ключей шифрования и HMAC
    session.encrypt_key.resize(32); // 256 бит для AES-256
    session.decrypt_key.resize(32);
    session.hmac_key_encrypt.resize(32);
    session.hmac_key_decrypt.resize(32);
    
    // Заполняем ключи случайными значениями (в реальности - из мастер-ключа)
    for (size_t i = 0; i < 32; ++i) {
        session.encrypt_key[i] = i % 256;
        session.decrypt_key[i] = (i + 100) % 256;
        session.hmac_key_encrypt[i] = (i + 200) % 256;
        session.hmac_key_decrypt[i] = (i + 50) % 256;
    }
}