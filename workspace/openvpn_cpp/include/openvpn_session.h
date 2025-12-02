#ifndef OPENVPN_SESSION_H
#define OPENVPN_SESSION_H

#include <vector>
#include <chrono>
#include <cstdint>

struct OpenVPNSession {
    uint32_t session_id;
    uint32_t key_id;
    std::vector<uint8_t> encrypt_key;
    std::vector<uint8_t> decrypt_key;
    std::vector<uint8_t> hmac_key_encrypt;
    std::vector<uint8_t> hmac_key_decrypt;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_activity;
    
    OpenVPNSession() : session_id(0), key_id(0) {
        created_at = last_activity = std::chrono::steady_clock::now();
    }
};

#endif // OPENVPN_SESSION_H