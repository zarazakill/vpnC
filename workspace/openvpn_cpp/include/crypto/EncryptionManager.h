#pragma once
#include <memory>
#include <vector>
#include <string>
#include <mutex>
#include <openssl/evp.h>

class EncryptionManager {
public:
    enum class CipherAlgorithm {
        AES_256_CBC,
        AES_256_GCM,
        CHACHA20_POLY1305,
        BF_CBC
    };

    EncryptionManager();
    ~EncryptionManager();

    bool initialize(CipherAlgorithm algorithm,
                    const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& iv);

    bool encrypt(const std::vector<uint8_t>& plaintext,
                 std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& tag = std::vector<uint8_t>());

    bool decrypt(const std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& tag = std::vector<uint8_t>());

    bool updateKey(const std::vector<uint8_t>& new_key,
                   const std::vector<uint8_t>& new_iv);

    void reset();

    static std::vector<uint8_t> generateRandomKey(int length);
    static std::vector<uint8_t> generateRandomIV(int length);

private:
    EVP_CIPHER_CTX* encrypt_ctx_;
    EVP_CIPHER_CTX* decrypt_ctx_;
    CipherAlgorithm algorithm_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
    std::mutex mutex_;

    const EVP_CIPHER* getCipher(CipherAlgorithm algorithm) const;
    bool setupContexts();
};
