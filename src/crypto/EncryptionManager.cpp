#include "crypto/EncryptionManager.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cstring>

EncryptionManager::EncryptionManager() : initialized_(false) {
    // Initialize OpenSSL if needed
}

EncryptionManager::~EncryptionManager() {
    cleanup();
}

bool EncryptionManager::initialize(const std::vector<unsigned char>& key, 
                                 const std::vector<unsigned char>& iv,
                                 Algorithm algo) {
    if (key.empty()) {
        return false;
    }
    
    key_ = key;
    iv_ = iv;
    algorithm_ = algo;
    
    // Validate key size based on algorithm
    switch (algo) {
        case Algorithm::AES_128_CBC:
            if (key.size() != 16) return false;
            break;
        case Algorithm::AES_256_CBC:
            if (key.size() != 32) return false;
            break;
        case Algorithm::AES_192_CBC:
            if (key.size() != 24) return false;
            break;
        default:
            return false;
    }
    
    initialized_ = true;
    return true;
}

bool EncryptionManager::encrypt(std::vector<unsigned char>& data) {
    if (!initialized_ || data.empty()) {
        return false;
    }
    
    const EVP_CIPHER* cipher = getCipher(algorithm_);
    if (!cipher) {
        return false;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key_.data(), iv_.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Set padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    
    std::vector<unsigned char> encrypted(data.size() + AES_BLOCK_SIZE);
    int len;
    int total_len = 0;
    
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += len;
    
    encrypted.resize(total_len);
    data = std::move(encrypted);
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool EncryptionManager::decrypt(std::vector<unsigned char>& data) {
    if (!initialized_ || data.empty()) {
        return false;
    }
    
    const EVP_CIPHER* cipher = getCipher(algorithm_);
    if (!cipher) {
        return false;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key_.data(), iv_.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Set padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    
    std::vector<unsigned char> decrypted(data.size());
    int len;
    int total_len = 0;
    
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += len;
    
    decrypted.resize(total_len);
    data = std::move(decrypted);
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

const EVP_CIPHER* EncryptionManager::getCipher(Algorithm algo) const {
    switch (algo) {
        case Algorithm::AES_128_CBC:
            return EVP_aes_128_cbc();
        case Algorithm::AES_192_CBC:
            return EVP_aes_192_cbc();
        case Algorithm::AES_256_CBC:
            return EVP_aes_256_cbc();
        default:
            return nullptr;
    }
}

void EncryptionManager::cleanup() {
    key_.clear();
    iv_.clear();
    initialized_ = false;
}