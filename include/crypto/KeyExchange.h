#pragma once
#include <memory>
#include <vector>
#include <string>
#include <openssl/ec.h>
#include <openssl/dh.h>

class KeyExchange {
public:
    enum class KeyExchangeMethod {
        RSA,
        DH,
        ECDH,
        TLS
    };

    KeyExchange(KeyExchangeMethod method);
    ~KeyExchange();

    bool generateKeys();
    std::vector<uint8_t> getPublicKey() const;
    bool computeSharedSecret(const std::vector<uint8_t>& peer_public_key);
    std::vector<uint8_t> getSharedSecret() const;

    bool loadPrivateKey(const std::string& filename);
    bool loadPublicKey(const std::string& filename);
    bool saveKeys(const std::string& private_file,
                  const std::string& public_file) const;

                  static std::vector<uint8_t> deriveKey(const std::vector<uint8_t>& secret,
                                                        const std::vector<uint8_t>& salt,
                                                        size_t key_length);

private:
    KeyExchangeMethod method_;
    EC_KEY* ec_key_;
    DH* dh_key_;
    EVP_PKEY* pkey_;
    std::vector<uint8_t> shared_secret_;

    bool generateECDHKeys();
    bool generateDHKeys();
    bool generateRSAKeys();

    void cleanup();
};
