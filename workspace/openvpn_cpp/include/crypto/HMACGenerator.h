#ifndef HMAC_GENERATOR_H
#define HMAC_GENERATOR_H

#include <string>
#include <vector>
#include <openssl/hmac.h>

class HMACGenerator {
public:
    enum class Algorithm {
        SHA1,
        SHA256,
        MD5
    };

    static bool generateHMAC(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& data,
                            std::vector<unsigned char>& result,
                            Algorithm algo = Algorithm::SHA256);
                            
    static bool verifyHMAC(const std::vector<unsigned char>& key,
                          const std::vector<unsigned char>& data,
                          const std::vector<unsigned char>& expectedHMAC,
                          Algorithm algo = Algorithm::SHA256);
                          
    static std::string algorithmToString(Algorithm algo);
    static Algorithm stringToAlgorithm(const std::string& algoStr);

private:
    static const EVP_MD* getEVP_MD(Algorithm algo);
};

#endif // HMAC_GENERATOR_H