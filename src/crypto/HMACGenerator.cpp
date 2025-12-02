#include "crypto/HMACGenerator.h"
#include <openssl/evp.h>
#include <cstring>

const EVP_MD* HMACGenerator::getEVP_MD(Algorithm algo) {
    switch (algo) {
        case Algorithm::SHA1:
            return EVP_sha1();
        case Algorithm::SHA256:
            return EVP_sha256();
        case Algorithm::MD5:
            return EVP_md5();
        default:
            return EVP_sha256();
    }
}

bool HMACGenerator::generateHMAC(const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& data,
                                std::vector<unsigned char>& result,
                                Algorithm algo) {
    if (key.empty() || data.empty()) {
        return false;
    }

    const EVP_MD* md = getEVP_MD(algo);
    if (!md) {
        return false;
    }

    unsigned int len;
    unsigned char md_result[EVP_MAX_MD_SIZE];

    HMAC(md, key.data(), key.size(), data.data(), data.size(), md_result, &len);

    result.resize(len);
    std::copy(md_result, md_result + len, result.begin());

    return true;
}

bool HMACGenerator::verifyHMAC(const std::vector<unsigned char>& key,
                              const std::vector<unsigned char>& data,
                              const std::vector<unsigned char>& expectedHMAC,
                              Algorithm algo) {
    std::vector<unsigned char> calculatedHMAC;
    if (!generateHMAC(key, data, calculatedHMAC, algo)) {
        return false;
    }

    if (calculatedHMAC.size() != expectedHMAC.size()) {
        return false;
    }

    // Use constant-time comparison to prevent timing attacks
    unsigned char diff = 0;
    for (size_t i = 0; i < calculatedHMAC.size(); i++) {
        diff |= calculatedHMAC[i] ^ expectedHMAC[i];
    }

    return diff == 0;
}

std::string HMACGenerator::algorithmToString(Algorithm algo) {
    switch (algo) {
        case Algorithm::SHA1:
            return "SHA1";
        case Algorithm::SHA256:
            return "SHA256";
        case Algorithm::MD5:
            return "MD5";
        default:
            return "SHA256";
    }
}

HMACGenerator::Algorithm HMACGenerator::stringToAlgorithm(const std::string& algoStr) {
    if (algoStr == "SHA1") {
        return Algorithm::SHA1;
    } else if (algoStr == "SHA256") {
        return Algorithm::SHA256;
    } else if (algoStr == "MD5") {
        return Algorithm::MD5;
    } else {
        return Algorithm::SHA256;
    }
}