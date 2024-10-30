#pragma once

#include "includeAll.hpp"
#include <aes.h>
#include <modes.h>
#include <filters.h>





#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <hex.h>
#include <files.h>
#include <secblock.h>
#include <memory>



class RSAKeys {
private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;

public:
    // Constructor: generates RSA key pair
    RSAKeys();
    RSAKeys(const std::vector<uint8_t>& inputPrivateKey);

 

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encryptedData);
    std::vector<uint8_t> getPublicKey()const;
    std::vector<uint8_t> exportPrivateKey() const;

};




class AESKey {
    std::vector<uint8_t> _key;

public:
    AESKey(const std::vector<uint8_t>& key);
    const std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data)const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data);
};





class CryptoManager {
private:
    std::unique_ptr<RSAKeys> rsaKeyPair;
    std::unique_ptr<AESKey> aes;

public:
    CryptoManager() = default;
    void initRSAKeys();
    void initRSAKeys(const std::vector<uint8_t>& privateKey);
    std::vector<uint8_t> getPublicKey();
    std::vector<uint8_t> getPrivateKey();
    void initAESKey(const std::vector<uint8_t>& encryptedAesKey);
    std::vector<uint8_t> encryptFile(const std::vector<uint8_t>& fileContent) const;
};