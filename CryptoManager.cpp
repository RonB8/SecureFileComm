#include "CryptoManager.hpp"

RSAKeys::RSAKeys() {
    CryptoPP::AutoSeededRandomPool rng;

    // יצירת מפתח פרטי ומפתח ציבורי
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    publicKey = CryptoPP::RSA::PublicKey(privateKey);
}

RSAKeys::RSAKeys(const std::vector<uint8_t>& inputPrivateKey) {
    // Convert vector<uint8_t> to ByteQueue
    CryptoPP::ByteQueue queue;
    queue.Put(inputPrivateKey.data(), inputPrivateKey.size());
    queue.MessageEnd();

    // Load the private key from ByteQueue
    privateKey.Load(queue);

    // Generate the public key from the private key
    publicKey = CryptoPP::RSA::PublicKey(privateKey);
}


// Decrypt function: takes an encrypted vector of uint8_t and returns the decrypted vector
std::vector<uint8_t> RSAKeys::decrypt(const std::vector<uint8_t>& encryptedData) {
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<uint8_t> decryptedData;

    // הכנה לפענוח עם המפתח הפרטי
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    // פענוח המידע
    size_t maxLength = decryptor.MaxPlaintextLength(encryptedData.size());
    decryptedData.resize(maxLength);

    CryptoPP::DecodingResult result = decryptor.Decrypt(rng, encryptedData.data(), encryptedData.size(), decryptedData.data());

    // התאמת הגודל לגודל המידע המפוענח
    decryptedData.resize(result.messageLength);
    return decryptedData;
}



std::vector<uint8_t> RSAKeys::getPublicKey() const {
    std::vector<uint8_t> publicKeyBytes;

    // סדרת המפתח הציבורי לפורמט בינארי
    CryptoPP::ByteQueue queue;
    publicKey.Save(queue);

    size_t size = queue.CurrentSize();
    publicKeyBytes.resize(size);
    queue.Get(&publicKeyBytes[0], size);

    return publicKeyBytes;
}

std::vector<uint8_t> RSAKeys::exportPrivateKey() const {
    // Create a ByteQueue to hold the private key
    CryptoPP::ByteQueue queue;

    // Save the private key to the ByteQueue
    privateKey.Save(queue);

    // Convert ByteQueue to vector<uint8_t>
    size_t size = queue.MaxRetrievable();
    std::vector<uint8_t> privateKeyBytes(size);

    // Read the private key bytes from the ByteQueue into the vector
    queue.Get(privateKeyBytes.data(), privateKeyBytes.size());

    return privateKeyBytes;
}











AESKey::AESKey(const std::vector<uint8_t>& key) {
    _key = key;
}


const std::vector<uint8_t> AESKey::encrypt(const std::vector<uint8_t>& plaintext)const {

    // וקטור לאחסון הנתונים המוצפנים
    std::vector<uint8_t> encryptedData;

    // בדיקה שמפתח ה-AES הוא באורך 256 ביט (32 בתים)
    if (_key.size() != 32) {
        throw std::runtime_error("Invalid key size, must be 256 bits (32 bytes).");
    }

    // יצירת אתחול וקטור (IV) באורך של AES::BLOCKSIZE (16 בתים)
    uint8_t iv[CryptoPP::AES::BLOCKSIZE] = { 0 }; // לדוגמה, IV מאופס (לצורך ההדגמה)

    try {
        // יצירת מצפין AES במצב CBC
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(_key.data(), _key.size(), iv);

        // ביצוע ההצפנה באמצעות StreamTransformationFilter
        CryptoPP::StreamTransformationFilter stfEncryptor(encryption, new CryptoPP::VectorSink(encryptedData));
        stfEncryptor.Put(plaintext.data(), plaintext.size());
        stfEncryptor.MessageEnd();
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Encryption failed: " << e.what() << std::endl;
        throw;
    }

    return encryptedData;
}


std::vector<uint8_t> AESKey::decrypt(const std::vector<uint8_t>& encryptedData) {

    // וקטור לאחסון הנתונים המפוענחים
    std::vector<uint8_t> decryptedData;

    // בדיקה שמפתח ה-AES הוא באורך 256 ביט (32 בתים)
    if (_key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Invalid key size, must be 256 bits (32 bytes).");
    }

    // אתחול וקטור (IV) חייב להיות בגודל של AES::BLOCKSIZE (16 בתים)
    // כאן אנו משתמשים ב-IV קבוע לצורך הדגמה, אך בפועל יש צורך להשתמש ב-IV ייחודי עבור כל פיענוח
    uint8_t iv[CryptoPP::AES::BLOCKSIZE] = { 0 }; // לדוגמה, IV מאופס (לצורך ההדגמה)

    try {
        // יצירת מפענח AES במצב CBC
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(_key.data(), _key.size(), iv);

        // ביצוע הפיענוח באמצעות StreamTransformationFilter
        CryptoPP::StreamTransformationFilter stfDecryptor(decryption, new CryptoPP::VectorSink(decryptedData));
        stfDecryptor.Put(encryptedData.data(), encryptedData.size());
        stfDecryptor.MessageEnd();
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        throw;
    }

    return decryptedData;
}




















    void CryptoManager::initRSAKeys() {
        rsaKeyPair = std::make_unique<RSAKeys>();
    }

    void CryptoManager::initRSAKeys(const std::vector<uint8_t>& privateKey) {
        rsaKeyPair = std::make_unique<RSAKeys>(privateKey);
    }

    std::vector<uint8_t> CryptoManager::getPublicKey() {
        if (!rsaKeyPair) {
            throw std::runtime_error("RSA key pair not initialized.");
        }
        return rsaKeyPair->getPublicKey();
    }

    std::vector<uint8_t> CryptoManager::getPrivateKey() {
        if (!rsaKeyPair) {
            throw std::runtime_error("RSA key pair not initialized.");
        }
        return rsaKeyPair->exportPrivateKey();
    }


    void CryptoManager::initAESKey(const std::vector<uint8_t>& encryptedAesKey) {
        std::vector<uint8_t> decryptedAesKey = rsaKeyPair->decrypt(encryptedAesKey);
        aes = std::make_unique<AESKey>(decryptedAesKey);
    }

    std::vector<uint8_t> CryptoManager::encryptFile(const std::vector<uint8_t>& fileContent) const {
        if (!aes) {
            throw std::runtime_error("AES key not initialized.");
        }
        return aes->encrypt(fileContent);
    }