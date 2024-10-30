//
// Created by user on 10/15/2024.
//

#include "DataBase.hpp"





DataBase::DataBase() {
    userInfoFile = "me.info";
    transferFile = "transfer.info";
    privKeyFile = "pri.txt"; //@@@@@@@@@@@@@@@@@@@@@@@@@  back to 'priv.key'
}

bool DataBase::userExist() {
    return std::filesystem::exists(userInfoFile);
}

// Function to extract all the required data from the file
bool DataBase::extractTransferInfo(std::string& ipAddress, u_short& port, std::string& userName, std::string& filePath) {
    std::ifstream file(transferFile);  // Open the file for reading
    if (!file.is_open()) {
        std::cerr << "Error: Could not open the file " << transferFile << std::endl;
        return false;
    }

    // Extract the first line (IP Address and Port)
    std::string firstLine;
    if (std::getline(file, firstLine)) {
        size_t colonPos = firstLine.find(':');
        if (colonPos != std::string::npos) {
            ipAddress = firstLine.substr(0, colonPos);  // Extract IP address
            std::string portStr = firstLine.substr(colonPos + 1);  // Extract Port
            std::istringstream(portStr) >> port;  // Convert port string to u_short
        }
        else {
            std::cerr << "Error: Malformed IP:Port format in file" << std::endl;
            return false;
        }
    }
    else {
        std::cerr << "Error: Could not read the first line (IP:Port) from file" << std::endl;
        return false;
    }

    // Extract the second line (User Name)
    std::string secondLine;
    if (std::getline(file, secondLine)) {
        userName = secondLine;
    }
    else {
        std::cerr << "Error: Could not read the second line (First Name and Last Name) from file" << std::endl;
        return false;
    }

    // Extract the third line (File Path)
    if (std::getline(file, filePath)) {
        return true;  // Successfully extracted all information
    }
    else {
        std::cerr << "Error: Could not read the third line (File Path) from file" << std::endl;
        return false;
    }
}

// Function to save the private key to a file (priv.key)
bool DataBase::savePrivateKey(const std::vector<uint8_t>& privKey) {
    std::ofstream file(privKeyFile);  // Open the file for writing
    if (!file.is_open()) {
        std::cerr << "Error: Could not open the file for writing" << std::endl;
        return false;
    }
    for (size_t i = 0; i < privKey.size(); ++i) {
        file << std::hex << std::setw(2) << std::setfill('0') << int(privKey[i]);
    }
    /*file << std::endl;*/
    return true;

}
bool DataBase::loadPrivateKey(std::vector<uint8_t>& privKey) {
    std::ifstream file(privKeyFile);  // Open the file for reading
    if (!file.is_open()) {
        std::cerr << "Error: Could not open the file for reading" << std::endl;
        return false;
    }

    std::string hexStr;
    std::getline(file, hexStr);  // Read the entire line (the private key in hex)
    file.close();

    // Convert hex string to vector<uint8_t>
    privKey.clear();  // Clear the vector before populating it
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteString = hexStr.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));  // Convert hex to byte
        privKey.push_back(byte);  // Add byte to vector
    }

    return true;
}





bool DataBase::writeUserDetailsToFile(const std::string& userName, const std::vector<uint8_t>& cID, const std::vector<uint8_t>& privateKey) {
    std::ofstream file("me.info");  // Open the file for writing
    if (!file.is_open()) {
        std::cerr << "Error: Could not open the file for writing" << std::endl;
        return false;
    }

    // Write the userName on the first line
    file << userName << std::endl;

    // Write the cID on the second line in hexadecimal format
    for (size_t i = 0; i < cID.size(); ++i) {
        file << std::hex << std::setw(2) << std::setfill('0') << int(cID[i]);
    }
    file << std::endl;

    // Write the private key on the third line in Base64 format
    std::string encodedPrivateKey;
    CryptoPP::StringSource(privateKey.data(), privateKey.size(), true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedPrivateKey), false));

    file << encodedPrivateKey << std::endl;

    file.close();
    return true;
}




int DataBase::saveCID(const std::vector<uint8_t>& cID) {
    std::ofstream file;
    file.open(userInfoFile);
    for (auto var : cID) {
        file << var;
    }
    file.close();
    return 0;
}

std::vector<uint8_t> DataBase::extractCID() {
    std::ifstream file(userInfoFile);
    std::string id;
    if (file)
        std::getline(file, id);

    std::vector<uint8_t> cID = strToBytes(id);

    return cID;
}

bool DataBase::extractUserDetails(std::string& name, std::vector<uint8_t>& cID, std::vector<uint8_t>& privateKey) {
    std::ifstream file(userInfoFile);

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file");
    }

    // Read the first line (full name)
    if (!std::getline(file, name)) {
        std::cerr << "Failed to read name from file";
        return false;
    }

    // Read the second line (cID in hex)
    std::string cIDHex;
    if (!std::getline(file, cIDHex)) {
        std::cerr << "Failed to read CID from file";
        return false;
    }

    // Convert cID from hex string to vector<uint8_t>
    CryptoPP::StringSource(cIDHex, true, new CryptoPP::HexDecoder(new CryptoPP::VectorSink(cID)));

    // Read the third line (private key in base64)
    std::string privateKeyBase64;
    if (!std::getline(file, privateKeyBase64)) {
        std::cerr << "Failed to read private key from file";
        return false;
    }

    // Convert private key from base64 string to vector<uint8_t>
    CryptoPP::StringSource(privateKeyBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::VectorSink(privateKey)));

    file.close();
    return true;
}