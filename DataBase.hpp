#pragma once

#include "commonInc.hpp"
#include <winsock.h>
#include <iostream>
#include <vector>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <string>
#include <cryptlib.h>
#include <hex.h>
#include <filters.h>
#include <osrng.h>
#include <base64.h>
#include "ByteUtils.hpp"


class DataBase {
private:
    std::string userInfoFile;
    std::string transferFile;
    std::string privKeyFile;

public:
    
    DataBase();
    bool userExist();
    bool extractTransferInfo(std::string& ipAddress, u_short& port, std::string& userName, std::string& filePath);
    bool writeUserDetailsToFile(const std::string& userName, const std::vector<uint8_t>& cID, const std::vector<uint8_t>& publicKey);
    bool extractUserDetails(std::string& name, std::vector<uint8_t>& cID, std::vector<uint8_t>& privateKey);

    bool savePrivateKey(const std::vector<uint8_t>& privKey);
    bool loadPrivateKey(std::vector<uint8_t>& privKey);

    int saveCID(const std::vector<uint8_t>& cID);
    std::vector<uint8_t> extractCID();
};


