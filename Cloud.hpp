#pragma once

#include "commonInc.hpp"


#include <files.h>
#include "iostream"
#include "Server.hpp"
#include "Request.hpp"
#include "ResponseParser.hpp"
#include <filesystem>
#include "CryptoManager.hpp"
#include "ByteUtils.hpp"



unsigned long checkSum(const std::string& fname);

class Server;

class Cloud {

private:
    std::unique_ptr<Server> server;

public:    
    Cloud();
    ~Cloud();
    Response registerName(const std::string& name);
    Response login(const std::string& name, const std::vector<uint8_t>& ID);
    Response sendPublicKey(const std::string& name, const std::vector<uint8_t>& ID, const std::vector<uint8_t>& public_key);
    Response sendFile(const std::vector<uint8_t>& ID, const std::filesystem::path& filePath, const CryptoManager& cryptoManager);
    



    std::vector<uint8_t> sendFileByPackets(const std::vector<uint8_t>& content, const std::vector<uint8_t>& IDArr, uint32_t origFileSize, const std::string& fileName);
};


