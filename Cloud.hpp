#pragma once

#include "includeAll.hpp"


#include <files.h>
#include "iostream"
#include "Server.hpp"
#include "Request.hpp"
#include "Response.hpp"
#include <filesystem>
#include "CryptoManager.hpp"
#include "ByteUtils.hpp"



unsigned long checkSum(const std::string& fname);


class Cloud {
    Server server;
public:
    Cloud();
    Response registerName(const std::string& name);
    Response login(const std::string& name, const std::vector<uint8_t>& ID);
    Response sendPublicKey(const std::string& name, const std::vector<uint8_t>& ID, const std::vector<uint8_t>& public_key);
    //Response sendFile(const std::vector<uint8_t>& ID, const std::filesystem::path& filePath, const AesKey& aesKey); $$$$$$$$
    Response sendFile(const std::vector<uint8_t>& ID, const std::filesystem::path& filePath, const CryptoManager& cryptoManager);
    std::vector<uint8_t> sendFileByPackets(const std::vector<uint8_t>& content, const uint8_t IDArr[], uint32_t origFileSize, const std::string& fileName);
};

