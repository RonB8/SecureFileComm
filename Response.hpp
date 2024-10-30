#pragma once

#include "includeAll.hpp"

#include <iostream>
#include <cstdint>
#include <vector>




class Response {
public:

    const int SUCCESSFUL_REGISTRATION = 1600;
    const int FAILED_REGISTRATION = 1601;
    const int PUBLIC_KEY_RECEIVED = 1602;
    const int VALID_FILE_ACCEPTED = 1603;
    const int MESSAGE_RECEIVED = 1604;
    const int LOGIN_ACCEPT = 1605;
    const int LOGIN_REJECT = 1606;
    const int GENERIC_ERROR = 1607;

    uint8_t version{};
    uint16_t code{};
    uint32_t payloadSize{};
    std::vector<uint8_t> payload;


    explicit Response(const std::vector<uint8_t>& packet);
    Response() = default;
    Response& operator=(const Response& other);
    void setPacket(const std::vector<uint8_t>& packet);
    /**
    *
    * @param start start position of the desired sub vector
    * @param end end position of the desired sub vector
    * @return sub vector in the range [start : end]
    */
    std::vector<uint8_t> getSubPayload(size_t start, size_t end);
    std::vector<uint8_t> getClientID();
    std::vector<uint8_t> getEncryptedSymmetricKey();
    std::vector<uint8_t> getContentSize();
    std::vector<uint8_t> getFileName();
    std::vector<uint8_t> getCksum();
    uint32_t getCksumAsNum();
};



