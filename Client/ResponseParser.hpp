#pragma once

#include "commonInc.hpp"
#include <iostream>
#include <cstdint>
#include <vector>


class Response {

private:
    
    uint8_t version{};
    uint16_t code{};
    uint32_t payloadSize{};
    std::vector<uint8_t> payload;

    /**
    *
    * @param start start position of the desired sub vector
    * @param end end position of the desired sub vector
    * @return sub vector in the range [start : end]
    */
    std::vector<uint8_t> getSubPayload(size_t start, size_t end);


public:
    static const uint16_t SUCCESSFUL_REGISTRATION = 1600;
    static const uint16_t FAILED_REGISTRATION = 1601;
    static const uint16_t PUBLIC_KEY_RECEIVED = 1602;
    static const uint16_t VALID_FILE_ACCEPTED = 1603;
    static const uint16_t MESSAGE_RECEIVED = 1604;
    static const uint16_t LOGIN_ACCEPT = 1605;
    static const uint16_t LOGIN_DENIED = 1606;
    static const uint16_t GENERIC_ERROR = 1607;


    explicit Response(const std::vector<uint8_t>& packet);
    Response() = default;
    Response& operator=(const Response& other);

    uint8_t getVersion() const;
    uint16_t getCode() const;
    uint32_t getPayloadSize() const;
    const std::vector<uint8_t>& getPayload() const;

    void setPacket(const std::vector<uint8_t>& packet);
    
    std::vector<uint8_t> getClientID();
    std::vector<uint8_t> getEncryptedSymmetricKey();
    uint32_t getContentSize();
    std::vector<uint8_t> getFileName();
    uint32_t getCksum();
    
};



