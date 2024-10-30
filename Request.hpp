
#pragma once


#include "includeAll.hpp"

#include <climits>
#include <iostream>
#include <vector>
#include "CodeFinals.hpp"
#include <stdexcept>
#include <cstdint>
#include "ByteUtils.hpp"



struct Payload {
    std::vector<uint8_t> _payload;
    Payload();
    explicit Payload(const std::string& name);
    Payload& operator=(const std::vector<uint8_t>& payload);
    Payload(const std::string& name, const std::vector<uint8_t>& publicKey);
    Payload(uint32_t contentSize, uint32_t origFileSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::vector<uint8_t>& messageContent);
    void pushUint32(uint32_t);
    void pushUint16(uint16_t);
    uint32_t getSize();
};

struct Request {

    static const uint16_t REGISTRY = 825;
    static const uint16_t SEND_PUBLIC_KEY = 826;
    static const uint16_t LOGIN = 827;
    static const uint16_t SEND_FILE = 828;
    static const uint16_t VALID_CRC = 900;
    static const uint16_t INVALID_CRC = 901;
    static const uint16_t FOURTH_INVALID_CRC = 902;

    static const size_t C_ID_LENGTH = 16;
    static const uint8_t DEFAULT_VERSION = 3;
    static const size_t FILE_NAME_FIELD_LENGTH = 255;
    static const size_t NAME_FIELD_LENGTH = 255;
    static const size_t PUBLIC_KEY_LENGTH = 160;
    static const size_t CONTENT_PACKET_SIZE = 16; //@@@@@@@@@@@@@@@@
    static const size_t MAX_SENDING_ATTEMPTS = 4;
    static const unsigned char MAX_ASCII_VALUE = 127;

   


    uint8_t _clientID[C_ID_LENGTH] = { 0 };
    uint8_t _version = 0;
    uint16_t _code = 0;
    uint32_t _payloadSize = 0;
    struct Payload _payload;
    size_t responseLength;

    Request(const uint8_t& clientID, uint8_t version, uint16_t code, uint32_t payloadSize, const struct Payload& payload);
    void setPayload(const char& pload, std::size_t size);
    void setResponseLength(size_t len);
    static std::vector<uint8_t> serializeReq(const Request& packet);
    static bool nameValidation(const std::string& name, std::string& errorDetails);


};




