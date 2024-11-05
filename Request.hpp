
#pragma once


#include "commonInc.hpp"

#include <climits>
#include <iostream>
#include <vector>
#include <set>
#include "CodeFinals.hpp"
#include <stdexcept>
#include <cstdint>
#include "ByteUtils.hpp"

#include "Cloud.hpp"

class Payload {
private:
    std::vector<uint8_t> _payload;

public:
    Payload();
    explicit Payload(const std::string& name);
    Payload& operator=(const std::vector<uint8_t>& payload);
    Payload(const std::string& name, const std::vector<uint8_t>& publicKey);
    Payload(uint32_t contentSize, uint32_t origFileSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::vector<uint8_t>& messageContent);
    uint32_t getSize() const;
    friend class Request;
};




class Request {
public:
    static const uint16_t REGISTRY, SEND_PUBLIC_KEY, LOGIN, SEND_FILE, VALID_CRC, INVALID_CRC, FOURTH_INVALID_CRC;

    static constexpr size_t C_ID_LENGTH = 16;
    static const size_t FILE_NAME_FIELD_LENGTH, NAME_FIELD_LENGTH, PUBLIC_KEY_LENGTH, CONTENT_PACKET_SIZE, MAX_SENDING_ATTEMPTS;

    // הצהרה עבור קבועים מסוג uint8_t
    static const uint8_t DEFAULT_VERSION;

    // הצהרה עבור קבועים מסוג unsigned char
    static const unsigned char MAX_ASCII_VALUE;



    static const size_t RESPONSE_LENGTH_REGISTRY, RESPONSE_LENGTH_SEND_PUBLIC_KEY, RESPONSE_LENGTH_LOGIN, RESPONSE_LENGTH_SEND_FILE, RESPONSE_LENGTH_VALID_CRC, RESPONSE_LENGTH_FOURTH_INVALID_CRC, RESPONSE_LENGTH_INVALID_CRC;



    Request(const std::vector<uint8_t>& clientID, uint8_t version, uint16_t code, uint32_t payloadSize, const struct Payload& payload);
    void setPayload(const char& pload, std::size_t size);




    //static std::vector<uint8_t> serializeReq(const Request& packet);
    std::vector<uint8_t> serializeReq() const;



    static bool nameValidation(const std::string& name, std::string& errorDetails);
    size_t getResponseLength() const;
    friend class Cloud;

private:
    std::vector<uint8_t> _clientID;
    uint8_t _version = 0;
    uint16_t _code = 0;
    uint32_t _payloadSize = 0;
    struct Payload _payload;
    size_t responseLength;

};

