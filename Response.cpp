//#include "common.hpp"
#include "CodeFinals.hpp"
//#include "Request.hpp"
#include "Response.hpp"



Response::Response(const std::vector<uint8_t>& packet)
{
    setPacket(packet);
}

Response& Response::operator=(const Response& other) {
    version = other.version;
    code = other.code;
    payloadSize = other.payloadSize;
    payload = other.payload;
    return *this;
}


/*inline */void Response::setPacket(const std::vector<uint8_t>& packet) {
    version = packet[0];
    code = (packet[1] << 8) + packet[2];
    payloadSize = (packet[3] << 24) + (packet[4] << 16) + (packet[5] << 8) + packet[6];

    // Ensure that the packet contains enough data for the payload
    if (packet.size() < static_cast<unsigned long long>(7) + payloadSize) {
        std::cerr << "Error: Packet size is smaller than expected payload size" << std::endl;
        return;
    }

    try {
        payload.insert(payload.end(), packet.begin() + 7, packet.begin() + 7 + payloadSize);
    }
    catch (const std::exception& e) {
        std::cout << "Inserting to vector failed\n" << e.what();
    }
}

/**
*
* @param start start position of the desired sub vector
* @param end end position of the desired sub vector
* @return sub vector in the range [start : end]
*/

std::vector<uint8_t> Response::getSubPayload(size_t start, size_t end) {
    if (code == FAILED_REGISTRATION || code == GENERIC_ERROR)
        throw std::invalid_argument::invalid_argument("Invalid request code for extracting sub-payload.");

    if (start >= payload.size() || end > payload.size() || start > end) {
        std::cout << "start = " << start << "\nend = " << end << std::endl;
        throw std::out_of_range::out_of_range("Invalid range for sub-payload extraction.");
    }

    std::vector<uint8_t> subVec;

    for (size_t i = start; i < end; i++)
        subVec.push_back(payload[i]);

    return subVec;
}

std::vector<uint8_t> Response::getClientID() {
    return getSubPayload(0, 16);
}

std::vector<uint8_t> Response::getEncryptedSymmetricKey() {
    if (code != PUBLIC_KEY_RECEIVED && code != LOGIN_ACCEPT)
        throw std::invalid_argument::invalid_argument(""); //To put something @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    
    return getSubPayload(16, payloadSize);
}

std::vector<uint8_t> Response::getContentSize() {
    if (code != VALID_FILE_ACCEPTED)
        throw std::invalid_argument::invalid_argument(""); //To put something @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    return getSubPayload(16, 20);
}
std::vector<uint8_t> Response::getFileName() {
    if (code != VALID_FILE_ACCEPTED)
        throw std::invalid_argument::invalid_argument(""); //To put something @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    return getSubPayload(20, 276);
}

std::vector<uint8_t> Response::getCksum() {
    if (code != VALID_FILE_ACCEPTED)
        throw std::invalid_argument::invalid_argument(""); //To put something @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    return getSubPayload(275, 279);
}

uint32_t Response::getCksumAsNum() {
    std::vector<uint8_t> temp = getCksum();
    uint32_t num = 0;
    num += temp[0] << 24;
    num += temp[1] << 16;
    num += temp[2] << 8;
    num += temp[3];

    return num;
}