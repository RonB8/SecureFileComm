//#include "CodeFinals.hpp"
//#include "common.hpp"
#include "Request.hpp"



Request::Request(const uint8_t& clientID, uint8_t version, uint16_t code, uint32_t payloadSize, const Payload& payload)
    : _version(version), _code(code), _payloadSize(payloadSize), _payload(payload)
{
    memcpy(_clientID, &clientID, 16);

    if (code == REGISTRY) {
        responseLength = 23;
    }
    else if (code == SEND_PUBLIC_KEY || code == LOGIN) {
        responseLength = 151;
    }
    else if (code == SEND_FILE) {
        responseLength = 286;
    }
    else if (code == VALID_CRC || code == FOURTH_INVALID_CRC) {
        responseLength = 23;
    }
    else if (code == INVALID_CRC) {
        responseLength = 0;
    }
    //@@@@@@@@@@@@@@@@@@@@@@@@  throw exception?
}

void Request::setPayload(const char& pload, size_t size) {
    if (size > _payloadSize)
        std::cerr << "Too big payload\n";
    else {
        for (int i = 0; i < size; i++)
            _payload._payload.push_back((&pload)[i]);
    }

}

void Request::setResponseLength(size_t len) {
    responseLength = len;
}









std::vector<uint8_t> Request::serializeReq(const Request& packet) {
    std::vector<uint8_t> buffer;
    buffer.reserve(16 + 1 + 2 + 4 + packet._payload._payload.size());

    // Adding client ID (16 bytes)
    buffer.insert(buffer.end(), std::begin(packet._clientID), std::end(packet._clientID));

    // Adding version (1 byte)
    buffer.push_back(packet._version);

    // Adding code (2 bytes)
    pushUintToBuffer(buffer, packet._code, 2);

    // Adding payload size (4 bytes)
    pushUintToBuffer(buffer, packet._payloadSize, 4);

    // Adding payload
    buffer.insert(buffer.end(), packet._payload._payload.begin(), packet._payload._payload.end());

    return buffer;
}
bool Request::nameValidation(const std::string& name, std::string& errorDetails) {

    if (name.empty()) {
        errorDetails += "The name can't be empty\n";
        return false;
    }

    // '>=' Cause the maximum length is include the null terminated
    if(name.length() >= NAME_FIELD_LENGTH) {
        errorDetails += "The length of the name must be less than " + NAME_FIELD_LENGTH + '\n';
        return false;
    }

    //Making sure the string is ASCII
    for (char ch : name) {
        if (static_cast<unsigned char>(ch) > MAX_ASCII_VALUE) {
            errorDetails += "The name must contains just ASCII characters\n";
            return false;
        }
    }

    return true;
}









Payload::Payload() = default;

void Payload::pushUint32(uint32_t var) {
    _payload.push_back(static_cast<uint8_t>(var >> 24));
    _payload.push_back(static_cast<uint8_t>(var >> 16));
    _payload.push_back(static_cast<uint8_t>(var >> 8));
    _payload.push_back(static_cast<uint8_t>(var & 0xFF));
}

void Payload::pushUint16(uint16_t var) {
    _payload.push_back(static_cast<uint8_t>(var >> 8));
    _payload.push_back(static_cast<uint8_t>(var & 0xFF));
}

std::string paddingZero(const std::string& str, int target) {
    size_t paddingSize = target - str.length();
    std::string result = str;
    if (paddingSize >= 0) {
        result.insert(0, paddingSize, '\0');
        return result;
    }
    std::cerr << "Padding zero Failed\n";
    return "";
}

/**
 *
 * @param name user name or file name
 */
Payload::Payload(const std::string& name) {
    if (name.length() > Request::NAME_FIELD_LENGTH)
        throw std::invalid_argument("Invalid name");

    std::string maskedName = paddingZero(name, Request::NAME_FIELD_LENGTH);
    _payload.insert(_payload.end(), maskedName.begin(), maskedName.end());
    //    _payload.push_back(0); //Null terminated
}

Payload& Payload::operator=(const std::vector<uint8_t>& payload) {
    _payload = payload;
    return *this;
}

Payload::Payload(const std::string& name, const std::vector<uint8_t>& publicKey)
    :Payload(name)
{
    _payload.insert(_payload.end(), publicKey.begin(), publicKey.end());
}

Payload::Payload(uint32_t contentSize, uint32_t origFileSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::vector<uint8_t>& messageContent) {
    pushUint32(contentSize);
    pushUint32(origFileSize);
    pushUint16(packetNumber);
    pushUint16(totalPackets);

    std::string maskedFileName = paddingZero(fileName, Request::FILE_NAME_FIELD_LENGTH);

    _payload.insert(_payload.end(), maskedFileName.begin(), maskedFileName.end());
    _payload.insert(_payload.end(), messageContent.begin(), messageContent.end());
}


/*
Returns an uint32_t type variable to a need for fitting into a 4-byte payload_size field.
An exception is thrown if the system you are working with is more than 32-bit and size_t is larger than uint32_t.
*/
uint32_t Payload::getSize() {
    if (_payload.size() > UINT32_MAX) {
        throw std::overflow_error("Payload size exceeds the maximum limit for uint32_t.");
    }
    return static_cast<uint32_t>(_payload.size());
}


