#include "Request.hpp"

// Define constant request codes for different operations.
const uint16_t Request::REGISTRY = 825;
const uint16_t Request::SEND_PUBLIC_KEY = 826;
const uint16_t Request::LOGIN = 827;
const uint16_t Request::SEND_FILE = 828;
const uint16_t Request::VALID_CRC = 900;
const uint16_t Request::INVALID_CRC = 901;
const uint16_t Request::FOURTH_INVALID_CRC = 902;



// Define constant sizes for various fields.
const size_t Request::FILE_NAME_FIELD_LENGTH = 255;
const size_t Request::NAME_FIELD_LENGTH = 255;
const size_t Request::PUBLIC_KEY_LENGTH = 160;
const size_t Request::CONTENT_PACKET_SIZE = 4000; 
const size_t Request::MAX_SENDING_ATTEMPTS = 4;


const uint8_t Request::DEFAULT_VERSION = 3;
const unsigned char Request::MAX_ASCII_VALUE = 127;


// Define response lengths for different request types.
const size_t Request::RESPONSE_LENGTH_REGISTRY = 23;
const size_t Request::RESPONSE_LENGTH_SEND_PUBLIC_KEY = 151;
const size_t Request::RESPONSE_LENGTH_LOGIN = 151;
const size_t Request::RESPONSE_LENGTH_SEND_FILE = 286;
const size_t Request::RESPONSE_LENGTH_VALID_CRC = 23;
const size_t Request::RESPONSE_LENGTH_FOURTH_INVALID_CRC = 23;
const size_t Request::RESPONSE_LENGTH_INVALID_CRC = 1; //Poing message


/**
 * Request constructor initializes the request with specified parameters.
 * Validates the version, request code, and payload size.
 * Sets the response length based on the request code.
 *
 * @param clientID The unique identifier for the client.
 * @param version The version of the request.
 * @param code The specific operation code for the request.
 * @param payloadSize The size of the payload.
 * @param payload The payload containing additional data.
 * @throws std::invalid_argument if the version or request code is invalid.
 */
Request::Request(const std::vector<uint8_t>& clientID, uint8_t version, uint16_t code, uint32_t payloadSize, const Payload& payload)
    : _version(version), _code(code), _payloadSize(payloadSize), _payload(payload)
{
    if (version < 1) {
        throw std::invalid_argument("Invalid version");
    }
   
    std::set<uint16_t> validCodes = { REGISTRY, SEND_PUBLIC_KEY, LOGIN, SEND_FILE, VALID_CRC, FOURTH_INVALID_CRC, INVALID_CRC };
    
    if (validCodes.find(code) == validCodes.end()) {
        throw std::invalid_argument("Invalid request code");
    }
    if (payload.getSize() != payloadSize) {
        throw std::invalid_argument("Payload size does not match specified payloadSize");
    }

    //In regisration the client id still not generated so the field is not relevant
    if (code != REGISTRY) {
        if (clientID.size() != C_ID_LENGTH) {
            throw std::invalid_argument("Invalid client ID size");
        }
        _clientID.assign(clientID.begin(), clientID.begin() + C_ID_LENGTH);
    }

    if (code == REGISTRY) {
        responseLength = RESPONSE_LENGTH_REGISTRY;
    }
    else if (code == SEND_PUBLIC_KEY || code == LOGIN) {
        responseLength = RESPONSE_LENGTH_SEND_PUBLIC_KEY;
    }
    else if (code == SEND_FILE) {
        responseLength = RESPONSE_LENGTH_SEND_FILE;
    }
    else if (code == VALID_CRC || code == FOURTH_INVALID_CRC) {
        responseLength = RESPONSE_LENGTH_VALID_CRC;
    }
    else if (code == INVALID_CRC) {
        responseLength = RESPONSE_LENGTH_INVALID_CRC;
    }
}

/**
 * Sets the payload of the request.
 *
 * @param pload The payload data as a character.
 * @param size The size of the payload to set.
*/
void Request::setPayload(const char& pload, size_t size) {
    if (size > _payloadSize)
        std::cerr << "Too big payload\n";
    else {
        for (int i = 0; i < size; i++)
            _payload._payload.push_back((&pload)[i]);
    }

}






/**
 * Serializes the request into a byte buffer for transmission.
 *
 * @return A vector of bytes representing the serialized request.
 */
std::vector<uint8_t> Request::serializeReq() const{
    std::vector<uint8_t> buffer;

    if (_clientID.size() == 0) {
        // In requests that the client ID non relevant, is posibble to send '0'.
        buffer.insert(buffer.end(), 16, 0);
    }
    else {
        if (_clientID.size() != C_ID_LENGTH) {
            throw std::invalid_argument("Invalid client ID");
        }
        buffer.insert(buffer.end(), std::begin(_clientID), std::end(_clientID));
    }

    buffer.push_back(_version);
    pushUintToBuffer(buffer, _code, 2);
    pushUintToBuffer(buffer, _payloadSize, 4);
    buffer.insert(buffer.end(), _payload._payload.begin(), _payload._payload.end());

    return buffer;
}


/**
 * Validates the name to ensure it meets specific criteria.
 *
 * @param name The name to validate.
 * @param errorDetails A reference to a string where error details will be appended if validation fails.
 * @return True if valid, otherwise false.
*/
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

/**
 * Retrieves the response length of the request.
 *
 * @return The length of the response.
 */
size_t Request::getResponseLength() const {
    return responseLength;
   }





Payload::Payload() = default;


/**
 * Pads a string with zeros to reach a target length.
 *
 * @param str The original string to pad.
 * @param target The target length after padding.
 * @return The padded string, or an empty string if padding fails.
 */
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
 * Payload constructor initializes with a name.
 *
 * @param name The user name or file name.
 * @throws std::invalid_argument if the name is invalid.
 */
Payload::Payload(const std::string& name) {
    if (name.length() > Request::NAME_FIELD_LENGTH)
        throw std::invalid_argument("Invalid name");

    std::string maskedName = paddingZero(name, Request::NAME_FIELD_LENGTH);
    _payload.insert(_payload.end(), maskedName.begin(), maskedName.end());
}


/**
 * Assignment operator for setting payload from a vector of bytes.
 *
 * @param payload The vector of bytes to set as payload.
 * @return A reference to this Payload object.
 */
Payload& Payload::operator=(const std::vector<uint8_t>& payload) {
    _payload = payload;
    return *this;
}


/**
 * Payload constructor initializes with a name and a public key.
 *
 * @param name The user name or file name.
 * @param publicKey The public key associated with the payload.
 */
Payload::Payload(const std::string& name, const std::vector<uint8_t>& publicKey)
    :Payload(name)
{
    _payload.insert(_payload.end(), publicKey.begin(), publicKey.end());
}

/**
 * Payload constructor initializes with various parameters for file transmission.
 *
 * @param contentSize The size of the content.
 * @param origFileSize The original size of the file.
 * @param packetNumber The number of the current packet.
 * @param totalPackets The total number of packets.
 * @param fileName The name of the file being transmitted.
 * @param messageContent The content of the message as bytes.
 */
Payload::Payload(uint32_t contentSize, uint32_t origFileSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::vector<uint8_t>& messageContent) {
    
    pushUintToBuffer(_payload, contentSize, 4);
    pushUintToBuffer(_payload, origFileSize, 4);
    pushUintToBuffer(_payload, packetNumber, 2);
    pushUintToBuffer(_payload, totalPackets, 2);


    std::string maskedFileName = paddingZero(fileName, Request::FILE_NAME_FIELD_LENGTH);

    _payload.insert(_payload.end(), maskedFileName.begin(), maskedFileName.end());
    _payload.insert(_payload.end(), messageContent.begin(), messageContent.end());
}


/*
Returns an uint32_t type variable to a need for fitting into a 4-byte payload_size field.
An exception is thrown if the system you are working with is more than 32-bit and size_t is larger than uint32_t.
*/
uint32_t Payload::getSize() const{
    if (_payload.size() > UINT32_MAX) {
        throw std::overflow_error("Payload size exceeds the maximum limit for uint32_t.");
    }
    return static_cast<uint32_t>(_payload.size());
}


