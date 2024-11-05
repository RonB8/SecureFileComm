#include "Cloud.hpp"



Cloud::Cloud() : server(std::make_unique<Server>()) {}

Cloud::~Cloud() {
}

Response Cloud::registerName(const std::string& name) {

    std::cout << "Registering...\n";

    std::string errorMessages = "Registration failed.\n";
    std::string errorDetails;

    if (!Request::nameValidation(name, errorDetails)) {
        errorMessages += "Invalid name:\n" + errorDetails;
        throw std::invalid_argument(errorMessages);
    }

    Payload payload(name);
    Request req({}, Request::DEFAULT_VERSION, Request::REGISTRY, payload.getSize(), payload);
    std::vector<uint8_t> resp = server->sendReq(req);

    Response response(resp);
    if (response.getCode() == Response::FAILED_REGISTRATION) {
        throw std::runtime_error("Registration failed.");
    }
    else if (response.getCode() != Response::SUCCESSFUL_REGISTRATION) {
        throw std::runtime_error("An unknown code was received from the server for the registration operation.");
    }
    return response;
}

Response Cloud::sendPublicKey(const std::string& name, const std::vector<uint8_t>& ID, const std::vector<uint8_t>& public_key) {

    std::cout << "Sending public key...\n";

    bool validArgs = true;
    std::string errorMessages = "Sending public key failed.\n";
    std::string errorDetails;

    if (!Request::nameValidation(name, errorDetails)) {
        validArgs = false;
        errorMessages += "Invalid name:\n" + errorDetails;
    }
    if (ID.empty() || ID.size() != Request::C_ID_LENGTH) {
        validArgs = false;
        errorMessages += "The length of the Client ID must be " + Request::C_ID_LENGTH + '\n';
    }
    if (public_key.empty() || public_key.size() != Request::PUBLIC_KEY_LENGTH) {
        validArgs = false;
        errorMessages += "The length of the Public Key musts be " + Request::PUBLIC_KEY_LENGTH + '\n';
    }
    if (!validArgs) {
        throw std::invalid_argument(errorMessages);
    }

    Payload payload(name, public_key);

    uint8_t IDArr[Request::C_ID_LENGTH] = { 0 };
    for (size_t i = 0; i < Request::C_ID_LENGTH; i++)
        IDArr[i] = ID[i];

    //Request req(*IDArr, DEFAULT_VERSION, SEND_PUBLIC_KEY, DEFAULT_PAYLOAD_SIZE, payload);  $$$$$$$$$$$$
    Request req(ID, Request::DEFAULT_VERSION, Request::SEND_PUBLIC_KEY, payload.getSize(), payload);


    std::vector<uint8_t> resp = server->sendReq(req);


    Response response(resp);

    if (response.getCode() != Response::PUBLIC_KEY_RECEIVED) {
        throw std::runtime_error("An unknown code was received from the server for the public key sending.");
    }

    return response;
}

Response Cloud::login(const std::string& name, const std::vector<uint8_t>& ID) {
    std::cout << "Login...\n";

    bool validArgs = true;
    std::string errorMessages = "Login failed.\n";
    std::string errorDetails;

    if (!Request::nameValidation(name, errorDetails)) {
        validArgs = false;
        errorMessages += "Invalid name:\n" + errorDetails;
    }
    if (ID.empty() || ID.size() != Request::C_ID_LENGTH) {
        validArgs = false;
        errorMessages += "The length of the Client ID must be " + Request::C_ID_LENGTH + '\n';
    }
    if (!validArgs) {
        throw std::invalid_argument(errorMessages);
    }

    uint8_t IDArr[Request::C_ID_LENGTH] = { 0 };

    for (size_t i = 0; i < Request::C_ID_LENGTH; i++)
        IDArr[i] = ID[i];

    Payload payload(name);
    Request req(ID, Request::DEFAULT_VERSION, Request::LOGIN, payload.getSize(), payload);
    std::vector<uint8_t> resp = server->sendReq(req);

    Response response(resp);

    if (response.getCode() == Response::LOGIN_DENIED) {
        throw std::runtime_error("Login request denied, re-registration required.");
    }
    else if (response.getCode() != Response::LOGIN_ACCEPT) {
        throw std::runtime_error("An unknown code was received from the server for the login operation.");
    }

    return response;
}


Response Cloud::sendFile(const std::vector<uint8_t>& ID, const std::filesystem::path& filePath, const CryptoManager& cryptoManager) {
    std::cout << "Sending file...\n";

    bool validArgs = true;
    std::string errorMessages = "Sending file failed.\n";

    if (ID.empty() || ID.size() != Request::C_ID_LENGTH) {
        validArgs = false;
        errorMessages += "The length of the Client ID must be " + Request::C_ID_LENGTH + '\n';
    }
    if (!std::filesystem::exists(filePath)) {
        validArgs = false;
        errorMessages += "The file does not exist: " + filePath.string() + '\n';
    }
    else if (!std::filesystem::is_regular_file(filePath)) {
        validArgs = false;
        errorMessages += "The path is not a valid file: " + filePath.string() + '\n';
    }
    else if ((std::filesystem::status(filePath).permissions() & std::filesystem::perms::owner_read) == std::filesystem::perms::none) {
        validArgs = false;
        errorMessages += "No read permissions for the file: " + filePath.string() + '\n';
    }
    if (!validArgs) {
        throw std::invalid_argument(errorMessages);
    }
   
    uint8_t IDArr[Request::C_ID_LENGTH] = { 0 };
    uint32_t origFileSize = 0;
    std::vector<uint8_t> content;

    for (size_t i = 0; i < Request::C_ID_LENGTH; i++)
        IDArr[i] = ID[i];

    std::string fileName = filePath.filename().string();

    std::ifstream file(filePath, std::ios::binary);
    
    char ch;
    uint32_t index = 0;
    while (file.get(ch)) {
        content.push_back(ch);
        index++;
    }

    origFileSize = index;
    file.close();

    std::vector<uint8_t> encryptedContent = cryptoManager.encryptFile(content);
    
    uint32_t ckSum = checkSum(filePath.string());

    Response response;
    Payload fileNamePayload(fileName);
    size_t attempts = 1;

    do {
        server->disConnectSrv();
        std::vector<uint8_t> resp = sendFileByPackets(encryptedContent, ID, origFileSize, fileName);
        response.setPacket(resp);

        if (response.getCode() != Response::VALID_FILE_ACCEPTED) {
            throw std::runtime_error("File sending request failed.");
        }

        uint32_t respCkSum = response.getCksum();
        if (respCkSum == ckSum) {

            Request validCrcRequest(ID, Request::DEFAULT_VERSION, Request::VALID_CRC, fileNamePayload.getSize(), fileNamePayload);

            server->disConnectSrv();
            std::vector<uint8_t> validCrcResponse = server->sendReq(validCrcRequest);
            response.setPacket(validCrcResponse);

            if (response.getCode() != Response::MESSAGE_RECEIVED) {
                throw std::runtime_error("File sending request failed.");
            }

            break;
        }

        Request inValidCrcRequest(ID, Request::DEFAULT_VERSION, Request::INVALID_CRC, fileNamePayload.getSize(), fileNamePayload);
        server->disConnectSrv();
        std::vector<uint8_t> inValidCrcResponse = server->sendReq(inValidCrcRequest);

        attempts++;
    } while (attempts < Request::MAX_SENDING_ATTEMPTS);

    if (attempts == 4) {
        errorMessages += "CRC verification failed, file sending failed\n";
        std::cerr << errorMessages;
        Request fourthInValidCrcReq(ID, Request::DEFAULT_VERSION, Request::FOURTH_INVALID_CRC, fileNamePayload.getSize(), fileNamePayload);
        server->disConnectSrv();
        std::vector<uint8_t> fourthInValidCrcResp = server->sendReq(fourthInValidCrcReq);
        response.setPacket(fourthInValidCrcResp);

        if (response.getCode() != Response::MESSAGE_RECEIVED) {
            throw std::runtime_error("An error occurred while sending the file.");
        }

    }

    return response;
}

std::vector<uint8_t> Cloud::sendFileByPackets(const std::vector<uint8_t>& content, const std::vector<uint8_t>& ID, uint32_t origFileSize, const std::string& fileName)
{
    uint32_t contentSize = content.size();
    uint32_t totalPackets = std::ceil((double)contentSize / Request::CONTENT_PACKET_SIZE);
    uint32_t packetNumber = 1;
    size_t index = 0;

    while (packetNumber < totalPackets) {
        std::vector<uint8_t> currPacket = getSubVector(content, index * Request::CONTENT_PACKET_SIZE, index * Request::CONTENT_PACKET_SIZE + Request::CONTENT_PACKET_SIZE);


        Payload payload(contentSize, origFileSize, packetNumber, totalPackets, fileName, currPacket);



        Request req(ID, Request::DEFAULT_VERSION, Request::SEND_FILE, payload.getSize(), payload);
        server->disConnectSrv();
        server->sendReq(req);
        packetNumber++;
        index++;
    }

    std::vector<uint8_t> currPacket(content.begin() + index * Request::CONTENT_PACKET_SIZE, content.end());
    Payload payload(contentSize, origFileSize, packetNumber, totalPackets, fileName, currPacket);
    Request req(ID, Request::DEFAULT_VERSION, Request::SEND_FILE, payload.getSize(), payload);
    std::vector<uint8_t> response = server->sendReq(req);
    return response;
}

