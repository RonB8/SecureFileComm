#include "Server.hpp"
#include "Request.hpp"


void Server::initializeWinSock() {
    //Initialize the winsock
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return;
    }

    port = 1234;
    const char* host = "127.0.0.1";
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    //serverAddr.sin_addr.s_addr = inet_pton(host);

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    /*if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }*/

    if (inet_pton(AF_INET, host, &serverAddr.sin_addr.s_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        WSACleanup();
        return ;
    }
}

void Server::connectSrv() {

    initializeWinSock();

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return;
    }
}

void Server::disConnectSrv() {
    closesocket(clientSocket);
    WSACleanup();
}

std::vector<uint8_t> Server::sendReq(const Request& req) {
    connectSrv();

    //std::vector<uint8_t> dataBytes = Request::serializeReq(req);
    std::vector<uint8_t> dataBytes = req.serializeReq();
    send(clientSocket, reinterpret_cast<const char*>(dataBytes.data()), dataBytes.size(), 0);

    /*if (req.getResponseLength() == 0) {
        return {};
    }*/

    std::vector<char> buffer(req.getResponseLength());
    int bytesReceived = recv(clientSocket, buffer.data(), req.getResponseLength(), 0);
    disConnectSrv();

    if (bytesReceived > 0) {
        std::cout << "Received from server: " << buffer[0] << std::endl;
    }
    else if (bytesReceived == 0) {
        std::cerr << "Connection closed by the server." << std::endl;
    }
    else {
        std::cerr << "Error receiving data from server." << std::endl;
    }

    std::vector<uint8_t> res(buffer.begin(), buffer.begin() + bytesReceived);

    
    return res;
}



