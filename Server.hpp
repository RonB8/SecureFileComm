#pragma once

#include "includeAll.hpp"



//#define WIN32_LEAN_AND_MEAN
//#include "common.hpp"
#include "Request.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")


class Server {
    WSADATA wsaData;
    u_short port;
    sockaddr_in serverAddr;
    SOCKET clientSocket;

public:
    Server();
    ~Server();
    void initializeWinSock();
    void connectSrv();
    void disConnectSrv();
    std::vector<uint8_t> sendReq(const struct Request& req);
};
