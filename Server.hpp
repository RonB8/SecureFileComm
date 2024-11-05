#pragma once

#include "commonInc.hpp"

#include "Request.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")


class Server {
public:
    WSADATA wsaData;
    u_short port;
    sockaddr_in serverAddr;
    SOCKET clientSocket;

    void initializeWinSock();


   /* Server() {}
    ~Server();*/
   
    void connectSrv();
    void disConnectSrv();
    std::vector<uint8_t> sendReq(const struct Request& req);
};
