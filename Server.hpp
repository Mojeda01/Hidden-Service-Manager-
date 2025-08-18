#pragma once

#include <memory>
#include "Protocol.hpp"

class TcpServer{
public:
    explicit TcpServer(int port);
    void start();
    void run();
    void stop();
    void attachProtocol(IProtocol* protocol);

private:
    int listeningPort;
    IProtocol* attachedProtocol;    // not owned, just reference
};
