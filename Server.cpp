// Server.cpp

#include "Server.hpp"
#include <iostream>

TcpServer::TcpServer(int port) : listeningPort(port), attachedProtocol(nullptr) {}

void TcpServer::start(){
    // Placeholder: bind socket, listen
    std::cout << "[Server] Starting on port " << listeningPort << std::endl;
}

void TcpServer::run(){
    // Placeholder: accept connections, read/write using attachedProtocol
    std::cout << "[Server] Running main loop..." << std::endl;
}

void TcpServer::stop() {
    std::cout << "[Server] Stopping..." << std::endl;
}

void TcpServer::attachProtocol(IProtocol* protocol){
    attachedProtocol = protocol;
}
