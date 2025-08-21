#pragma once

#include <memory>
#include <string>
#include "Protocol.hpp"

/*
 * @brief Holds configuration parameters and setup state for starting Tor.
 *
 * This class will evolve into the central structure containing
 * paths, ports, and other parameters needed to bootstrap Tor correctly.
 */

class SetupStructure{
public:
    SetupStructure();

    // initialize default parameters
    void initializeDefaults();

    // validate current configuration
    bool validate(std::string& out_error) const;

    // log current configuration
    void dumpConfiguration() const;

private:
    // members we will need later
    int controlPort_;       // Tor control port (9051).
    std::string torBinaryPath_; // Path Tor Binary
    std::string dataDirectory_; // Directory for Tor's state
    std::string cookieAuthFile_;    // Path to cookie file for authentication.
    std::string logFile_;           // Path to Tor's log output.
};

class TcpServer{
public:
    explicit TcpServer(int port);

    // Lifecycle control
    void start();   // Bind and listen on port.
    void run();     // Accept and process incoming connections.
    void stop();    // Stop server loop and close socket.

    // Attach protocol handler (does not take ownership)
    void attachProtocol(IProtocol* protocol);

private:
    int listeningPort_;         // TCP port this server listens on.
    IProtocol* attachedProtocol_;   // Protocol handler (not owned).

};
