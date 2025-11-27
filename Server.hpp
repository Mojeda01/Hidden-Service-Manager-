#pragma once

#include <memory>
#include <string>
#include "Protocol.hpp"
#include "ConfigureTor.hpp"
#include "HiddenService.hpp"
#include "TorUnitTests.hpp"

/*
 * @brief Orchestrates the full startup pipeline for Tor.
 *
 * This class integrates configuration setup, Tor process startup,
 * bootstrap monitoring, hidden service creation, and optional tests.
 *
 * Design goal: this header contains the full public contract so the .cpp
 * can be implemented end-to-end without repeatedly editing the header.
 */

class SetupStructure{
public:
    SetupStructure();

    // --- Pipeline entrypoints ---
    bool initialize(std::string& out_error);    // Prepare defaults, validate paths.
    bool configureTor(std::string& out_error);  // Ensure torrc, binaries, directories.
    bool startTor(std::string& out_error);      // Launch Tor process and wait for bootstrap.
    bool setupHiddenService(std::string& out_error);    // Add onion service once Tor is running.
    bool runDiagnostics();                      // Optionally call into TorUnitTests
    void shutdown();                            // Cleanly tear down Tor + services.

    // --- Utility
    bool validate(std::string& out_error) const;    // validate current config.
    void dumpConfiguration() const;                 // Log current config for debugging.

    // --- Accessors
    const std::string& onionAddress() const { return onionAddress_; }
    const std::string& lastError() const {return lastError_; }
    bool torRunning() const { return torRunning_; }

    // --- Ports
    void setLocalServicePort(uint16_t p) { localServicePort_ = p; }
    void setOnionVirtualPort(uint16_t p) { onionVirtualPort_ = p; }

    // --- IP
    void setLocalBindIp(std::string ip) { localBindIp_ = std::move(ip); }

private:
    // --- Configuration state ---
    int controlPort_;                   // Tor control port (default: 9051).
    std::string torBinaryPath_;         // Path to Tor binary.
    std::string dataDirectory_;         // Tor's data directory.
    std::string cookieAuthFile_;        // Cookie file for authentication.
    std::string logFile_;               // path for Tor log.

    // Localservice and OnionVirtual Port
    uint16_t localServicePort_ = 5000;      // default same as now 
    uint16_t onionVirtualPort_ = 12345;     // default same as now
    
    // IP
    std::string localBindIp_ = "127.0.0.1";

    // --- Subsystem handles
    std::unique_ptr<ConfigureTor> configureTor_;        // Responsible for low-level Tor setup.
    std::unique_ptr<HiddenServiceManager> hsManager_;   // Manages onion services.

    // --- Runtime state
    bool torRunning_;       // Whether Tor has been successfully started.
    int torPid_;            // Process ID for spawned Tor (if managed directly)
    std::string onionAddress_;  // The active onion service address, if created
    std::string lastError_;     // Captures the last error string for diagnostics.
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
