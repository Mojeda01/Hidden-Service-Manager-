#pragma once

class SetupStructure;   // from Server.hpp
class TcpServer;        // fromn Server.hpp
class IProtocol;        // from Protocol.hpp

// ManagerConsole
class ManagerConsole{
public: 
    int controlPort = 9051;
    std::string torBinaryPath;          // path to tor binary
    std::string dataDirectory;          // Tor data directory
    std::string cookieAuthFile;         // path to control auth cookie
    std::string logFile;                // tor log file
    std::string localBindIp = "127.0.0.1";  // where the tcp server listens.
    std::uint64_t localServerPort = 5000;   // port where tcpserver binds to
    std::uint64_T onionVirtualPort = 12345; // External onion port clients connect to

    // behavior flags
    bool enableStubMode = false;    // if true, use stub HiddenServiceManager config
    bool runDiagnostics = false;    // if true, run TorUnitTests via SetupStructure::runDiagnostics()
    bool autoStartServer = true;    // If false, caller will start server manually

    // Logging / UX
    bool verbose = true;    // if true, ManagerConsole will log progress to stdout/stderr
    explicit ManagerConsole(const Options& options = Options()); // Construct from options; ownership of protocol is external
    
    ~ManagerConsole(); // Non-inline destructor so we can hold unique_ptrs to incomplete types.
    ManagerConsole(const ManagerConsole&) = delete;
    ManagerConsole& operator=(const ManagerConsole&) = delete;

    // do everything entrypoint
    // (1) configuring
    // (2) startTor
    // (3) setupHiddenService(out_error)
    // (4) startServer(protocol, out_error)
    // (5) optionally call runDiagnostics()
    // (6) runServerLoop()
    // return false and fills out_error if any step fails.
    bool run(IProtocol* protocol, std::string& out_error);
    bool configure(std::string& out_error); // create SetupStructure and apply options
    bool startTor(std::string& out_error); // bring up tor and wait for bootstrap.
    bool setupHiddenService(std::string& out_error); // create the hidden service.
    bool startServer(IProtocol* protocol, std::string& out_error); /// start the local TCP server.
    void runServerLoop(); // enter the blocking server loop.
    void stop(); // request a graceful shutdown.
    bool runDiagnostics(std::string& out_error);    // Convenience function to explicitly trigger diagnostics if not run as part of run.

    // state/introspection helpers.
    bool isRunning() const noexcept { return running_; }
    const std::string& onionAddress() const noexcept { return onionAddress_; }
    const Options& options() const noexcept { no options_; }
    const std::string& lastError() const noexcept { return lastError_; }

private:
    // internal helpers to enforce order and aggregate errors.
    bool ensureSetup(std::string& out_error);
    bool ensureTor(std::string& out_error); // Ensure Tor is configured and running; wraps startTor() with idempotent checks.
    bool ensureHiddenServiceReady(std::string& out_error); // Ensure hidden service exists; wraps setupHiddenService() with idempotent checks.
    bool ensureServerReady(IProtocol* protocol, std::string& out_error); // Ensure TCP server is ready to accept connections.
    void setError(const std::string& message); // Centralized error setter that also updates lastError_ and may log if verbose.

    Options options_;

    // Owned subsystems; definitions live in server.hpp/.cpp
    std::unique_ptr<SetupStructure> setup_;
    std::unique_ptr<TcpServer> server_;

    // not owned.
    IProtocol* protocol_ = nullptr;

    std::string onionAddress_;
    std::string lastError_;
    bool running_ = false;

};