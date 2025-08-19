// HiddenService.cpp
#include "HiddenService.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <functional> // std::hash
#include <fstream>      // read Tor cookie
#include <iterator>     // istreambuf_iterator
#include <vector>       // byte buffer
#include <sstream>      // hex encode
#include <iomanip>      // std::stew, std::setfill, std::hex

// ------------------------- Public API -------------------------

HiddenServiceManager::HiddenServiceManager(Config cfg) : config_(std::move(cfg)) {}

bool HiddenServiceManager::setupHiddenService () {
    // Stub-first policy:
    // We deliberately let teams wire up the rest of the app without Tor installed.
    // Flip Config::enable_stub_mode=false once you're ready to exercise the real control flow.

    if (config_.enable_stub_mode){
        service_id_ = makeDeterministicStubId();
        ready_ = !service_id_.empty();
        std::cout << "[HiddenService] STUB mode active. Using fake address: " << onionAddress() << std::endl;
        return ready_;
    }

    // --- Real control flow (skeleton; not implemented yet) ---
    // Each step returns false with a meaningful log if it cannot proceed.

    if (!connectControl()) {
        std::cerr << "[HiddenService] Failed to connect to Tor ControlPort at " << config_.tor_control_host << ":" << config_.tor_control_port << std::endl;
        return false;
    }

    if (!authenticate()){
        std::cerr << "[HiddenService] Authentication to Tor ControlPort failed "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(config_.bootstrap_timeout).count()
                  << " ms." << std::endl;
        closeControl();
        return false;
    }

    if (!addOnion()){
        std::cerr << "[HiddenService] ADD_ONION command failed." << std::endl;
        closeControl();
        return false;
    }

    // At this point service_id_ should be populated by addOnion().
    ready_ = !service_id_.empty();

    // We intentionally keep the control connection open in the skeleton so that DEL_ONION
    // can be issued on teardown. In a real impl, you may choose to close earlier
    // if you don't need to stream events.

    std::cout << "[HiddenService] Ready at" << onionAddress() << std::endl;
    return ready_;

}

bool HiddenServiceManager::teardownHiddenService(){
    bool ok = true;

    if (config_.enable_stub_mode){
        // Nothing to tell Tor; just clear local state.
        std::cout << "[HiddenService] STUB teardown for " << onionAddress() << std::endl;
        service_id_.clear();
        private_key_.clear();
        ready_ = false;
        return true;
    }

    // Real mode: attempt DEL_ONION then close connection.
    if (!service_id_.empty()){
        ok = delOnion();
        if (!ok){
            std::cerr << "[HiddenService] Warning: DEL_ONION failed for " << onionAddress() << std::endl;
        }
    }

    if (!closeControl()){
        std::cerr << "[HiddenService] Warning: failed to close ControlPort connection cleanly." << std::endl;
        ok = false;
    }

    service_id_.clear();
    private_key_.clear();
    ready_ = false;
    return ok;
}

std::string HiddenServiceManager::onionAddress() const {
    if (service_id_.empty()) return {};
    return service_id_ + ".onion";
}

// ------------------------- Private: high-level steps (skeleton stubs) -------------------------

bool HiddenServiceManager::connectControl() {
    // Skeleton rationale:
    //  - We don't pick a socket library yet. This method will open a TCP connection to
    //    config_.tor_control_host:config_.tor_control_port and set control_fd_.
    //  - Returning false keeps the calling flow simple and explicit.

    std::cout << "[HiddenService] (skeleton) connectControl -> " << config_.tor_control_host << ":" << config_.tor_control_port << std::endl;
    control_fd_ = -1; // Not implemented yet.
    return false;
}

bool HiddenServiceManager::waitBootstrapped() {
    // Future behavior:
    //  - Poll GETINFO status/bootstrap-phase until progress=100 or timeout.
    //  - This avoids racing against Tor startup on cold boots.

    std::cout << "[HiddenService] (skeleton) waitBootstrapped up to"
              << std::chrono::duration_cast<std::chrono::milliseconds>(config_.bootstrap_timeout).count()
              << " ms." << std::endl;
    return false;
}

bool HiddenServiceManager::addOnion() {
    // Future behavior:
    //  - If Ephemeral: "ADD_ONION NEW:ED25519-V3 Port=<virt>,<local_ip>:<local_port>"
    //    Expect:
    //      250-ServiceID=<id>
    //      250-PrivateKey=ED25519-V3:<base64>
    //      250 OK
    //    Save <id> and optionally <base64> (securely) if you want to persist later.
    //  - If ProvidedKey: "ADD_ONION ED25519-V3:<base64> Port=..."
    //    Expect ServiceID only; key is already known.
    std::cout << "[HiddenService] (skeleton) addOnion virt_port=" << config_.onion_virtual_port
              << " -> " << config_.local_bind_ip << ":" << config_.local_service_port
              << " persistence=" << (config_.persistence_mode == PersistenceMode::Ephemeral ? "ephemeral" : "provided-key")
              << std::endl;

    // Indicate failure in skeleton so callers do not mistake this for a working implementation.
    return false;
}

bool HiddenServiceManager::delOnion(){
    // Future behavior:
    //  - Close socket/file descriptor and reset control_fd_.
    std::cout << "[HiddenService] (skeleton) closeControl" << std::endl;
    return false;
}

bool HiddenServiceManager::closeControl() {
    // Future behavior:
    //  - Close socket/file descriptor and reset control_fd_.
    std::cout << "[HiddenService] (skeleton) closeControl" << std::endl;
    control_fd_ = -1;
    return true;
}

bool HiddenServiceManager::authenticate() {
    // Stub bypass: keep the rest of the app runnable until ControlPort I/O lands.
    if (config_.enable_stub_mode) {
        std::cout << "[HiddenService] (stub) authenticate: Cookie mode bypassed" << std::endl;
        return true;
    }

    // Only cookie mode is implemented in this step.
    if (config_.auth_mode != AuthMode::Cookie){
        std::cerr << "[HiddenService] authenticate: only Cookie mode is implemented in this step. "
                  << "Selected mode is not Cookie." << std::endl;
        return false;
    }

    // Precondition (design intent) : connectControl() should have successfully opened control_fd_
    // before we try to authenticate. We don't enforce it here to keep concerns separated, but
    // a defensive check can help during bring‑up.

    if (control_fd_ < 0) {
        std::cerr << "[HiddenService] authenticate: ControlPort not connected (control_fd_ < 0)." << std::endl;
        return false;
    }

    // 1) Read Tor's control.authcookie (binary) from config_.tor_cookie_path
    const std::string cookie_path = config_.tor_cookie_path;
    std::ifstream in(cookie_path, std::ios::binary);
    if (!in) {
        std::cerr << "[HiddenService] authenticate: failed to open cookie file at "
                  << maybeRedact(cookie_path) << std::endl;
        return false;
    }

    std::vector<unsigned char> cookie_bytes (
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );

    if (cookie_bytes.empty()) {
        std::cerr << "[HiddenService] authenticate: cookie file is empty at "
                  << maybeRedact(cookie_path) << std::endl;
        return false;
    }

    // 2) Hex-encode the cookie bytes for Tor's AUTHENTICATE command.
    // Tor accepts hex (case-insensitive). We emit uppercase for readability.
    auto hexEncode = [](const std::vector<unsigned char>& bytes) -> std::string {
        std::ostringstream oss;
        oss << std::uppercase << std::hex << std::setfill('0');
        for (unsigned char b : bytes){
            oss << std::setw(2) << static_cast<int>(b);
        }
        return oss.str();
    };

    const std::string cookie_hex = hexEncode(cookie_bytes);


    // 3) Send AUTHENTICATE <hex>\r\n over the ControlPort and expect a 250 OK.
    // NOTE: sendCommand is still a thin stub right now. This function wires the command
    // and success criteria so when sendCommand is implemented, this path becomes “real”
    // without changing authenticate().
    std::vector<std::string> reply;
    const std::string cmd = "AUTHENTICATE" + cookie_hex + "\r\n";

    if (!sendCommand(cmd, reply)) {
        std::cerr << "[HiddenService] authenticate: sendCommand failed (no response)." << std::endl;
        return false;
    }

    // Parse for a success line. Tor replies with "250 OK" on success.
    bool ok = false;
    for (const std::string& line  : reply) {
        // Defensive trim not added to avoid extra utilities; ControlPort lines typically end with CRLF.
        if (line.rfind("250", 0) == 0) {    // starts with "250"
            ok = true;
            break;
        }
        if (line.rfind("5",0) == 0) { // any 5xx indicates an error
            ok = false;
            break;
        }
    }

    if (!ok){
        std::cerr << "[HiddenService] authenticate: Tor did not return 250 OK (got "
                  << (reply.empty() ? "no lines" : "non‑success response") << ")." << std::endl;
        return false;
    }

    std::cout << "[HiddenService] authenticate: Cookie authentication succeeded." << std::endl;
    return true;
}

// ------------------------- Private: low-level helpers (skeleton stubs) -------------------------

bool HiddenServiceManager::sendCommand(const std::string& command, std::vector<std::string>& response_lines) {
    // Future behavior:
    //  - Write the Tor control command + CRLF.
    //  - Read lines until a "250 " or "5xx " final line.
    //  - Populate response_lines with all lines (for parsing in callers).
    (void) command;
    response_lines.clear();
    std::cout << "[HiddenService] (skeleton) sendCommand: " << command << std::endl;
    return false;
}

std::string HiddenServiceManager::maybeRedact (const std::string& s) const {
    return config_.redact_secrets_in_logs ? std::string{"[REDACTED]"} : s;
}

std::string HiddenServiceManager::makeDeterminsticStubId() const {
    // Why this approach:
    //  - We want a repeatable placeholder address that depends on config knobs,
    //    without trying to mimic a real 56-char v3 ID (which could mislead testing).
    //  - We include the local port and virtual port so different configs yield different stub IDs.

    std::ostringstream oss;
    std::string key = config_.local_bind_ip + ":" + std::to_string(config_.local_service_port) + "->" + std::to_string(config_.onion_virtual_port);
    std::size_t h = std::hash<std::string>{}(key);
    // Produce a short, readable token (not a real onion ID).
    oss << "stub-" << std::hex << std::setw(8) << std::setfill('0') << (static_cast<unsigned>(h) & 0xFFFFFFFFu);
    return oss.str();   // e.g., "stub-deadbeef".
}
















