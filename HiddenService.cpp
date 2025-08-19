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
#include <iomanip>      // std::setw, std::setfill, std::hex
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>   // close()
#include <cstring>    //
#include <thread>

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
    if (config_.enable_stub_mode) {
        std::cout << "[HiddenService] (stub) connectControl bypassed" << std::endl;
        control_fd_ = -1;
        return true;
    }

    // Resolve Tor control host + port
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;    // TCP

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(config_.tor_control_host.c_str(),
                         std::to_string(config_.tor_control_port).c_str(),
                         &hints, &res);

    if (rc != 0) {
        std::cerr << "[HiddenService] connectControl: getaddrinfo failed: " << gai_strerror(rc) << std::endl;
        return false;
    }

    int fd = -1;
    struct addrinfo* rp;
    for (rp = res; rp != nullptr; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;
        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd == -1) {
        std::cerr << "[HiddenService] connectControl: failed to connect to "
                  << config_.tor_control_host << ":" << config_.tor_control_port << std::endl;
        return false;
    }
    control_fd_ = fd;
    std::cout << "[HiddenService] connectControl: connected to "
              << config_.tor_control_host << ":" << config_.tor_control_port << std::endl;
    return true;
}

bool HiddenServiceManager::waitBootstrapped() {
    if (config_.enable_stub_mode) {
        std::cout << "[HiddenService] (stub) waitBootstrapped bypassed" << std::endl;
        return true;
    }

    if (control_fd_ < 0) {
        std::cerr << "[HiddenService] waitBootstrapped: control_fd_ < 0 (not connected)" << std::endl;
        return false;
    }

    auto start = std::chrono::steady_clock::now();
    while (true){
        std::vector<std::string> reply;
        if (!sendCommand("GETINFO status/bootstrap-phase\r\n", reply)) {
            std::cerr << "[HiddenService] waitBootstrapped: GETINFO failed" << std::endl;
            return false;
        }

        // look through reply lines for PROGRESS.
        for (const auto& line : reply){
            // Tor returns lines like: "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 ..."
            if (line.find("PROGRESS=") != std::string::npos) {
                std::size_t pos = line.find("PROGRESS=");
                if (pos != std::string::npos) {
                    int progress = std::atoi(line.c_str() + pos + 9);
                    std::cout << "[HiddenService] Bootstrap progress=" << progress << "%" << std::endl;
                    if (progress >= 100) {
                        return true; // bootstrapped!
                    }
                }
            }
        }

        // Check timeout.
        auto now = std::chrono::steady_clock::now();
        if (now - start > config_.bootstrap_timeout){
            std::cerr << "[HiddenService] waitBootstrapped: timeout ("
                      << std::chrono::duration_cast<std::chrono::milliseconds>(
                             config_.bootstrap_timeout).count()
                      << " ms)" << std::endl;
            return false;
        }

        // Sleep a little before polling again
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
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
    /*std::cout << "[HiddenService] (skeleton) addOnion virt_port=" << config_.onion_virtual_port
              << " -> " << config_.local_bind_ip << ":" << config_.local_service_port
              << " persistence=" << (config_.persistence_mode == PersistenceMode::Ephemeral ? "ephemeral" : "provided-key")
              << std::endl;*/

    // Indicate failure in skeleton so callers do not mistake this for a working implementation.
    // return false;

    // Dev convenience allow running without Tor
    if (config_.enable_stub_mode){
        service_id_= makeDeterministicStubId();
        std::cout << "[HiddenService] (Stub) addOnion -> " << onionAddress() << std::endl;
        return true;
    }

    if (control_fd_ < 0) {
        std::cerr << "[HiddenService] addOnion: control_fd_ < 0 (not connected)" << std::endl;
        return false;
    }

    // Build ADD_ONION command.
    // Why we keep it explicit here:
    //  - Easy to reason about VPORT -> local_ip:local_port mapping.
    //  - Keeps future flags (e.g., Flags=DiscardPK) obvious if you add them later.
    std::ostringstream oss;

    if (config_.persistence_mode == PersistenceMode::Ephemeral) {
        oss << "ADD_ONION NEW:ED25519-V3 "
            << "Port=" << config_.onion_virtual_port << ","
            << config_.local_bind_ip << ":" << config_.local_service_port
            << "\r\n";
    } else {    // Persistencemode::ProvidedKey
        if (config_.provided_private_key_base64.empty()) {
            std::cerr << "[HiddenService] addOnion: ProvidedKey mode but key is empty" << std::endl;
            return false;
        }
        oss << "ADD_ONION ED25519-V3:" << config_.provided_private_key_base64 << " "
            << "Port=" << config_.onion_virtual_port << ","
            << config_.local_bind_ip << ":" << config_.local_service_port
            << "\r\n";
    }

    std::vector<std::string> reply;
    if (!sendCommand(oss.str(), reply)){
        std::cerr << "[HiddenService] addOnion: ControlPort returned failure" << std::endl;
        return false;
    }

    // Parse Tor's multiple success:
    //    250-ServiceID=<id>
    //    250-PrivateKey=ED25519-V3:<base64>   (only on NEW)
    //    250 OK

    std::string out_service_id;
    std::string out_private_key;

    for (const auto& line : reply) {
        if (line.rfind("250-ServiceId=", 0) == 0) {
            out_service_id = line.substr(std::string("250-ServiceID=").size());
        } else if (line.rfind("250-PrivateKey=", 0) == 0){
            out_private_key = line.substr(std::string("250-PrivateKey=").size());
        }
    }

    if (out_service_id.empty()){
        std::cerr << "[HiddenService] addOnion: ServiceID not found in reply" << std::endl;
        return false;
    }

    service_id_ = out_service_id;
    if (config_.persistence_mode == PersistenceMode::Ephemeral && !out_private_key.empty()){
        // Store it for potential future persistence; do NOT log it.
        private_key_ = out_private_key;
    }
    std::cout << "[HiddenService] ADD_ONION created: " << onionAddress() << std::endl;
    return true;
}

bool HiddenServiceManager::delOnion(){
    // Future behavior:
    //  - Close socket/file descriptor and reset control_fd_.
    //std::cout << "[HiddenService] (skeleton) closeControl" << std::endl;
    //return false;

    // Dev convenience: in stub mode there's nothing to remove from Tor.
    if (config_.enable_stub_mode) {
        std::cout << "[HiddenService] (stub) delOnion for " << onionAddress() << std::endl;
        return true;
    }

    // If we never created a service (or it was already cleared), there's nothing to delete.
    if (service_id_.empty()) {
        std::cout << "[HiddenService] delOnion: no active ServiceID; nothing to delete." << std::endl;
        return true;
    }

    if (control_fd_ < 0) {
        std::cerr << "[HiddenService] delOnion: control_fd_ < 0 (not connected)" << std::endl;
        return false;
    }

    // Build and send DEL_ONION <ServiceID>\r\n. Tor replies with "250 OK" on success.
    std::vector<std::string> reply;
    const std::string cmd = "DEL_ONION" + service_id_ + "\r\n";
    if (!sendCommand(cmd, reply)){
        std::cerr << "[HiddenService] DEL_ONION failed for " << onionAddress() << std::endl;
        return false;
    }

    std::cout << "[HiddenService] DEL_ONION removed: " << onionAddress() << std::endl;

    // Local cleanup: clear identifiers so repeated teardown is idempotent.
    service_id_.clear();
    private_key_.clear();
    return true;

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
    const std::string cmd = "AUTHENTICATE " + cookie_hex + "\r\n";

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
    // Safety: caller must have connected first.
    if (config_.enable_stub_mode) {
        // In stub mode we don't actually talk to Tor; pretend send/recv succeeded.
        response_lines.clear();
        response_lines.emplace_back("250 OK");
        std::cout << "[HiddenService] (stub) sendCommand: " << command;
        return true;
    }

    if (control_fd_ < 0) {
        std::cerr << "[HiddenService] sendCommand: control_fd_ < 0 (not connected)" << std::endl;
        return false;
    }

    // 1) write the entire command string (caller must include trailing \r\n).
    {
        const char* data = command.data();
        std::size_t total = command.size();
        while (total > 0) {
            ssize_t n = ::write(control_fd_, data, total);
            if (n < 0) {
                if (errno == EINTR) continue; // Interrupted by signal; retry.
                std::cerr << "[HiddenService] sendCommand: write() failed (errno=" << errno << ")" << std::endl;
                return false;
            }
            data += static_cast<std::size_t>(n);
            total -= static_cast<std::size_t>(n);
        }
    }
    // 2) Read lines until Tor sends a final reply line.
    // Tor control replies:
    //   250-... (continuation)
    //   250 OK  (final success)  -> space after code means final
    //   5xx ... (final error)
    auto is_final_line = [] (const std::string& line) -> bool {
        // Need at least "250 " (4 chars). Tor also may emit "650 " for events; we still treat space as final.
        if (line.size() < 4) return false;
        // Three digits + either ' ' (final) or '-' (more lines).
        if (!std::isdigit(static_cast<unsigned char>(line[0])) ||
            !std::isdigit(static_cast<unsigned char>(line[1])) ||
            !std::isdigit(static_cast<unsigned char>(line[2])))
            return false;
        return line[3] == ' '; // space => final; '-' => continuation
    };

    auto is_success_2xx = [](const std::string& line) -> bool {
        return line.size() >= 3 && line[0] == '2';
    };

    response_lines.clear();
    std::string buffer;             // accumulate bytes across read() calls
    std::string pending_line;       // not strictly needed, but keeps intent clear

    constexpr std::size_t kBufSz = 4096;
    char io[kBufSz];

    bool got_final = false;
    bool final_success = false;

    for (;;) {
        ssize_t n = ::read(control_fd_, io, kBufSz);
        if (n < 0) {
            if (errno == EINTR) continue;
            std::cerr << "[HiddenService] sendCommand: read() failed (errno=" << errno << ")" << std::endl;
            return false;
        }
        if (n == 0) {
            // Peer closed connection unexpectedly before final line.
            std::cerr << "[HiddenService] sendCommand: EOF before final reply" << std::endl;
            return false;
        }

        buffer.append(io, static_cast<std::size_t>(n));

        // Extract complete CRLF-terminated lines.
        std::size_t start = 0;
        for (;;) {
            std::size_t pos = buffer.find("\r\n", start);
            if (pos == std::string::npos) {
                // Keep leftover (from 'start') for next read.
                buffer.erase(0, start);
                break;
            }

            std::string line = buffer.substr(start, pos - start);
            response_lines.emplace_back(line);

            // Check if this is a final line (250<space>... or 5xx<space>...).
            if (is_final_line(line)) {
                got_final = true;
                final_success = is_success_2xx(line);
            }
            start = pos + 2; // skip CRLF and continue scanning within the current buffer.
        }
        if (got_final) break; // We’ve collected the full reply.
    }
    // Optional: log last line for quick debugging (redact if needed elsewhere).
    if (!response_lines.empty()) {
        std::cout << "[HiddenService] <-- " << response_lines.back() << std::endl;
    }
    return final_success;
}

std::string HiddenServiceManager::maybeRedact (const std::string& s) const {
    return config_.redact_secrets_in_logs ? std::string{"[REDACTED]"} : s;
}

std::string HiddenServiceManager::makeDeterministicStubId() const {
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
















