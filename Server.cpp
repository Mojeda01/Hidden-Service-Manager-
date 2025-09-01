// Server.cpp

#include "Server.hpp"
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <sys/stat.h>   // ::stat, struct stat, S_ISREG

/*
 * @file SetupStructure.cpp
 * @brief Implements the orchestration of Tor configuration, startup,
 *        bootstrap monitoring, hidden service creation, and shutdown.
 */

SetupStructure::SetupStructure() : controlPort_(9051), torRunning_(false), torPid_(-1), onionAddress_(), lastError_()
{
    // Assign default values here - constructor should only set safe defaults.

    // Common default; adjust per system (THIS WILL NEED TO BE ADJUSTED FOR MAC AT SOME POINT).
    torBinaryPath_      = "/usr/bin/tor";

    dataDirectory_      = "./tor_data";  // Local working directory for Tor state - also check later if this compatible with MAC M1.
    cookieAuthFile_     = dataDirectory_ + "/control_auth_cookie";
    logFile_            = "./tor.log";
}

/*
 * @brief  Validate current SetupStructure configuration without side effects.
 *
 * @details Performs read-only checks to ensure the subsequent configuration pipeline can succeed:
 *      - ControlPort range sanity.
 *      - Tor binary (if explicitly provided) is executable
 *      - DataDirectory is present & writeable, or its parent is writable.
 *      - CookieAuthFile parent directory exists & is writable (if set)
 *      - Log file parent directory exists & is writable (if set)
 *
 *      This function MUST NOT create directories/files or mutate members.
 *
 * @param[out] out_error Set to precise, actionable message on failure.
 * @return true if all checks pass; false on the first fatal failure.
 *
 * @warning This does not guarantee Tor can start; it only filters out obvious configuration errors
 *          'configureTor()' performs the actual creation/patching and may still fail.
 */
bool SetupStructure::validate(std::string& out_error) const {

    // NOTE: POSIX writability checks rely on ::access(); ensure <unistd.h> is available in the TU.

    // ControlPort sanity. --- Prevents passing obviously invalid ports to later steps (torrc, socket ops).
    constexpr int kMinPort = 1;
    constexpr int kMaxPort = 65535;
    if (controlPort_ < kMinPort || controlPort_ > kMaxPort) {
        out_error = "ControlPort" + std::to_string(controlPort_) +
                    " is out of range [" + std::to_string(kMinPort) + ", " + std::to_string(kMaxPort) + "].";
        return false;
    }

    // Local helpers kept small and intention-revealing.
    auto isWritable = [](const std::string& path) -> bool {
        return ::access(path.c_str(), W_OK) == 0;
    };

    // Local dirname helper to avoid calling ConfigureTor's private API.
    // POISX-like behavior:
    //      ""                  -> "."
    //      "file"              -> "."
    //      "/file"             -> "/"
    //      "/a/b"              -> "/a"
    //      "/a/b/"             -> "/a"     ( trims trailing slashes )
    auto parentDirOf = [](const std::string& p) -> std::string {
        if (p.empty()) return ".";
        // Trim trailing slashes (but keep "/" if all slashes)
        std::size_t end = p.find_last_not_of('/');
        if (end == std::string::npos) return "/";       // path is all slashes
        // Find separator before basename
        std::size_t slash = p.rfind('/', end);
        if (slash == std::string::npos) return ".";  // no slash at all
        if (slash == 0) return "/";                  // parent is root
        return p.substr(0, slash);
    };

    // Local "is executable regular file" probe.
    // Why: ConfigureTor::isExecutable is private; we mirror its behavior
    // to keep validate() independent and non-mutating
    auto isExecutableFileLocal = [](const std::string& p) -> bool {
        struct stat st{};
        if (::stat(p.c_str(), &st) != 0) return false;
        if (!S_ISREG(st.st_mode)) return false;
        return (::access(p.c_str(), X_OK) == 0);
    };

    // Tor binary - optional strictness
    // If user explictly set a path, demand it is executable; otherwise allow later auto-discovery.
    if (!torBinaryPath_.empty()) {
        if (!isExecutableFileLocal(torBinaryPath_)) {
            out_error = "Tor binary is not an executable regular file at: " + torBinaryPath_ +
            "  (tip: on macOS/Homebrew it is often /opt/homebrew/bin/tor)";
            return false;
        }
    }

    // DataDirectory must be usable or creatable by the next stage
    // We don't create anything here; we only ensure that either the directory is writable.
    // or its parent exists and is writable so ConfigureTor can safely create it.
    if (dataDirectory_.empty()) {
        out_error = "DataDirectory path is empty; provide a writable directory path for Tor state.";
        return false;
    }

    // Local "directory exists" probe.
    // ConfigureTor::dirExists is private; we only need a lightweight check here.
    auto dirExistsLocal = [](const std::string& path) -> bool {
        struct stat st{};
        return (::stat(path.c_str(), &st) == 0) && S_ISDIR(st.st_mode);
    };

    if (dirExistsLocal(dataDirectory_)){
        if (!isWritable(dataDirectory_)) {
            out_error = "DataDirectory exists but is not writable: " + dataDirectory_;
            return false;
        }
    } else {
        const std::string parent = parentDirOf(dataDirectory_);
        if (!isWritable(parent)) {
            out_error = "DataDirectory does not exist and its parent directory is missing: " + parent;
            return false;
        }
        if (!isWritable(parent)) {
            out_error = "DataDirectory does not exist and its parent directory is not writable: " + parent;
            return false;
        }
    }

    // CookieAuthFile parent directory (if configured)
    // Tor will create the cookie file; we only ensure its parent is viable.
    if (!cookieAuthFile_.empty()){
        const std::string parent = parentDirOf(cookieAuthFile_);
        if (dirExistsLocal(parent)){
            out_error = "CookieAuthFile parent directory does not exist: " + parent;
            return false;
        }
    }

    return true;
}

/*
 * @brief Log configuration values for debugging.
 *
 * Why: Helps diagnose startup issues quickly.
 */
void SetupStructure::dumpConfiguration() const {
    std::cout << "[Setup] Tor binary: " << torBinaryPath_ << "\n"
              << "[Setup] Data dir  : " << dataDirectory_ << "\n"
              << "[Setup] Cookie    : " << cookieAuthFile_ << "\n"
              << "[Setup] Log file  : " << logFile_ << "\n"
              << "[Setup] ControlPt : " << controlPort_ << "\n";
}

/*
 * @brief Initialize and validate configuration before Tor launch.
 */
bool SetupStructure::initialize(std::string& out_error) {
    if (!validate(out_error)) {
        lastError_ = out_error;
        return false;
    }
    dumpConfiguration();
    return true;
}

/*
 * @brief Prepare torrc, directories, and other prerequisites.
 */
bool SetupStructure::configureTor(std::string& out_error) {
    return true;
}


/*
 * @brief Launch Tor and wait for bootstrap to complete.
 */
bool SetupStructure::startTor(std::string& out_error) {
    return true;
}

/*
 * @brief Set up a hidden service once Tor is live.
 */
bool SetupStructure::setupHiddenService(std::string& out_error) {
    return true;
}

/*
 * @brief Run diagnostic tests if enabled.
 */
bool SetupStructure::runDiagnostics() {
    return true;
}

/*
 * @brief Shut down Tor and cleanup resources.
 */
void SetupStructure::shutdown() {

}
