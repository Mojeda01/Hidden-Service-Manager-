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

SetupStructure::SetupStructure() :
    controlPort_(9051),             // Default Tor ControlPort
    torRunning_(false),             // Tor not started yet
    torPid_(-1),                    // No PID known
    onionAddress_(),                // Empty until addOnion() assigns
    lastError_()                    // Empty until first error
{
    // Tor binary path (macOS focus)
    // on macOS, Tor is NOT installed in /usr/bin by default.
    // Homebrew puts it under:
    //  - Apple silicon (M1/M2):    /opt/homebrew/bin/tor
    //  - Intel macs:               /usr/local/bin/tor
    //
    // We default to Apple Silicon because this project targets M1.
    // NOTE: validate() / configureTor() will still confirm that the
    // path is executable and can be adjusted at runtime if needed.
    torBinaryPath_ = "/opt/homebrew/bin/tor";
    // Alternative for Intel-based Macs:
    // torBinaryPath_ = "/usr/local/bin/tor";

    // Tor runtime state & logs (project-local defaults)
    //
    // We use relative paths so that Tor writes its state into the
    // project's working directory - easy to inspect and wipe between runs.
    dataDirectory_  = "./tor_data";                                      // Tor state dir
    cookieAuthFile_ = dataDirectory_ + "/control_auth_cookie";           // Auth cookie
    logFile_        = "./tor.log";                                       // Tor runtime log

    // Constructor must stay side-effect free:
    //  - Do not validate paths here.
    //  - Do not create directories/files here.
    //  - Do not attempt to spawn Tor here.
    // Those belong in validate(), configureTor(), and startTor() respectively.
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
        out_error = "ControlPort " + std::to_string(controlPort_) + " is out of range [" + std::to_string(kMinPort) +
            ", " + std::to_string(kMaxPort) + "].";
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
        if (!dirExistsLocal(parent)) {
            out_error = "DataDirectory does not exist and its parent directory is missing: " + parent;
            return false;
        }
        if (!isWritable(parent)) {
            out_error = "DataDirectory does not exist and its parent directory is not writable: " + parent;
            return false;
        }
        if (dataDirectory_ == "/"){
            out_error = "DataDirectory cannot be '/'. Choose a project-local path.";
            return false;
        }
    }

    // CookieAuthFile parent directory (if configured)
    // Tor will create the cookie file; we only ensure its parent is viable.
    if (!cookieAuthFile_.empty()){
        const std::string parent = parentDirOf(cookieAuthFile_);
        if (!dirExistsLocal(parent)){
            out_error = "CookieAuthFile parent directory does not exist: " + parent;
            return false;
        }
        if (!isWritable(parent)) {
            out_error = "CookieAuthFile parent directory is not writable: " + parent;
            return false;
        }
    }

    // Log file parent directory (if configured)
    // Tor will create/append the log file; we only ensure its parent is viable.
    if (!logFile_.empty()){
        const std::string parent = parentDirOf(logFile_);
        if (!dirExistsLocal(parent)){
            out_error = "Log file parent directory does not exist: " + parent;
            return false;
        }
        if (!isWritable(parent)){
            out_error = "Log file parent directory is not writable: " + parent;
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
 *
 * @details
 *  This function transitions SetupStructure from a validated-but-idle state
 *  into a configured state by delegating to ConfigureTor. It performs the
 *  following steps:
 *      (i)     Assemble ConfigureTor::Paths from SetupStrcture members.
 *      (ii)    Assemble ConfigureTor::Settings with sane defaults.
 *      (iii)   Construct a ConfigureTor instance and store it in configureTor_.
 *      (iv)    Call ensureConfigured(), which:
 *          - Validates or discovers Tor binary,
 *          - Creates DataDirectory, cookie, and log dirs (0700 perms),
 *          - Writes or appends torrc with required directives,
 *          - Spawns Tor if ControlPort not already listening,
 *          - Waits for cookie file and ControlPort readiness.
 *
 *  On failure, the precise error message is propagated into out_error
 *  and cached in lastError_. On success, SetupStructure is ready for
 *  startTor() to manage runtime.
 *
 *  @param[out] out_error   Filed with human-readabel reason if configuration fails.
 *  @return true if configuration succeeded; false otherwise.
 */
bool SetupStructure::configureTor(std::string& out_error) {

    // Builds paths
    ConfigureTor::Paths paths;
    paths.tor_binary = torBinaryPath_;
    paths.data_dir = dataDirectory_;
    paths.cookie_path = cookieAuthFile_;
    paths.log_file = logFile_;

    // Decide where torrc should live.
    // project-local default: inside DataDirectory for isolation.
    paths.torrc_path = dataDirectory_ + "/torrc";

    // Build settings
    ConfigureTor::Settings settings;
    settings.control_port = controlPort_;
    settings.cookie_group_readable = true;          // dev Convenience
    settings.append_if_exists = true;               // last-wins semantics
    settings.cookie_timeout = std::chrono::seconds(10);
    settings.connect_control_timeout = std::chrono::seconds(15);
    settings.spawn_grace = std::chrono::seconds(1);

    // Construct ConfigureTor instance
    configureTor_ = std::make_unique<ConfigureTor>(paths, settings);

    // Run configuration
    if (!configureTor_->ensureConfigured(out_error)){
        lastError_ = out_error; // cache the failure reason
        return false;
    }

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
