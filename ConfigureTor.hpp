#pragma once

#include <string>
#include <chrono>

/*
 * @file ConfigureTor.hpp
 * @brief Minimal Tor bootstrap/validation helper for macOS/Linux (POSIX).
 *
 * Why this exists:
 *  - Avoid brittle manual steps (guessing DataDirectory paths, creating cookies by hand, etc.).
 *  - Provide a deterministic, programmatic way to ensure Tor is configured and reachable.
 *  - Keep assumptions explicit and validated at runtime; fail fast with actionable messages.
 *
 * Scope:
 *  - Writes/patches a torrc with ControlPort + CookieAuthentication + DataDirectory + CookieAuthFile.
 *  - Ensures directories exist with correct perms.
 *  - Starts a Tor process (if ControlPort is not already open) using the given torrc.
 *  - Waits for control_auth_cookie to appear and for the ControlPort to be connectable.
 *
 * Not included:
 *  - Windows support (this is POSIX-oriented).
 *  - Advanced torrc options (HiddenServiceDir, bridge mode, etc.).
 *  - Managing a Homebrew launch daemon; we spawn our own Tor if needed.
 */

class ConfigureTor{
public:

    /*
     * @brief File/dir/binary paths used by the configurator.
     *
     * Why explicit paths:
     *  - Eliminate "magic" defaults. Make each assumption visible and overrideable.
     */

    struct Paths{
        std::string tor_binary;     // /< Path to Tor executable; empty -> auto-discover common locations.
        std::string torrc_path;     // /< Path to torrc to use/create, e.g. /opt/homebrew/etc/tor/torrc
        std::string data_dir;       // /< Tor DataDirectory, e.g. /opt/homebrew/var/lib/tor
        std::string cookie_path;    // /< CookieAuthFile path, e.g. /opt/homebrew/var/lib/tor/control_auth_cookie
        std::string log_file;       // /< Optional tor notices log (empty to disable file logging)
    };

    /*
     *  @brief operational settings for Tor and checks.
     */

    struct Settings{
        unsigned short control_port = 9051;                 // /< ControlPort to open/verify.
        std::chrono::milliseconds cookie_timeout{15000};    // /< Wait time for cookie creation.
        std::chrono::milliseconds connect_control_timeout{8000};    // /< Wait time to reach ControlPort.
        std::chrono::milliseconds spawn_grace{1500};                // Small delay after spawning Tor before checks.
        bool cookie_group_readable = true;                 // /< Emit CookieAuthFileGroupReadable 1 in torrc.
        bool append_if_exists = true;                      // /< If torrc exists, append missing directives (last wins in Tor).
    };

    /*
     * @brief Construct with explicit paths + settings.
     */
    ConfigureTor(Paths paths, Settings settings);

    /*
     * @brief Ensure Tor is configured and reachable.
     *
     * Steps:
     *  1) Ensure tor binary is discoverable.
     *  2) Ensure DataDirectory exists with 0700 perms.
     *  3) Ensure torrc contains required directives (create or append).
     *  4) If ControlPort not open, spawn tor: "tor -f <torrc_path>".
     *  5) Wait for cookie file to appear and be readable.
     *  6) Wait for ControlPort to accept TCP connections.
     *
     * @param out_error On failure, contains a human-readable reason + corrective action.
     * @return true if Tor is ready to accept ControlPort commands (cookie + TCP OK).
     */

    bool ensureConfigured(std::string& out_error);

    // Accessors
    const Paths& paths() const noexcept { return paths_; }
    const Settings& settings() const noexcept { return settings_; }

    std::string dirnameOf(const std::string& p);
    std::string dirnameof(const std::string& p);
    static bool probeTcpConnect(const std::string& host, unsigned short port, std::chrono::milliseconds timeout_ms);

private:
    // ---- Step helpers (single-responsibility; small & testable) ---
    bool ensureTorBinary(std::string& out_error);
    bool ensureDataDirectory(std::string& out_error);
    bool ensureTorrc(std::string& out_error);
    bool controlPortOpen() const;
    bool spawnTor(std::string& out_error);
    bool waitForCookie(std::string& out_error);
    bool waitForControlPort(std::string& out_error);


    // --- Utilities
    static bool fileExists(const std::string& p);
    static bool dirExists(const std::string& p);
    static bool mkDirs0700(const std::string& p, std::string& out_error);
    static bool isReadableFile(const std::string& p);
    static bool isExecutableFile(const std::string& p);

    bool spawnTor();

    Paths paths_;
    Settings settings_;

    // Last spawned PID (optional; not used to kill Tor automatically, we only ensure it starts).
    int tor_pid_ = -1;
};


























