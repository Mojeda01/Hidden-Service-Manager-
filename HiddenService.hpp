// HiddenService.hpp
#pragma once
#include <cstdint>
#include <chrono>
#include <string>
#include <vector>

/*
 * @file HiddenService.hpp
 * @brief Minimal, C++17-friendly skeleton for managing a Tor onion service from inside the program.
 *
 *  * Design goals (why this shape):
 *  - Keep responsibilities narrow: this class only coordinates Tor ControlPort interactions and
 *    tracks the service lifecycle. It does not run the TCP server itself.
 *  - Make runtime behavior explicit via a Config struct (no magic numbers or globals).
 *  - Be testable: each step (connect/auth/bootstrap/add/del) is a separate method we can unit test or stub.
 *  - Allow "stub mode" so the app can run without Tor installed while we fill in low-level I/O later.
 *
 *   * What is NOT here (on purpose for the skeleton):
 *  - No socket code yet (platform choices and error handling will be added later).
 *  - No persistence or crypto; if you choose "provided-key" later, we will add secure storage then.
 */

class HiddenServiceManager{
public:
    HiddenServiceManager () = default;

    /*
     * @brief Authentication method for Tor ControlPort.
     *
     * Why enum:
     *  - Eliminates stringly-typed bugs, makes switch statements exhaustive, and documents intent.
     */

    enum class AuthMode{
        Cookie, // Tor's control.authcookie file.
        Password, // Use a hashed control password configured in torrc.
        None    // Only for special setups (generally not recommended).
    };

    /*
     * @brief Onion persistence mode.
     *
     * - Ephemeral: Tor generates a new ED25519-V3 key each run (service disappears when Tor stops).
     * - ProvidedKey: You supply a key so the .onion address stays stable across runs.
     */

    enum class PersistenceMode{
        Ephemeral,
        ProvidedKey
    };

    /*
     * @brief Configuration for creating/managing the hidden service.
     *
     * Why a single struct:
     *  - Keeps ctor parameter list readable.
     *  - Encourages consistent naming and prevents "magic numbers".
     */

    struct Config{
        // Local service the onion will forward to (your TCP server should bind here).
        std::string local_bind_ip = "127.0.0.1";
        std::uint16_t local_service_port = 5000;

        // Remote-facing virtual port exposed on <serviceID>.onion
        std::uint16_t onion_virtual_port = 12345;

        // Tor ControlPort location.
        std::string tor_control_host = "127.0.0.1";
        std::uint16_t tor_control_port = 9051;

        // Authentication settings.
        AuthMode auth_mode = AuthMode::Cookie;
        std::string tor_cookie_path = "/run/tor/control.authcookie"; // Debian/Ubuntu default.
        std::string tor_control_password; // Only used if auth_mode == Password.

        // Onion persistence.
        PersistenceMode persistence_mode = PersistenceMode::Ephemeral;
        std::string provided_private_key_base64; // Only used if persistence_mode == ProvidedKey.

        // Operational knobs.
        std::chrono::milliseconds bootstrap_timeout{15000}; // How long to wait for Tor bootstrap in real mode.
        bool redact_secrets_in_logs = true; // Avoid printing secrets by default.

        // Development helper:
        bool enable_stub_mode = true; // When true, skip real ControlPort I/O and fabricate a deterministic stub ID.
    };

    /*
     * @brief Construct with explicit configuration.
     */

    explicit HiddenServiceManager(Config cfg);


    /*
     * @brief Create/register the onion service with Tor (or stub it, if stub mode is enabled).
     *
     * Return value contract:
     *  - true  -> Manager has a usable service ID (real or stub); onionAddress() will be non-empty.
     *  - false -> A fatal error occurred (e.g., Tor unreachable in non-stub mode). Callers should abort startup.
     */
    bool setupHiddenService();

    /*
     * @brief Remove the onion service from Tor (no-op in stub mode) and release resources.
     *
     * Why explicit teardown:
     *  - Predictable lifecycles are easier to test and debug than relying on destructors alone.
     */
    bool teardownHiddenService();


    /*
     * @brief Returns the v3 service ID (base32 without ".onion") once created, else empty.
     */
    const std::string& serviceID() const noexcept { return service_id_; }

    /*
     * @brief Convenience: full address "<serviceID>.onion" or empty if not available.
     */

    std::string onionAddress() const;

    /*
     * @brief Whether the manager believes the service is usable (stub or real).
     *
     * Why:
     *  - Lets main() short-circuit early with a clear message, rather than crashing later.
     */
    bool isReady() const noexcept { return ready_; }

    /*
     * @brief End-to-end integration test hook for onion service lifecycle.
     *
     * @details This method exists primarily to support TorUnitTests. It exercises the
     *          complete hidden service setup sequence against a real Tor ControlPort:
     *          - Connect to ControlPort
     *          - Authenticate using cookie auth
     *          - Wait until Tor reports fully bootstrapped
     *          - Request creation of an ephemeral v3 onion service
     *          - Remove the service again to leave Tor in a clean state
     *          - Close the ControlPort connection
     *
     * @param out_onion On success, populated with the newly created v3 onion address.
     *
     * @return true if all steps succeeded and a syntactically valid onion address was returned,
     *         false otherwise (no partial success is considered acceptable in tests).
     *
     * @note Why this exists: unit tests need to validate the full onion lifecycle,
     *       but low-level methods (connectControl, authenticate, etc.) are private
     *       by design to enforce encapsulation. This single orchestrated method
     *       provides a safe, public way to exercise the internals without exposing
     *       them directly or breaking encapsulation.
     *
     * @warning This method should be used in test contexts only. Production code
     *          should call higher-level APIs (e.g., setupHiddenService) instead.
     */
    bool integrationTestAddOnion(std::string& out_onion);

    bool connectControl();      // Open TCP connection to ControlPort.
    bool authenticate();        // Send AUTHENTICATE based on selected mode.
    bool closeControl();        // Close ControlPort connection.
    bool waitBootstrapped();    // Poll GETINFO status/bootstrap-phase until done or timeout.

private:
    // ----- High-level steps (will hold real logic later) -----

    bool addOnion();            // Issue ADD_ONION (NEW:ED25519-V3 or ED25519-V3:<key>).
    bool delOnion();            // Issue DEL_ONION for the current service_id_.


    // ----- Low-level helpers (placeholders in skeleton) -----
    /*
     * @brief Send a single Tor control command and collect response lines.
     *
     * Why separate function:
     *  - Keeps protocol formatting/parsing in one place and makes unit testing easier.
     */
    bool sendCommand(const std::string& command, std::vector<std::string>& response_lines);

    /*
     *  @brief Utility to keep secrets out of logs based on config.
     */
    std::string maybeReact(const std::string& s) const;

    /*
     * @brief Deterministic stub service id to unblock development without Tor.
     *
     * Why deterministic:
     *  - Makes integration tests consistent; same inputs -> same fake ID.
     */
    std::string makeDeterministicStubId() const;

private:
    Config config_;

    // Connection state (opaque in the skeleton; will become a socket/FD later).
    int control_fd_ = -1;

    // Onion state.
    std::string service_id_;    //  Base32 v3 ID (no ".onion").
    std::string private_key_;   //  Only populated when Tor returns one (ephemeral NEW case).
    bool ready_ = false;        //  True after setupHiddenService() succeeds.

    // Disallow copy to avoid double teardown; allow move later if needed.
    HiddenServiceManager(const HiddenServiceManager&) = delete;
    HiddenServiceManager& operator = (const HiddenServiceManager&) = delete;

// Redacts secrets in logs; simple skeleton helper so calls compile cleanly.
private:
    std::string maybeRedact(const std::string& s) const;

    // Deterministic stub generator for onion service ID (used in stub mode).
    std::string makeDeterminsticStubId() const;
};




























