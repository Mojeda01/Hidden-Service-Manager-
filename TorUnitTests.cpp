#include "TorUnitTests.hpp"
#include <iostream>
#include <regex>        // for onion address validation

// Utility to print results consistently.
static void report(const std::string& name, bool result, const std::string& msg = ""){
    std::cout << "[Test] " << name << " : "
              << (result ? "PASS" : "FAIL");

    if (!msg.empty()) std::cout << " (" << msg << ")";
    std::cout << std::endl;
}



void TorUnitTests::runAll() {
    report("setupHiddenService (stub)", testSetupHiddenServiceStub());
    report("addOnion (real)", testAddOnionReal());
}

// ---- Stub tests -----
// Each uses enable_stub_mode = true so we can validate flow without Tor

bool TorUnitTests::testSetupHiddenServiceStub() {
    HiddenServiceManager::Config cfg;
    cfg.enable_stub_mode = true;
    HiddenServiceManager mgr(cfg);
    return mgr.setupHiddenService(); // This calls everything internally.
}

// ---- Real integration Test ----

bool TorUnitTests::testAddOnionReal(){
    HiddenServiceManager::Config cfg;
    cfg.enable_stub_mode = false;       // real Tor interaction.
    HiddenServiceManager mgr(cfg);

    std::string onion_address;
    if (!mgr.integrationTestAddOnion(onion_address)) {
        return false;   // the integration hook failed somewhere.
    }

    // validate onion address format:  v3 onions 56 base32 chars + ".onion"
    static const std::regex v3_regex("^[a-z2-7]{56}\\.onion$");
    return std::regex_match(onion_address, v3_regex);
}
