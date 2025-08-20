#include "TorUnitTests.hpp"
#include <iostream>

// Utility to print results consistently.
static void report(const std::string& name, bool result){
    std::cout << "[Test] " << name << " : " << (result ? "PASS" : "FAIL") << std::endl;
}

void TorUnitTests::runAll() {
    report("setupHiddenService (stub)", testSetupHiddenServiceStub());
}

// ---- Stub tests -----
// Each uses enable_stub_mode = true so we can validate flow without Tor

bool TorUnitTests::testSetupHiddenServiceStub() {
    HiddenServiceManager::Config cfg;
    cfg.enable_stub_mode = true;
    HiddenServiceManager mgr(cfg);
    return mgr.setupHiddenService(); // This calls everything internally.
}
