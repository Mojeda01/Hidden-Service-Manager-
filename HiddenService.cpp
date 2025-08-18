// HiddenService.cpp
#include "HiddenService.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <functional> // std::hash

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
    }

}
