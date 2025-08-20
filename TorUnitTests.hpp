#pragma once

#include "HiddenService.hpp"

// A minimal unit test harness for exercising Tor hidden service lifecycle.
// Keeps everything header-only declarations so test remain organized.

class TorUnitTests{
public:
    // Run all available tests
    static void runAll();
private:
    // Individual tests, each returns true if passed, false otherwise.
    static bool testConnectControlStub();
    static bool testAuthenticateStub();
    static bool testWaitBootstrappedStub();
    static bool testAddOnionStub();
    static bool testDelOnionStub();
    static bool testCloseControlStub();

    // new public-flow test
    static bool testSetupHiddenServiceStub();

    // Future: real Tor integration tests.
    static bool testConnectControlReal();
    static bool testAuthenticateReal();
    static bool testAddOnionReal();
};
