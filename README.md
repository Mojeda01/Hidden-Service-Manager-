# Hidden-Service-Manager

[![Author](https://img.shields.io/badge/site-marco--oj.no-black)](https://marco-oj.no)

Small C++20 experiment for working with Tor’s ControlPort and v3 hidden services.  
Includes helpers for configuring Tor, talking to the ControlPort, and creating/removing
hidden services, plus a stub mode for development without Tor.

## Status

Early-stage and experimental.

Core pieces exist (Tor configuration, ControlPort I/O, hidden-service manager skeleton
and basic tests), but this is not production-ready and the API may change.

## Build

Requires a C++20 compiler and Tor installed.

```bash
git clone https://github.com/Mojeda01/Hidden-Service-Manager.git
cd Hidden-Service-Manager
g++ -std=c++20 -O2 -o hsm main.cpp src/*.cpp
```

## Usage
In stub mode (no Tor needed):

```
HiddenServiceManager::Config cfg;
cfg.enable_stub_mode = true;

HiddenServiceManager mgr(cfg);
if (mgr.setupHiddenService()) {
    std::cout << mgr.onionAddress() << "\n";
}
```

For real Tore interaction, run Tor with ControlPort and CookieAuthentication enabled
and point the config fields to the correct host, port, and cookie path.
