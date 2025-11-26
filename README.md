# Hidden-Service-Manager

[![Author](https://img.shields.io/badge/site-marco--oj.no-black)](https://marco-oj.no)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue)](#build)
[![Status](https://img.shields.io/badge/status-experimental-orange)](#status)
[![Tor](https://img.shields.io/badge/tor-controlport-7D4896?logo=tor-browser&logoColor=white)](https://www.torproject.org/)

Small C++20 experiment for working with Tor’s ControlPort and v3 hidden services.  
Provides helpers for configuring Tor, talking to the ControlPort, and creating/removing
hidden services, plus a stub mode for development without Tor.

## Status

Early-stage and experimental.

Core pieces exist (Tor configuration, ControlPort I/O, hidden-service manager skeleton
and basic tests), but this is not production-ready and the API may change.

## Build

Requires:

- C++20 compiler
- Tor installed locally

```
bash
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

Real Tor interaction:

- Run Tor with `ControlPort` and `CookieAuthentication` enabled.
- Point `Config` fields at the correct control host, port, and cookie path.
