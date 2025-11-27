<center>
  <h1>Hidden Service Manager</h1>
</center>

[![Site](https://img.shields.io/badge/site-marco--oj.no-black)](https://marco-oj.no)
[![Language](https://img.shields.io/badge/C%2B%2B-20-blue)](#build)
[![Status](https://img.shields.io/badge/status-experimental-orange)](#status)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tor](https://img.shields.io/badge/tor-v3%20onion%20services-7D4896?logo=tor-browser&logoColor=white)](https://www.torproject.org/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](#build)

Hidden-Service-Manager is a small C++20 playground for Tor’s ControlPort and v3 onion services.  
It takes care of torrc generation, data directory setup, ControlPort bootstrap, and ephemeral hidden-service creation, so you can focus on whatever protocol you want to serve behind the onion.

Use it when you want to:

- spin up a throwaway v3 onion for a local TCP service
- experiment with Tor’s ControlPort without hand-writing commands
- run the same code in a stub mode when Tor is not available

## Build

Requires:

- C++20 compiler
- Tor installed locally

```bash
git clone https://github.com/Mojeda01/Hidden-Service-Manager.git
cd Hidden-Service-Manager
g++ -std=c++20 -O2 -o hsm main.cpp src/*.cpp
```

## Usage
In stub mode (no Tor needed):

```bash
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
