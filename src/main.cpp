// src/main.cpp
#include "crypto.hpp"
#include "server.hpp"

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>

static std::string get_env_str(const char *name,
                               const std::string &def_val) {
    const char *v = std::getenv(name);
    if (!v || !*v) return def_val;
    return std::string(v);
}

static uint16_t get_env_port(const char *name, uint16_t def_val) {
    const char *v = std::getenv(name);
    if (!v || !*v) return def_val;
    long p = std::strtol(v, nullptr, 10);
    if (p <= 0 || p > 65535) return def_val;
    return static_cast<uint16_t>(p);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    if (!crypto_global_init()) {
        std::cerr << "[FATAL] crypto_global_init() failed\n";
        return 1;
    }

    // Environment variables (same as before):
    //   SS_LISTEN_HOST  (default: "0.0.0.0")
    //   SS_LISTEN_PORT  (default: 8089)
    //   SS_PASSWORD     (no default; must be set in production)
    std::string host = get_env_str("SS_LISTEN_HOST", "0.0.0.0");
    uint16_t port    = get_env_port("SS_LISTEN_PORT", 8089);
    std::string password = get_env_str("SS_PASSWORD", "");

    if (password.empty()) {
        std::cerr << "[FATAL] SS_PASSWORD is not set\n";
        return 1;
    }

    std::cerr << "[CONFIG] host=" << host
              << " port=" << port
              << " password_len=" << password.size() << "\n";

    return run_server(host, port, password);
}
