#include "server.hpp"
#include "crypto.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

static std::string getenv_or(const char* name, const std::string& def) {
    const char* v = std::getenv(name);
    if (!v || !*v) return def;
    return std::string(v);
}

static uint16_t getenv_port_or(const char* name, uint16_t def) {
    const char* v = std::getenv(name);
    if (!v || !*v) return def;
    try {
        int p = std::stoi(v);
        if (p <= 0 || p > 65535) return def;
        return static_cast<uint16_t>(p);
    } catch (...) {
        return def;
    }
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    if (!crypto_global_init()) {
        std::cerr << "crypto_global_init() failed\n";
        return 1;
    }

    // Read from env (Docker / docker-compose)
    std::string host     = getenv_or("SS_LISTEN_HOST", "0.0.0.0");
    uint16_t    port     = getenv_port_or("SS_LISTEN_PORT", 8089);
    std::string password = getenv_or("SS_PASSWORD", "");

    if (password.empty()) {
        std::cerr << "ERROR: SS_PASSWORD is not set\n";
        return 1;
    }

    std::cout << "Starting Shadowsocks C++ server on " << host << ":" << port
              << " with method chacha20-ietf-poly1305\n";

    try {
        ShadowsocksServer server(host, port, password);
        server.run();
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
