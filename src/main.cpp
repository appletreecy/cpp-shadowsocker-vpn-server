#include "server.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

static uint16_t env_to_port(const char* val, uint16_t def_port) {
    if (!val || !*val) return def_port;
    try {
        int p = std::stoi(val);
        if (p <= 0 || p > 65535) {
            std::cerr << "Invalid port in env (" << val << "), using default "
                      << def_port << "\n";
            return def_port;
        }
        return static_cast<uint16_t>(p);
    } catch (...) {
        std::cerr << "Failed to parse port from env (" << val
                  << "), using default " << def_port << "\n";
        return def_port;
    }
}

int main(int argc, char** argv) {
    // Read host/port/password from environment
    const char* host_env = std::getenv("SS_LISTEN_HOST");
    const char* port_env = std::getenv("SS_LISTEN_PORT");
    const char* pass_env = std::getenv("SS_PASSWORD");

    std::string host = host_env && *host_env ? host_env : "0.0.0.0";
    uint16_t port = env_to_port(port_env, 8388);

    if (!pass_env || !*pass_env) {
        std::cerr << "[MAIN] ERROR: SS_PASSWORD is not set or empty\n";
        return 1;
    }
    std::string password = pass_env;

    std::cerr << "[MAIN] Listening on " << host << ":" << port << "\n";
    std::cerr << "[MAIN] Using password of length " << password.size() << "\n";
    if (!password.empty()) {
        std::string preview = password.substr(0, std::min<size_t>(password.size(), 8));
        std::cerr << "[MAIN] Password preview (first up to 8 chars, not hex): '"
                  << preview << (password.size() > 8 ? "...'" : "'") << "\n";
    }

    try {
        Server server(host, port, password);
        server.run();
    } catch (const std::exception& ex) {
        std::cerr << "[MAIN] Exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[MAIN] Unknown exception in main\n";
        return 1;
    }

    return 0;
}
