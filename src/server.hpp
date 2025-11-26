#pragma once

#include <cstdint>
#include <string>

class ShadowsocksServer {
public:
    ShadowsocksServer(const std::string& host,
                      uint16_t port,
                      const std::string& password);

    // Blocking run() – starts TCP listener (and optionally UDP in server.cpp)
    void run();

private:
    std::string listen_host_;
    uint16_t listen_port_;
    std::string password_;
};
