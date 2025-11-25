#pragma once

#include <cstdint>
#include <string>

class Server {
public:
    Server(const std::string& host, uint16_t port, const std::string& password);
    void run();

private:
    std::string host_;
    uint16_t port_;
    std::string password_;
};
