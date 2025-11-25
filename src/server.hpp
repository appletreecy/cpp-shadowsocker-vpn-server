// src/server.hpp
#pragma once

#include <string>
#include <cstdint>

class Server {
public:
    Server(const std::string& host, uint16_t port, const std::string& password);
    void run();

private:
    std::string host_;
    uint16_t port_;
    std::string password_;
    int listen_fd_;

    void setup_listener();
    void handle_client(int client_fd);
};
