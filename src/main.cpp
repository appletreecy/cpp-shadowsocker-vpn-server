// src/main.cpp
#include "server.hpp"
#include "crypto.hpp"

#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <listen_host> <listen_port> <password>\n";
        std::cerr << "Example: " << argv[0]
                  << " 0.0.0.0 8388 my_password\n";
        return 1;
    }

    std::string host = argv[1];
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string password = argv[3];

    if (!crypto_global_init()) {
        return 1;
    }

    Server s(host, port, password);
    s.run();
    return 0;
}
