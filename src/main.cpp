#include "server.hpp"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <listen_host> <listen_port> <password>\n";
        return 1;
    }

    std::string host = argv[1];
    std::string port_str = argv[2];
    std::string password = argv[3];

    int port_int = 0;
    try {
        port_int = std::stoi(port_str);
    } catch (const std::exception& e) {
        std::cerr << "Invalid port '" << port_str
                  << "': " << e.what() << "\n";
        return 1;
    }

    if (port_int <= 0 || port_int > 65535) {
        std::cerr << "Port out of range: " << port_int << "\n";
        return 1;
    }

    uint16_t port = static_cast<uint16_t>(port_int);

    Server s(host, port, password);
    s.run();
    return 0;
}
