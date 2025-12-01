// src/server.hpp
#pragma once

#include <string>
#include <cstdint>

// Start TCP + UDP Shadowsocks server on given host/port with password.
// This is implemented in server.cpp.
int run_server(const std::string &listen_host,
               uint16_t listen_port,
               const std::string &password);

// UDP loop is exposed for completeness, but you normally just call run_server().
void udp_server_loop(uint16_t listen_port, std::string password);
