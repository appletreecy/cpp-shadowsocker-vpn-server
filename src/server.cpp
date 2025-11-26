#include "server.hpp"
#include "crypto.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

// ========= small helpers =========

static void perror_msg(const char* msg) {
    std::cerr << msg << ": " << std::strerror(errno) << "\n";
}

static bool send_all(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror_msg("send");
            return false;
        }
        if (n == 0) {
            // peer closed
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Parse SS address header from |plain| (at offset 0)
// Returns true on success, fills host, port, and header_len
static bool parse_ss_target(const std::vector<uint8_t>& plain,
                            std::string& host_out,
                            uint16_t& port_out,
                            size_t& header_len_out) {
    if (plain.empty()) return false;
    size_t idx = 0;
    uint8_t atyp = plain[idx++];

    if (atyp == 0x01) { // IPv4
        if (plain.size() < idx + 4 + 2) return false;
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr{};
        std::memcpy(&addr, &plain[idx], 4);
        idx += 4;
        if (!::inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            perror_msg("inet_ntop IPv4");
            return false;
        }
        host_out = buf;
    } else if (atyp == 0x04) { // IPv6
        if (plain.size() < idx + 16 + 2) return false;
        char buf[INET6_ADDRSTRLEN];
        struct in6_addr addr6{};
        std::memcpy(&addr6, &plain[idx], 16);
        idx += 16;
        if (!::inet_ntop(AF_INET6, &addr6, buf, sizeof(buf))) {
            perror_msg("inet_ntop IPv6");
            return false;
        }
        host_out = buf;
    } else if (atyp == 0x03) { // domain
        if (plain.size() < idx + 1) return false;
        uint8_t len = plain[idx++];
        if (plain.size() < idx + len + 2) return false;
        host_out.assign(reinterpret_cast<const char*>(&plain[idx]), len);
        idx += len;
    } else {
        std::cerr << "Unsupported ATYP=" << static_cast<int>(atyp) << "\n";
        return false;
    }

    // port
    uint16_t p = (static_cast<uint16_t>(plain[idx]) << 8) |
                 static_cast<uint16_t>(plain[idx + 1]);
    idx += 2;
    port_out = p;
    header_len_out = idx;
    return true;
}

// Build SS address header for host:port
static bool build_ss_addr_header(const std::string& host,
                                 uint16_t port,
                                 std::vector<uint8_t>& out) {
    out.clear();

    // Try IPv4
    struct in_addr addr4{};
    if (::inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        out.push_back(0x01);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&addr4);
        out.insert(out.end(), p, p + 4);
    } else {
        // Try IPv6
        struct in6_addr addr6{};
        if (::inet_pton(AF_INET6, host.c_str(), &addr6) == 1) {
            out.push_back(0x04);
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&addr6);
            out.insert(out.end(), p, p + 16);
        } else {
            // Domain
            if (host.size() > 255) {
                std::cerr << "Host name too long\n";
                return false;
            }
            out.push_back(0x03);
            out.push_back(static_cast<uint8_t>(host.size()));
            out.insert(out.end(), host.begin(), host.end());
        }
    }

    // Port
    out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(port & 0xFF));
    return true;
}

// Connect to remote host:port, return fd or -1
static int connect_remote(const std::string& host, uint16_t port) {
    struct addrinfo hints{};
    struct addrinfo* res = nullptr;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int err = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (err != 0) {
        std::cerr << "getaddrinfo(" << host << ":" << port_str
                  << "): " << gai_strerror(err) << "\n";
        return -1;
    }

    int fd = -1;
    for (auto* rp = res; rp; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // success
        }

        ::close(fd);
        fd = -1;
    }

    ::freeaddrinfo(res);
    if (fd < 0) {
        std::cerr << "Failed to connect to " << host << ":" << port << "\n";
    }
    return fd;
}

// ========= TCP per-client handler =========

static void handle_client_tcp(int client_fd, std::string password) {
    std::cout << "[*] New client\n";

    // 1) Read salt for this connection
    uint8_t salt[SS_SALT_LEN];
    size_t got = 0;
    while (got < SS_SALT_LEN) {
        ssize_t n = ::recv(client_fd, salt + got, SS_SALT_LEN - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror_msg("recv salt");
            ::close(client_fd);
            return;
        }
        if (n == 0) {
            std::cerr << "Client closed before sending salt\n";
            ::close(client_fd);
            return;
        }
        got += static_cast<size_t>(n);
    }

    // 2) Initialize crypto (master + subkey)
    CryptoState cs{};
    if (!crypto_init_master(cs, password)) {
        std::cerr << "crypto_init_master failed\n";
        ::close(client_fd);
        return;
    }
    if (!crypto_init_session_from_salt(cs, salt, SS_SALT_LEN)) {
        std::cerr << "crypto_init_session_from_salt failed\n";
        ::close(client_fd);
        return;
    }

    NonceCounter nonce_c2r{};
    NonceCounter nonce_r2c{};
    nonce_reset(nonce_c2r);
    nonce_reset(nonce_r2c);

    // 3) Read & decrypt first chunk until we have the full header
    std::vector<uint8_t> c2r_inbuf;       // encrypted from client
    std::vector<uint8_t> first_plain;     // decrypted first chunk
    bool first_chunk_done = false;

    const size_t BUF_SIZE = 4096;
    std::vector<uint8_t> tmp(BUF_SIZE);

    while (!first_chunk_done) {
        ssize_t n = ::recv(client_fd, tmp.data(), tmp.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror_msg("recv first chunk");
            ::close(client_fd);
            return;
        }
        if (n == 0) {
            std::cerr << "Client closed during first chunk\n";
            ::close(client_fd);
            return;
        }

        c2r_inbuf.insert(c2r_inbuf.end(), tmp.begin(), tmp.begin() + n);

        size_t consumed = 0;
        std::vector<uint8_t> plain;
        DecryptStatus st = ss_decrypt_chunk(cs,
                                            nonce_c2r,
                                            c2r_inbuf.data(),
                                            c2r_inbuf.size(),
                                            consumed,
                                            plain);
        if (st == DecryptStatus::NEED_MORE) {
            continue; // read more ciphertext
        } else if (st == DecryptStatus::ERROR) {
            std::cerr << "Decrypt error for first chunk\n";
            ::close(client_fd);
            return;
        } else {
            // OK
            first_plain = std::move(plain);
            c2r_inbuf.erase(c2r_inbuf.begin(),
                            c2r_inbuf.begin() + static_cast<long>(consumed));
            first_chunk_done = true;
        }
    }

    // 4) Parse target from first_plain
    std::string target_host;
    uint16_t target_port = 0;
    size_t header_len = 0;
    if (!parse_ss_target(first_plain, target_host, target_port, header_len)) {
        std::cerr << "Failed to parse target from first chunk\n";
        ::close(client_fd);
        return;
    }

    std::cout << "Target: " << target_host << ":" << target_port << "\n";

    // 5) Connect to remote
    int remote_fd = connect_remote(target_host, target_port);
    if (remote_fd < 0) {
        ::close(client_fd);
        return;
    }

    // Any leftover data in first_plain after header = payload
    if (header_len < first_plain.size()) {
        const uint8_t* p = first_plain.data() + header_len;
        size_t payload_len = first_plain.size() - header_len;
        if (payload_len > 0) {
            if (!send_all(remote_fd, p, payload_len)) {
                ::close(client_fd);
                ::close(remote_fd);
                return;
            }
        }
    }

    // 6) Full-duplex relay loop using poll()
    bool client_read_closed = false;
    bool remote_read_closed = false;

    while (!(client_read_closed && remote_read_closed)) {
        struct pollfd fds[2];
        fds[0].fd = client_fd;
        fds[0].events = client_read_closed ? 0 : POLLIN;
        fds[1].fd = remote_fd;
        fds[1].events = remote_read_closed ? 0 : POLLIN;

        int ret = ::poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror_msg("poll");
            break;
        }

        // ----- client -> remote -----
        if (!client_read_closed && (fds[0].revents & (POLLIN | POLLERR | POLLHUP))) {
            ssize_t n = ::recv(client_fd, tmp.data(), tmp.size(), 0);
            if (n < 0) {
                if (errno == EINTR) {
                    // ignore
                } else {
                    perror_msg("[C->R] recv");
                    break;
                }
            } else if (n == 0) {
                // Client closed its write side
                client_read_closed = true;
                ::shutdown(remote_fd, SHUT_WR);
            } else {
                std::cout << "[C->R] recv() got " << n
                          << " bytes, inbuf=" << (c2r_inbuf.size() + n) << "\n";

                c2r_inbuf.insert(c2r_inbuf.end(), tmp.begin(), tmp.begin() + n);

                // Decrypt as many complete chunks as available
                while (!c2r_inbuf.empty()) {
                    size_t consumed = 0;
                    std::vector<uint8_t> plain;
                    DecryptStatus st = ss_decrypt_chunk(cs,
                                                        nonce_c2r,
                                                        c2r_inbuf.data(),
                                                        c2r_inbuf.size(),
                                                        consumed,
                                                        plain);
                    if (st == DecryptStatus::NEED_MORE) {
                        break;
                    } else if (st == DecryptStatus::ERROR) {
                        std::cerr << "[C->R] decrypt error in relay\n";
                        client_read_closed = true;
                        ::shutdown(remote_fd, SHUT_WR);
                        break;
                    } else {
                        // OK
                        if (!plain.empty()) {
                            if (!send_all(remote_fd, plain.data(), plain.size())) {
                                std::cerr << "[C->R] send_all to remote failed\n";
                                client_read_closed = true;
                                remote_read_closed = true;
                                break;
                            }
                        }
                        if (consumed > 0) {
                            c2r_inbuf.erase(
                                c2r_inbuf.begin(),
                                c2r_inbuf.begin() + static_cast<long>(consumed));
                        } else {
                            // should not happen; avoid infinite loop
                            break;
                        }
                    }
                }
            }
        }

        // ----- remote -> client -----
        if (!remote_read_closed && (fds[1].revents & (POLLIN | POLLERR | POLLHUP))) {
            ssize_t n = ::recv(remote_fd, tmp.data(), tmp.size(), 0);
            if (n < 0) {
                if (errno == EINTR) {
                    // ignore
                } else {
                    perror_msg("[R->C] recv");
                    break;
                }
            } else if (n == 0) {
                // Remote closed its write side
                remote_read_closed = true;
                ::shutdown(client_fd, SHUT_WR);
            } else {
                size_t offset = 0;
                while (offset < static_cast<size_t>(n)) {
                    size_t chunk_len =
                        std::min(SS_MAX_PAYLOAD, static_cast<size_t>(n) - offset);

                    std::vector<uint8_t> enc_chunk;
                    if (!ss_encrypt_chunk(cs,
                                          nonce_r2c,
                                          tmp.data() + offset,
                                          static_cast<uint16_t>(chunk_len),
                                          enc_chunk)) {
                        std::cerr << "[R->C] encrypt failed\n";
                        client_read_closed = true;
                        remote_read_closed = true;
                        break;
                    }

                    if (!send_all(client_fd, enc_chunk.data(), enc_chunk.size())) {
                        std::cerr << "[R->C] send_all to client failed\n";
                        client_read_closed = true;
                        remote_read_closed = true;
                        break;
                    }

                    offset += chunk_len;
                }
            }
        }
    }

    ::close(client_fd);
    ::close(remote_fd);
    std::cout << "[*] Client done\n";
}

// ========= UDP relay loop =========
//
// Uses ss_udp_decrypt/ss_udp_encrypt declared in crypto.hpp
// and implemented in crypto.cpp, so NO static redefinitions here.

static void udp_server_loop(uint16_t listen_port, std::string password) {
    int sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror_msg("socket(AF_INET6, UDP)");
        return;
    }

    int on = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    int off = 0;
    ::setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(listen_port);
    addr.sin6_addr   = in6addr_any;

    if (::bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror_msg("bind UDP");
        ::close(sock);
        return;
    }

    std::cout << "[UDP] listening on 0.0.0.0:" << listen_port << "\n";

    CryptoState master_state{};
    if (!crypto_init_master(master_state, password)) {
        std::cerr << "[UDP] crypto_init_master failed\n";
        ::close(sock);
        return;
    }

    const size_t BUF_SIZE = 65535;
    std::vector<uint8_t> buf(BUF_SIZE);

    for (;;) {
        struct sockaddr_storage cliaddr{};
        socklen_t clilen = sizeof(cliaddr);
        ssize_t n = ::recvfrom(sock,
                               buf.data(),
                               buf.size(),
                               0,
                               reinterpret_cast<struct sockaddr*>(&cliaddr),
                               &clilen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror_msg("[UDP] recvfrom");
            continue;
        }

        std::cout << "[UDP] got " << n << " bytes from client\n";

        std::vector<uint8_t> addr_plus_payload;
        if (!ss_udp_decrypt(master_state,
                            buf.data(),
                            static_cast<size_t>(n),
                            addr_plus_payload)) {
            continue;
        }

        // Parse target
        std::string host;
        uint16_t port = 0;
        size_t header_len = 0;
        if (!parse_ss_target(addr_plus_payload, host, port, header_len)) {
            std::cerr << "[UDP] parse_ss_target failed\n";
            continue;
        }

        const uint8_t* payload = addr_plus_payload.data() + header_len;
        size_t payload_len     = addr_plus_payload.size() - header_len;

        std::cout << "[UDP] target=" << host << ":" << port
                  << " payload_len=" << payload_len << "\n";

        // Send payload to remote via UDP
        struct addrinfo hints{};
        struct addrinfo* res = nullptr;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        std::string port_str = std::to_string(port);
        int err = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (err != 0 || !res) {
            std::cerr << "[UDP] getaddrinfo(" << host << ":" << port_str
                      << "): " << gai_strerror(err) << "\n";
            if (res) ::freeaddrinfo(res);
            continue;
        }

        int rsock = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (rsock < 0) {
            perror_msg("[UDP] remote socket");
            ::freeaddrinfo(res);
            continue;
        }

        ssize_t sent = ::sendto(rsock,
                                payload,
                                payload_len,
                                0,
                                res->ai_addr,
                                res->ai_addrlen);
        if (sent < 0) {
            perror_msg("[UDP] sendto remote");
            ::close(rsock);
            ::freeaddrinfo(res);
            continue;
        }

        // Wait for a single response (good for DNS/most UDP)
        struct pollfd pfd;
        pfd.fd     = rsock;
        pfd.events = POLLIN;
        int pret   = ::poll(&pfd, 1, 1500); // 1.5s timeout
        if (pret <= 0) {
            ::close(rsock);
            ::freeaddrinfo(res);
            continue;
        }

        std::vector<uint8_t> rbuf(BUF_SIZE);
        ssize_t rn = ::recvfrom(rsock,
                                rbuf.data(),
                                rbuf.size(),
                                0,
                                nullptr,
                                nullptr);
        ::close(rsock);
        ::freeaddrinfo(res);

        if (rn <= 0) {
            if (rn < 0) perror_msg("[UDP] recvfrom remote");
            continue;
        }

        // Build ADDR header + payload for response
        std::vector<uint8_t> resp_plain;
        if (!build_ss_addr_header(host, port, resp_plain)) {
            continue;
        }
        resp_plain.insert(resp_plain.end(), rbuf.begin(), rbuf.begin() + rn);

        std::vector<uint8_t> out_packet;
        if (!ss_udp_encrypt(master_state,
                            resp_plain.data(),
                            resp_plain.size(),
                            out_packet)) {
            continue;
        }


        // Send back to client
        ssize_t sn = ::sendto(sock,
                              out_packet.data(),
                              out_packet.size(),
                              0,
                              reinterpret_cast<struct sockaddr*>(&cliaddr),
                              clilen);
        if (sn < 0) {
            perror_msg("[UDP] sendto client");
            continue;
        }

        std::cout << "[UDP] sent reply packet of " << sn << " bytes back to client\n";
    }

    ::close(sock);
}

// ========= ShadowsocksServer =========

ShadowsocksServer::ShadowsocksServer(const std::string& host,
                                     uint16_t port,
                                     const std::string& password)
    : listen_host_(host),
      listen_port_(port),
      password_(password) {}

void ShadowsocksServer::run() {
    // TCP listen socket
    int listen_fd = ::socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror_msg("socket(AF_INET6)");
        return;
    }

    int on = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    // Allow IPv4-mapped on IPv6 (so 0.0.0.0 works via ::)
    int off = 0;
    ::setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(listen_port_);
    addr.sin6_addr   = in6addr_any;

    if (::bind(listen_fd,
               reinterpret_cast<struct sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        perror_msg("bind");
        ::close(listen_fd);
        return;
    }

    if (::listen(listen_fd, 128) < 0) {
        perror_msg("listen");
        ::close(listen_fd);
        return;
    }

    std::cout << "Listening on 0.0.0.0:" << listen_port_ << "\n";

    // Start UDP relay on same port
    std::thread(udp_server_loop, listen_port_, password_).detach();

    for (;;) {
        struct sockaddr_storage cliaddr{};
        socklen_t clilen = sizeof(cliaddr);
        int cfd = ::accept(listen_fd,
                           reinterpret_cast<struct sockaddr*>(&cliaddr),
                           &clilen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror_msg("accept");
            continue;
        }

        // Spawn a detached thread per TCP client
        std::thread th(handle_client_tcp, cfd, password_);
        th.detach();
    }

    ::close(listen_fd);
}
