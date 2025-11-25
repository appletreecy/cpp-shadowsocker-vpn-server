#include "server.hpp"
#include "crypto.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool read_n(int fd, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::recv(fd, buf + got, n - got, 0);
        if (r == 0) return false; // EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return false;
        }
        got += static_cast<size_t>(r);
    }
    return true;
}

bool send_all(int fd, const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = ::send(fd, buf + sent, n - sent, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return false;
        }
        sent += static_cast<size_t>(r);
    }
    return true;
}

// Connect to host:port using getaddrinfo (IPv4/IPv6)
int connect_remote(const std::string& host, uint16_t port) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        std::cerr << "getaddrinfo(" << host << ":" << port << "): "
                  << gai_strerror(rc) << "\n";
        return -1;
    }

    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break; // success
        }
        ::close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

void client_to_remote(int client_fd, int remote_fd,
                      CryptoState& crypto,
                      NonceCounter& recv_nonce) {
    std::vector<uint8_t> inbuf;
    inbuf.reserve(4096);

    while (true) {
        uint8_t tmp[4096];
        ssize_t r = ::recv(client_fd, tmp, sizeof(tmp), 0);
        if (r == 0) {
            // client closed
            shutdown(remote_fd, SHUT_WR);
            return;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("recv(client)");
            shutdown(remote_fd, SHUT_WR);
            return;
        }

        inbuf.insert(inbuf.end(), tmp, tmp + r);

        while (!inbuf.empty()) {
            size_t consumed = 0;
            std::vector<uint8_t> plain;
            DecryptStatus st = ss_decrypt_chunk(
                crypto, recv_nonce, inbuf.data(), inbuf.size(),
                consumed, plain
            );

            if (st == DecryptStatus::NEED_MORE) {
                // Need more data from client
                if (inbuf.size() > 65536) {
                    std::cerr << "Too much encrypted data without complete chunk\n";
                    shutdown(remote_fd, SHUT_WR);
                    return;
                }
                break;
            }

            if (st == DecryptStatus::ERROR) {
                std::cerr << "Decrypt error in client_to_remote\n";
                shutdown(remote_fd, SHUT_WR);
                return;
            }

            // OK
            inbuf.erase(inbuf.begin(),
                        inbuf.begin() + static_cast<long>(consumed));

            if (!plain.empty()) {
                if (!send_all(remote_fd,
                              plain.data(), plain.size())) {
                    shutdown(remote_fd, SHUT_WR);
                    return;
                }
            }
        }
    }
}

void remote_to_client(int remote_fd, int client_fd,
                      CryptoState& crypto,
                      NonceCounter& send_nonce) {
    uint8_t buf[4096];

    while (true) {
        ssize_t r = ::recv(remote_fd, buf, sizeof(buf), 0);
        if (r == 0) {
            // remote closed
            shutdown(client_fd, SHUT_WR);
            return;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("recv(remote)");
            shutdown(client_fd, SHUT_WR);
            return;
        }

        size_t off = 0;
        while (off < static_cast<size_t>(r)) {
            uint16_t chunk_len = static_cast<uint16_t>(
                std::min<size_t>(SS_MAX_PAYLOAD,
                                 static_cast<size_t>(r) - off));

            std::vector<uint8_t> out_chunk;
            if (!ss_encrypt_chunk(crypto, send_nonce,
                                  buf + off, chunk_len, out_chunk)) {
                std::cerr << "Encrypt error in remote_to_client\n";
                shutdown(client_fd, SHUT_WR);
                return;
            }
            off += chunk_len;

            if (!send_all(client_fd,
                          out_chunk.data(), out_chunk.size())) {
                shutdown(client_fd, SHUT_WR);
                return;
            }
        }
    }
}

void handle_client(int client_fd, const std::string& password) {
    std::cerr << "[*] New client\n";

    CryptoState crypto{};
    if (!crypto_init_master(crypto, password)) {
        std::cerr << "crypto_init_master failed\n";
        ::close(client_fd);
        return;
    }

    // 1) Read salt from client
    uint8_t salt[SS_SALT_LEN];
    if (!read_n(client_fd, salt, SS_SALT_LEN)) {
        std::cerr << "Failed to read salt\n";
        ::close(client_fd);
        return;
    }

    if (!crypto_init_session_from_salt(crypto, salt, SS_SALT_LEN)) {
        std::cerr << "crypto_init_session_from_salt failed\n";
        ::close(client_fd);
        return;
    }

    NonceCounter recv_nonce{};
    NonceCounter send_nonce{};
    nonce_reset(recv_nonce);
    nonce_reset(send_nonce);

    // 2) Decrypt first AEAD chunk to get target address
    std::vector<uint8_t> inbuf;
    inbuf.reserve(4096);

    std::string target_host;
    uint16_t target_port = 0;
    std::vector<uint8_t> first_payload; // extra bytes after header

    while (true) {
        uint8_t tmp[4096];
        ssize_t r = ::recv(client_fd, tmp, sizeof(tmp), 0);
        if (r == 0) {
            std::cerr << "Client closed before sending first chunk\n";
            ::close(client_fd);
            return;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("recv(first chunk)");
            ::close(client_fd);
            return;
        }

        inbuf.insert(inbuf.end(), tmp, tmp + r);

        size_t consumed = 0;
        std::vector<uint8_t> plain;
        DecryptStatus st = ss_decrypt_chunk(
            crypto, recv_nonce,
            inbuf.data(), inbuf.size(),
            consumed, plain
        );

        if (st == DecryptStatus::NEED_MORE) {
            if (inbuf.size() > 65536) {
                std::cerr << "Too much data waiting for first chunk\n";
                ::close(client_fd);
                return;
            }
            continue;
        }

        if (st == DecryptStatus::ERROR) {
            std::cerr << "Decrypt error for first chunk\n";
            ::close(client_fd);
            return;
        }

        // OK
        inbuf.erase(inbuf.begin(),
                    inbuf.begin() + static_cast<long>(consumed));

        if (plain.empty()) {
            std::cerr << "First chunk plaintext empty\n";
            ::close(client_fd);
            return;
        }

        size_t off = 0;
        uint8_t atyp = plain[off++];

        if (atyp == 0x01) { // IPv4
            if (plain.size() < off + 4 + 2) {
                std::cerr << "Plain header too short for IPv4\n";
                ::close(client_fd);
                return;
            }
            char addr_buf[INET_ADDRSTRLEN];
            struct in_addr addr{};
            std::memcpy(&addr, &plain[off], 4);
            off += 4;
            inet_ntop(AF_INET, &addr, addr_buf, sizeof(addr_buf));
            target_host = addr_buf;
        } else if (atyp == 0x03) { // domain
            if (plain.size() < off + 1) {
                std::cerr << "Plain header too short for domain length\n";
                ::close(client_fd);
                return;
            }
            uint8_t len = plain[off++];
            if (plain.size() < off + len + 2) {
                std::cerr << "Plain header too short for domain\n";
                ::close(client_fd);
                return;
            }
            target_host.assign(
                reinterpret_cast<char*>(&plain[off]),
                reinterpret_cast<char*>(&plain[off]) + len
            );
            off += len;
        } else if (atyp == 0x04) { // IPv6
            if (plain.size() < off + 16 + 2) {
                std::cerr << "Plain header too short for IPv6\n";
                ::close(client_fd);
                return;
            }
            char addr_buf[INET6_ADDRSTRLEN];
            struct in6_addr addr6{};
            std::memcpy(&addr6, &plain[off], 16);
            off += 16;
            inet_ntop(AF_INET6, &addr6, addr_buf, sizeof(addr_buf));
            target_host = addr_buf;
        } else {
            std::cerr << "Unsupported ATYP: " << int(atyp) << "\n";
            ::close(client_fd);
            return;
        }

        if (plain.size() < off + 2) {
            std::cerr << "Plain header too short for port\n";
            ::close(client_fd);
            return;
        }

        target_port = (static_cast<uint16_t>(plain[off]) << 8) |
                      static_cast<uint16_t>(plain[off + 1]);
        off += 2;

        // Remaining bytes in this chunk are first payload to target
        if (off < plain.size()) {
            first_payload.assign(plain.begin() + static_cast<long>(off),
                                 plain.end());
        }

        std::cerr << "Target: " << target_host << ":" << target_port << "\n";
        break;
    }

    int remote_fd = connect_remote(target_host, target_port);
    if (remote_fd < 0) {
        std::cerr << "Failed to connect to remote\n";
        ::close(client_fd);
        return;
    }

    // Send first payload (if any)
    if (!first_payload.empty()) {
        if (!send_all(remote_fd,
                      first_payload.data(), first_payload.size())) {
            ::close(remote_fd);
            ::close(client_fd);
            return;
        }
    }

    // 3) Relay in both directions
    std::thread t1(client_to_remote,
                   client_fd, remote_fd,
                   std::ref(crypto),
                   std::ref(recv_nonce));
    std::thread t2(remote_to_client,
                   remote_fd, client_fd,
                   std::ref(crypto),
                   std::ref(send_nonce));

    t1.join();
    t2.join();

    ::close(remote_fd);
    ::close(client_fd);
    std::cerr << "[*] Client done\n";
}

} // namespace

Server::Server(const std::string& host, uint16_t port, const std::string& password)
    : host_(host), port_(port), password_(password) {}

void Server::run() {
    if (!crypto_global_init()) {
        std::cerr << "crypto_global_init failed\n";
        return;
    }

    int fd = ::socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return;
    }

    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    // Bind as IPv6, but allow IPv4-mapped addresses.
    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port_);
    addr.sin6_addr = in6addr_any;

    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        ::close(fd);
        return;
    }

    if (::listen(fd, 128) < 0) {
        perror("listen");
        ::close(fd);
        return;
    }

    std::cerr << "Listening on " << host_ << ":" << port_ << "\n";

    while (true) {
        struct sockaddr_storage cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        int cfd = ::accept(fd, reinterpret_cast<struct sockaddr*>(&cli_addr),
                           &cli_len);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        std::thread(handle_client, cfd, password_).detach();
    }

    ::close(fd);
}
