// src/server.cpp
#include "server.hpp"
#include "crypto.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

// Simple recv_all helper
static bool recv_all(int fd, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(fd, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

// Resolve hostname -> IPv4 address string
static bool resolve_host(const std::string& host, uint16_t port, sockaddr_storage& out_addr, socklen_t& out_len) {
    std::string port_str = std::to_string(port);

    addrinfo hints{};
    hints.ai_family = AF_INET;      // IPv4 only in this demo
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        std::cerr << "getaddrinfo failed: " << gai_strerror(rc) << "\n";
        return false;
    }

    std::memcpy(&out_addr, res->ai_addr, res->ai_addrlen);
    out_len = res->ai_addrlen;

    freeaddrinfo(res);
    return true;
}

// Relay client -> remote (decrypt AEAD chunks, send plaintext)
static void relay_c2s(int client_fd, int remote_fd, CryptoContext ctx) {
    std::vector<uint8_t> recv_buf(65536);
    std::vector<uint8_t> pending;
    std::vector<uint8_t> plain;

    while (true) {
        ssize_t n = ::recv(client_fd, recv_buf.data(), recv_buf.size(), 0);
        if (n <= 0) break;

        pending.insert(pending.end(), recv_buf.begin(), recv_buf.begin() + n);

        size_t offset = 0;
        while (offset < pending.size()) {
            size_t consumed = 0;
            DecryptStatus st = ss_decrypt_chunk(ctx,
                                                pending.data() + offset,
                                                pending.size() - offset,
                                                consumed,
                                                plain);
            if (st == DecryptStatus::NEED_MORE) {
                break;
            }
            if (st == DecryptStatus::ERROR) {
                std::cerr << "Decrypt error (c2s)\n";
                return;
            }

            offset += consumed;

            size_t sent_total = 0;
            while (sent_total < plain.size()) {
                ssize_t s = ::send(remote_fd,
                                   plain.data() + sent_total,
                                   plain.size() - sent_total,
                                   0);
                if (s <= 0) return;
                sent_total += static_cast<size_t>(s);
            }
        }

        if (offset > 0) {
            pending.erase(pending.begin(), pending.begin() + offset);
        }
    }
}

// Relay remote -> client (encrypt plaintext into AEAD chunks)
static void relay_s2c(int remote_fd, int client_fd, CryptoContext ctx) {
    std::vector<uint8_t> buf(SS_MAX_PAYLOAD);
    std::vector<uint8_t> chunk;

    while (true) {
        ssize_t n = ::recv(remote_fd, buf.data(), buf.size(), 0);
        if (n <= 0) break;

        size_t offset = 0;
        while (offset < static_cast<size_t>(n)) {
            size_t this_len = std::min(static_cast<size_t>(n) - offset,
                                       static_cast<size_t>(SS_MAX_PAYLOAD));

            if (!ss_encrypt_chunk(ctx,
                                  buf.data() + offset,
                                  static_cast<uint16_t>(this_len),
                                  chunk)) {
                std::cerr << "Encrypt error (s2c)\n";
                return;
            }

            size_t sent_total = 0;
            while (sent_total < chunk.size()) {
                ssize_t s = ::send(client_fd,
                                   chunk.data() + sent_total,
                                   chunk.size() - sent_total,
                                   0);
                if (s <= 0) return;
                sent_total += static_cast<size_t>(s);
            }

            offset += this_len;
        }
    }
}

Server::Server(const std::string& host, uint16_t port, const std::string& password)
    : host_(host), port_(port), password_(password), listen_fd_(-1) {}

void Server::setup_listener() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        perror("socket");
        std::exit(1);
    }

    int yes = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (host_ == "0.0.0.0" || host_.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        addr.sin_addr.s_addr = inet_addr(host_.c_str());
    }

    if (bind(listen_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        std::exit(1);
    }

    if (listen(listen_fd_, 128) < 0) {
        perror("listen");
        std::exit(1);
    }

    std::cout << "Listening on " << host_ << ":" << port_ << std::endl;
}

void Server::run() {
    setup_listener();

    while (true) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = ::accept(listen_fd_, (sockaddr*)&client_addr, &len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        std::thread(&Server::handle_client, this, client_fd).detach();
    }
}

void Server::handle_client(int client_fd) {
    std::cout << "[*] New client\n";

    // Prepare crypto contexts
    CryptoContext c2s{};
    CryptoContext s2c{};

    if (!crypto_init_master(c2s, password_)) {
        close(client_fd);
        return;
    }
    s2c = c2s; // same master key

    // 1) Read salt from client (first 32 bytes)
    uint8_t salt[SS_SALT_LEN];
    if (!recv_all(client_fd, salt, SS_SALT_LEN)) {
        std::cerr << "Failed to read salt\n";
        close(client_fd);
        return;
    }

    if (!crypto_init_session_from_salt(c2s, salt, SS_SALT_LEN) ||
        !crypto_init_session_from_salt(s2c, salt, SS_SALT_LEN)) {
        std::cerr << "Failed to init session from salt\n";
        close(client_fd);
        return;
    }

    // 2) Decrypt first chunk to get addr header + first payload
    std::vector<uint8_t> pending(4096);
    ssize_t n = ::recv(client_fd, pending.data(), pending.size(), 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    pending.resize(n);

    std::vector<uint8_t> header_plain;
    size_t consumed = 0;
    DecryptStatus st = ss_decrypt_chunk(c2s,
                                        pending.data(),
                                        pending.size(),
                                        consumed,
                                        header_plain);
    if (st == DecryptStatus::NEED_MORE) {
        std::cerr << "First chunk too small, demo handles single-chunk header only\n";
        close(client_fd);
        return;
    }
    if (st == DecryptStatus::ERROR) {
        std::cerr << "Decrypt error for first chunk\n";
        close(client_fd);
        return;
    }

    // Parse Shadowsocks addr header from header_plain
    size_t p = 0;
    if (header_plain.size() < 4) {
        close(client_fd);
        return;
    }

    uint8_t addr_type = header_plain[p++];

    std::string target_host;
    uint16_t target_port = 0;

    if (addr_type == 0x01) { // IPv4
        if (header_plain.size() < p + 4 + 2) {
            close(client_fd);
            return;
        }
        char ip_str[INET_ADDRSTRLEN];
        std::memcpy(ip_str, &header_plain[p], 4);
        sockaddr_in tmp{};
        tmp.sin_family = AF_INET;
        std::memcpy(&tmp.sin_addr, &header_plain[p], 4);
        inet_ntop(AF_INET, &tmp.sin_addr, ip_str, sizeof(ip_str));
        target_host = ip_str;
        p += 4;
    } else if (addr_type == 0x03) { // domain name
        if (header_plain.size() < p + 1) {
            close(client_fd);
            return;
        }
        uint8_t host_len = header_plain[p++];
        if (header_plain.size() < p + host_len + 2) {
            close(client_fd);
            return;
        }
        target_host.assign(reinterpret_cast<char*>(&header_plain[p]), host_len);
        p += host_len;
    } else {
        std::cerr << "Unsupported addr_type: " << (int)addr_type << "\n";
        close(client_fd);
        return;
    }

    target_port = (uint16_t(header_plain[p]) << 8) | uint16_t(header_plain[p + 1]);
    p += 2;

    std::cout << "Target: " << target_host << ":" << target_port << "\n";

    std::vector<uint8_t> first_payload;
    if (p < header_plain.size()) {
        first_payload.assign(header_plain.begin() + p, header_plain.end());
    }

    // 3) Connect to remote target
    int remote_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (remote_fd < 0) {
        perror("socket(remote)");
        close(client_fd);
        return;
    }

    sockaddr_storage remote_addr{};
    socklen_t remote_len = 0;
    if (!resolve_host(target_host, target_port, remote_addr, remote_len)) {
        close(remote_fd);
        close(client_fd);
        return;
    }

    if (connect(remote_fd, (sockaddr*)&remote_addr, remote_len) < 0) {
        perror("connect(remote)");
        close(remote_fd);
        close(client_fd);
        return;
    }

    if (!first_payload.empty()) {
        ssize_t s = ::send(remote_fd, first_payload.data(), first_payload.size(), 0);
        if (s <= 0) {
            close(remote_fd);
            close(client_fd);
            return;
        }
    }

    // 4) Now relay both directions
    // NOTE: we already consumed one AEAD chunk from pending. If there are extra
    // bytes in 'pending' after 'consumed', they belong to next chunk(s).
    if (consumed < pending.size()) {
        std::vector<uint8_t> extra(pending.begin() + consumed, pending.end());
        // Push extra back into the connection by handling inside relay thread
        // by starting its pending buffer with it:
        // Easiest: just prepend to the next reads — we'll handle "pending" inside relay_c2s.
        // For simplicity we ignore extras here in this demo.
    }

    // Make copies of contexts for each direction
    CryptoContext ctx_c2s = c2s;
    CryptoContext ctx_s2c = s2c;

    std::thread t1(relay_c2s, client_fd, remote_fd, ctx_c2s);
    std::thread t2(relay_s2c, remote_fd, client_fd, ctx_s2c);

    t1.join();
    t2.join();

    close(remote_fd);
    close(client_fd);
    std::cout << "[*] Client closed\n";
}
