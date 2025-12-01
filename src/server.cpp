// src/server.cpp
#include "crypto.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

// ---------- small helpers ----------

static void perror_msg(const char *msg) {
    std::cerr << msg << ": " << std::strerror(errno) << "\n";
}

static bool set_nonblock(int fd) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return false;
    return true;
}

// hex for debug
static std::string hex_str(const uint8_t *data, size_t len) {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0f]);
    }
    return out;
}

// ---------- Shadowsocks addr header helpers ----------

static bool parse_ss_addr(const uint8_t *buf,
                          size_t len,
                          size_t &consumed,
                          std::string &host,
                          uint16_t &port) {
    if (len < 1) return false;
    uint8_t atyp = buf[0];
    size_t off   = 1;

    if (atyp == 0x01) { // IPv4
        if (len < off + 4 + 2) return false;
        char ip[INET_ADDRSTRLEN];
        std::memset(ip, 0, sizeof(ip));
        if (!::inet_ntop(AF_INET, buf + off, ip, sizeof(ip))) {
            return false;
        }
        host = ip;
        off += 4;
    } else if (atyp == 0x03) { // domain
        if (len < off + 1) return false;
        uint8_t dlen = buf[off++];
        if (len < off + dlen + 2) return false;
        host.assign(reinterpret_cast<const char*>(buf + off), dlen);
        off += dlen;
    } else if (atyp == 0x04) { // IPv6
        if (len < off + 16 + 2) return false;
        char ip[INET6_ADDRSTRLEN];
        std::memset(ip, 0, sizeof(ip));
        if (!::inet_ntop(AF_INET6, buf + off, ip, sizeof(ip))) {
            return false;
        }
        host = ip;
        off += 16;
    } else {
        return false;
    }

    port = static_cast<uint16_t>((buf[off] << 8) | buf[off + 1]);
    off += 2;

    consumed = off;
    return true;
}

// Used by UDP reply path as well
static bool build_ss_addr_header(const std::string &host,
                                 uint16_t port,
                                 std::vector<uint8_t> &out) {
    out.clear();
    in_addr a4{};
    in6_addr a6{};

    if (::inet_pton(AF_INET, host.c_str(), &a4) == 1) {
        out.push_back(0x01);
        const uint8_t *p = reinterpret_cast<const uint8_t*>(&a4);
        out.insert(out.end(), p, p + 4);
    } else if (::inet_pton(AF_INET6, host.c_str(), &a6) == 1) {
        out.push_back(0x04);
        const uint8_t *p = reinterpret_cast<const uint8_t*>(&a6);
        out.insert(out.end(), p, p + 16);
    } else {
        size_t dlen = host.size();
        if (dlen > 255) return false;
        out.push_back(0x03);
        out.push_back(static_cast<uint8_t>(dlen));
        out.insert(out.end(), host.begin(), host.end());
    }

    out.push_back(static_cast<uint8_t>((port >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(port & 0xff));
    return true;
}

// ---------- TCP per-client handler ----------

static void handle_client(int client_fd, const CryptoState &master_state) {
    // Per-connection crypto state
    CryptoState cs = master_state;
    cs.has_subkey  = false;

    NonceCounter nonce_c2r;
    NonceCounter nonce_r2c;
    nonce_reset(nonce_c2r);
    nonce_reset(nonce_r2c);

    // Make client non-blocking
    (void)set_nonblock(client_fd);

    // 1) Read salt (SS_SALT_LEN bytes)
    uint8_t salt[SS_SALT_LEN];
    size_t  salt_got = 0;
    std::vector<uint8_t> cbuf;  // ciphertext buffer after salt

    while (salt_got < SS_SALT_LEN) {
        uint8_t tmp[4096];
        ssize_t n = ::recv(client_fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Wait briefly
                struct pollfd pfd { client_fd, POLLIN, 0 };
                int pret = ::poll(&pfd, 1, 5000);
                if (pret <= 0) {
                    std::cerr << "[*] Salt recv timeout / error\n";
                    ::close(client_fd);
                    return;
                }
                continue;
            }
            perror_msg("[C] recv salt");
            ::close(client_fd);
            return;
        }
        if (n == 0) {
            std::cerr << "[*] Client closed before salt\n";
            ::close(client_fd);
            return;
        }

        size_t to_copy = std::min<size_t>(SS_SALT_LEN - salt_got, n);
        std::memcpy(salt + salt_got, tmp, to_copy);
        salt_got += to_copy;

        if (n > (ssize_t)to_copy) {
            // Extra bytes are already encrypted data
            cbuf.insert(cbuf.end(), tmp + to_copy, tmp + n);
        }
    }

    if (!crypto_init_session_from_salt(cs, salt, SS_SALT_LEN)) {
        std::cerr << "[CRYPTO] failed to init session from salt\n";
        ::close(client_fd);
        return;
    }

    std::cerr << "[*] New client\n";
    std::cerr << "[CRYPTO] master_key=" << hex_str(cs.master_key, SS_KEY_LEN) << "\n";
    std::cerr << "[CRYPTO] salt=" << hex_str(salt, SS_SALT_LEN) << "\n";
    std::cerr << "[CRYPTO] subkey=" << hex_str(cs.subkey, SS_KEY_LEN) << "\n";

    // 2) First decrypted chunk must contain addr header
    int remote_fd = -1;
    std::string target_host;
    uint16_t target_port = 0;

    std::vector<uint8_t> plain;
    bool first_chunk_ok = false;

    while (!first_chunk_ok) {
        size_t consumed = 0;
        DecryptStatus st =
            ss_decrypt_chunk(cs, nonce_c2r, cbuf.data(), cbuf.size(), consumed, plain);
        if (st == DecryptStatus::ERROR) {
            std::cerr << "Decrypt error for first chunk\n";
            ::close(client_fd);
            return;
        } else if (st == DecryptStatus::NEED_MORE) {
            uint8_t tmp[4096];
            ssize_t n = ::recv(client_fd, tmp, sizeof(tmp), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd pfd { client_fd, POLLIN, 0 };
                    int pret = ::poll(&pfd, 1, 5000);
                    if (pret <= 0) {
                        std::cerr << "[*] First chunk timeout\n";
                        ::close(client_fd);
                        return;
                    }
                    continue;
                }
                perror_msg("[C] recv first chunk");
                ::close(client_fd);
                return;
            }
            if (n == 0) {
                std::cerr << "[*] Client EOF before first chunk\n";
                ::close(client_fd);
                return;
            }
            cbuf.insert(cbuf.end(), tmp, tmp + n);
            continue;
        }

        // st == OK
        cbuf.erase(cbuf.begin(), cbuf.begin() + consumed);

        size_t hdr_consumed = 0;
        if (!parse_ss_addr(plain.data(), plain.size(), hdr_consumed,
                           target_host, target_port)) {
            std::cerr << "Failed to parse addr header in first chunk\n";
            ::close(client_fd);
            return;
        }

        std::cerr << "Target: " << target_host << ":" << target_port << "\n";

        // Connect to remote
        struct addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo *res = nullptr;
        std::string port_str = std::to_string(target_port);
        int gai = ::getaddrinfo(target_host.c_str(), port_str.c_str(), &hints, &res);
        if (gai != 0) {
            std::cerr << "getaddrinfo failed: " << ::gai_strerror(gai) << "\n";
            ::close(client_fd);
            return;
        }

        int sfd = -1;
        for (auto *rp = res; rp != nullptr; rp = rp->ai_next) {
            sfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd < 0) continue;
            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
                remote_fd = sfd;
                break;
            }
            ::close(sfd);
            sfd = -1;
        }
        ::freeaddrinfo(res);

        if (remote_fd < 0) {
            std::cerr << "Failed to connect remote\n";
            ::close(client_fd);
            return;
        }
        (void)set_nonblock(remote_fd);

        // Any remaining plaintext after header is first payload -> send to remote
        if (hdr_consumed < plain.size()) {
            ssize_t wn = ::send(remote_fd,
                                plain.data() + hdr_consumed,
                                plain.size() - hdr_consumed,
                                0);
            (void)wn;
        }

        first_chunk_ok = true;
    }

    // 3) Relay loop: client <-> remote
    std::vector<uint8_t> c2r_buf = cbuf; // leftover ciphertext from client (usually empty)
    std::vector<uint8_t> r2c_plain;      // plaintext from remote -> client
    cbuf.clear();

    bool client_read_closed = false;
    bool client_write_closed = false;
    bool remote_read_closed = false;
    bool remote_write_closed = false;

    const int TIMEOUT_MS = 300000; // 5 minutes idle

    while (true) {
        if ((client_read_closed || client_fd < 0) &&
            (remote_read_closed || remote_fd < 0)) {
            break;
        }

        struct pollfd fds[2];
        nfds_t nfds = 0;

        if (!client_read_closed && client_fd >= 0) {
            fds[nfds].fd     = client_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            ++nfds;
        }
        if (!remote_read_closed && remote_fd >= 0) {
            fds[nfds].fd     = remote_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            ++nfds;
        }

        int pret = ::poll(fds, nfds, TIMEOUT_MS);
        if (pret < 0) {
            if (errno == EINTR) continue;
            perror_msg("poll");
            break;
        }
        if (pret == 0) {
            std::cerr << "[*] poll timeout, closing connection\n";
            break;
        }

        nfds_t idx = 0;

        // ----- client -> remote -----
        if (!client_read_closed && client_fd >= 0) {
            short re = fds[idx].revents;
            int cfd  = fds[idx].fd;
            ++idx;

            if (re & (POLLIN | POLLERR | POLLHUP)) {
                uint8_t tmp[4096];
                ssize_t n = ::recv(cfd, tmp, sizeof(tmp), 0);
                if (n < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        // ignore transient
                    } else {
                        perror_msg("[C->R] recv");
                        break;
                    }
                } else if (n == 0) {
                    client_read_closed = true;
                    if (!remote_write_closed && remote_fd >= 0) {
                        ::shutdown(remote_fd, SHUT_WR);
                        remote_write_closed = true;
                    }
                } else {
                    c2r_buf.insert(c2r_buf.end(), tmp, tmp + n);

                    while (!c2r_buf.empty()) {
                        size_t consumed = 0;
                        std::vector<uint8_t> plain_chunk;
                        DecryptStatus st =
                            ss_decrypt_chunk(cs,
                                             nonce_c2r,
                                             c2r_buf.data(),
                                             c2r_buf.size(),
                                             consumed,
                                             plain_chunk);
                        if (st == DecryptStatus::ERROR) {
                            std::cerr << "Decrypt error in client_to_remote\n";
                            client_read_closed = true;
                            if (!remote_write_closed && remote_fd >= 0) {
                                ::shutdown(remote_fd, SHUT_WR);
                                remote_write_closed = true;
                            }
                            break;
                        } else if (st == DecryptStatus::NEED_MORE) {
                            break;
                        }

                        c2r_buf.erase(c2r_buf.begin(),
                                      c2r_buf.begin() + consumed);

                        size_t off = 0;
                        while (off < plain_chunk.size()) {
                            ssize_t wn = ::send(remote_fd,
                                                plain_chunk.data() + off,
                                                plain_chunk.size() - off,
                                                0);
                            if (wn < 0) {
                                if (errno == EINTR) continue;
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    struct pollfd wfd { remote_fd, POLLOUT, 0 };
                                    ::poll(&wfd, 1, 5000);
                                    continue;
                                }
                                perror_msg("[C->R] send");
                                remote_write_closed = true;
                                if (!client_read_closed) {
                                    ::shutdown(client_fd, SHUT_RD);
                                    client_read_closed = true;
                                }
                                off = plain_chunk.size();
                                break;
                            }
                            off += static_cast<size_t>(wn);
                        }
                    }
                }
            }
        } else {
            ++idx; // keep index in sync if client skipped
        }

        // ----- remote -> client -----
        if (!remote_read_closed && remote_fd >= 0) {
            short re = fds[idx - (client_fd >= 0 && !client_read_closed ? 0 : 1)].revents;
            int rfd  = fds[idx - (client_fd >= 0 && !client_read_closed ? 0 : 1)].fd;

            if (re & (POLLIN | POLLERR | POLLHUP)) {
                uint8_t tmp[4096];
                ssize_t n = ::recv(rfd, tmp, sizeof(tmp), 0);
                if (n < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        // ignore
                    } else {
                        perror_msg("[R->C] recv");
                        break;
                    }
                } else if (n == 0) {
                    remote_read_closed = true;
                    if (!client_write_closed && client_fd >= 0) {
                        ::shutdown(client_fd, SHUT_WR);
                        client_write_closed = true;
                    }
                } else {
                    // Encrypt this as one or more SS chunks
                    size_t off = 0;
                    while (off < static_cast<size_t>(n)) {
                        size_t chunk_len =
                            std::min(SS_MAX_PAYLOAD,
                                     static_cast<size_t>(n) - off);
                        std::vector<uint8_t> enc_chunk;
                        if (!ss_encrypt_chunk(cs,
                                              nonce_r2c,
                                              tmp + off,
                                              static_cast<uint16_t>(chunk_len),
                                              enc_chunk)) {
                            std::cerr << "[R->C] encrypt failed\n";
                            remote_read_closed = true;
                            break;
                        }

                        size_t sent_off = 0;
                        while (sent_off < enc_chunk.size()) {
                            ssize_t wn = ::send(client_fd,
                                                enc_chunk.data() + sent_off,
                                                enc_chunk.size() - sent_off,
                                                0);
                            if (wn < 0) {
                                if (errno == EINTR) continue;
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    struct pollfd wfd { client_fd, POLLOUT, 0 };
                                    ::poll(&wfd, 1, 5000);
                                    continue;
                                }
                                perror_msg("[R->C] send");
                                client_write_closed = true;
                                break;
                            }
                            sent_off += static_cast<size_t>(wn);
                        }
                        if (client_write_closed) break;
                        off += chunk_len;
                    }
                }
            }
        }
    }

    if (remote_fd >= 0) ::close(remote_fd);
    if (client_fd >= 0) ::close(client_fd);
    std::cerr << "[*] Client done\n";
}

// ---------- UDP server (Shadowsocks UDP relay) ----------
//
// Assumes crypto.cpp implements:
//   bool ss_udp_decrypt(const CryptoState& master_state,
//                       const uint8_t* packet, size_t packet_len,
//                       std::vector<uint8_t>& plain_out);
//
//   bool ss_udp_encrypt(const CryptoState& master_state,
//                       const uint8_t* plaintext, size_t plaintext_len,
//                       std::vector<uint8_t>& packet_out);
//

bool ss_udp_decrypt(const CryptoState& master_state,
                    const uint8_t* packet,
                    size_t packet_len,
                    std::vector<uint8_t>& plain_out);

bool ss_udp_encrypt(const CryptoState& master_state,
                    const uint8_t* plaintext,
                    size_t plaintext_len,
                    std::vector<uint8_t>& packet_out);

void udp_server_loop(uint16_t listen_port, std::string password) {
    CryptoState master{};
    if (!crypto_init_master(master, password)) {
        std::cerr << "[UDP] failed to init master key\n";
        return;
    }

    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror_msg("[UDP] socket");
        return;
    }

    int opt = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror_msg("[UDP] bind");
        ::close(sock);
        return;
    }

    std::cerr << "[UDP] listening on 0.0.0.0:" << listen_port << "\n";

    uint8_t buf[65535];

    while (true) {
        sockaddr_in cli{};
        socklen_t clilen = sizeof(cli);
        ssize_t n = ::recvfrom(sock, buf, sizeof(buf), 0,
                               reinterpret_cast<sockaddr*>(&cli), &clilen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror_msg("[UDP] recvfrom");
            break;
        }
        if (n == 0) continue;

        std::vector<uint8_t> plain;
        if (!ss_udp_decrypt(master, buf, static_cast<size_t>(n), plain)) {
            std::cerr << "[UDP] decrypt failed\n";
            continue;
        }

        // plain = [ADDR][PAYLOAD]
        std::string host;
        uint16_t port = 0;
        size_t addr_consumed = 0;
        if (!parse_ss_addr(plain.data(), plain.size(), addr_consumed,
                           host, port)) {
            std::cerr << "[UDP] addr parse failed\n";
            continue;
        }

        if (addr_consumed >= plain.size()) {
            continue;
        }

        const uint8_t *payload = plain.data() + addr_consumed;
        size_t payload_len     = plain.size() - addr_consumed;

        std::cerr << "[UDP] target=" << host << ":" << port
                  << " payload_len=" << payload_len << "\n";

        // Send via UDP to remote
        int rsock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (rsock < 0) {
            perror_msg("[UDP] rsock");
            continue;
        }

        sockaddr_in raddr{};
        raddr.sin_family = AF_INET;
        raddr.sin_port   = htons(port);

        if (::inet_pton(AF_INET, host.c_str(), &raddr.sin_addr) != 1) {
            // simple: do not resolve domains here to keep code compact
            ::close(rsock);
            continue;
        }

        ssize_t sn = ::sendto(rsock, payload, payload_len, 0,
                              reinterpret_cast<sockaddr*>(&raddr),
                              sizeof(raddr));
        (void)sn;

        // Wait for reply (best-effort, single packet)
        struct pollfd pfd;
        pfd.fd     = rsock;
        pfd.events = POLLIN;
        int pret   = ::poll(&pfd, 1, 1500);
        if (pret <= 0) {
            ::close(rsock);
            continue;
        }

        uint8_t rbuf[65535];
        ssize_t rn = ::recvfrom(rsock, rbuf, sizeof(rbuf), 0, nullptr, nullptr);
        ::close(rsock);
        if (rn <= 0) continue;

        // Build ADDR + payload
        std::vector<uint8_t> resp_plain;
        if (!build_ss_addr_header(host, port, resp_plain)) {
            continue;
        }
        resp_plain.insert(resp_plain.end(), rbuf, rbuf + rn);

        std::vector<uint8_t> out_packet;
        if (!ss_udp_encrypt(master,
                            resp_plain.data(),
                            resp_plain.size(),
                            out_packet)) {
            std::cerr << "[UDP] encrypt failed\n";
            continue;
        }

        ::sendto(sock,
                 out_packet.data(),
                 out_packet.size(),
                 0,
                 reinterpret_cast<sockaddr*>(&cli),
                 clilen);
    }

    ::close(sock);
}

// ---------- TCP listen loop & run_server entry ----------

static void tcp_server_loop(const std::string &listen_host,
                            uint16_t listen_port,
                            const std::string &password) {
    CryptoState master{};
    if (!crypto_init_master(master, password)) {
        std::cerr << "[TCP] failed to init master key\n";
        return;
    }

    int lsock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) {
        perror_msg("[TCP] socket");
        return;
    }

    int opt = 1;
    ::setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(listen_port);
    addr.sin_addr.s_addr =
        listen_host.empty() ? htonl(INADDR_ANY) : inet_addr(listen_host.c_str());
    if (addr.sin_addr.s_addr == INADDR_NONE && !listen_host.empty()) {
        perror_msg("[TCP] invalid listen_host");
        ::close(lsock);
        return;
    }

    if (::bind(lsock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror_msg("[TCP] bind");
        ::close(lsock);
        return;
    }

    if (::listen(lsock, 128) < 0) {
        perror_msg("[TCP] listen");
        ::close(lsock);
        return;
    }

    std::cerr << "Listening on " << listen_host << ":" << listen_port << "\n";

    while (true) {
        sockaddr_in cli{};
        socklen_t clilen = sizeof(cli);
        int cfd = ::accept(lsock, reinterpret_cast<sockaddr*>(&cli), &clilen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror_msg("[TCP] accept");
            break;
        }

        std::thread th(handle_client, cfd, master);
        th.detach();
    }

    ::close(lsock);
}

int run_server(const std::string &listen_host,
               uint16_t listen_port,
               const std::string &password) {
    std::thread udp_thr(udp_server_loop, listen_port, password);
    tcp_server_loop(listen_host, listen_port, password);
    udp_thr.join();
    return 0;
}
