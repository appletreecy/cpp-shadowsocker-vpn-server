#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

constexpr size_t SS_KEY_LEN     = 32;      // chacha20-ietf-poly1305 key
constexpr size_t SS_SALT_LEN    = 32;      // recommended salt length
constexpr size_t SS_NONCE_LEN   = 12;      // IETF nonce size
constexpr size_t SS_TAG_LEN     = 16;      // chacha20poly1305 tag
constexpr size_t SS_MAX_PAYLOAD = 0x3FFF;  // per-chunk max payload (TCP)

enum class DecryptStatus {
    OK,
    NEED_MORE,
    ERROR
};

struct CryptoState {
    uint8_t master_key[SS_KEY_LEN];
    uint8_t subkey[SS_KEY_LEN];
    bool has_master = false;
    bool has_subkey = false;
};

struct NonceCounter {
    uint8_t nonce[SS_NONCE_LEN];
};

// Global init (libsodium)
bool crypto_global_init();

// Derive master key from password using EVP_BytesToKey(MD5)
bool crypto_init_master(CryptoState& state, const std::string& password);

// Derive subkey from master key and salt using HKDF-SHA1("ss-subkey")
bool crypto_init_session_from_salt(CryptoState& state,
                                   const uint8_t* salt,
                                   size_t salt_len);

// Nonce helpers
void nonce_reset(NonceCounter& n);
void nonce_increment(NonceCounter& n);

// AEAD TCP chunk encrypt: [len+tag][payload+tag]
bool ss_encrypt_chunk(const CryptoState& state,
                      NonceCounter& nonce,
                      const uint8_t* plaintext,
                      uint16_t plaintext_len,
                      std::vector<uint8_t>& out_chunk);

DecryptStatus ss_decrypt_chunk(const CryptoState& state,
                               NonceCounter& nonce,
                               const uint8_t* in,
                               size_t in_len,
                               size_t& consumed,
                               std::vector<uint8_t>& plaintext_out);

// ---------- UDP AEAD helpers ----------
// UDP packet format: [salt][encrypted payload+tag]
// Payload = [ADDR][UDP data], nonce is all-zero per packet.

bool ss_udp_decrypt(const CryptoState& master_state,
                    const uint8_t* in,
                    size_t in_len,
                    std::vector<uint8_t>& plaintext_out);

bool ss_udp_encrypt(const CryptoState& master_state,
                    const uint8_t* plaintext,
                    size_t plaintext_len,
                    std::vector<uint8_t>& out_packet);
