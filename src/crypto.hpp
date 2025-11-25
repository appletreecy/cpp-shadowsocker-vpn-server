// src/crypto.hpp
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// Shadowsocks AEAD (chacha20-ietf-poly1305) parameters
constexpr size_t SS_KEY_LEN    = 32;   // 256-bit key
constexpr size_t SS_SALT_LEN   = 32;   // salt size
constexpr size_t SS_NONCE_LEN  = 12;   // IETF CHACHA nonce
constexpr size_t SS_TAG_LEN    = 16;   // AEAD tag
constexpr size_t SS_MAX_PAYLOAD = 0x3FFF; // 16383 bytes per chunk

struct CryptoContext {
    bool has_master = false;
    bool has_subkey = false;

    uint8_t master_key[SS_KEY_LEN]; // derived from password (EVP_BytesToKey style)
    uint8_t subkey[SS_KEY_LEN];     // HKDF-SHA1(master_key, salt, "ss-subkey")

    uint8_t nonce[SS_NONCE_LEN];    // 96-bit little-endian counter
};

// Call once at startup (or let crypto_init_master call it implicitly)
bool crypto_global_init();

// Derive master key from password (OpenSSL EVP_BytesToKey(MD5)-like)
bool crypto_init_master(CryptoContext& ctx, const std::string& password);

// Initialize per-session subkey from salt (sent by client)
bool crypto_init_session_from_salt(CryptoContext& ctx,
                                   const uint8_t* salt,
                                   size_t salt_len);

// Reset/advance nonce counter
void crypto_reset_nonce(CryptoContext& ctx);
void crypto_increment_nonce(CryptoContext& ctx);

// Decrypt status
enum class DecryptStatus {
    OK,
    NEED_MORE,
    ERROR
};

// Encrypt one Shadowsocks AEAD TCP chunk:
// input: plaintext (<= SS_MAX_PAYLOAD)
// output: [enc_len(2+tag)][enc_payload(len+tag)]
bool ss_encrypt_chunk(CryptoContext& ctx,
                      const uint8_t* plaintext,
                      uint16_t plaintext_len,
                      std::vector<uint8_t>& out_chunk);

// Try to decrypt one chunk from `in`:
// - status = OK: plaintext_out filled, `consumed` bytes used from `in`
// - status = NEED_MORE: no plaintext, consumed=0, need more data
// - status = ERROR: auth failed or invalid format
DecryptStatus ss_decrypt_chunk(CryptoContext& ctx,
                               const uint8_t* in,
                               size_t in_len,
                               size_t& consumed,
                               std::vector<uint8_t>& plaintext_out);
