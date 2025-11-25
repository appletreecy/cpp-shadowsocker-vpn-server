#include "crypto.hpp"

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

// ------------------------
// Global init
// ------------------------

bool crypto_global_init() {
    static bool inited = false;
    if (inited) return true;
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return false;
    }
    inited = true;
    return true;
}

// ------------------------
// Master key derivation (MD5 KDF like EVP_BytesToKey)
// ------------------------

bool crypto_init_master(CryptoState& state, const std::string& password) {
    if (!crypto_global_init()) return false;
    if (password.empty()) {
        std::cerr << "Empty password\n";
        return false;
    }

    const EVP_CIPHER* cipher = EVP_aes_256_cfb(); // we only care key_len=32
    const EVP_MD* md = EVP_md5();

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    int key_len = EVP_BytesToKey(
        cipher,
        md,
        nullptr, // no salt
        reinterpret_cast<const unsigned char*>(password.data()),
        static_cast<int>(password.size()),
        1,       // iterations
        key,
        iv
    );

    if (key_len < static_cast<int>(SS_KEY_LEN)) {
        std::cerr << "EVP_BytesToKey returned short key: " << key_len << "\n";
        return false;
    }

    std::memcpy(state.master_key, key, SS_KEY_LEN);
    sodium_memzero(key, sizeof key);
    sodium_memzero(iv, sizeof iv);

    state.has_master = true;
    state.has_subkey = false;
    return true;
}

// ------------------------
// HKDF-SHA1 (RFC5869) for "ss-subkey"
// ------------------------

namespace {

void hkdf_sha1(const uint8_t* key,  size_t key_len,
               const uint8_t* salt, size_t salt_len,
               const uint8_t* info, size_t info_len,
               uint8_t* out,       size_t out_len) {
    // Extract: PRK = HMAC(salt, IKM)
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;

    HMAC(EVP_sha1(),
         salt, static_cast<int>(salt_len),
         key,  key_len,
         prk,  &prk_len);

    // Expand
    unsigned char t[EVP_MAX_MD_SIZE];
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t pos = 0;

    while (pos < out_len) {
        HMAC_CTX* ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk, prk_len, EVP_sha1(), nullptr);
        if (t_len > 0) {
            HMAC_Update(ctx, t, t_len);
        }
        if (info && info_len > 0) {
            HMAC_Update(ctx, info, info_len);
        }
        HMAC_Update(ctx, &counter, 1);

        unsigned int len = 0;
        HMAC_Final(ctx, t, &len);
        HMAC_CTX_free(ctx);

        t_len = len;
        size_t copy_len = std::min(out_len - pos, static_cast<size_t>(len));
        std::memcpy(out + pos, t, copy_len);
        pos += copy_len;
        counter++;
    }

    sodium_memzero(prk, sizeof prk);
    sodium_memzero(t, sizeof t);
}

} // anonymous namespace

bool crypto_init_session_from_salt(CryptoState& state,
                                   const uint8_t* salt,
                                   size_t salt_len) {
    if (!state.has_master) {
        std::cerr << "crypto_init_session_from_salt: master key not set\n";
        return false;
    }
    if (!salt || salt_len != SS_SALT_LEN) {
        std::cerr << "crypto_init_session_from_salt: invalid salt length "
                  << salt_len << "\n";
        return false;
    }

    static const uint8_t info[] = { 's','s','-','s','u','b','k','e','y' };

    hkdf_sha1(state.master_key, SS_KEY_LEN,
              salt, salt_len,
              info, sizeof(info),
              state.subkey, SS_KEY_LEN);

    state.has_subkey = true;
    return true;
}

// ------------------------
// Nonce helpers
// ------------------------

void nonce_reset(NonceCounter& n) {
    std::memset(n.nonce, 0, SS_NONCE_LEN);
}

void nonce_increment(NonceCounter& n) {
    // little-endian increment
    for (size_t i = 0; i < SS_NONCE_LEN; ++i) {
        if (++n.nonce[i] != 0) break;
    }
}

// ------------------------
// AEAD chunk helpers
// ------------------------

bool ss_encrypt_chunk(const CryptoState& state,
                      NonceCounter& nonce,
                      const uint8_t* plaintext,
                      uint16_t plaintext_len,
                      std::vector<uint8_t>& out_chunk) {
    if (!state.has_subkey) return false;
    if (plaintext_len == 0 || plaintext_len > SS_MAX_PAYLOAD) return false;

    out_chunk.clear();

    // 1) Encrypt length (2 bytes, big-endian, & 0x3FFF)
    uint16_t len_field = plaintext_len & 0x3FFF;
    uint8_t len_plain[2];
    len_plain[0] = static_cast<uint8_t>((len_field >> 8) & 0xFF);
    len_plain[1] = static_cast<uint8_t>(len_field & 0xFF);

    uint8_t len_ct[2 + SS_TAG_LEN];
    unsigned long long len_ct_len = sizeof(len_ct);

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            len_ct, &len_ct_len,
            len_plain, sizeof(len_plain),
            nullptr, 0,        // no AD
            nullptr,           // no secret nonce
            nonce.nonce,
            state.subkey) != 0) {
        return false;
    }
    if (len_ct_len != sizeof(len_ct)) return false;
    nonce_increment(nonce);

    // 2) Encrypt payload
    std::vector<uint8_t> payload_ct(plaintext_len + SS_TAG_LEN);
    unsigned long long payload_ct_len = payload_ct.size();

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            payload_ct.data(), &payload_ct_len,
            plaintext, plaintext_len,
            nullptr, 0,
            nullptr,
            nonce.nonce,
            state.subkey) != 0) {
        return false;
    }
    if (payload_ct_len != plaintext_len + SS_TAG_LEN) return false;
    nonce_increment(nonce);

    out_chunk.reserve(sizeof(len_ct) + payload_ct.size());
    out_chunk.insert(out_chunk.end(), len_ct, len_ct + sizeof(len_ct));
    out_chunk.insert(out_chunk.end(), payload_ct.begin(), payload_ct.end());

    return true;
}

DecryptStatus ss_decrypt_chunk(const CryptoState& state,
                               NonceCounter& nonce,
                               const uint8_t* in,
                               size_t in_len,
                               size_t& consumed,
                               std::vector<uint8_t>& plaintext_out) {
    consumed = 0;
    plaintext_out.clear();

    if (!state.has_subkey) return DecryptStatus::ERROR;

    const size_t len_ct_total = 2 + SS_TAG_LEN;
    if (in_len < len_ct_total) {
        return DecryptStatus::NEED_MORE;
    }

    uint8_t len_plain[2];
    unsigned long long len_plain_len = sizeof(len_plain);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            len_plain, &len_plain_len,
            nullptr,
            in, len_ct_total,
            nullptr, 0,
            nonce.nonce,
            state.subkey) != 0) {
        return DecryptStatus::ERROR;
    }
    if (len_plain_len != sizeof(len_plain)) {
        return DecryptStatus::ERROR;
    }
    nonce_increment(nonce);

    uint16_t len_field = (static_cast<uint16_t>(len_plain[0]) << 8) |
                         static_cast<uint16_t>(len_plain[1]);
    len_field &= 0x3FFF;
    if (len_field == 0 || len_field > SS_MAX_PAYLOAD) {
        return DecryptStatus::ERROR;
    }

    size_t payload_ct_len = len_field + SS_TAG_LEN;
    if (in_len < len_ct_total + payload_ct_len) {
        return DecryptStatus::NEED_MORE;
    }

    plaintext_out.resize(len_field);
    unsigned long long out_len = len_field;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext_out.data(), &out_len,
            nullptr,
            in + len_ct_total,
            payload_ct_len,
            nullptr, 0,
            nonce.nonce,
            state.subkey) != 0) {
        return DecryptStatus::ERROR;
    }
    if (out_len != len_field) {
        return DecryptStatus::ERROR;
    }
    nonce_increment(nonce);

    consumed = len_ct_total + payload_ct_len;
    return DecryptStatus::OK;
}
