#include "crypto.hpp"

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

// Simple hex helper for debugging
static std::string to_hex(const uint8_t* data, size_t len) {
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        s.push_back(hexd[b >> 4]);
        s.push_back(hexd[b & 0x0F]);
    }
    return s;
}

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

    const EVP_CIPHER* cipher = EVP_aes_256_cfb(); // key_len=32
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

    // Debug: print master key (matches Python's master_key)
    std::cerr << "[CRYPTO] master_key=" << to_hex(state.master_key, SS_KEY_LEN) << "\n";

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
    // Extract: PRK = HMAC(salt, IKM = key)
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;

    // If salt is empty, use zeros of hash length (RFC5869 recommendation)
    unsigned char zero_salt[EVP_MAX_MD_SIZE];
    if (salt == nullptr || salt_len == 0) {
        std::memset(zero_salt, 0, EVP_MD_size(EVP_sha1()));
        salt = zero_salt;
        salt_len = EVP_MD_size(EVP_sha1());
    }

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

    // Debug: show salt we received (should match Python's "salt")
    std::cerr << "[CRYPTO] salt=" << to_hex(salt, salt_len) << "\n";

    static const uint8_t info[] = { 's','s','-','s','u','b','k','e','y' };

    hkdf_sha1(state.master_key, SS_KEY_LEN,
              salt, salt_len,
              info, sizeof(info),
              state.subkey, SS_KEY_LEN);

    state.has_subkey = true;

    // Debug: show derived subkey (should match Python's "subkey")
    std::cerr << "[CRYPTO] subkey=" << to_hex(state.subkey, SS_KEY_LEN) << "\n";

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
// AEAD TCP chunk helpers
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

// FIXED: do not advance real nonce on NEED_MORE
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

    // Not enough even for encrypted length
    if (in_len < len_ct_total) {
        return DecryptStatus::NEED_MORE;
    }

    // Work on a *copy* of the nonce so that in NEED_MORE case
    // we do NOT advance the real nonce.
    NonceCounter tmp_nonce = nonce;

    uint8_t len_plain[2];
    unsigned long long len_plain_len = sizeof(len_plain);

    // Decrypt length with tmp_nonce
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            len_plain, &len_plain_len,
            nullptr,
            in, len_ct_total,
            nullptr, 0,
            tmp_nonce.nonce,
            state.subkey) != 0) {
        std::cerr << "[CRYPTO] ss_decrypt_chunk: length decrypt failed\n";
        return DecryptStatus::ERROR;
    }
    if (len_plain_len != sizeof(len_plain)) {
        std::cerr << "[CRYPTO] ss_decrypt_chunk: unexpected len_plain_len="
                  << len_plain_len << "\n";
        return DecryptStatus::ERROR;
    }
    nonce_increment(tmp_nonce);

    uint16_t len_field = (static_cast<uint16_t>(len_plain[0]) << 8) |
                         static_cast<uint16_t>(len_plain[1]);
    len_field &= 0x3FFF;
    if (len_field == 0 || len_field > SS_MAX_PAYLOAD) {
        std::cerr << "[CRYPTO] ss_decrypt_chunk: invalid len_field=" << len_field << "\n";
        return DecryptStatus::ERROR;
    }

    size_t payload_ct_len = len_field + SS_TAG_LEN;

    // Check if we have the full payload ciphertext *before* touching the real nonce
    if (in_len < len_ct_total + payload_ct_len) {
        // Not enough data for the full chunk; do NOT change real nonce.
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
            tmp_nonce.nonce,
            state.subkey) != 0) {
        std::cerr << "[CRYPTO] ss_decrypt_chunk: payload decrypt failed\n";
        return DecryptStatus::ERROR;
    }
    if (out_len != len_field) {
        std::cerr << "[CRYPTO] ss_decrypt_chunk: out_len("
                  << out_len << ") != len_field(" << len_field << ")\n";
        return DecryptStatus::ERROR;
    }
    nonce_increment(tmp_nonce);

    // Only now commit the updated nonce and consumed size
    nonce = tmp_nonce;
    consumed = len_ct_total + payload_ct_len;
    return DecryptStatus::OK;
}

// ------------------------
// UDP AEAD helpers
// ------------------------

// UDP: [salt][encrypted payload][tag]
// Payload = [ADDR][UDP data], nonce is all-zero per packet.

bool ss_udp_decrypt(const CryptoState& master_state,
                    const uint8_t* in,
                    size_t in_len,
                    std::vector<uint8_t>& plaintext_out) {
    plaintext_out.clear();

    if (!master_state.has_master) {
        std::cerr << "ss_udp_decrypt: master key not set\n";
        return false;
    }
    if (!in || in_len < SS_SALT_LEN + SS_TAG_LEN + 1) {
        // must at least have salt + tag + 1 byte payload
        return false;
    }

    const uint8_t* salt = in;
    const uint8_t* ct   = in + SS_SALT_LEN;
    size_t ct_len       = in_len - SS_SALT_LEN;

    CryptoState st{};
    std::memcpy(st.master_key, master_state.master_key, SS_KEY_LEN);
    st.has_master = true;
    if (!crypto_init_session_from_salt(st, salt, SS_SALT_LEN)) {
        return false;
    }

    NonceCounter n;
    nonce_reset(n); // all-zero nonce for UDP AEAD

    if (ct_len < SS_TAG_LEN) {
        return false;
    }

    plaintext_out.resize(ct_len - SS_TAG_LEN);
    unsigned long long out_len = plaintext_out.size();

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext_out.data(), &out_len,
            nullptr,
            ct, ct_len,
            nullptr, 0,
            n.nonce,
            st.subkey) != 0) {
        return false;
    }

    plaintext_out.resize(static_cast<size_t>(out_len));
    return true;
}

bool ss_udp_encrypt(const CryptoState& master_state,
                    const uint8_t* plaintext,
                    size_t plaintext_len,
                    std::vector<uint8_t>& out_packet) {
    out_packet.clear();

    if (!master_state.has_master) {
        std::cerr << "ss_udp_encrypt: master key not set\n";
        return false;
    }
    if (!plaintext || plaintext_len == 0) {
        return false;
    }

    uint8_t salt[SS_SALT_LEN];
    randombytes_buf(salt, sizeof(salt));

    CryptoState st{};
    std::memcpy(st.master_key, master_state.master_key, SS_KEY_LEN);
    st.has_master = true;
    if (!crypto_init_session_from_salt(st, salt, SS_SALT_LEN)) {
        return false;
    }

    NonceCounter n;
    nonce_reset(n); // all-zero nonce per UDP packet

    std::vector<uint8_t> ct(plaintext_len + SS_TAG_LEN);
    unsigned long long ct_len = ct.size();

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            plaintext, plaintext_len,
            nullptr, 0,
            nullptr,
            n.nonce,
            st.subkey) != 0) {
        return false;
    }

    ct.resize(static_cast<size_t>(ct_len));

    out_packet.reserve(SS_SALT_LEN + ct.size());
    out_packet.insert(out_packet.end(), salt, salt + SS_SALT_LEN);
    out_packet.insert(out_packet.end(), ct.begin(), ct.end());

    return true;
}
