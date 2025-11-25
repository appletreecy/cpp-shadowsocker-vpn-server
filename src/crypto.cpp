// src/crypto.cpp
#include "crypto.hpp"

#include <sodium.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <algorithm>

// ==========================================================
// MD5 (for EVP_BytesToKey)  -- same as before
// ==========================================================

struct MD5_CTX {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

static void MD5_Transform(uint32_t state[4], const uint8_t block[64]);

static void MD5_Init(MD5_CTX* context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

static void MD5_Update(MD5_CTX* context, const uint8_t* input, size_t inputLen) {
    size_t i = 0;
    size_t index = (context->count[0] >> 3) & 0x3F;
    if ((context->count[0] += (inputLen << 3)) < (inputLen << 3)) {
        context->count[1]++;
    }
    context->count[1] += (inputLen >> 29);

    size_t partLen = 64 - index;

    if (inputLen >= partLen) {
        std::memcpy(&context->buffer[index], input, partLen);
        MD5_Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64) {
            MD5_Transform(context->state, &input[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    std::memcpy(&context->buffer[index], &input[i], inputLen - i);
}

static void MD5_Encode(uint8_t* output, const uint32_t* input, size_t len) {
    for (size_t i = 0, j = 0; j < len; ++i, j += 4) {
        output[j]   = (uint8_t)(input[i] & 0xff);
        output[j+1] = (uint8_t)((input[i] >> 8) & 0xff);
        output[j+2] = (uint8_t)((input[i] >> 16) & 0xff);
        output[j+3] = (uint8_t)((input[i] >> 24) & 0xff);
    }
}

static void MD5_Final(uint8_t digest[16], MD5_CTX* context) {
    static const uint8_t PADDING[64] = { 0x80 };

    uint8_t bits[8];
    MD5_Encode(bits, context->count, 8);

    size_t index = (context->count[0] >> 3) & 0x3f;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5_Update(context, PADDING, padLen);
    MD5_Update(context, bits, 8);

    MD5_Encode(digest, context->state, 16);
    std::memset(context, 0, sizeof(*context));
}

// MD5 core

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}
static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
    return (x & z) | (y & ~z);
}
static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (x | ~z);
}
static inline uint32_t ROTATE_LEFT(uint32_t x, int n) {
    return (x << n) | (x >> (32-n));
}
static inline void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, int s, uint32_t ac) {
    a += F(b, c, d) + x + ac;
    a = ROTATE_LEFT(a, s);
    a += b;
}
static inline void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, int s, uint32_t ac) {
    a += G(b, c, d) + x + ac;
    a = ROTATE_LEFT(a, s);
    a += b;
}
static inline void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, int s, uint32_t ac) {
    a += H(b, c, d) + x + ac;
    a = ROTATE_LEFT(a, s);
    a += b;
}
static inline void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, int s, uint32_t ac) {
    a += I(b, c, d) + x + ac;
    a = ROTATE_LEFT(a, s);
    a += b;
}

static void MD5_Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    uint32_t x[16];
    for (int i = 0, j = 0; j < 64; ++i, j += 4) {
        x[i] = (uint32_t)block[j]
             | ((uint32_t)block[j+1] << 8)
             | ((uint32_t)block[j+2] << 16)
             | ((uint32_t)block[j+3] << 24);
    }

    // Round 1
    FF(a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF(d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], S13, 0x242070db);
    FF(b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF(a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], S13, 0xa8304613);
    FF(b, c, d, a, x[ 7], S14, 0xfd469501);
    FF(a, b, c, d, x[ 8], S11, 0x698098d8);
    FF(d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);
    FF(b, c, d, a, x[11], S14, 0x895cd7be);
    FF(a, b, c, d, x[12], S11, 0x6b901122);
    FF(d, a, b, c, x[13], S12, 0xfd987193);
    FF(c, d, a, b, x[14], S13, 0xa679438e);
    FF(b, c, d, a, x[15], S14, 0x49b40821);

    // Round 2
    GG(a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG(d, a, b, c, x[ 6], S22, 0xc040b340);
    GG(c, d, a, b, x[11], S23, 0x265e5a51);
    GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG(d, a, b, c, x[10], S22,  0x2441453);
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9], S21, 0x21e1cde6);
    GG(d, a, b, c, x[14], S22, 0xc33707d6);
    GG(c, d, a, b, x[ 3], S23, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], S24, 0x455a14ed);
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);
    GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], S23, 0x676f02d9);
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, x[ 5], S31, 0xfffa3942);
    HH(d, a, b, c, x[ 8], S32, 0x8771f681);
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);
    HH(b, c, d, a, x[14], S34, 0xfde5380c);
    HH(a, b, c, d, x[ 1], S31, 0xa4beea44);
    HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60);
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], S32, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], S33, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], S34,  0x4881d05);
    HH(a, b, c, d, x[ 9], S31, 0xd9d4d039);
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], S34, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, x[ 0], S41, 0xf4292244);
    II(d, a, b, c, x[ 7], S42, 0x432aff97);
    II(c, d, a, b, x[14], S43, 0xab9423a7);
    II(b, c, d, a, x[ 5], S44, 0xfc93a039);
    II(a, b, c, d, x[12], S41, 0x655b59c3);
    II(d, a, b, c, x[ 3], S42, 0x8f0ccc92);
    II(c, d, a, b, x[10], S43, 0xffeff47d);
    II(b, c, d, a, x[ 1], S44, 0x85845dd1);
    II(a, b, c, d, x[ 8], S41, 0x6fa87e4f);
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], S43, 0xa3014314);
    II(b, c, d, a, x[13], S44, 0x4e0811a1);
    II(a, b, c, d, x[ 4], S41, 0xf7537e82);
    II(d, a, b, c, x[11], S42, 0xbd3af235);
    II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], S44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// EVP_BytesToKey-like MD5 KDF
static void evp_bytes_to_key_md5(const std::string& password,
                                 uint8_t* out_key, size_t key_len) {
    std::vector<uint8_t> result;
    std::vector<uint8_t> prev;

    while (result.size() < key_len) {
        MD5_CTX ctx;
        MD5_Init(&ctx);

        if (!prev.empty()) {
            MD5_Update(&ctx, prev.data(), prev.size());
        }
        MD5_Update(&ctx,
                   reinterpret_cast<const uint8_t*>(password.data()),
                   password.size());

        uint8_t md[16];
        MD5_Final(md, &ctx);

        prev.assign(md, md + 16);
        size_t to_copy = std::min(key_len - result.size(), (size_t)16);
        result.insert(result.end(), md, md + to_copy);
    }

    std::memcpy(out_key, result.data(), key_len);
}

// ==========================================================
// SHA1 + HMAC-SHA1 + HKDF-SHA1 (for SIP007 "ss-subkey")
// ==========================================================

struct SHA1_CTX {
    uint32_t state[5];
    uint64_t count;  // bits
    uint8_t buffer[64];
};

static void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]);

static void SHA1_Init(SHA1_CTX* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void SHA1_Update(SHA1_CTX* ctx, const uint8_t* data, size_t len) {
    size_t i = 0;
    size_t j = (size_t)((ctx->count >> 3) & 63);

    ctx->count += (uint64_t)len << 3;

    size_t part_len = 64 - j;

    if (len >= part_len) {
        std::memcpy(&ctx->buffer[j], data, part_len);
        SHA1_Transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < len; i += 64) {
            SHA1_Transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }

    std::memcpy(&ctx->buffer[j], &data[i], len - i);
}

static void SHA1_Final(uint8_t digest[20], SHA1_CTX* ctx) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; ++i) {
        finalcount[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 0xFF);
    }

    static const uint8_t  PADDING[64] = { 0x80 };
    uint8_t pad[64];
    std::memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    size_t index = (size_t)((ctx->count >> 3) & 63);
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);

    SHA1_Update(ctx, pad, padLen);
    SHA1_Update(ctx, finalcount, 8);

    for (int i = 0; i < 20; ++i) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF);
    }

    std::memset(ctx, 0, sizeof(*ctx));
}

static inline uint32_t SHA1_ROTL(uint32_t value, unsigned int bits) {
    return (value << bits) | (value >> (32 - bits));
}

static void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, t;
    uint32_t W[80];

    for (int i = 0; i < 16; ++i) {
        W[i] = ((uint32_t) buffer[i * 4]) << 24;
        W[i] |= ((uint32_t) buffer[i * 4 + 1]) << 16;
        W[i] |= ((uint32_t) buffer[i * 4 + 2]) << 8;
        W[i] |= ((uint32_t) buffer[i * 4 + 3]);
    }

    for (int i = 16; i < 80; ++i) {
        W[i] = SHA1_ROTL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        t = SHA1_ROTL(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

// HMAC-SHA1
static void hmac_sha1(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t out[20]) {
    const size_t block_size = 64;
    uint8_t k0[block_size];
    std::memset(k0, 0, sizeof(k0));

    if (key_len > block_size) {
        // key = SHA1(key)
        uint8_t kh[20];
        SHA1_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, key, key_len);
        SHA1_Final(kh, &ctx);
        std::memcpy(k0, kh, 20);
        std::memset(kh, 0, sizeof(kh));
    } else {
        std::memcpy(k0, key, key_len);
    }

    uint8_t ipad[block_size];
    uint8_t opad[block_size];
    for (size_t i = 0; i < block_size; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t inner_hash[20];
    SHA1_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, ipad, block_size);
    SHA1_Update(&ctx, data, data_len);
    SHA1_Final(inner_hash, &ctx);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, opad, block_size);
    SHA1_Update(&ctx, inner_hash, sizeof(inner_hash));
    SHA1_Final(out, &ctx);

    std::memset(k0, 0, sizeof(k0));
    std::memset(ipad, 0, sizeof(ipad));
    std::memset(opad, 0, sizeof(opad));
    std::memset(inner_hash, 0, sizeof(inner_hash));
}

// HKDF-SHA1 (RFC5869-style), used as HKDF_SHA1 in Shadowsocks spec
static bool hkdf_sha1(const uint8_t* ikm, size_t ikm_len,
                      const uint8_t* salt, size_t salt_len,
                      const uint8_t* info, size_t info_len,
                      uint8_t* okm, size_t okm_len) {
    if (okm_len == 0 || okm_len > 255 * 20) return false;

    uint8_t zero_salt[20];
    if (salt_len == 0 || salt == nullptr) {
        std::memset(zero_salt, 0, sizeof(zero_salt));
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    uint8_t prk[20];
    // PRK = HMAC(salt, IKM)
    hmac_sha1(salt, salt_len, ikm, ikm_len, prk);

    size_t n = (okm_len + 20 - 1) / 20;
    std::vector<uint8_t> t;
    t.reserve(n * 20);

    uint8_t prev[20];
    size_t prev_len = 0;

    for (size_t i = 1; i <= n; ++i) {
        // T(i) = HMAC(PRK, T(i-1) | info | i)
        std::vector<uint8_t> buf;
        buf.reserve(prev_len + info_len + 1);
        if (prev_len > 0) {
            buf.insert(buf.end(), prev, prev + prev_len);
        }
        if (info && info_len > 0) {
            buf.insert(buf.end(), info, info + info_len);
        }
        buf.push_back(static_cast<uint8_t>(i));

        hmac_sha1(prk, sizeof(prk), buf.data(), buf.size(), prev);
        prev_len = 20;
        t.insert(t.end(), prev, prev + 20);
    }

    std::memcpy(okm, t.data(), okm_len);
    std::memset(prk, 0, sizeof(prk));
    std::memset(prev, 0, sizeof(prev));
    return true;
}

// ==========================================================
// Public API
// ==========================================================

bool crypto_global_init() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return false;
    }
    return true;
}

bool crypto_init_master(CryptoContext& ctx, const std::string& password) {
    if (password.empty()) {
        std::cerr << "Empty password\n";
        return false;
    }
    if (!crypto_global_init()) return false;

    evp_bytes_to_key_md5(password, ctx.master_key, SS_KEY_LEN);
    ctx.has_master = true;
    ctx.has_subkey = false;
    std::memset(ctx.nonce, 0, SS_NONCE_LEN);
    return true;
}

bool crypto_init_session_from_salt(CryptoContext& ctx,
                                   const uint8_t* salt,
                                   size_t salt_len) {
    if (!ctx.has_master) return false;
    if (!salt || salt_len != SS_SALT_LEN) {
        std::cerr << "Invalid salt length\n";
        return false;
    }

    static const uint8_t info[] = "ss-subkey";

    if (!hkdf_sha1(ctx.master_key, SS_KEY_LEN,
                   salt, salt_len,
                   info, sizeof(info) - 1,
                   ctx.subkey, SS_KEY_LEN)) {
        std::cerr << "HKDF_SHA1 failed\n";
        return false;
    }

    crypto_reset_nonce(ctx);
    ctx.has_subkey = true;
    return true;
}

void crypto_reset_nonce(CryptoContext& ctx) {
    std::memset(ctx.nonce, 0, SS_NONCE_LEN);
}

void crypto_increment_nonce(CryptoContext& ctx) {
    // little-endian increment
    for (size_t i = 0; i < SS_NONCE_LEN; ++i) {
        if (++ctx.nonce[i] != 0) break;
    }
}

// Encrypt one TCP chunk
bool ss_encrypt_chunk(CryptoContext& ctx,
                      const uint8_t* plaintext,
                      uint16_t plaintext_len,
                      std::vector<uint8_t>& out_chunk) {
    if (!ctx.has_subkey) return false;
    if (plaintext_len == 0 || plaintext_len > SS_MAX_PAYLOAD) return false;

    out_chunk.clear();

    // 1) length (2 bytes, big-endian, top 2 bits zero)
    uint16_t len_field = plaintext_len & 0x3FFF;
    uint8_t len_plain[2];
    len_plain[0] = (uint8_t)((len_field >> 8) & 0xFF);
    len_plain[1] = (uint8_t)(len_field & 0xFF);

    uint8_t len_ct[2 + SS_TAG_LEN];
    unsigned long long len_ct_len = sizeof(len_ct);

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            len_ct, &len_ct_len,
            len_plain, sizeof(len_plain),
            nullptr, 0,
            nullptr,
            ctx.nonce,
            ctx.subkey) != 0) {
        return false;
    }
    if (len_ct_len != sizeof(len_ct)) return false;
    crypto_increment_nonce(ctx);

    // 2) payload
    std::vector<uint8_t> payload_ct(plaintext_len + SS_TAG_LEN);
    unsigned long long payload_ct_len = payload_ct.size();

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            payload_ct.data(), &payload_ct_len,
            plaintext, plaintext_len,
            nullptr, 0,
            nullptr,
            ctx.nonce,
            ctx.subkey) != 0) {
        return false;
    }
    if (payload_ct_len != plaintext_len + SS_TAG_LEN) return false;
    crypto_increment_nonce(ctx);

    out_chunk.reserve(sizeof(len_ct) + payload_ct.size());
    out_chunk.insert(out_chunk.end(), len_ct, len_ct + sizeof(len_ct));
    out_chunk.insert(out_chunk.end(), payload_ct.begin(), payload_ct.end());

    return true;
}

// Decrypt one TCP chunk
DecryptStatus ss_decrypt_chunk(CryptoContext& ctx,
                               const uint8_t* in,
                               size_t in_len,
                               size_t& consumed,
                               std::vector<uint8_t>& plaintext_out) {
    consumed = 0;
    plaintext_out.clear();

    if (!ctx.has_subkey) return DecryptStatus::ERROR;

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
            ctx.nonce,
            ctx.subkey) != 0) {
        return DecryptStatus::ERROR;
    }
    if (len_plain_len != sizeof(len_plain)) {
        return DecryptStatus::ERROR;
    }
    crypto_increment_nonce(ctx);

    uint16_t len_field = (uint16_t(len_plain[0]) << 8) | uint16_t(len_plain[1]);
    len_field &= 0x3FFF;
    if (len_field == 0 || len_field > SS_MAX_PAYLOAD) {
        return DecryptStatus::ERROR;
    }

    size_t payload_ct_len = len_field + SS_TAG_LEN;
    if (in_len < len_ct_total + payload_ct_len) {
        // need more data for full payload
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
            ctx.nonce,
            ctx.subkey) != 0) {
        return DecryptStatus::ERROR;
    }
    if (out_len != len_field) {
        return DecryptStatus::ERROR;
    }
    crypto_increment_nonce(ctx);

    consumed = len_ct_total + payload_ct_len;
    return DecryptStatus::OK;
}
