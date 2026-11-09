#include "olympus/codec/v24919/hmac_sha1_96.hpp"

#include <array>
#include <cstring>

namespace olympus::codec::v24919 {
namespace {

constexpr std::size_t SHA1_BLOCK_SIZE = 64;
constexpr std::size_t SHA1_DIGEST_SIZE = 20;

constexpr std::uint32_t rotl32(std::uint32_t x, unsigned int n) noexcept {
    return (x << n) | (x >> (32u - n));
}

struct Sha1Context {
    std::uint32_t state[5]{
        0x67452301u,
        0xEFCDAB89u,
        0x98BADCFEu,
        0x10325476u,
        0xC3D2E1F0u
    };
    std::uint64_t total_bytes{0};
    std::uint8_t  buffer[SHA1_BLOCK_SIZE]{};
    std::size_t   buffer_len{0};

    void process_block(const std::uint8_t block[SHA1_BLOCK_SIZE]) noexcept {
        std::uint32_t w[80]{};
        for (std::size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24u) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16u) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8u)  |
                   (static_cast<std::uint32_t>(block[i * 4 + 3]));
        }
        for (std::size_t i = 16; i < 80; ++i) {
            w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1u);
        }

        std::uint32_t a = state[0];
        std::uint32_t b = state[1];
        std::uint32_t c = state[2];
        std::uint32_t d = state[3];
        std::uint32_t e = state[4];

        for (std::size_t i = 0; i < 80; ++i) {
            std::uint32_t f = 0;
            std::uint32_t k = 0;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            const std::uint32_t temp = rotl32(a, 5u) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl32(b, 30u);
            b = a;
            a = temp;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

    void update(std::span<const std::uint8_t> data) noexcept {
        total_bytes += data.size();
        std::size_t offset = 0;

        if (buffer_len > 0) {
            const std::size_t take = std::min(SHA1_BLOCK_SIZE - buffer_len, data.size());
            std::memcpy(buffer + buffer_len, data.data(), take);
            buffer_len += take;
            offset += take;
            if (buffer_len == SHA1_BLOCK_SIZE) {
                process_block(buffer);
                buffer_len = 0;
            }
        }

        while (offset + SHA1_BLOCK_SIZE <= data.size()) {
            process_block(data.data() + offset);
            offset += SHA1_BLOCK_SIZE;
        }

        if (offset < data.size()) {
            buffer_len = data.size() - offset;
            std::memcpy(buffer, data.data() + offset, buffer_len);
        }
    }

    void finalize(std::uint8_t digest[SHA1_DIGEST_SIZE]) noexcept {
        const std::uint64_t total_bits = total_bytes * 8ull;
        buffer[buffer_len++] = 0x80u;

        if (buffer_len > 56u) {
            std::memset(buffer + buffer_len, 0, SHA1_BLOCK_SIZE - buffer_len);
            process_block(buffer);
            buffer_len = 0;
        }

        std::memset(buffer + buffer_len, 0, 56u - buffer_len);
        for (std::size_t i = 0; i < 8; ++i) {
            buffer[56 + i] = static_cast<std::uint8_t>((total_bits >> ((7u - i) * 8u)) & 0xFFu);
        }
        process_block(buffer);

        for (std::size_t i = 0; i < 5; ++i) {
            digest[i * 4 + 0] = static_cast<std::uint8_t>((state[i] >> 24u) & 0xFFu);
            digest[i * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 16u) & 0xFFu);
            digest[i * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 8u) & 0xFFu);
            digest[i * 4 + 3] = static_cast<std::uint8_t>(state[i] & 0xFFu);
        }
    }
};

} // namespace

void compute_hmac_sha1_96(
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> key,
    std::span<const std::uint8_t> payload,
    std::span<std::uint8_t, HMAC_SHA1_96_TAG_SIZE> out_tag) noexcept {

    std::uint8_t ipad[SHA1_BLOCK_SIZE];
    std::uint8_t opad[SHA1_BLOCK_SIZE];
    std::memset(ipad, 0x36, SHA1_BLOCK_SIZE);
    std::memset(opad, 0x5C, SHA1_BLOCK_SIZE);

    for (std::size_t i = 0; i < HMAC_SHA1_KEY_SIZE; ++i) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    std::uint8_t inner_digest[SHA1_DIGEST_SIZE]{};
    {
        Sha1Context inner;
        inner.update(ipad);
        inner.update(payload);
        inner.finalize(inner_digest);
    }

    std::uint8_t outer_digest[SHA1_DIGEST_SIZE]{};
    {
        Sha1Context outer;
        outer.update(opad);
        outer.update(inner_digest);
        outer.finalize(outer_digest);
    }

    std::memcpy(out_tag.data(), outer_digest, HMAC_SHA1_96_TAG_SIZE);
}

bool verify_hmac_sha1_96(
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> key,
    std::span<const std::uint8_t> payload,
    std::span<const std::uint8_t, HMAC_SHA1_96_TAG_SIZE> expected_tag) noexcept {

    std::array<std::uint8_t, HMAC_SHA1_96_TAG_SIZE> computed{};
    compute_hmac_sha1_96(key, payload, computed);

    // Constant-time comparison matching +0xE53098..+0xE530C5
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < HMAC_SHA1_96_TAG_SIZE; ++i) {
        diff |= static_cast<std::uint8_t>(computed[i] ^ expected_tag[i]);
    }
    return diff == 0u;
}

} // namespace olympus::codec::v24919
