#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace olympus::codec::v24919 {

constexpr std::size_t HMAC_SHA1_KEY_SIZE = 20; // 0x14 bytes (delivered in ClientInLobbyInstance 0x5078 +0x88)
constexpr std::size_t HMAC_SHA1_96_TAG_SIZE = 12; // 0x0C bytes (pkt[0x00..0x0B], +0xE535A0)

// Computes 96-bit truncated HMAC-SHA1 over `payload` (pkt[0x0C .. pkt_len - 1])
// using the 20-byte session secret key. Matches GameClientApp.exe +0xE535A0.
void compute_hmac_sha1_96(
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> key,
    std::span<const std::uint8_t> payload,
    std::span<std::uint8_t, HMAC_SHA1_96_TAG_SIZE> out_tag) noexcept;

// Constant-time 12-byte tag verification matching +0xE53098..+0xE530C5.
[[nodiscard]] bool verify_hmac_sha1_96(
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> key,
    std::span<const std::uint8_t> payload,
    std::span<const std::uint8_t, HMAC_SHA1_96_TAG_SIZE> expected_tag) noexcept;

} // namespace olympus::codec::v24919
