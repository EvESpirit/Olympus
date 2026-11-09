#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "olympus/codec/v24919/hmac_sha1_96.hpp"

namespace olympus::codec::v24919 {

// Verified in GameClientApp.exe (+0xE527C0, +0xE52EE0, +0xE54470, +0xE54640)
constexpr std::size_t GCM_HEADER_SIZE = 0x22;         // 34 bytes minimum (+0xE52F6A: cmp r8d, 0x22)
constexpr std::size_t GCM_MAX_WIRE_MTU = 0x538;       // 1336 bytes maximum (+0xE527DC: cmp r9d, 0x538)
constexpr std::size_t GCM_MAX_PAYLOAD_SIZE = GCM_MAX_WIRE_MTU - GCM_HEADER_SIZE; // 1302 bytes
constexpr std::size_t GCM_MAX_CHANNELS = 16;

enum class GCMPacketType : std::uint8_t {
    ControlOrHandshake = 0x00, // Pure SYN/ACK/FIN/Keepalive (no simulation payload)
    SequencedSimulation = 0x01, // Dispatched to +0xC701DF (Tick header + Sub-Channels 0..4 + Entity deltas)
    UnsequencedOutOfBand = 0x0F // Dispatched to +0xC701EA -> Sub-Channel 5 (+0xC7057A)
};

namespace GCMControlFlags {
    constexpr std::uint8_t None = 0x00;
    constexpr std::uint8_t SYN  = 0x01; // Bit 0
    constexpr std::uint8_t ACK  = 0x02; // Bit 1
    constexpr std::uint8_t FIN  = 0x04; // Bit 2
} // namespace GCMControlFlags

enum class GCMSessionState : std::uint8_t {
    Listen      = 0,
    SynSent     = 1,
    SynReceived = 2,
    Established = 3,
    Closed      = 4
};

#pragma pack(push, 1)
struct NativeGCMUdpHeader {
    std::uint8_t  hmac_sha1_96[12];     // +0x00..+0x0B: HMAC-SHA1-96 over pkt[0x0C..end]
    std::uint32_t flags_and_session_id; // +0x0C..+0x0F: (session_token_28bit << 4) | (pkt_type & 0x0F)
    std::uint32_t seq_num;              // +0x10..+0x13: Sender sequence number
    std::uint32_t ack_num;              // +0x14..+0x17: Latest remote sequence number received
    std::uint64_t window_state;         // +0x18..+0x1F: Sliding-window ACK bitfield & timing metadata
    std::uint8_t  control_flags;        // +0x20: GCMControlFlags (SYN=0x01, ACK=0x02, FIN=0x04)
    std::uint8_t  congestion_feedback;  // +0x21: Rate-control feedback byte

    [[nodiscard]] constexpr std::uint32_t session_token() const noexcept {
        return flags_and_session_id >> 4u;
    }

    [[nodiscard]] constexpr GCMPacketType packet_type() const noexcept {
        return static_cast<GCMPacketType>(flags_and_session_id & 0x0Fu);
    }

    constexpr void set_session_and_type(std::uint32_t token_28bit, GCMPacketType type) noexcept {
        flags_and_session_id = ((token_28bit & 0x0FFFFFFFu) << 4u) | (static_cast<std::uint32_t>(type) & 0x0Fu);
    }
};
#pragma pack(pop)

static_assert(sizeof(NativeGCMUdpHeader) == GCM_HEADER_SIZE,
              "NativeGCMUdpHeader must be 0x22 (34) bytes");

// 0xA0-byte in-flight packet tracking record equivalent (+0xE54759 -> +0x104F8F0)
struct GCMInFlightPacketRecord {
    std::array<std::uint64_t, GCM_MAX_CHANNELS> channel_tokens{}; // +0x00..+0x7F
    std::uint32_t seq_num{0};                                     // +0x80
    std::uint64_t send_time_ms{0};                                // +0x88
    std::uint32_t byte_size{0};                                   // +0x90
};

// Signs pkt[0x0C..pkt.size()-1] into pkt[0x00..0x0B]
[[nodiscard]] bool sign_gcm_udp_packet(
    std::span<std::uint8_t> packet_bytes,
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> secret_key) noexcept;

// Verifies pkt.size() in [0x22, 0x538] and constant-time checks pkt[0x00..0x0B]
[[nodiscard]] bool verify_gcm_udp_packet(
    std::span<const std::uint8_t> packet_bytes,
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> secret_key) noexcept;

} // namespace olympus::codec::v24919
