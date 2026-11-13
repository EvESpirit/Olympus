#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "olympus/codec/v24919/bitstream.hpp"
#include "olympus/codec/v24919/jam_compact_codec.hpp"
#include "olympus/codec/v24919/jam_schema_db.hpp"

namespace olympus::codec::v24919 {

// ------------------------------------------------------------------------------
// 1. Outer TCP JAM Frame (+0xF29940 -> +0xF2A090 -> +0xF2E5D0)
// ------------------------------------------------------------------------------
struct JAMTcpFrame {
    std::uint8_t                        pool_index{0};
    std::optional<std::uint32_t>        sequence_or_token{}; // Present if pool header_flags & 0x08
    std::optional<JAMRoutingAddress>    routing_address{};   // Present if pool header_flags & 0x1F0
    std::uint8_t                        relative_opcode{0};  // opcode = pool.start_opcode + relative_opcode
    std::vector<std::uint8_t>           compact_payload{};
};

[[nodiscard]] std::vector<std::uint8_t> encode_jam_tcp_frame(
    const JAMTcpFrame& frame,
    std::uint32_t pool_header_flags = 0u);

[[nodiscard]] bool decode_jam_tcp_frame(
    std::span<const std::uint8_t> raw_frame,
    std::uint32_t pool_header_flags,
    JAMTcpFrame& out_frame);

// ------------------------------------------------------------------------------
// 1b. Outer JAMConnection TCP Socket Framing (+0x1602E50: +0xE65610 Send / +0xE65750 Recv)
//     Every JAMStream payload on TCP is prefixed with a 3-byte (24-bit Big-Endian)
//     payload length: [ (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF ].
// ------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::uint8_t> wrap_jam_tcp_socket_payload(
    std::span<const std::uint8_t> inner_jam_stream);

[[nodiscard]] std::vector<std::uint8_t> encode_jam_tcp_wire_packet(
    const JAMTcpFrame& frame,
    std::uint32_t pool_header_flags = 0u);

class JAMTcpStreamAssembler {
public:
    void feed_bytes(std::span<const std::uint8_t> chunk);

    // Extracts the next complete inner JAMStream payload if >= 3 + payload_len bytes are buffered.
    [[nodiscard]] bool pop_raw_jam_stream(std::vector<std::uint8_t>& out_inner_stream);

    // Extracts and decodes the next complete JAMTcpFrame.
    [[nodiscard]] bool pop_frame(
        JAMTcpFrame& out_frame,
        std::uint32_t pool_header_flags = 0u);

    [[nodiscard]] std::size_t buffered_bytes() const noexcept {
        return buffer_.size() - read_offset_;
    }

    void clear() noexcept {
        buffer_.clear();
        read_offset_ = 0;
    }

private:
    std::vector<std::uint8_t> buffer_;
    std::size_t               read_offset_{0};
};

// ------------------------------------------------------------------------------
// 2. UDP Sub-Channel 0: ClientJAMUDPSubChannel (+0x10504C0 & +0x1050DF0)
//    Multiplexes the 8 Simulation Plane JAM Protocol Pools (pool_index 0..7)
//    and manages reliable sequence numbers + channel_tokens[0] retransmission!
// ------------------------------------------------------------------------------
struct JAMUdpQueuedMessage {
    bool                      is_reliable{true};
    std::uint32_t             reliable_seq{0};    // [peer + 0x48]++, only written on wire when is_reliable == true
    std::uint8_t              sim_pool_index{0};  // 0..7
    std::uint8_t              relative_opcode{0}; // opcode = pool->start_opcode + relative_opcode
    std::vector<std::uint8_t> compact_payload{};

    [[nodiscard]] std::uint32_t full_opcode() const noexcept {
        if (const auto* pool = find_sim_jam_pool(sim_pool_index)) {
            return pool->start_opcode + relative_opcode;
        }
        return 0u;
    }
};

class JAMSubChannel0Tracker {
public:
    // Queues a Simulation JAM message (by full opcode, e.g. 0x61A8, 0x61B1, 0x4F4C)
    [[nodiscard]] bool queue_outbound_message(
        std::uint32_t opcode,
        const JAMObject& msg_fields,
        bool reliable = true);

    // Writes Sub-Channel 0's section into an outbound UDP datagram BitStreamWriter (+0x1050DF0).
    // If reliable messages are sent, allocates a non-zero delivery token in `out_channel_token` (channel_tokens[0]).
    [[nodiscard]] bool write_outbound_datagram(
        BitStreamWriter& bitstream,
        std::uint64_t& out_channel_token);

    // Reads Sub-Channel 0's section from an incoming UDP datagram BitStreamReader (+0x10504C0).
    // Returns all in-order reliable messages and immediate unreliable messages ready for dispatch.
    [[nodiscard]] bool read_inbound_datagram(
        BitStreamReader& bitstream,
        std::vector<JAMUdpQueuedMessage>& out_ready_messages);

    // Called by GCM Event 5 (+0x104F8F0 -> +0x10502F0 OnPacketAcked)
    void on_packet_acked(std::uint64_t channel_token) noexcept;

    // Called by GCM Event 5 (+0x104F8F0 -> +0x10503D0 OnPacketDropped):
    // Re-inserts dropped reliable messages in sequence order at the head of reliable_out_queue_!
    void on_packet_dropped(std::uint64_t channel_token);

    [[nodiscard]] std::size_t pending_reliable_count() const noexcept { return reliable_out_queue_.size(); }
    [[nodiscard]] std::size_t in_flight_token_count() const noexcept { return in_flight_batches_.size(); }

private:
    std::uint32_t next_out_reliable_seq_{0}; // [peer + 0x48]
    std::uint32_t expected_in_reliable_seq_{0}; // [peer + 0x50]
    std::uint64_t next_delivery_token_{1};

    std::deque<JAMUdpQueuedMessage> reliable_out_queue_;
    std::deque<JAMUdpQueuedMessage> unreliable_out_queue_;
    std::map<std::uint64_t, std::vector<JAMUdpQueuedMessage>> in_flight_batches_;
    std::map<std::uint32_t, JAMUdpQueuedMessage> inbound_reorder_buffer_; // [peer + 0x58]
};

} // namespace olympus::codec::v24919
