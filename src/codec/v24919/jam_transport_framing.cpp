#include "olympus/codec/v24919/jam_transport_framing.hpp"

#include <algorithm>

namespace olympus::codec::v24919 {

std::vector<std::uint8_t> encode_jam_tcp_frame(
    const JAMTcpFrame& frame,
    std::uint32_t pool_header_flags) {

    JAMCompactWriter writer;
    writer.write_u8(frame.pool_index);

    if ((pool_header_flags & 0x08u) != 0u) {
        writer.write_u32(frame.sequence_or_token.value_or(0u));
    }

    if ((pool_header_flags & 0x1F0u) != 0u) {
        const JAMRoutingAddress addr = frame.routing_address.value_or(JAMRoutingAddress{});
        const std::size_t len = addr.wire_byte_length();
        writer.write_fixed_bytes(std::span<const std::uint8_t>(addr.bytes.data(), len));
    }

    writer.write_u8(frame.relative_opcode);
    writer.write_fixed_bytes(frame.compact_payload);
    return writer.take_bytes();
}

bool decode_jam_tcp_frame(
    std::span<const std::uint8_t> raw_frame,
    std::uint32_t pool_header_flags,
    JAMTcpFrame& out_frame) {

    JAMCompactReader reader(raw_frame);
    if (!reader.read_u8(out_frame.pool_index)) {
        return false;
    }

    if ((pool_header_flags & 0x08u) != 0u) {
        std::uint32_t seq = 0;
        if (!reader.read_u32(seq)) return false;
        out_frame.sequence_or_token = seq;
    } else {
        out_frame.sequence_or_token.reset();
    }

    if ((pool_header_flags & 0x1F0u) != 0u) {
        JAMRoutingAddress addr{};
        if ((pool_header_flags & 0x10u) != 0u) addr.addr_type = 1;
        else if ((pool_header_flags & 0x20u) != 0u) addr.addr_type = 2;
        else if ((pool_header_flags & 0x40u) != 0u) addr.addr_type = 3;
        else if ((pool_header_flags & 0x80u) != 0u) addr.addr_type = 4;
        else addr.addr_type = 5;

        const std::size_t len = addr.wire_byte_length();
        if (!reader.read_fixed_bytes(std::span<std::uint8_t>(addr.bytes.data(), len))) {
            return false;
        }
        out_frame.routing_address = addr;
    } else {
        out_frame.routing_address.reset();
    }

    if (!reader.read_u8(out_frame.relative_opcode)) {
        return false;
    }
    return reader.read_remaining_bytes(out_frame.compact_payload);
}

// ------------------------------------------------------------------------------
// JAMSubChannel0Tracker (+0x10504C0 / +0x1050DF0 / +0x10502F0 / +0x10503D0)
// ------------------------------------------------------------------------------
bool JAMSubChannel0Tracker::queue_outbound_message(
    std::uint32_t opcode,
    const JAMObject& msg_fields,
    bool reliable) {

    const JAMMessageDesc* desc = find_jam_message_by_opcode(opcode);
    if (!desc) return false;

    const JAMPoolSpec* pool = find_jam_pool_by_hash(desc->protocol_hash);
    if (!pool || pool->sim_pool_index < 0 || pool->sim_pool_index > 7) {
        return false;
    }

    JAMCompactWriter writer;
    if (!serialize_jam_schema(writer, desc->fields, msg_fields)) {
        return false;
    }

    JAMUdpQueuedMessage msg{};
    msg.is_reliable     = reliable;
    msg.sim_pool_index  = static_cast<std::uint8_t>(pool->sim_pool_index);
    msg.relative_opcode = static_cast<std::uint8_t>(opcode - pool->start_opcode);
    msg.compact_payload = writer.take_bytes();

    if (reliable) {
        msg.reliable_seq = next_out_reliable_seq_++;
        reliable_out_queue_.push_back(std::move(msg));
    } else {
        unreliable_out_queue_.push_back(std::move(msg));
    }
    return true;
}

bool JAMSubChannel0Tracker::write_outbound_datagram(
    BitStreamWriter& bitstream,
    std::uint64_t& out_channel_token) {

    out_channel_token = 0u;
    if (reliable_out_queue_.empty() && unreliable_out_queue_.empty()) {
        // Bit 0 = 0 (no JAM section -> consumes only 1 bit!)
        return bitstream.write_bit(false);
    }

    const std::size_t rel_count   = std::min<std::size_t>(reliable_out_queue_.size(), 15u);
    const std::size_t unrel_count = std::min<std::size_t>(unreliable_out_queue_.size(), 15u);

    // Bit 0 = 1 (has_jam_section), followed by 4-bit reliable count and 4-bit unreliable count
    if (!bitstream.write_bit(true) ||
        !bitstream.write_bits(rel_count, 4u) ||
        !bitstream.write_bits(unrel_count, 4u)) {
        return false;
    }

    // +0xF10DB0 transfers ownership to byte-aligned JAMStream
    JAMCompactWriter jam_block;
    std::vector<JAMUdpQueuedMessage> sent_reliable;
    sent_reliable.reserve(rel_count);

    // Part A: Reliable messages (+0x10505C5..+0x10506FD)
    for (std::size_t i = 0; i < rel_count; ++i) {
        JAMUdpQueuedMessage msg = std::move(reliable_out_queue_.front());
        reliable_out_queue_.pop_front();

        jam_block.write_u32(msg.reliable_seq);
        jam_block.write_u8(msg.sim_pool_index);
        jam_block.write_u8(msg.relative_opcode);
        jam_block.write_fixed_bytes(msg.compact_payload);

        sent_reliable.push_back(std::move(msg));
    }

    // Part B: Unreliable messages (+0x1050712..+0x10507B9)
    for (std::size_t i = 0; i < unrel_count; ++i) {
        JAMUdpQueuedMessage msg = std::move(unreliable_out_queue_.front());
        unreliable_out_queue_.pop_front();

        jam_block.write_u8(msg.sim_pool_index);
        jam_block.write_u8(msg.relative_opcode);
        jam_block.write_fixed_bytes(msg.compact_payload);
    }

    if (!bitstream.write_bytes_aligned(jam_block.bytes())) {
        return false;
    }

    if (!sent_reliable.empty()) {
        const std::uint64_t token = next_delivery_token_++;
        in_flight_batches_.emplace(token, std::move(sent_reliable));
        out_channel_token = token;
    }
    return true;
}

bool JAMSubChannel0Tracker::read_inbound_datagram(
    BitStreamReader& bitstream,
    std::vector<JAMUdpQueuedMessage>& out_ready_messages) {

    out_ready_messages.clear();
    bool has_jam_section = false;
    if (!bitstream.read_bit(has_jam_section)) {
        return false;
    }
    if (!has_jam_section) {
        return true;
    }

    std::uint64_t rel_count   = 0;
    std::uint64_t unrel_count = 0;
    if (!bitstream.read_bits(4u, rel_count) ||
        !bitstream.read_bits(4u, unrel_count)) {
        return false;
    }

    bitstream.align_to_byte();
    const std::size_t rem_bytes = bitstream.remaining_bits() >> 3u;
    std::vector<std::uint8_t> raw_block(rem_bytes, 0u);
    if (!bitstream.read_bytes_aligned(raw_block)) {
        return false;
    }

    JAMCompactReader reader(raw_block);

    // Part A: Reliable messages (+0x10505C5..+0x10506FD)
    for (std::uint64_t i = 0; i < rel_count; ++i) {
        std::uint32_t seq = 0;
        std::uint8_t pool_idx = 0;
        std::uint8_t rel_op = 0;
        if (!reader.read_u32(seq) ||
            !reader.read_u8(pool_idx) ||
            !reader.read_u8(rel_op)) {
            return false;
        }
        const JAMPoolSpec* pool = find_sim_jam_pool(pool_idx);
        if (!pool) return false;
        const std::uint32_t opcode = pool->start_opcode + rel_op;
        const JAMMessageDesc* desc = find_jam_message(pool->protocol_hash, opcode);
        if (!desc) return false;

        const std::size_t payload_start = reader.offset();
        JAMObject decoded{};
        if (!deserialize_jam_schema(reader, desc->fields, decoded)) {
            return false;
        }
        const std::size_t payload_end = reader.offset();

        JAMUdpQueuedMessage msg{};
        msg.is_reliable     = true;
        msg.reliable_seq    = seq;
        msg.sim_pool_index  = pool_idx;
        msg.relative_opcode = rel_op;
        msg.compact_payload.assign(
            raw_block.begin() + static_cast<std::ptrdiff_t>(payload_start),
            raw_block.begin() + static_cast<std::ptrdiff_t>(payload_end));

        if (seq == expected_in_reliable_seq_) {
            out_ready_messages.push_back(std::move(msg));
            ++expected_in_reliable_seq_;
            while (true) {
                auto it = inbound_reorder_buffer_.find(expected_in_reliable_seq_);
                if (it == inbound_reorder_buffer_.end()) break;
                out_ready_messages.push_back(std::move(it->second));
                inbound_reorder_buffer_.erase(it);
                ++expected_in_reliable_seq_;
            }
        } else if (seq > expected_in_reliable_seq_) {
            inbound_reorder_buffer_.emplace(seq, std::move(msg));
        }
    }

    // Part B: Unreliable messages (+0x1050712..+0x10507B9)
    for (std::uint64_t i = 0; i < unrel_count; ++i) {
        std::uint8_t pool_idx = 0;
        std::uint8_t rel_op = 0;
        if (!reader.read_u8(pool_idx) || !reader.read_u8(rel_op)) {
            return false;
        }
        const JAMPoolSpec* pool = find_sim_jam_pool(pool_idx);
        if (!pool) return false;
        const std::uint32_t opcode = pool->start_opcode + rel_op;
        const JAMMessageDesc* desc = find_jam_message(pool->protocol_hash, opcode);
        if (!desc) return false;

        const std::size_t payload_start = reader.offset();
        JAMObject decoded{};
        if (!deserialize_jam_schema(reader, desc->fields, decoded)) {
            return false;
        }
        const std::size_t payload_end = reader.offset();

        JAMUdpQueuedMessage msg{};
        msg.is_reliable     = false;
        msg.sim_pool_index  = pool_idx;
        msg.relative_opcode = rel_op;
        msg.compact_payload.assign(
            raw_block.begin() + static_cast<std::ptrdiff_t>(payload_start),
            raw_block.begin() + static_cast<std::ptrdiff_t>(payload_end));
        out_ready_messages.push_back(std::move(msg));
    }

    return true;
}

void JAMSubChannel0Tracker::on_packet_acked(std::uint64_t channel_token) noexcept {
    if (channel_token != 0u) {
        in_flight_batches_.erase(channel_token);
    }
}

void JAMSubChannel0Tracker::on_packet_dropped(std::uint64_t channel_token) {
    if (channel_token == 0u) return;
    auto it = in_flight_batches_.find(channel_token);
    if (it == in_flight_batches_.end()) return;

    // Re-insert dropped reliable messages in sequence order (+0x10503D0)
    for (auto& msg : it->second) {
        reliable_out_queue_.push_back(std::move(msg));
    }
    in_flight_batches_.erase(it);

    std::sort(
        reliable_out_queue_.begin(),
        reliable_out_queue_.end(),
        [](const JAMUdpQueuedMessage& a, const JAMUdpQueuedMessage& b) {
            return a.reliable_seq < b.reliable_seq;
        });
}

} // namespace olympus::codec::v24919
