#include "olympus/codec/v24919/jam_compact_codec.hpp"

#include <cstring>

namespace olympus::codec::v24919 {

void JAMCompactWriter::write_bool(bool value) {
    // Matches +0xF2C916: up to 8 consecutive bools pack into 1 byte
    if (bit_pos_ == 0u) {
        bool_byte_index_ = buffer_.size();
        buffer_.push_back(0u);
    }
    if (value) {
        buffer_[bool_byte_index_] |= static_cast<std::uint8_t>(1u << bit_pos_);
    }
    bit_pos_ = static_cast<std::uint8_t>((bit_pos_ + 1u) & 7u);
}

void JAMCompactWriter::write_u8(std::uint8_t value) {
    reset_bool_packing();
    buffer_.push_back(value);
}

void JAMCompactWriter::write_i8(std::int8_t value) {
    write_u8(static_cast<std::uint8_t>(value));
}

void JAMCompactWriter::write_u16(std::uint16_t value) {
    reset_bool_packing();
    buffer_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    buffer_.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

void JAMCompactWriter::write_i16(std::int16_t value) {
    write_u16(static_cast<std::uint16_t>(value));
}

void JAMCompactWriter::write_u32(std::uint32_t value) {
    reset_bool_packing();
    for (unsigned int i = 0; i < 4u; ++i) {
        buffer_.push_back(static_cast<std::uint8_t>((value >> (i * 8u)) & 0xFFu));
    }
}

void JAMCompactWriter::write_i32(std::int32_t value) {
    write_u32(static_cast<std::uint32_t>(value));
}

void JAMCompactWriter::write_u64(std::uint64_t value) {
    reset_bool_packing();
    for (unsigned int i = 0; i < 8u; ++i) {
        buffer_.push_back(static_cast<std::uint8_t>((value >> (i * 8u)) & 0xFFu));
    }
}

void JAMCompactWriter::write_f32(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    write_u32(bits);
}

void JAMCompactWriter::write_f64(double value) {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    write_u64(bits);
}

void JAMCompactWriter::write_string(std::string_view str) {
    // Matches 0x0C at +0xF2C9F0: uint32_t length + UTF-8 bytes
    write_u32(static_cast<std::uint32_t>(str.size()));
    buffer_.insert(buffer_.end(), str.begin(), str.end());
}

void JAMCompactWriter::write_fixed_bytes(std::span<const std::uint8_t> bytes) {
    reset_bool_packing();
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
}

bool JAMCompactReader::read_bool(bool& out_value) noexcept {
    // Matches +0xF2C916: bit_pos at [stream + 0x20], bool_byte at [stream + 0x21]
    if (bit_pos_ == 0u) {
        if (remaining() < 1u) {
            return false;
        }
        bool_byte_ = buffer_[cursor_++];
    }
    out_value = ((bool_byte_ >> bit_pos_) & 1u) != 0u;
    bit_pos_ = static_cast<std::uint8_t>((bit_pos_ + 1u) & 7u);
    return true;
}

bool JAMCompactReader::read_u8(std::uint8_t& out_value) noexcept {
    reset_bool_packing();
    if (remaining() < 1u) {
        return false;
    }
    out_value = buffer_[cursor_++];
    return true;
}

bool JAMCompactReader::read_i8(std::int8_t& out_value) noexcept {
    std::uint8_t u = 0;
    if (!read_u8(u)) {
        return false;
    }
    out_value = static_cast<std::int8_t>(u);
    return true;
}

bool JAMCompactReader::read_u16(std::uint16_t& out_value) noexcept {
    reset_bool_packing();
    if (remaining() < 2u) {
        return false;
    }
    out_value = static_cast<std::uint16_t>(buffer_[cursor_]) |
                static_cast<std::uint16_t>(static_cast<std::uint16_t>(buffer_[cursor_ + 1u]) << 8u);
    cursor_ += 2u;
    return true;
}

bool JAMCompactReader::read_i16(std::int16_t& out_value) noexcept {
    std::uint16_t u = 0;
    if (!read_u16(u)) {
        return false;
    }
    out_value = static_cast<std::int16_t>(u);
    return true;
}

bool JAMCompactReader::read_u32(std::uint32_t& out_value) noexcept {
    reset_bool_packing();
    if (remaining() < 4u) {
        return false;
    }
    out_value = (static_cast<std::uint32_t>(buffer_[cursor_ + 0u]))        |
                (static_cast<std::uint32_t>(buffer_[cursor_ + 1u]) << 8u)  |
                (static_cast<std::uint32_t>(buffer_[cursor_ + 2u]) << 16u) |
                (static_cast<std::uint32_t>(buffer_[cursor_ + 3u]) << 24u);
    cursor_ += 4u;
    return true;
}

bool JAMCompactReader::read_i32(std::int32_t& out_value) noexcept {
    std::uint32_t u = 0;
    if (!read_u32(u)) {
        return false;
    }
    out_value = static_cast<std::int32_t>(u);
    return true;
}

bool JAMCompactReader::read_u64(std::uint64_t& out_value) noexcept {
    reset_bool_packing();
    if (remaining() < 8u) {
        return false;
    }
    std::uint64_t val = 0;
    for (unsigned int i = 0; i < 8u; ++i) {
        val |= (static_cast<std::uint64_t>(buffer_[cursor_ + i]) << (i * 8u));
    }
    cursor_ += 8u;
    out_value = val;
    return true;
}

bool JAMCompactReader::read_f32(float& out_value) noexcept {
    std::uint32_t bits = 0;
    if (!read_u32(bits)) {
        return false;
    }
    std::memcpy(&out_value, &bits, sizeof(out_value));
    return true;
}

bool JAMCompactReader::read_f64(double& out_value) noexcept {
    std::uint64_t bits = 0;
    if (!read_u64(bits)) {
        return false;
    }
    std::memcpy(&out_value, &bits, sizeof(out_value));
    return true;
}

bool JAMCompactReader::read_string(std::string& out_str) {
    std::uint32_t len = 0;
    if (!read_u32(len) || remaining() < len) {
        return false;
    }
    out_str.assign(reinterpret_cast<const char*>(buffer_.data() + cursor_), len);
    cursor_ += len;
    return true;
}

bool JAMCompactReader::read_fixed_bytes(std::span<std::uint8_t> out_bytes) noexcept {
    reset_bool_packing();
    if (remaining() < out_bytes.size()) {
        return false;
    }
    if (!out_bytes.empty()) {
        std::memcpy(out_bytes.data(), buffer_.data() + cursor_, out_bytes.size());
        cursor_ += out_bytes.size();
    }
    return true;
}

void JAM_ClientInLobbyInstance_0x5078::serialize_compact(JAMCompactWriter& writer) const {
    writer.write_u64(m_instanceId);
    writer.write_string(m_address);
    writer.write_u16(m_udpPort);
    writer.write_u32(m_connectionToken);
    writer.write_fixed_bytes(m_secretKey);
    writer.write_u64(m_gameServerAddressA);
    writer.write_u64(m_gameServerAddressB);
}

bool JAM_ClientInLobbyInstance_0x5078::deserialize_compact(JAMCompactReader& reader) {
    return reader.read_u64(m_instanceId) &&
           reader.read_string(m_address) &&
           reader.read_u16(m_udpPort) &&
           reader.read_u32(m_connectionToken) &&
           reader.read_fixed_bytes(m_secretKey) &&
           reader.read_u64(m_gameServerAddressA) &&
           reader.read_u64(m_gameServerAddressB);
}

} // namespace olympus::codec::v24919
