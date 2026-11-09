#include "olympus/codec/v24919/bitstream.hpp"

#include <cstring>

namespace olympus::codec::v24919 {

bool BitStreamReader::read_bit(bool& out_bit) noexcept {
    if (bit_offset_ >= total_bits()) {
        return false;
    }
    const std::size_t byte_idx = bit_offset_ >> 3u;
    const std::size_t bit_idx  = bit_offset_ & 7u;
    out_bit = ((buffer_[byte_idx] >> bit_idx) & 1u) != 0u;
    ++bit_offset_;
    return true;
}

bool BitStreamReader::read_bits(std::uint32_t bit_count, std::uint64_t& out_value) noexcept {
    if (bit_count > 64u || remaining_bits() < bit_count) {
        return false;
    }
    std::uint64_t val = 0;
    for (std::uint32_t i = 0; i < bit_count; ++i) {
        bool b = false;
        if (!read_bit(b)) {
            return false;
        }
        if (b) {
            val |= (std::uint64_t{1u} << i);
        }
    }
    out_value = val;
    return true;
}

bool BitStreamReader::read_bytes_aligned(std::span<std::uint8_t> out_bytes) noexcept {
    align_to_byte();
    const std::size_t byte_idx = bit_offset_ >> 3u;
    if (byte_idx + out_bytes.size() > buffer_.size()) {
        return false;
    }
    if (!out_bytes.empty()) {
        std::memcpy(out_bytes.data(), buffer_.data() + byte_idx, out_bytes.size());
        bit_offset_ += out_bytes.size() * 8u;
    }
    return true;
}

bool BitStreamWriter::write_bit(bool bit) noexcept {
    if (bit_offset_ >= max_bits_) {
        return false;
    }
    const std::size_t byte_idx = bit_offset_ >> 3u;
    const std::size_t bit_idx  = bit_offset_ & 7u;
    if (byte_idx >= buffer_.size()) {
        buffer_.resize(byte_idx + 1u, 0u);
    }
    if (bit) {
        buffer_[byte_idx] |= static_cast<std::uint8_t>(1u << bit_idx);
    }
    ++bit_offset_;
    return true;
}

bool BitStreamWriter::write_bits(std::uint64_t value, std::uint32_t bit_count) noexcept {
    if (bit_count > 64u || remaining_bits() < bit_count) {
        return false;
    }
    for (std::uint32_t i = 0; i < bit_count; ++i) {
        const bool b = ((value >> i) & 1u) != 0u;
        if (!write_bit(b)) {
            return false;
        }
    }
    return true;
}

bool BitStreamWriter::write_bytes_aligned(std::span<const std::uint8_t> bytes) noexcept {
    align_to_byte();
    if (remaining_bits() < bytes.size() * 8u) {
        return false;
    }
    const std::size_t byte_idx = bit_offset_ >> 3u;
    if (byte_idx + bytes.size() > buffer_.size()) {
        buffer_.resize(byte_idx + bytes.size(), 0u);
    }
    if (!bytes.empty()) {
        std::memcpy(buffer_.data() + byte_idx, bytes.data(), bytes.size());
        bit_offset_ += bytes.size() * 8u;
    }
    return true;
}

} // namespace olympus::codec::v24919
