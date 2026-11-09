#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace olympus::codec::v24919 {

// Bit-level reader matching GameClientApp.exe BitStreamReader (+0xE490E0 / +0x833380).
class BitStreamReader {
public:
    explicit BitStreamReader(std::span<const std::uint8_t> buffer) noexcept
        : buffer_(buffer), bit_offset_(0) {}

    [[nodiscard]] bool read_bit(bool& out_bit) noexcept;
    [[nodiscard]] bool read_bits(std::uint32_t bit_count, std::uint64_t& out_value) noexcept;
    [[nodiscard]] bool read_bytes_aligned(std::span<std::uint8_t> out_bytes) noexcept;

    void align_to_byte() noexcept {
        if ((bit_offset_ & 7u) != 0u) {
            bit_offset_ = (bit_offset_ + 7u) & ~std::size_t{7u};
        }
    }

    [[nodiscard]] std::size_t bit_offset() const noexcept { return bit_offset_; }
    [[nodiscard]] std::size_t total_bits() const noexcept { return buffer_.size() * 8u; }
    [[nodiscard]] std::size_t remaining_bits() const noexcept {
        return (bit_offset_ <= total_bits()) ? (total_bits() - bit_offset_) : 0u;
    }

private:
    std::span<const std::uint8_t> buffer_;
    std::size_t bit_offset_;
};

// Bit-level writer matching GameClientApp.exe BitStreamWriter (+0xE49080 / +0xE492E0).
class BitStreamWriter {
public:
    explicit BitStreamWriter(std::size_t max_bytes = 1302u)
        : buffer_(), bit_offset_(0), max_bits_(max_bytes * 8u) {
        buffer_.reserve(max_bytes);
    }

    [[nodiscard]] bool write_bit(bool bit) noexcept;
    [[nodiscard]] bool write_bits(std::uint64_t value, std::uint32_t bit_count) noexcept;
    [[nodiscard]] bool write_bytes_aligned(std::span<const std::uint8_t> bytes) noexcept;

    void align_to_byte() noexcept {
        if ((bit_offset_ & 7u) != 0u) {
            bit_offset_ = (bit_offset_ + 7u) & ~std::size_t{7u};
        }
    }

    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return buffer_; }
    [[nodiscard]] std::size_t bit_offset() const noexcept { return bit_offset_; }
    [[nodiscard]] std::size_t remaining_bits() const noexcept {
        return (bit_offset_ <= max_bits_) ? (max_bits_ - bit_offset_) : 0u;
    }

private:
    std::vector<std::uint8_t> buffer_;
    std::size_t bit_offset_;
    std::size_t max_bits_;
};

} // namespace olympus::codec::v24919
