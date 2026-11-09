#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace olympus::codec::v24919 {

// Exact field type IDs from Jump Table +0xF2CC28 in +0xF2C7D0..+0xF2CE00
enum class JAMFieldType : std::uint32_t {
    Int8           = 0x01, // 1 byte
    UInt8          = 0x02, // 1 byte
    BoolBitPacked  = 0x03, // 1-bit packed! Up to 8 consecutive bools pack into 1 wire byte (+0xF2C916)
    UInt16LE       = 0x04, // 2 bytes LE
    Int16LE        = 0x05, // 2 bytes LE
    UInt32LE       = 0x06, // 4 bytes LE
    Int32LE        = 0x07, // 4 bytes LE
    UInt64LE       = 0x08, // 8 bytes LE
    Float32LE      = 0x09, // 4 bytes LE
    Enum32LE       = 0x0A, // 4 bytes LE
    Float64LE      = 0x0B, // 8 bytes LE
    StringOrGuid   = 0x0C, // u32 len + UTF-8 bytes (+0xF2C9F0)
    RoutingAddress = 0x0D, // u8 tag (1..5) + 1/2/4/8/16 bytes (+0xF2CA67)
    NestedStruct   = 0x0E, // Recurses into +0xF2CE00 with sub_schema (+0xF2C9BA)
    RemainingBlob  = 0x0F, // Remaining bytes in frame (+0xF2C996)
    FixedByteBlob  = 0x10, // Reads element_size raw bytes (+0xF2C9D0)
    EndOfFields    = 0x11  // Terminator
};

// Verified in GameClientApp.decrypted.bin (.data RVA 0x1734000..0x1745000, sizeof = 0x28)
struct JAMFieldDesc {
    const char*         field_name{nullptr};      // +0x00
    JAMFieldType        field_type{JAMFieldType::EndOfFields}; // +0x08
    std::uint32_t       struct_offset{0};         // +0x0C
    std::uint32_t       element_size{0};          // +0x10
    std::int32_t        array_count{0};           // +0x14: 0 = scalar, >0 = fixed T[N], -1 = dynamic teList<T>
    const JAMFieldDesc* sub_schema{nullptr};      // +0x18
    void*               array_helper_fn{nullptr}; // +0x20
};

// Verified in GameClientApp.decrypted.bin (sizeof = 0x20)
struct JAMMessageDesc {
    const char*         msg_name{nullptr};      // +0x00
    const char*         proto_name{nullptr};    // +0x08
    const JAMFieldDesc* fields{nullptr};        // +0x10
    std::uint32_t       protocol_hash{0};       // +0x18
    std::uint32_t       opcode{0};              // +0x1C
};

// Stateful JAM stream writer implementing +0xF2CE00 / +0xF2C7D0 compact binary rules
// (specifically bit-packing consecutive 0x03 booleans into a single byte and resetting
// bit_pos = 0 on any non-bool field or dynamic array length).
class JAMCompactWriter {
public:
    void write_bool(bool value);
    void write_u8(std::uint8_t value);
    void write_i8(std::int8_t value);
    void write_u16(std::uint16_t value);
    void write_i16(std::int16_t value);
    void write_u32(std::uint32_t value);
    void write_i32(std::int32_t value);
    void write_u64(std::uint64_t value);
    void write_f32(float value);
    void write_f64(double value);
    void write_string(std::string_view str);
    void write_fixed_bytes(std::span<const std::uint8_t> bytes);

    void reset_bool_packing() noexcept { bit_pos_ = 0; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return buffer_; }

private:
    std::vector<std::uint8_t> buffer_;
    std::uint8_t bit_pos_{0};
    std::size_t bool_byte_index_{0};
};

// Stateful JAM stream reader implementing +0xF2CE00 / +0xF2C7D0 compact binary rules.
class JAMCompactReader {
public:
    explicit JAMCompactReader(std::span<const std::uint8_t> buffer) noexcept
        : buffer_(buffer) {}

    [[nodiscard]] bool read_bool(bool& out_value) noexcept;
    [[nodiscard]] bool read_u8(std::uint8_t& out_value) noexcept;
    [[nodiscard]] bool read_i8(std::int8_t& out_value) noexcept;
    [[nodiscard]] bool read_u16(std::uint16_t& out_value) noexcept;
    [[nodiscard]] bool read_i16(std::int16_t& out_value) noexcept;
    [[nodiscard]] bool read_u32(std::uint32_t& out_value) noexcept;
    [[nodiscard]] bool read_i32(std::int32_t& out_value) noexcept;
    [[nodiscard]] bool read_u64(std::uint64_t& out_value) noexcept;
    [[nodiscard]] bool read_f32(float& out_value) noexcept;
    [[nodiscard]] bool read_f64(double& out_value) noexcept;
    [[nodiscard]] bool read_string(std::string& out_str);
    [[nodiscard]] bool read_fixed_bytes(std::span<std::uint8_t> out_bytes) noexcept;

    void reset_bool_packing() noexcept { bit_pos_ = 0; }
    [[nodiscard]] std::size_t offset() const noexcept { return cursor_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return buffer_.size() - cursor_; }

private:
    std::span<const std::uint8_t> buffer_;
    std::size_t cursor_{0};
    std::uint8_t bit_pos_{0};   // [stream + 0x20]
    std::uint8_t bool_byte_{0}; // [stream + 0x21]
};

// Verified schema struct for ClientInLobbyInstance (Opcode 0x5078, Hash 0x6E5D38B1, +0xC7D580)
struct JAM_ClientInLobbyInstance_0x5078 {
    static constexpr std::uint32_t kProtocolHash = 0x6E5D38B1u;
    static constexpr std::uint32_t kOpcode       = 0x5078u;

    std::uint64_t m_instanceId{0};                    // +0x68 (type 0x08)
    std::string   m_address{"127.0.0.1"};             // +0x70 (type 0x0C)
    std::uint16_t m_udpPort{0};                       // +0x80 (type 0x04)
    std::uint32_t m_connectionToken{0};               // +0x84 (type 0x06)
    std::uint8_t  m_secretKey[20]{};                  // +0x88 (type 0x02, array_count = 20)
    std::uint64_t m_gameServerAddressA{0};            // +0xA0 (type 0x0E sub-schema)
    std::uint64_t m_gameServerAddressB{0};            // +0xA8

    void serialize_compact(JAMCompactWriter& writer) const;
    [[nodiscard]] bool deserialize_compact(JAMCompactReader& reader);
};

} // namespace olympus::codec::v24919
