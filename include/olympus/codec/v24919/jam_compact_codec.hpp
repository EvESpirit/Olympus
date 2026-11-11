#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace olympus::codec::v24919 {

// Exact field type IDs from 17-entry Jump Table +0xF2CC28 in +0xF2C7D0..+0xF2CE00
enum class JAMFieldType : std::uint32_t {
    BoolBitPacked       = 0x00, // +0xF2C916: 1-bit packed! Up to 8 consecutive 0x00 bools pack into 1 wire byte
    Int8                = 0x01, // +0xF2C802: 1 byte
    UInt8               = 0x02, // +0xF2C802: 1 byte
    Char8               = 0x03, // +0xF2C802: 1 byte
    Int16LE             = 0x04, // +0xF2C846: 2 bytes LE
    UInt16LE            = 0x05, // +0xF2C846: 2 bytes LE
    Int32LE             = 0x06, // +0xF2C88C: 4 bytes LE
    UInt32LE            = 0x07, // +0xF2C88C: 4 bytes LE
    Int64LE             = 0x08, // +0xF2C8D0: 8 bytes LE
    UInt64LE            = 0x09, // +0xF2C8D0: 8 bytes LE
    Float32LE           = 0x0A, // +0xF2C88C: 4 bytes LE
    Float64LE           = 0x0B, // +0xF2C8D0: 8 bytes LE
    CStringTeString     = 0x0C, // +0xF2C996 -> +0xE49660: NUL-terminated '\0' C-string on wire -> teString
    CStringFixedBuf     = 0x0D, // +0xF2C9D0 -> +0xE495E0: NUL-terminated '\0' C-string on wire -> char[element_size]
    NestedStruct        = 0x0E, // +0xF2C9BA -> +0xF2CE00: Recurses into +0xF2CE00 with sub_schema
    LengthPrefixedBlob  = 0x0F, // +0xF2C9F0 -> +0xE4A360: u32 byte_len + raw bytes
    RoutingAddress      = 0x10, // +0xF2CA67: u8 tag (1..5) + 1/2/4/8/16 bytes
    EndOfFields         = 0x11  // +0xF2CE0F: Terminator
};

// Tagged routing address matching 0x0D at +0xF2CA67
struct JAMRoutingAddress {
    std::uint8_t               addr_type{1}; // 1=1B, 2=2B, 3=4B, 4=8B, 5=16B
    std::array<std::uint8_t, 16> bytes{};

    [[nodiscard]] constexpr std::size_t wire_byte_length() const noexcept {
        switch (addr_type) {
            case 1: return 1u;
            case 2: return 2u;
            case 3: return 4u;
            case 4: return 8u;
            case 5: return 16u;
            default: return 0u;
        }
    }
};

// Verified in GameClientApp.decrypted.bin (.data RVA 0x1709000..0x1814DFF, sizeof = 0x28)
struct JAMFieldDesc {
    const char*         field_name{nullptr};                   // +0x00
    JAMFieldType        field_type{JAMFieldType::EndOfFields}; // +0x08
    std::uint32_t       struct_offset{0};                      // +0x0C
    std::uint32_t       element_size{0};                       // +0x10
    std::int32_t        array_count{0};                        // +0x14: 0 = scalar, >0 = fixed T[N], -1 = dynamic teList<T>
    const JAMFieldDesc* sub_schema{nullptr};                   // +0x18
    void*               array_helper_fn{nullptr};              // +0x20
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
    void write_cstring(std::string_view str);
    void write_length_prefixed_blob(std::span<const std::uint8_t> blob);
    void write_routing_address(const JAMRoutingAddress& addr);
    void write_fixed_bytes(std::span<const std::uint8_t> bytes);

    void reset_bool_packing() noexcept { bit_pos_ = 0; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return buffer_; }
    [[nodiscard]] std::vector<std::uint8_t> take_bytes() noexcept { return std::move(buffer_); }

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
    [[nodiscard]] bool read_cstring(std::string& out_str, std::size_t max_len = 0);
    [[nodiscard]] bool read_length_prefixed_blob(std::vector<std::uint8_t>& out_blob);
    [[nodiscard]] bool read_routing_address(JAMRoutingAddress& out_addr) noexcept;
    [[nodiscard]] bool read_fixed_bytes(std::span<std::uint8_t> out_bytes) noexcept;
    [[nodiscard]] bool read_remaining_bytes(std::vector<std::uint8_t>& out_bytes);

    void reset_bool_packing() noexcept { bit_pos_ = 0; }
    [[nodiscard]] std::size_t offset() const noexcept { return cursor_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return buffer_.size() - cursor_; }

private:
    std::span<const std::uint8_t> buffer_;
    std::size_t cursor_{0};
    std::uint8_t bit_pos_{0};   // [stream + 0x20]
    std::uint8_t bool_byte_{0}; // [stream + 0x21]
};

// ------------------------------------------------------------------------------
// Generic Offset-Keyed Reflective JAMObject (works with all 371 JAMMessageDesc schemas)
// ------------------------------------------------------------------------------
struct JAMObject;

using JAMScalarValue = std::variant<
    bool,
    std::uint64_t,
    double,
    std::string,
    JAMRoutingAddress,
    std::vector<std::uint8_t>,
    JAMObject>;

using JAMFieldStorage = std::variant<
    JAMScalarValue,
    std::vector<JAMScalarValue>>;

struct JAMObject {
    // Keyed by JAMFieldDesc::struct_offset (e.g. 0x68, 0x70, 0x80, 0x84, 0x88, 0xA0)
    std::map<std::uint32_t, JAMFieldStorage> fields;

    void set_bool(std::uint32_t offset, bool v) { fields[offset] = JAMScalarValue{v}; }
    void set_uint(std::uint32_t offset, std::uint64_t v) { fields[offset] = JAMScalarValue{v}; }
    void set_int(std::uint32_t offset, std::int64_t v) { fields[offset] = JAMScalarValue{static_cast<std::uint64_t>(v)}; }
    void set_float(std::uint32_t offset, double v) { fields[offset] = JAMScalarValue{v}; }
    void set_string(std::uint32_t offset, std::string v) { fields[offset] = JAMScalarValue{std::move(v)}; }
    void set_routing_addr(std::uint32_t offset, JAMRoutingAddress v) { fields[offset] = JAMScalarValue{v}; }
    void set_bytes(std::uint32_t offset, std::span<const std::uint8_t> b) {
        fields[offset] = JAMScalarValue{std::vector<std::uint8_t>(b.begin(), b.end())};
    }
    void set_struct(std::uint32_t offset, JAMObject v) { fields[offset] = JAMScalarValue{std::move(v)}; }
    void set_array(std::uint32_t offset, std::vector<JAMScalarValue> arr) { fields[offset] = std::move(arr); }

    [[nodiscard]] std::uint64_t get_uint(std::uint32_t offset, std::uint64_t fallback = 0) const noexcept;
    [[nodiscard]] bool get_bool(std::uint32_t offset, bool fallback = false) const noexcept;
    [[nodiscard]] double get_float(std::uint32_t offset, double fallback = 0.0) const noexcept;
    [[nodiscard]] std::string_view get_string(std::uint32_t offset) const noexcept;
    [[nodiscard]] const JAMObject* get_struct(std::uint32_t offset) const noexcept;
    [[nodiscard]] const std::vector<JAMScalarValue>* get_array(std::uint32_t offset) const noexcept;
};

// Table-driven Compact Binary Serializer & Deserializer (+0xF2CE00 / +0xF2C7D0)
[[nodiscard]] bool serialize_jam_schema(
    JAMCompactWriter& writer,
    const JAMFieldDesc* schema,
    const JAMObject& obj);

[[nodiscard]] bool deserialize_jam_schema(
    JAMCompactReader& reader,
    const JAMFieldDesc* schema,
    JAMObject& out_obj);

// Verified schema struct for ClientInLobbyInstance (Opcode 0x5078, Hash 0x6E5D38B1, +0xC7D580)
struct JAM_ClientInLobbyInstance_0x5078 {
    static constexpr std::uint32_t kProtocolHash = 0x6E5D38B1u;
    static constexpr std::uint32_t kOpcode       = 0x5078u;

    std::uint64_t m_instanceId{0};                    // +0x68 (type 0x08)
    std::string   m_address{"127.0.0.1"};             // +0x70 (type 0x0C)
    std::uint16_t m_udpPort{0};                       // +0x80 (type 0x04)
    std::uint32_t m_connectionToken{0};               // +0x84 (type 0x06)
    std::uint8_t  m_secretKey[20]{};                  // +0x88 (type 0x02, array_count = 20)
    std::uint64_t m_gameServerAddressA{0};            // +0xA0 (type 0x0E sub-schema +0x00)
    std::uint64_t m_gameServerAddressB{0};            // +0xA8 (type 0x0E sub-schema +0x08)

    void serialize_compact(JAMCompactWriter& writer) const;
    [[nodiscard]] bool deserialize_compact(JAMCompactReader& reader);
    [[nodiscard]] JAMObject to_jam_object() const;
};

} // namespace olympus::codec::v24919
