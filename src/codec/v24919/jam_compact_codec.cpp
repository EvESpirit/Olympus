#include "olympus/codec/v24919/jam_compact_codec.hpp"

#include <cstring>

namespace olympus::codec::v24919 {

void JAMCompactWriter::write_bool(bool value) {
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

void JAMCompactWriter::write_cstring(std::string_view str) {
    // Matches 0x0C (+0xF2C996 -> +0xE49660) & 0x0D (+0xF2C9D0 -> +0xE495E0):
    // NUL-terminated C-string on the wire!
    reset_bool_packing();
    for (char c : str) {
        if (c == '\0') break;
        buffer_.push_back(static_cast<std::uint8_t>(c));
    }
    buffer_.push_back(0u);
}

void JAMCompactWriter::write_length_prefixed_blob(std::span<const std::uint8_t> blob) {
    // Matches 0x0F (+0xF2C9F0 -> +0xE4A360): uint32_t byte_len + raw bytes
    write_u32(static_cast<std::uint32_t>(blob.size()));
    buffer_.insert(buffer_.end(), blob.begin(), blob.end());
}

void JAMCompactWriter::write_routing_address(const JAMRoutingAddress& addr) {
    // Matches 0x10 (+0xF2CA67): 1B tag (1..5) followed by 1, 2, 4, 8, or 16 bytes
    const std::uint8_t valid_type = (addr.addr_type >= 1u && addr.addr_type <= 5u) ? addr.addr_type : 1u;
    write_u8(valid_type);
    JAMRoutingAddress copy = addr;
    copy.addr_type = valid_type;
    const std::size_t len = copy.wire_byte_length();
    buffer_.insert(buffer_.end(), copy.bytes.begin(), copy.bytes.begin() + len);
}

void JAMCompactWriter::write_fixed_bytes(std::span<const std::uint8_t> bytes) {
    reset_bool_packing();
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
}

bool JAMCompactReader::read_bool(bool& out_value) noexcept {
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

bool JAMCompactReader::read_cstring(std::string& out_str, std::size_t max_len) {
    // Matches +0xE49660 (0x0C) and +0xE495E0 (0x0D): scans for NUL terminator '\0'
    reset_bool_packing();
    const std::size_t rem = remaining();
    const std::size_t limit = (max_len > 0u && max_len < rem) ? max_len : rem;
    std::size_t len = 0u;
    while (len < limit && buffer_[cursor_ + len] != 0u) {
        ++len;
    }
    if (len >= rem || buffer_[cursor_ + len] != 0u) {
        return false;
    }
    out_str.assign(reinterpret_cast<const char*>(buffer_.data() + cursor_), len);
    cursor_ += (len + 1u); // Advance past NUL byte
    return true;
}

bool JAMCompactReader::read_length_prefixed_blob(std::vector<std::uint8_t>& out_blob) {
    // Matches 0x0F (+0xF2C9F0): uint32_t byte_len + raw bytes
    std::uint32_t len = 0;
    if (!read_u32(len) || remaining() < len) {
        return false;
    }
    out_blob.assign(
        buffer_.begin() + static_cast<std::ptrdiff_t>(cursor_),
        buffer_.begin() + static_cast<std::ptrdiff_t>(cursor_ + len));
    cursor_ += len;
    return true;
}

bool JAMCompactReader::read_routing_address(JAMRoutingAddress& out_addr) noexcept {
    std::uint8_t tag = 0;
    if (!read_u8(tag) || tag < 1u || tag > 5u) {
        return false;
    }
    out_addr = JAMRoutingAddress{};
    out_addr.addr_type = tag;
    const std::size_t len = out_addr.wire_byte_length();
    if (remaining() < len) {
        return false;
    }
    std::memcpy(out_addr.bytes.data(), buffer_.data() + cursor_, len);
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

bool JAMCompactReader::read_remaining_bytes(std::vector<std::uint8_t>& out_bytes) {
    reset_bool_packing();
    const std::size_t rem = remaining();
    out_bytes.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(cursor_), buffer_.end());
    cursor_ += rem;
    return true;
}

// ------------------------------------------------------------------------------
// JAMObject Accessors
// ------------------------------------------------------------------------------
std::uint64_t JAMObject::get_uint(std::uint32_t offset, std::uint64_t fallback) const noexcept {
    auto it = fields.find(offset);
    if (it == fields.end()) return fallback;
    if (const auto* s = std::get_if<JAMScalarValue>(&it->second)) {
        if (const auto* v = std::get_if<std::uint64_t>(s)) return *v;
        if (const auto* sub = std::get_if<JAMObject>(s)) return sub->get_uint(0u, fallback);
    }
    return fallback;
}

bool JAMObject::get_bool(std::uint32_t offset, bool fallback) const noexcept {
    auto it = fields.find(offset);
    if (it == fields.end()) return fallback;
    if (const auto* s = std::get_if<JAMScalarValue>(&it->second)) {
        if (const auto* v = std::get_if<bool>(s)) return *v;
    }
    return fallback;
}

double JAMObject::get_float(std::uint32_t offset, double fallback) const noexcept {
    auto it = fields.find(offset);
    if (it == fields.end()) return fallback;
    if (const auto* s = std::get_if<JAMScalarValue>(&it->second)) {
        if (const auto* v = std::get_if<double>(s)) return *v;
    }
    return fallback;
}

std::string_view JAMObject::get_string(std::uint32_t offset) const noexcept {
    auto it = fields.find(offset);
    if (it == fields.end()) return {};
    if (const auto* s = std::get_if<JAMScalarValue>(&it->second)) {
        if (const auto* v = std::get_if<std::string>(s)) return *v;
    }
    return {};
}

const JAMObject* JAMObject::get_struct(std::uint32_t offset) const noexcept {
    auto it = fields.find(offset);
    if (it == fields.end()) return nullptr;
    if (const auto* s = std::get_if<JAMScalarValue>(&it->second)) {
        return std::get_if<JAMObject>(s);
    }
    return nullptr;
}

const std::vector<JAMScalarValue>* JAMObject::get_array(std::uint32_t offset) const noexcept {
    auto it = fields.find(offset);
    if (it == fields.end()) return nullptr;
    return std::get_if<std::vector<JAMScalarValue>>(&it->second);
}

// ------------------------------------------------------------------------------
// Table-Driven Compact Binary Engine (+0xF2CE00 / +0xF2C7D0)
// ------------------------------------------------------------------------------
namespace {

bool write_single_element(
    JAMCompactWriter& writer,
    const JAMFieldDesc& field,
    const JAMScalarValue* val_opt) {

    const auto get_u64 = [&]() noexcept -> std::uint64_t {
        if (val_opt) {
            if (const auto* u = std::get_if<std::uint64_t>(val_opt)) return *u;
        }
        return 0ull;
    };

    switch (field.field_type) {
        case JAMFieldType::BoolBitPacked: {
            bool b = false;
            if (val_opt) {
                if (const auto* bv = std::get_if<bool>(val_opt)) b = *bv;
            }
            writer.write_bool(b);
            return true;
        }
        case JAMFieldType::Int8:
        case JAMFieldType::UInt8:
        case JAMFieldType::Char8:
            writer.write_u8(static_cast<std::uint8_t>(get_u64() & 0xFFu));
            return true;
        case JAMFieldType::Int16LE:
        case JAMFieldType::UInt16LE:
            writer.write_u16(static_cast<std::uint16_t>(get_u64() & 0xFFFFu));
            return true;
        case JAMFieldType::Int32LE:
        case JAMFieldType::UInt32LE:
            writer.write_u32(static_cast<std::uint32_t>(get_u64() & 0xFFFFFFFFu));
            return true;
        case JAMFieldType::Int64LE:
        case JAMFieldType::UInt64LE:
            writer.write_u64(get_u64());
            return true;
        case JAMFieldType::Float32LE: {
            float f = 0.0f;
            if (val_opt) {
                if (const auto* dv = std::get_if<double>(val_opt)) f = static_cast<float>(*dv);
            }
            writer.write_f32(f);
            return true;
        }
        case JAMFieldType::Float64LE: {
            double d = 0.0;
            if (val_opt) {
                if (const auto* dv = std::get_if<double>(val_opt)) d = *dv;
            }
            writer.write_f64(d);
            return true;
        }
        case JAMFieldType::CStringTeString:
        case JAMFieldType::CStringFixedBuf: {
            std::string_view sv{};
            if (val_opt) {
                if (const auto* s = std::get_if<std::string>(val_opt)) sv = *s;
            }
            if (field.field_type == JAMFieldType::CStringFixedBuf && field.element_size > 0u &&
                sv.size() >= field.element_size) {
                sv = sv.substr(0u, field.element_size - 1u);
            }
            writer.write_cstring(sv);
            return true;
        }
        case JAMFieldType::NestedStruct: {
            if (!field.sub_schema) return false;
            if (val_opt) {
                if (const auto* sub = std::get_if<JAMObject>(val_opt)) {
                    return serialize_jam_schema(writer, field.sub_schema, *sub);
                }
                if (const auto* u = std::get_if<std::uint64_t>(val_opt)) {
                    JAMObject wrapper{};
                    wrapper.set_uint(0u, *u);
                    return serialize_jam_schema(writer, field.sub_schema, wrapper);
                }
            }
            const JAMObject empty_sub{};
            return serialize_jam_schema(writer, field.sub_schema, empty_sub);
        }
        case JAMFieldType::LengthPrefixedBlob: {
            if (val_opt) {
                if (const auto* b = std::get_if<std::vector<std::uint8_t>>(val_opt)) {
                    writer.write_length_prefixed_blob(*b);
                    return true;
                }
            }
            writer.write_length_prefixed_blob({});
            return true;
        }
        case JAMFieldType::RoutingAddress: {
            JAMRoutingAddress addr{};
            if (val_opt) {
                if (const auto* a = std::get_if<JAMRoutingAddress>(val_opt)) addr = *a;
            }
            writer.write_routing_address(addr);
            return true;
        }
        default:
            return false;
    }
}

bool read_single_element(
    JAMCompactReader& reader,
    const JAMFieldDesc& field,
    JAMScalarValue& out_val) {

    switch (field.field_type) {
        case JAMFieldType::BoolBitPacked: {
            bool v = false;
            if (!reader.read_bool(v)) return false;
            out_val = v;
            return true;
        }
        case JAMFieldType::Int8: {
            std::int8_t v = 0;
            if (!reader.read_i8(v)) return false;
            out_val = static_cast<std::uint64_t>(static_cast<std::int64_t>(v));
            return true;
        }
        case JAMFieldType::UInt8:
        case JAMFieldType::Char8: {
            std::uint8_t v = 0;
            if (!reader.read_u8(v)) return false;
            out_val = static_cast<std::uint64_t>(v);
            return true;
        }
        case JAMFieldType::Int16LE: {
            std::int16_t v = 0;
            if (!reader.read_i16(v)) return false;
            out_val = static_cast<std::uint64_t>(static_cast<std::int64_t>(v));
            return true;
        }
        case JAMFieldType::UInt16LE: {
            std::uint16_t v = 0;
            if (!reader.read_u16(v)) return false;
            out_val = static_cast<std::uint64_t>(v);
            return true;
        }
        case JAMFieldType::Int32LE: {
            std::int32_t v = 0;
            if (!reader.read_i32(v)) return false;
            out_val = static_cast<std::uint64_t>(static_cast<std::int64_t>(v));
            return true;
        }
        case JAMFieldType::UInt32LE: {
            std::uint32_t v = 0;
            if (!reader.read_u32(v)) return false;
            out_val = static_cast<std::uint64_t>(v);
            return true;
        }
        case JAMFieldType::Int64LE:
        case JAMFieldType::UInt64LE: {
            std::uint64_t v = 0;
            if (!reader.read_u64(v)) return false;
            out_val = v;
            return true;
        }
        case JAMFieldType::Float32LE: {
            float v = 0.0f;
            if (!reader.read_f32(v)) return false;
            out_val = static_cast<double>(v);
            return true;
        }
        case JAMFieldType::Float64LE: {
            double v = 0.0;
            if (!reader.read_f64(v)) return false;
            out_val = v;
            return true;
        }
        case JAMFieldType::CStringTeString: {
            std::string s;
            if (!reader.read_cstring(s, 0u)) return false;
            out_val = std::move(s);
            return true;
        }
        case JAMFieldType::CStringFixedBuf: {
            std::string s;
            if (!reader.read_cstring(s, field.element_size)) return false;
            out_val = std::move(s);
            return true;
        }
        case JAMFieldType::NestedStruct: {
            if (!field.sub_schema) return false;
            JAMObject sub{};
            if (!deserialize_jam_schema(reader, field.sub_schema, sub)) return false;
            out_val = std::move(sub);
            return true;
        }
        case JAMFieldType::LengthPrefixedBlob: {
            std::vector<std::uint8_t> b;
            if (!reader.read_length_prefixed_blob(b)) return false;
            out_val = std::move(b);
            return true;
        }
        case JAMFieldType::RoutingAddress: {
            JAMRoutingAddress addr{};
            if (!reader.read_routing_address(addr)) return false;
            out_val = addr;
            return true;
        }
        default:
            return false;
    }
}

} // namespace

bool serialize_jam_schema(
    JAMCompactWriter& writer,
    const JAMFieldDesc* schema,
    const JAMObject& obj) {

    if (!schema) return false;
    for (const JAMFieldDesc* f = schema; f->field_type != JAMFieldType::EndOfFields; ++f) {
        auto it = obj.fields.find(f->struct_offset);
        if (f->array_count == 0) {
            // Case 1: Scalar (+0xF2C7D0)
            const JAMScalarValue* s_ptr = (it != obj.fields.end())
                                              ? std::get_if<JAMScalarValue>(&it->second)
                                              : nullptr;
            if (!write_single_element(writer, *f, s_ptr)) return false;
        } else if (f->array_count > 0) {
            // Case 2: Fixed Array T[N] (+0xF2CD50)
            // Fast path for uint8_t[N] / int8_t[N] stored as vector<uint8_t>
            if ((f->field_type == JAMFieldType::UInt8 || f->field_type == JAMFieldType::Int8) &&
                it != obj.fields.end()) {
                if (const auto* s_ptr = std::get_if<JAMScalarValue>(&it->second)) {
                    if (const auto* b_vec = std::get_if<std::vector<std::uint8_t>>(s_ptr)) {
                        std::vector<std::uint8_t> fixed(static_cast<std::size_t>(f->array_count), 0u);
                        const std::size_t n = std::min(fixed.size(), b_vec->size());
                        std::memcpy(fixed.data(), b_vec->data(), n);
                        writer.write_fixed_bytes(fixed);
                        continue;
                    }
                }
            }
            const auto* arr_ptr = (it != obj.fields.end())
                                      ? std::get_if<std::vector<JAMScalarValue>>(&it->second)
                                      : nullptr;
            for (std::int32_t i = 0; i < f->array_count; ++i) {
                const JAMScalarValue* elem = (arr_ptr && static_cast<std::size_t>(i) < arr_ptr->size())
                                                 ? &(*arr_ptr)[static_cast<std::size_t>(i)]
                                                 : nullptr;
                if (!write_single_element(writer, *f, elem)) return false;
            }
        } else if (f->array_count == -1) {
            // Case 3: Dynamic teList<T> (+0xF2CC70) -> resets bit_pos and writes u32 count
            const auto* arr_ptr = (it != obj.fields.end())
                                      ? std::get_if<std::vector<JAMScalarValue>>(&it->second)
                                      : nullptr;
            const std::uint32_t count = arr_ptr ? static_cast<std::uint32_t>(arr_ptr->size()) : 0u;
            writer.write_u32(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                if (!write_single_element(writer, *f, &(*arr_ptr)[i])) return false;
            }
        } else {
            return false;
        }
    }
    return true;
}

bool deserialize_jam_schema(
    JAMCompactReader& reader,
    const JAMFieldDesc* schema,
    JAMObject& out_obj) {

    if (!schema) return false;
    out_obj.fields.clear();

    for (const JAMFieldDesc* f = schema; f->field_type != JAMFieldType::EndOfFields; ++f) {
        if (f->array_count == 0) {
            JAMScalarValue val{};
            if (!read_single_element(reader, *f, val)) return false;
            out_obj.fields[f->struct_offset] = std::move(val);
        } else if (f->array_count > 0) {
            std::vector<JAMScalarValue> arr;
            arr.reserve(static_cast<std::size_t>(f->array_count));
            for (std::int32_t i = 0; i < f->array_count; ++i) {
                JAMScalarValue elem{};
                if (!read_single_element(reader, *f, elem)) return false;
                arr.push_back(std::move(elem));
            }
            out_obj.fields[f->struct_offset] = std::move(arr);
        } else if (f->array_count == -1) {
            std::uint32_t count = 0;
            if (!reader.read_u32(count)) return false;
            std::vector<JAMScalarValue> arr;
            arr.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                JAMScalarValue elem{};
                if (!read_single_element(reader, *f, elem)) return false;
                arr.push_back(std::move(elem));
            }
            out_obj.fields[f->struct_offset] = std::move(arr);
        } else {
            return false;
        }
    }
    return true;
}

void JAM_ClientInLobbyInstance_0x5078::serialize_compact(JAMCompactWriter& writer) const {
    writer.write_u64(m_instanceId);
    writer.write_cstring(m_address);
    writer.write_u16(m_udpPort);
    writer.write_u32(m_connectionToken);
    writer.write_fixed_bytes(m_secretKey);
    writer.write_u64(m_gameServerAddressA);
    writer.write_u64(m_gameServerAddressB);
}

bool JAM_ClientInLobbyInstance_0x5078::deserialize_compact(JAMCompactReader& reader) {
    return reader.read_u64(m_instanceId) &&
           reader.read_cstring(m_address) &&
           reader.read_u16(m_udpPort) &&
           reader.read_u32(m_connectionToken) &&
           reader.read_fixed_bytes(m_secretKey) &&
           reader.read_u64(m_gameServerAddressA) &&
           reader.read_u64(m_gameServerAddressB);
}

JAMObject JAM_ClientInLobbyInstance_0x5078::to_jam_object() const {
    JAMObject obj{};
    obj.set_uint(0x68, m_instanceId);
    obj.set_string(0x70, m_address);
    obj.set_uint(0x80, m_udpPort);
    obj.set_uint(0x84, m_connectionToken);
    obj.set_bytes(0x88, m_secretKey);

    JAMObject sub_addr{};
    sub_addr.set_uint(0x00, m_gameServerAddressA);
    sub_addr.set_uint(0x08, m_gameServerAddressB);
    obj.set_struct(0xA0, std::move(sub_addr));
    return obj;
}

} // namespace olympus::codec::v24919
