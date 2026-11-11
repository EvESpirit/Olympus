#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "olympus/codec/v24919/jam_compact_codec.hpp"

namespace olympus::codec::v24919 {

struct JAMPoolSpec {
    const char*   name{nullptr};
    std::uint32_t protocol_hash{0};
    std::uint32_t start_opcode{0};
    std::uint32_t end_opcode{0};
    std::uint32_t vtable_rva{0};
    std::int32_t  sim_pool_index{-1}; // 0..7 for Simulation Sub-Channel 0 pools, -1 for Lobby/Control pools

    [[nodiscard]] constexpr std::uint32_t message_count() const noexcept {
        return (end_opcode >= start_opcode) ? (end_opcode - start_opcode) : 0u;
    }
};

// Complete static database extracted from GameClientApp.exe 0.8.0.24919 (.rdata & .data)
[[nodiscard]] std::span<const JAMPoolSpec> all_jam_pools() noexcept;
[[nodiscard]] std::span<const JAMMessageDesc> all_jam_messages() noexcept;

[[nodiscard]] const JAMPoolSpec* find_jam_pool_by_hash(std::uint32_t protocol_hash) noexcept;
[[nodiscard]] const JAMPoolSpec* find_jam_pool_by_name(std::string_view name) noexcept;
[[nodiscard]] const JAMPoolSpec* find_sim_jam_pool(std::uint8_t sim_pool_index) noexcept;

[[nodiscard]] const JAMMessageDesc* find_jam_message_by_opcode(std::uint32_t opcode) noexcept;
[[nodiscard]] const JAMMessageDesc* find_jam_message(std::uint32_t protocol_hash, std::uint32_t opcode) noexcept;

} // namespace olympus::codec::v24919