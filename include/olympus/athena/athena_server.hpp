#pragma once

#include <cstdint>
#include <string>

#include "olympus/codec/v24919/hmac_sha1_96.hpp"
#include "olympus/codec/v24919/jam_compact_codec.hpp"

namespace olympus::athena {

struct AthenaConfig {
    std::string   bind_address{"0.0.0.0"};
    std::uint16_t bgs_tls_port{1119};
    std::string   chiron_public_ip{"127.0.0.1"};
    std::uint16_t chiron_udp_port{26503};
};

// Plane 1: Control Plane (Aurora BGS TLS + 31 Lobby JAM Protocol Pools)
class AthenaServer {
public:
    explicit AthenaServer(AthenaConfig config = {}) noexcept
        : config_(std::move(config)) {}

    [[nodiscard]] const AthenaConfig& config() const noexcept { return config_; }

    // Builds the authoritative ClientInLobbyInstance (0x5078) handoff payload
    // that transitions GameClientApp.exe (+0xC7D580 -> +0xC6FAB0 -> +0xE52CE0)
    // onto Chiron's UDP Simulation Plane.
    [[nodiscard]] codec::v24919::JAM_ClientInLobbyInstance_0x5078 build_instance_handoff(
        std::uint64_t instance_id,
        std::uint32_t session_token_28bit,
        std::span<const std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> hmac_key) const;

private:
    AthenaConfig config_;
};

} // namespace olympus::athena
