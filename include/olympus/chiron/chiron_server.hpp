#pragma once

#include <cstdint>
#include <vector>

namespace olympus::chiron {

struct ChironConfig {
    std::uint16_t udp_port{26503};
    double        tick_rate_hz{62.5}; // Native 62.5 Hz (16.0 ms fixed dt), scalable to 125/250 Hz (Q4)

    [[nodiscard]] constexpr float fixed_dt_seconds() const noexcept {
        return static_cast<float>(1.0 / tick_rate_hz);
    }
};

// Plane 2: Simulation Plane & Protocol-Agnostic Sparse-Set ECS Core
class ChironServer {
public:
    explicit ChironServer(ChironConfig config = {}) noexcept
        : config_(config) {}

    void step_tick() noexcept {
        ++current_command_frame_;
    }

    [[nodiscard]] const ChironConfig& config() const noexcept { return config_; }
    [[nodiscard]] std::uint32_t current_command_frame() const noexcept { return current_command_frame_; }

private:
    ChironConfig  config_;
    std::uint32_t current_command_frame_{0};
};

} // namespace olympus::chiron
