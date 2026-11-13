#include <cstdio>

#include "olympus/athena/athena_server.hpp"
#include "olympus/chiron/chiron_server.hpp"
#include "olympus/codec/v24919/gcm_udp_header.hpp"

int main() {
    olympus::athena::AthenaServer athena{};
    olympus::chiron::ChironServer chiron{};

    std::printf("[Olympus] Sovereign Dedicated Server Suite (Target: Overwatch 0.8.0.24919)\n");
    std::printf("[Athena]  Control Plane configured on BGS TCP+TLS %s:%u | JAM Lobby TCP %s:%u (Client JAMListener: %s:%u)\n",
                athena.config().bind_address.c_str(),
                athena.config().bgs_tls_port,
                athena.config().bind_address.c_str(),
                athena.config().jam_lobby_port,
                athena.config().client_jam_listener_host.c_str(),
                athena.config().client_jam_listener_port);
    std::printf("[Chiron]  Simulation Plane configured on UDP %s:%u (Tickrate: %.1f Hz, dt = %.4fs)\n",
                athena.config().chiron_public_ip.c_str(),
                chiron.config().udp_port,
                chiron.config().tick_rate_hz,
                chiron.config().fixed_dt_seconds());
    return 0;
}
