#include "olympus/athena/athena_server.hpp"

#include <cstring>

namespace olympus::athena {

codec::v24919::JAM_ClientInLobbyInstance_0x5078 AthenaServer::build_instance_handoff(
    std::uint64_t instance_id,
    std::uint32_t session_token_28bit,
    std::span<const std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> hmac_key) const {

    codec::v24919::JAM_ClientInLobbyInstance_0x5078 msg{};
    msg.m_instanceId      = instance_id;
    msg.m_address         = config_.chiron_public_ip;
    msg.m_udpPort         = config_.chiron_udp_port;
    msg.m_connectionToken = session_token_28bit & 0x0FFFFFFFu;
    std::memcpy(msg.m_secretKey, hmac_key.data(), codec::v24919::HMAC_SHA1_KEY_SIZE);
    msg.m_gameServerAddressA = instance_id;
    msg.m_gameServerAddressB = 1ull;
    return msg;
}

} // namespace olympus::athena
