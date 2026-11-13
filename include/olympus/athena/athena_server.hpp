#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "olympus/codec/v24919/hmac_sha1_96.hpp"
#include "olympus/codec/v24919/jam_compact_codec.hpp"
#include "olympus/codec/v24919/jam_schema_db.hpp"
#include "olympus/codec/v24919/jam_transport_framing.hpp"

namespace olympus::athena {

// ------------------------------------------------------------------------------
// 1. JAMConnection 16-Byte Connection ID (kFields_0x172C910 at Base_0x0002 +0x68)
//    Verified at +0xF2208E..+0xF220C4, +0xF2338B..+0xF233CA, +0xC67442, +0x8BBD72:
//    - word0 (+0x00): (uint64_t(resource_type) << 40) | (uint64_t(sub_type) << 32) | instance_uid
//      * LobbyEntityAdmin (+0xC67442) requires ((word0 >> 40) & 0xFFFF) == 0x000D!
//      * DirectoryClient  (+0x8BBD72) requires ((word0 >> 40) & 0xFFFF) == 0x0004!
//    - word1 (+0x08): (uint64_t(ipv4_host_order) << 32) | (uint64_t(port) << 16) | process_id
// ------------------------------------------------------------------------------
struct JAMConnectionId {
    static constexpr std::uint16_t kResourceClient    = 0x0001u;
    static constexpr std::uint16_t kResourceDirectory = 0x0004u;
    static constexpr std::uint16_t kResourceLobby     = 0x000Du;

    std::uint64_t word0{0};
    std::uint64_t word1{0};

    [[nodiscard]] constexpr std::uint16_t resource_type() const noexcept {
        return static_cast<std::uint16_t>((word0 >> 40u) & 0xFFFFu);
    }

    [[nodiscard]] constexpr std::uint8_t sub_type() const noexcept {
        return static_cast<std::uint8_t>((word0 >> 32u) & 0xFFu);
    }

    [[nodiscard]] constexpr std::uint32_t instance_uid() const noexcept {
        return static_cast<std::uint32_t>(word0 & 0xFFFFFFFFu);
    }

    [[nodiscard]] static constexpr JAMConnectionId make(
        std::uint16_t resource_type,
        std::uint8_t  sub_type      = 0x01u,
        std::uint32_t instance_uid  = 1u,
        std::uint32_t ipv4_host     = 0x7F000001u,
        std::uint16_t port          = 13001u,
        std::uint16_t process_id    = 1u) noexcept {

        return JAMConnectionId{
            (static_cast<std::uint64_t>(resource_type) << 40u) |
                (static_cast<std::uint64_t>(sub_type) << 32u) |
                static_cast<std::uint64_t>(instance_uid),
            (static_cast<std::uint64_t>(ipv4_host) << 32u) |
                (static_cast<std::uint64_t>(port) << 16u) |
                static_cast<std::uint64_t>(process_id)
        };
    }

    [[nodiscard]] static constexpr JAMConnectionId make_lobby(
        std::uint16_t port = 13001u,
        std::uint32_t instance_uid = 1u) noexcept {
        return make(kResourceLobby, 0x01u, instance_uid, 0x7F000001u, port, 1u);
    }
};

// ------------------------------------------------------------------------------
// 2. Athena Control Plane Configuration & Session State
// ------------------------------------------------------------------------------
struct AthenaConfig {
    std::string   bind_address{"127.0.0.1"};
    std::uint16_t bgs_tls_port{1119};
    std::uint16_t jam_lobby_port{13001};
    std::string   client_jam_listener_host{"127.0.0.1"};
    std::uint16_t client_jam_listener_port{13000}; // +0x8A2123 default client JAMListener port
    std::string   chiron_public_ip{"127.0.0.1"};
    std::uint16_t chiron_udp_port{26503};
    std::uint32_t required_client_build{24919u};   // [0x1417B8768] checked in ClientOutLobbyConnect_0x5528
    bool          auto_handoff_to_chiron{true};
    std::uint64_t default_instance_id{0x0000000100000001ull};
    std::uint32_t default_session_token_28bit{0x01234567u};
    std::array<std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> default_hmac_key{
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9,
        0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B
    };
};

// Matches both connection directions supported by GameClientApp.exe (+0xF28370 & +0xF281A0):
enum class AthenaSessionRole : std::uint8_t {
    // Athena accepted a TCP connection from GameClientApp.exe (Client is_client=1, state=3):
    // 1. Client sends Base_0x0002 -> 2. Athena replies Base_0x0002 -> 3. Client sends Base_0x0003
    PassiveListener = 0,

    // Athena connected to GameClientApp.exe's local JAMListener on port 13000 (Client is_client=0, state=2):
    // 1. Athena sends Base_0x0002 -> 2. Client replies Base_0x0002 (state=4) -> 3. Athena sends Base_0x0003
    ActiveConnector = 1,
};

enum class AthenaSessionState : std::uint8_t {
    AwaitingPeerHello_0x0002    = 0,
    AwaitingPeerReady_0x0003    = 1,
    AwaitingLobbyConnect_0x5528 = 2,
    LobbyConnected              = 3,
    InstanceHandedOff           = 4,
    Disconnected                = 5,
};

struct AthenaLobbyIdentity {
    std::string   battle_tag{};
    std::uint64_t bgs_account_id{0};
    std::uint64_t bgs_game_account_id{0};
    std::uint32_t build_version{0};
};

struct AthenaReceivedMessage {
    std::uint32_t             protocol_hash{0};
    std::uint32_t             opcode{0};
    std::string_view          pool_name{};
    std::string_view          message_name{};
    codec::v24919::JAMObject  fields{};
};

// Returns the 32 Lobby JAM protocol pools registered by ClientLobbyMessageSystem_C (+0xC66560).
[[nodiscard]] std::vector<codec::v24919::JAMPoolSpec> get_lobby_jam_pools();

// Builds a Base_0x0002 (kFields_0x172CB30) JAMObject from a connection ID and pool list (+0xF265B0).
[[nodiscard]] codec::v24919::JAMObject build_base_0x0002_hello(
    const JAMConnectionId& conn_id,
    std::span<const codec::v24919::JAMPoolSpec> advertised_pools);

// ------------------------------------------------------------------------------
// 3. AthenaJamSession: Deterministic JAMConnection + Lobby Handshake Engine
// ------------------------------------------------------------------------------
class AthenaJamSession {
public:
    explicit AthenaJamSession(
        AthenaConfig config = {},
        AthenaSessionRole role = AthenaSessionRole::PassiveListener);

    [[nodiscard]] AthenaSessionRole role() const noexcept { return role_; }
    [[nodiscard]] AthenaSessionState state() const noexcept { return state_; }
    [[nodiscard]] const JAMConnectionId& local_connection_id() const noexcept { return local_conn_id_; }
    [[nodiscard]] const JAMConnectionId& peer_connection_id() const noexcept { return peer_conn_id_; }
    [[nodiscard]] const std::optional<AthenaLobbyIdentity>& client_identity() const noexcept { return client_identity_; }
    [[nodiscard]] const std::vector<AthenaReceivedMessage>& received_messages() const noexcept { return received_messages_; }

    // Feeds raw bytes received from the TCP socket into the 24-bit Big-Endian frame assembler (+0xE65750)
    // and processes all complete JAM frames. Returns false if a protocol or framing error occurs.
    [[nodiscard]] bool feed_incoming_bytes(std::span<const std::uint8_t> tcp_bytes);

    // Pops the next length-prefixed wire packet (3-byte BE length + JAMStream) ready to send on TCP.
    [[nodiscard]] bool pop_outbound_wire_packet(std::vector<std::uint8_t>& out_packet);
    [[nodiscard]] std::size_t pending_outbound_packets() const noexcept { return outbound_wire_packets_.size(); }

    // Queues any JAM message by full opcode (e.g. 0x0002, 0x0003, 0x5014, 0x5015, 0x5016, 0x5078)
    [[nodiscard]] bool queue_jam_message(
        std::uint32_t opcode,
        const codec::v24919::JAMObject& fields = {});

    // Explicitly queues the ClientInLobbyInstance_0x5078 UDP simulation handoff to Chiron (+0xC7D580)
    [[nodiscard]] bool queue_instance_handoff(
        std::uint64_t instance_id,
        std::uint32_t session_token_28bit,
        std::span<const std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> hmac_key);

    // Initiates a clean JAM disconnect (sends Base_0x0004)
    [[nodiscard]] bool queue_disconnect();

private:
    [[nodiscard]] bool handle_decoded_frame(const codec::v24919::JAMTcpFrame& frame);
    [[nodiscard]] bool handle_base_0x0002(const codec::v24919::JAMObject& msg);
    [[nodiscard]] bool handle_base_0x0003();
    [[nodiscard]] bool handle_lobby_connect_0x5528(const codec::v24919::JAMObject& msg);

    void rebuild_negotiated_pool_maps();

    AthenaConfig                                    config_;
    AthenaSessionRole                               role_;
    AthenaSessionState                              state_;
    JAMConnectionId                                 local_conn_id_;
    JAMConnectionId                                 peer_conn_id_{};
    std::vector<codec::v24919::JAMPoolSpec>         negotiated_pools_; // index i corresponds to wire pool_index = i + 1
    std::unordered_map<std::uint32_t, std::uint8_t> hash_to_pool_index_;
    codec::v24919::JAMTcpStreamAssembler            rx_assembler_;
    std::deque<std::vector<std::uint8_t>>           outbound_wire_packets_;
    std::optional<AthenaLobbyIdentity>              client_identity_{};
    std::vector<AthenaReceivedMessage>              received_messages_;
};

// ------------------------------------------------------------------------------
// 4. Plane 1: AthenaServer (TCP Control Plane Listener & Active Connector)
// ------------------------------------------------------------------------------
class AthenaServer {
public:
    explicit AthenaServer(AthenaConfig config = {}) noexcept;
    ~AthenaServer();

    AthenaServer(const AthenaServer&) = delete;
    AthenaServer& operator=(const AthenaServer&) = delete;

    [[nodiscard]] const AthenaConfig& config() const noexcept { return config_; }

    // Builds the authoritative ClientInLobbyInstance (0x5078) handoff payload
    // that transitions GameClientApp.exe (+0xC7D580 -> +0xC6FAB0 -> +0xE52CE0)
    // onto Chiron's UDP Simulation Plane.
    [[nodiscard]] codec::v24919::JAM_ClientInLobbyInstance_0x5078 build_instance_handoff(
        std::uint64_t instance_id,
        std::uint32_t session_token_28bit,
        std::span<const std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> hmac_key) const;

    // Binds and listens on a non-blocking TCP socket (pass port=0 for OS-assigned ephemeral port).
    [[nodiscard]] bool start_listening(std::uint16_t port_override = 0xFFFFu);
    void stop();

    [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }

    // Actively connects to GameClientApp.exe's local JAMListener (default 127.0.0.1:13000, +0x8A2123)
    // and initiates the ActiveConnector 3-way Base (0x11D82194) + Lobby (0x000D) handshake.
    [[nodiscard]] AthenaJamSession* connect_to_client_jam_listener(
        const std::string& host = "",
        std::uint16_t port = 0u);

    // Non-blocking poll: accepts new connections, reads incoming TCP bytes, and flushes outbound JAM frames.
    void poll_once();

    [[nodiscard]] std::size_t active_session_count() const noexcept;
    [[nodiscard]] AthenaJamSession* session_at(std::size_t index) noexcept;

private:
    struct SocketPeer;

    AthenaConfig                             config_;
    std::uintptr_t                           listen_socket_{~static_cast<std::uintptr_t>(0)};
    std::uint16_t                            bound_port_{0};
    std::vector<std::unique_ptr<SocketPeer>> peers_;
};

} // namespace olympus::athena
