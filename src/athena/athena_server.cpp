#include "olympus/athena/athena_server.hpp"

#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace olympus::athena {

namespace {

constexpr std::uint32_t kBaseProtocolHash             = 0x11D82194u;
constexpr std::uint32_t kOpcodeBaseHello_0x0002       = 0x0002u;
constexpr std::uint32_t kOpcodeBaseReady_0x0003       = 0x0003u;
constexpr std::uint32_t kOpcodeBaseDisconnect_0x0004  = 0x0004u;
constexpr std::uint32_t kOpcodeLobbyConnectOut_0x5528 = 0x5528u;
constexpr std::uint32_t kOpcodeLobbyConnectIn_0x5014  = 0x5014u;
constexpr std::uint32_t kOpcodeLobbyConnectIn_0x5015  = 0x5015u;
constexpr std::uint32_t kOpcodeLobbyConnectIn_0x5016  = 0x5016u;
constexpr std::uint32_t kOpcodeLobbyInstanceIn_0x5078 = 0x5078u;

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;

void ensure_winsock_initialized() {
    static const bool initialized = []() {
        WSADATA wsa{};
        return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}

void close_native_socket(NativeSocket s) noexcept {
    if (s != kInvalidSocket) {
        closesocket(s);
    }
}

bool set_socket_nonblocking_and_nodelay(NativeSocket s) noexcept {
    u_long non_blocking = 1;
    if (ioctlsocket(s, FIONBIO, &non_blocking) != 0) {
        return false;
    }
    BOOL no_delay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&no_delay), sizeof(no_delay));
    return true;
}

bool is_would_block() noexcept {
    const int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
}
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

void ensure_winsock_initialized() {}

void close_native_socket(NativeSocket s) noexcept {
    if (s != kInvalidSocket) {
        close(s);
    }
}

bool set_socket_nonblocking_and_nodelay(NativeSocket s) noexcept {
    const int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
        return false;
    }
    int no_delay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay));
    return true;
}

bool is_would_block() noexcept {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS;
}
#endif

} // namespace

// ------------------------------------------------------------------------------
// 1. Lobby Pool List & Base_0x0002 Builder (+0xC66560 & +0xF265B0)
// ------------------------------------------------------------------------------
std::vector<codec::v24919::JAMPoolSpec> get_lobby_jam_pools() {
    std::vector<codec::v24919::JAMPoolSpec> result;
    result.reserve(32u);
    for (const auto& pool : codec::v24919::all_jam_pools()) {
        const std::string_view name(pool.name);
        if (name.starts_with("ClientInLobby") || name.starts_with("ClientOutLobby")) {
            result.push_back(pool);
        }
    }
    return result;
}

codec::v24919::JAMObject build_base_0x0002_hello(
    const JAMConnectionId& conn_id,
    std::span<const codec::v24919::JAMPoolSpec> advertised_pools) {

    codec::v24919::JAMObject msg{};

    // +0x68: kFields_0x172C910 (16-byte connection ID: word0 at +0x00, word1 at +0x08)
    codec::v24919::JAMObject id_obj{};
    id_obj.set_int(0x00, static_cast<std::int64_t>(conn_id.word0));
    id_obj.set_int(0x08, static_cast<std::int64_t>(conn_id.word1));
    msg.set_struct(0x68, std::move(id_obj));

    // +0x78: teList<kFields_0x172C9B0> (+0xF265B0..+0xF2667D & +0xF2A960..+0xF2AC41)
    std::vector<codec::v24919::JAMScalarValue> pool_entries;
    pool_entries.reserve(advertised_pools.size());
    for (const auto& pool : advertised_pools) {
        if (pool.protocol_hash == kBaseProtocolHash) {
            continue; // Base is always implicitly pool_index 0 (+0xF2A470)
        }
        codec::v24919::JAMObject entry{};
        entry.set_int(0x00, static_cast<std::int32_t>(pool.protocol_hash));
        entry.set_int(0x04, static_cast<std::int32_t>(pool.start_opcode));
        entry.set_int(0x08, static_cast<std::int32_t>(pool.end_opcode));
        entry.set_int(0x0C, 0x04); // Flag 0x04 = has pool name string (+0xF2A980)
        entry.set_uint(0x10, 0u);  // reserved_10 == 0 (+0xF2972A)
        entry.set_string(0x18, std::string(pool.name));
        pool_entries.emplace_back(std::move(entry));
    }
    msg.set_array(0x78, std::move(pool_entries));
    return msg;
}

// ------------------------------------------------------------------------------
// 2. AthenaJamSession Implementation
// ------------------------------------------------------------------------------
AthenaJamSession::AthenaJamSession(AthenaConfig config, AthenaSessionRole role)
    : config_(std::move(config)),
      role_(role),
      state_(AthenaSessionState::AwaitingPeerHello_0x0002),
      local_conn_id_(JAMConnectionId::make_lobby(config_.jam_lobby_port, 1u)),
      negotiated_pools_(get_lobby_jam_pools()) {

    rebuild_negotiated_pool_maps();

    // In ActiveConnector mode (Athena connects to Client's JAMListener on port 13000, +0xF281A0),
    // Athena immediately sends Base_0x0002 upon connection start!
    if (role_ == AthenaSessionRole::ActiveConnector) {
        const auto hello = build_base_0x0002_hello(local_conn_id_, negotiated_pools_);
        (void)queue_jam_message(kOpcodeBaseHello_0x0002, hello);
    }
}

void AthenaJamSession::rebuild_negotiated_pool_maps() {
    hash_to_pool_index_.clear();
    hash_to_pool_index_.emplace(kBaseProtocolHash, static_cast<std::uint8_t>(0u));
    for (std::size_t i = 0; i < negotiated_pools_.size() && i < 254u; ++i) {
        hash_to_pool_index_.emplace(
            negotiated_pools_[i].protocol_hash,
            static_cast<std::uint8_t>(i + 1u));
    }
}

bool AthenaJamSession::feed_incoming_bytes(std::span<const std::uint8_t> tcp_bytes) {
    if (state_ == AthenaSessionState::Disconnected) {
        return false;
    }
    rx_assembler_.feed_bytes(tcp_bytes);

    codec::v24919::JAMTcpFrame frame{};
    while (rx_assembler_.pop_frame(frame, 0u)) {
        if (!handle_decoded_frame(frame)) {
            state_ = AthenaSessionState::Disconnected;
            return false;
        }
    }
    return true;
}

bool AthenaJamSession::pop_outbound_wire_packet(std::vector<std::uint8_t>& out_packet) {
    if (outbound_wire_packets_.empty()) {
        return false;
    }
    out_packet = std::move(outbound_wire_packets_.front());
    outbound_wire_packets_.pop_front();
    return true;
}

bool AthenaJamSession::queue_jam_message(
    std::uint32_t opcode,
    const codec::v24919::JAMObject& fields) {

    const codec::v24919::JAMMessageDesc* desc = codec::v24919::find_jam_message_by_opcode(opcode);
    if (!desc) {
        return false;
    }
    const codec::v24919::JAMPoolSpec* pool = codec::v24919::find_jam_pool_by_hash(desc->protocol_hash);
    if (!pool) {
        return false;
    }

    auto it = hash_to_pool_index_.find(desc->protocol_hash);
    if (it == hash_to_pool_index_.end()) {
        return false;
    }

    codec::v24919::JAMCompactWriter payload_writer;
    if (!codec::v24919::serialize_jam_schema(payload_writer, desc->fields, fields)) {
        return false;
    }

    codec::v24919::JAMTcpFrame frame{};
    frame.pool_index      = it->second;
    frame.relative_opcode = static_cast<std::uint8_t>(opcode - pool->start_opcode);
    frame.compact_payload = payload_writer.take_bytes();

    outbound_wire_packets_.push_back(codec::v24919::encode_jam_tcp_wire_packet(frame, 0u));
    return true;
}

bool AthenaJamSession::queue_instance_handoff(
    std::uint64_t instance_id,
    std::uint32_t session_token_28bit,
    std::span<const std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> hmac_key) {

    codec::v24919::JAM_ClientInLobbyInstance_0x5078 msg{};
    msg.m_instanceId         = instance_id;
    msg.m_address            = config_.chiron_public_ip;
    msg.m_udpPort            = config_.chiron_udp_port;
    msg.m_connectionToken    = session_token_28bit & 0x0FFFFFFFu;
    std::memcpy(msg.m_secretKey, hmac_key.data(), codec::v24919::HMAC_SHA1_KEY_SIZE);
    msg.m_gameServerAddressA = instance_id;
    msg.m_gameServerAddressB = 1ull;

    if (!queue_jam_message(kOpcodeLobbyInstanceIn_0x5078, msg.to_jam_object())) {
        return false;
    }
    state_ = AthenaSessionState::InstanceHandedOff;
    return true;
}

bool AthenaJamSession::queue_disconnect() {
    const bool ok = queue_jam_message(kOpcodeBaseDisconnect_0x0004, {});
    state_ = AthenaSessionState::Disconnected;
    return ok;
}

bool AthenaJamSession::handle_decoded_frame(const codec::v24919::JAMTcpFrame& frame) {
    const codec::v24919::JAMPoolSpec* pool = nullptr;
    if (frame.pool_index == 0u) {
        pool = codec::v24919::find_jam_pool_by_hash(kBaseProtocolHash);
    } else {
        const std::size_t idx = static_cast<std::size_t>(frame.pool_index - 1u);
        if (idx < negotiated_pools_.size()) {
            pool = codec::v24919::find_jam_pool_by_hash(negotiated_pools_[idx].protocol_hash);
        }
    }
    if (!pool) {
        return false;
    }

    const std::uint32_t opcode = pool->start_opcode + frame.relative_opcode;
    const codec::v24919::JAMMessageDesc* desc = codec::v24919::find_jam_message(pool->protocol_hash, opcode);
    if (!desc) {
        return false;
    }

    codec::v24919::JAMCompactReader reader(frame.compact_payload);
    codec::v24919::JAMObject decoded_fields{};
    if (!codec::v24919::deserialize_jam_schema(reader, desc->fields, decoded_fields)) {
        return false;
    }

    received_messages_.push_back(AthenaReceivedMessage{
        pool->protocol_hash,
        opcode,
        pool->name,
        desc->msg_name,
        decoded_fields
    });

    if (pool->protocol_hash == kBaseProtocolHash) {
        if (opcode == kOpcodeBaseHello_0x0002) {
            return handle_base_0x0002(decoded_fields);
        }
        if (opcode == kOpcodeBaseReady_0x0003) {
            return handle_base_0x0003();
        }
        if (opcode == kOpcodeBaseDisconnect_0x0004) {
            state_ = AthenaSessionState::Disconnected;
            return true;
        }
        return true;
    }

    if (opcode == kOpcodeLobbyConnectOut_0x5528) {
        return handle_lobby_connect_0x5528(decoded_fields);
    }

    return true;
}

bool AthenaJamSession::handle_base_0x0002(const codec::v24919::JAMObject& msg) {
    if (state_ != AthenaSessionState::AwaitingPeerHello_0x0002) {
        return false;
    }

    // 1. Extract peer's 16-byte connection ID (+0x68: kFields_0x172C910)
    if (const auto* id_struct = msg.get_struct(0x68)) {
        peer_conn_id_.word0 = id_struct->get_uint(0x00);
        peer_conn_id_.word1 = id_struct->get_uint(0x08);
    }

    // 2. Parse and verify peer's advertised JAMProtocolPool list (+0x78: teList<kFields_0x172C9B0>)
    std::vector<codec::v24919::JAMPoolSpec> peer_pools;
    if (const auto* arr = msg.get_array(0x78)) {
        peer_pools.reserve(arr->size());
        for (const auto& elem : *arr) {
            const auto* entry = std::get_if<codec::v24919::JAMObject>(&elem);
            if (!entry) return false;

            const auto hash     = static_cast<std::uint32_t>(entry->get_uint(0x00));
            const auto start_op = static_cast<std::uint32_t>(entry->get_uint(0x04));
            const auto end_op   = static_cast<std::uint32_t>(entry->get_uint(0x08));
            const auto reserved = static_cast<std::uint32_t>(entry->get_uint(0x10));
            if (reserved != 0u) {
                return false; // Checked at +0xF2972A
            }

            const auto* known_pool = codec::v24919::find_jam_pool_by_hash(hash);
            if (!known_pool || known_pool->start_opcode != start_op || known_pool->end_opcode != end_op) {
                return false; // Checked at +0xF2A960..+0xF2AB00
            }
            peer_pools.push_back(*known_pool);
        }
    }

    if (role_ == AthenaSessionRole::PassiveListener) {
        // In PassiveListener mode (Client connected to Athena and sent Base_0x0002 first):
        // Adopt the Client's exact pool list order (if non-empty) so both sides share identical pool_index 1..N,
        // reply with Athena's Base_0x0002 (resource_type = 0x000D), and wait for Client's Base_0x0003!
        if (!peer_pools.empty()) {
            negotiated_pools_ = std::move(peer_pools);
            rebuild_negotiated_pool_maps();
        }
        const auto reply_hello = build_base_0x0002_hello(local_conn_id_, negotiated_pools_);
        if (!queue_jam_message(kOpcodeBaseHello_0x0002, reply_hello)) {
            return false;
        }
        state_ = AthenaSessionState::AwaitingPeerReady_0x0003;
        return true;
    }

    // In ActiveConnector mode (Athena connected to Client's JAMListener on port 13000 and sent Base_0x0002 first):
    // Client is at state_18 == 4 (+0xF2AEB6) waiting for Athena's Base_0x0003 (+0xF2AF90).
    if (!queue_jam_message(kOpcodeBaseReady_0x0003, {})) {
        return false;
    }
    state_ = AthenaSessionState::AwaitingLobbyConnect_0x5528;
    return true;
}

bool AthenaJamSession::handle_base_0x0003() {
    if (state_ != AthenaSessionState::AwaitingPeerReady_0x0003) {
        return false;
    }
    state_ = AthenaSessionState::AwaitingLobbyConnect_0x5528;
    return true;
}

bool AthenaJamSession::handle_lobby_connect_0x5528(const codec::v24919::JAMObject& msg) {
    // Verified ClientOutLobbyConnect_0x5528 (+0xC669A0 -> +0xFEF2D0, kFields_0x1739EC0):
    // - +0x68 (teString): Player BattleTag
    // - +0x78 (kFields_0x17C7000): { uint64_t bgs_account_id, uint64_t bgs_game_account_id }
    // - +0x88 (uint32_t): Client build version (24919)
    // - +0x90 (kFields_0x17305E0): Platform/session struct
    const auto build_ver = static_cast<std::uint32_t>(msg.get_uint(0x88));
    if (config_.required_client_build != 0u && build_ver != config_.required_client_build) {
        return false;
    }

    AthenaLobbyIdentity id{};
    const std::string_view tag_view = msg.get_string(0x68);
    id.battle_tag    = tag_view.empty() ? std::string("Hero#1337") : std::string(tag_view);
    id.build_version = build_ver;
    if (const auto* acct = msg.get_struct(0x78)) {
        id.bgs_account_id      = acct->get_uint(0x00, 1ull);
        id.bgs_game_account_id = acct->get_uint(0x08, 1ull);
    } else {
        id.bgs_account_id      = 1ull;
        id.bgs_game_account_id = 1ull;
    }
    client_identity_ = id;
    state_           = AthenaSessionState::LobbyConnected;

    // 1. Send ClientInLobbyConnect_0x5014 (+0xC695EF -> +0xC7D0E0):
    //    +0x68 (kFields_0x17C7000: { bgs_account_id, bgs_game_account_id }), +0x78 (teString BattleTag)
    codec::v24919::JAMObject msg_5014{};
    codec::v24919::JAMObject acct_obj{};
    acct_obj.set_int(0x00, static_cast<std::int64_t>(id.bgs_account_id));
    acct_obj.set_int(0x08, static_cast<std::int64_t>(id.bgs_game_account_id));
    msg_5014.set_struct(0x68, std::move(acct_obj));
    msg_5014.set_string(0x78, id.battle_tag);
    if (!queue_jam_message(kOpcodeLobbyConnectIn_0x5014, msg_5014)) {
        return false;
    }

    // 2. Send ClientInLobbyConnect_0x5015 (+0xC69606):
    //    Empty payload -> sets [Lobby + 0x23C] = 1 and notifies [bnet + 0x1B8] via +0xC87220
    if (!queue_jam_message(kOpcodeLobbyConnectIn_0x5015, {})) {
        return false;
    }

    // 3. Send ClientInLobbyConnect_0x5016 (+0xC69640):
    //    +0x68 (bool = true) -> updates [0x1417B7FE0]
    codec::v24919::JAMObject msg_5016{};
    msg_5016.set_bool(0x68, true);
    if (!queue_jam_message(kOpcodeLobbyConnectIn_0x5016, msg_5016)) {
        return false;
    }

    // 4. Automatically transition the client onto Chiron's UDP Simulation Plane via 0x5078 if enabled!
    if (config_.auto_handoff_to_chiron) {
        return queue_instance_handoff(
            config_.default_instance_id,
            config_.default_session_token_28bit,
            config_.default_hmac_key);
    }

    return true;
}

// ------------------------------------------------------------------------------
// 3. AthenaServer Implementation (TCP Listener & Active Client Connector)
// ------------------------------------------------------------------------------
struct AthenaServer::SocketPeer {
    NativeSocket                sock{kInvalidSocket};
    AthenaJamSession            session;
    std::vector<std::uint8_t>   current_tx_buf{};
    std::size_t                 current_tx_offset{0};

    SocketPeer(NativeSocket s, const AthenaConfig& cfg, AthenaSessionRole role)
        : sock(s), session(cfg, role) {}

    ~SocketPeer() {
        close_native_socket(sock);
    }
};

AthenaServer::AthenaServer(AthenaConfig config) noexcept
    : config_(std::move(config)) {}

AthenaServer::~AthenaServer() {
    stop();
}

codec::v24919::JAM_ClientInLobbyInstance_0x5078 AthenaServer::build_instance_handoff(
    std::uint64_t instance_id,
    std::uint32_t session_token_28bit,
    std::span<const std::uint8_t, codec::v24919::HMAC_SHA1_KEY_SIZE> hmac_key) const {

    codec::v24919::JAM_ClientInLobbyInstance_0x5078 msg{};
    msg.m_instanceId         = instance_id;
    msg.m_address            = config_.chiron_public_ip;
    msg.m_udpPort            = config_.chiron_udp_port;
    msg.m_connectionToken    = session_token_28bit & 0x0FFFFFFFu;
    std::memcpy(msg.m_secretKey, hmac_key.data(), codec::v24919::HMAC_SHA1_KEY_SIZE);
    msg.m_gameServerAddressA = instance_id;
    msg.m_gameServerAddressB = 1ull;
    return msg;
}

bool AthenaServer::start_listening(std::uint16_t port_override) {
    ensure_winsock_initialized();
    stop();

    const std::uint16_t listen_port = (port_override == 0xFFFFu) ? config_.jam_lobby_port : port_override;
    NativeSocket s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) {
        return false;
    }

    int reuse = 1;
#if defined(_WIN32)
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif

    if (!set_socket_nonblocking_and_nodelay(s)) {
        close_native_socket(s);
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(listen_port);
    if (config_.bind_address.empty() || config_.bind_address == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    if (::bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(s, SOMAXCONN) != 0) {
        close_native_socket(s);
        return false;
    }

    sockaddr_in bound{};
#if defined(_WIN32)
    int bound_len = sizeof(bound);
#else
    socklen_t bound_len = sizeof(bound);
#endif
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
        bound_port_ = ntohs(bound.sin_port);
    } else {
        bound_port_ = listen_port;
    }

    listen_socket_ = static_cast<std::uintptr_t>(s);
    return true;
}

void AthenaServer::stop() {
    peers_.clear();
    const auto s = static_cast<NativeSocket>(listen_socket_);
    if (s != kInvalidSocket) {
        close_native_socket(s);
        listen_socket_ = static_cast<std::uintptr_t>(kInvalidSocket);
    }
    bound_port_ = 0;
}

AthenaJamSession* AthenaServer::connect_to_client_jam_listener(
    const std::string& host,
    std::uint16_t port) {

    ensure_winsock_initialized();
    const std::string& target_host = host.empty() ? config_.client_jam_listener_host : host;
    const std::uint16_t target_port = (port == 0u) ? config_.client_jam_listener_port : port;

    NativeSocket s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) {
        return nullptr;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(target_port);
    if (::inet_pton(AF_INET, target_host.c_str(), &addr.sin_addr) != 1) {
        close_native_socket(s);
        return nullptr;
    }

    // Connect synchronously on loopback/LAN, then switch to non-blocking + TCP_NODELAY
    if (::connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_native_socket(s);
        return nullptr;
    }
    if (!set_socket_nonblocking_and_nodelay(s)) {
        close_native_socket(s);
        return nullptr;
    }

    peers_.push_back(std::make_unique<SocketPeer>(s, config_, AthenaSessionRole::ActiveConnector));
    return &peers_.back()->session;
}

void AthenaServer::poll_once() {
    // 1. Accept any pending incoming TCP connections on listen_socket_
    const auto ls = static_cast<NativeSocket>(listen_socket_);
    if (ls != kInvalidSocket) {
        while (true) {
            sockaddr_in client_addr{};
#if defined(_WIN32)
            int addr_len = sizeof(client_addr);
#else
            socklen_t addr_len = sizeof(client_addr);
#endif
            NativeSocket cs = ::accept(ls, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (cs == kInvalidSocket) {
                break;
            }
            if (!set_socket_nonblocking_and_nodelay(cs)) {
                close_native_socket(cs);
                continue;
            }
            peers_.push_back(std::make_unique<SocketPeer>(cs, config_, AthenaSessionRole::PassiveListener));
        }
    }

    // 2. Service RX and TX for all active sessions
    std::array<std::uint8_t, 4096> rx_buf{};
    for (auto& peer : peers_) {
        if (peer->sock == kInvalidSocket) continue;

        // 2a. Read incoming bytes
        while (true) {
#if defined(_WIN32)
            const int n = ::recv(peer->sock, reinterpret_cast<char*>(rx_buf.data()), static_cast<int>(rx_buf.size()), 0);
#else
            const ssize_t n = ::recv(peer->sock, rx_buf.data(), rx_buf.size(), 0);
#endif
            if (n > 0) {
                if (!peer->session.feed_incoming_bytes(
                        std::span<const std::uint8_t>(rx_buf.data(), static_cast<std::size_t>(n)))) {
                    close_native_socket(peer->sock);
                    peer->sock = kInvalidSocket;
                    break;
                }
            } else if (n == 0) {
                close_native_socket(peer->sock);
                peer->sock = kInvalidSocket;
                break;
            } else {
                if (!is_would_block()) {
                    close_native_socket(peer->sock);
                    peer->sock = kInvalidSocket;
                }
                break;
            }
        }

        if (peer->sock == kInvalidSocket) continue;

        // 2b. Flush outbound wire packets
        while (true) {
            if (peer->current_tx_offset >= peer->current_tx_buf.size()) {
                peer->current_tx_buf.clear();
                peer->current_tx_offset = 0;
                if (!peer->session.pop_outbound_wire_packet(peer->current_tx_buf)) {
                    break;
                }
            }

            const std::uint8_t* ptr = peer->current_tx_buf.data() + peer->current_tx_offset;
            const std::size_t rem   = peer->current_tx_buf.size() - peer->current_tx_offset;
#if defined(_WIN32)
            const int sent = ::send(peer->sock, reinterpret_cast<const char*>(ptr), static_cast<int>(rem), 0);
#else
            const ssize_t sent = ::send(peer->sock, ptr, rem, 0);
#endif
            if (sent > 0) {
                peer->current_tx_offset += static_cast<std::size_t>(sent);
            } else {
                if (!is_would_block()) {
                    close_native_socket(peer->sock);
                    peer->sock = kInvalidSocket;
                }
                break;
            }
        }
    }
}

std::size_t AthenaServer::active_session_count() const noexcept {
    return peers_.size();
}

AthenaJamSession* AthenaServer::session_at(std::size_t index) noexcept {
    if (index >= peers_.size()) {
        return nullptr;
    }
    return &peers_[index]->session;
}

} // namespace olympus::athena
