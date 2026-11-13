#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

#include "olympus/athena/athena_server.hpp"
#include "olympus/chiron/chiron_server.hpp"
#include "olympus/codec/v24919/bitstream.hpp"
#include "olympus/codec/v24919/gcm_udp_header.hpp"
#include "olympus/codec/v24919/hmac_sha1_96.hpp"
#include "olympus/codec/v24919/jam_compact_codec.hpp"
#include "olympus/codec/v24919/jam_schema_db.hpp"
#include "olympus/codec/v24919/jam_transport_framing.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace olympus;
using namespace olympus::codec::v24919;

static void verify(bool cond, const char* msg) {
    if (!cond) {
        std::fprintf(stderr, "[FAIL] %s\n", msg);
        std::abort();
    }
}

static void test_gcm_header_and_hmac() {
    static_assert(sizeof(NativeGCMUdpHeader) == 0x22, "Header must be 34 bytes");

    std::array<std::uint8_t, HMAC_SHA1_KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(0xA0u + i);
    }

    std::vector<std::uint8_t> pkt(GCM_HEADER_SIZE + 16u, 0u);
    auto* hdr = reinterpret_cast<NativeGCMUdpHeader*>(pkt.data());
    hdr->set_session_and_type(0x0ABCDEFull, GCMPacketType::SequencedSimulation);
    hdr->seq_num = 42u;
    hdr->ack_num = 41u;
    hdr->window_state = 0xFFFFFFFFFFFFFFFFull;
    hdr->control_flags = GCMControlFlags::ACK;

    verify(hdr->session_token() == 0x0ABCDEFull, "Session token unpack");
    verify(hdr->packet_type() == GCMPacketType::SequencedSimulation, "Packet type unpack");

    verify(sign_gcm_udp_packet(pkt, key), "GCM packet signing");
    verify(verify_gcm_udp_packet(pkt, key), "GCM packet verification");

    // Tamper with 1 bit of payload -> verification must fail
    pkt.back() ^= 0x01u;
    verify(!verify_gcm_udp_packet(pkt, key), "Tampered GCM packet must fail HMAC");
}

static void test_jam_bit_packed_bools_and_0x5078_parity() {
    JAMCompactWriter writer;
    const bool flags[8] = {true, false, true, true, false, false, true, false};
    for (bool b : flags) {
        writer.write_bool(b);
    }
    verify(writer.bytes().size() == 1u, "8 consecutive bools must pack into 1 byte");

    writer.write_u32(0x12345678u);
    verify(writer.bytes().size() == 5u, "Non-bool must reset bit_pos and align to next byte");

    JAMCompactReader reader(writer.bytes());
    for (bool expected : flags) {
        bool actual = false;
        verify(reader.read_bool(actual) && actual == expected, "Bit-packed bool round-trip");
    }
    std::uint32_t u32_val = 0;
    verify(reader.read_u32(u32_val) && u32_val == 0x12345678u, "Aligned u32 round-trip");

    // Verify byte-for-byte parity between typed JAM_ClientInLobbyInstance_0x5078 and
    // generic table-driven .data schema (kFields_0x1737FE0 + nested kFields_0x17C7000)
    athena::AthenaServer athena{};
    std::array<std::uint8_t, HMAC_SHA1_KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i + 1u);
    }
    auto handoff_out = athena.build_instance_handoff(0xCAFEBABE12345678ull, 0x07654321u, key);

    JAMCompactWriter typed_writer;
    handoff_out.serialize_compact(typed_writer);

    const JAMMessageDesc* desc_5078 = find_jam_message_by_opcode(0x5078u);
    verify(desc_5078 != nullptr, "0x5078 schema must exist in generated DB");
    verify(desc_5078->protocol_hash == 0x6E5D38B1u, "0x5078 protocol hash must match");

    JAMCompactWriter schema_writer;
    JAMObject obj_5078 = handoff_out.to_jam_object();
    verify(serialize_jam_schema(schema_writer, desc_5078->fields, obj_5078), "0x5078 schema serialize");

    verify(typed_writer.bytes().size() == schema_writer.bytes().size() &&
           std::memcmp(typed_writer.bytes().data(), schema_writer.bytes().data(), typed_writer.bytes().size()) == 0,
           "Typed 0x5078 and table-driven .data schema 0x5078 must produce identical wire bytes");

    JAMCompactReader schema_reader(schema_writer.bytes());
    JAMObject decoded_5078{};
    verify(deserialize_jam_schema(schema_reader, desc_5078->fields, decoded_5078), "0x5078 schema deserialize");
    verify(decoded_5078.get_uint(0x68) == 0xCAFEBABE12345678ull, "0x5078 +0x68 m_instanceId");
    verify(decoded_5078.get_string(0x70) == "127.0.0.1", "0x5078 +0x70 m_address");
    verify(decoded_5078.get_uint(0x80) == 26503u, "0x5078 +0x80 m_udpPort");
    verify(decoded_5078.get_uint(0x84) == 0x07654321u, "0x5078 +0x84 m_connectionToken");
    const JAMObject* sub_addr = decoded_5078.get_struct(0xA0);
    verify(sub_addr != nullptr && sub_addr->get_uint(0x00) == 0xCAFEBABE12345678ull, "0x5078 +0xA0 nested sub-schema");
}

static void test_all_52_pools_and_371_messages_round_trip() {
    auto pools = all_jam_pools();
    auto msgs  = all_jam_messages();
    verify(pools.size() == 52u, "Must have all 52 JAMProtocolPool specs");
    verify(msgs.size() == 371u, "Must have all 371 JAMMessageDesc schemas");

    // Verify all 8 Simulation Plane pools (0..7)
    for (std::uint8_t sim_idx = 0; sim_idx < 8u; ++sim_idx) {
        const JAMPoolSpec* sim_pool = find_sim_jam_pool(sim_idx);
        verify(sim_pool != nullptr, "Simulation JAM pool 0..7 must exist");
    }

    // Round-trip every single one of the 371 JAM messages through the table-driven codec!
    for (const auto& desc : msgs) {
        verify(desc.fields != nullptr, "Message fields pointer must not be null");
        JAMCompactWriter writer;
        JAMObject default_obj{};
        verify(serialize_jam_schema(writer, desc.fields, default_obj), "Default serialize of JAM message");

        JAMCompactReader reader(writer.bytes());
        JAMObject round_trip_obj{};
        verify(deserialize_jam_schema(reader, desc.fields, round_trip_obj), "Default deserialize of JAM message");
        verify(reader.remaining() == 0u, "Deserializer must consume exact byte length written by serializer");
    }
}

static void test_subchannel0_reliable_retransmission_and_combat_jams() {
    JAMSubChannel0Tracker sender;
    JAMSubChannel0Tracker receiver;

    // 1. Queue reliable ClientInCombat 0x61A9 (OnNetworkDamageDealt +0xCA7860:
    //    +0x68 target_entid [kFields_0x17C6FB0], +0x6C damage_int, +0x70 ticks, +0x74 flags)
    JAMObject dmg_msg{};
    dmg_msg.set_uint(0x68, 0x0000072Du); // target_entid (auto-wrapped into kFields_0x17C6FB0)
    dmg_msg.set_uint(0x6C, 120u);        // damage_int
    dmg_msg.set_uint(0x70, 62500u);      // duration_ticks
    dmg_msg.set_uint(0x74, 0x01u);       // Crit flag

    // 2. Queue reliable ClientInCombat 0x61AB (OnEliminationBanner +0xCA7EE0:
    //    +0x68 u64=0, +0x70 assister_entid, +0x74 victim_entid, +0x78 score=100)
    JAMObject elim_msg{};
    elim_msg.set_uint(0x68, 0ull);
    elim_msg.set_uint(0x70, 0xFFFFFFFFu);
    elim_msg.set_uint(0x74, 0x0000072Du);
    elim_msg.set_uint(0x78, 100u);

    verify(sender.queue_outbound_message(0x61A9u, dmg_msg, true), "Queue reliable 0x61A9");
    verify(sender.queue_outbound_message(0x61ABu, elim_msg, true), "Queue reliable 0x61AB");
    verify(sender.pending_reliable_count() == 2u, "2 reliable messages pending");

    // Pack into Datagram #1 -> simulate UDP packet drop!
    BitStreamWriter pkt1;
    std::uint64_t token1 = 0;
    verify(sender.write_outbound_datagram(pkt1, token1), "Write Datagram #1");
    verify(token1 != 0u, "Reliable batch must allocate non-zero delivery token");
    verify(sender.pending_reliable_count() == 0u, "Pending queue drained into in-flight batch");

    // GCM notifies packet 1 was dropped (+0x10503D0) -> messages must return to head of queue!
    sender.on_packet_dropped(token1);
    verify(sender.pending_reliable_count() == 2u, "Dropped reliable batch restored to pending queue");

    // Pack into Datagram #2 -> deliver to receiver and ACK!
    BitStreamWriter pkt2;
    std::uint64_t token2 = 0;
    verify(sender.write_outbound_datagram(pkt2, token2), "Write Datagram #2");
    sender.on_packet_acked(token2);
    verify(sender.in_flight_token_count() == 0u, "Acked token freed");

    BitStreamReader rx_stream(pkt2.bytes());
    std::vector<JAMUdpQueuedMessage> rx_msgs;
    verify(receiver.read_inbound_datagram(rx_stream, rx_msgs), "Read Datagram #2 on receiver");
    verify(rx_msgs.size() == 2u, "Receiver unpacked both retransmitted reliable JAM messages");
    verify(rx_msgs[0].full_opcode() == 0x61A9u, "First message is 0x61A9");
    verify(rx_msgs[1].full_opcode() == 0x61ABu, "Second message is 0x61AB");

    // Verify field values inside received 0x61A9
    const JAMMessageDesc* desc_61a9 = find_jam_message_by_opcode(0x61A9u);
    JAMCompactReader r61a9(rx_msgs[0].compact_payload);
    JAMObject decoded_61a9{};
    verify(deserialize_jam_schema(r61a9, desc_61a9->fields, decoded_61a9), "Decode received 0x61A9");
    verify(decoded_61a9.get_uint(0x68) == 0x0000072Du, "0x61A9 target_entid");
    verify(decoded_61a9.get_uint(0x6C) == 120u, "0x61A9 damage_int");
    verify(decoded_61a9.get_uint(0x70) == 62500u, "0x61A9 duration_ticks");
    verify(decoded_61a9.get_uint(0x74) == 0x01u, "0x61A9 crit flag");
}

static void test_tcp_24bit_framing_and_assembler() {
    JAMTcpFrame f1{};
    f1.pool_index      = 0u;
    f1.relative_opcode = 1u; // Base_0x0002
    f1.compact_payload = {0x11u, 0x22u, 0x33u, 0x44u};

    JAMTcpFrame f2{};
    f2.pool_index      = 3u;
    f2.relative_opcode = 0u; // 0x5078
    f2.compact_payload = {0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu};

    const auto wire1 = encode_jam_tcp_wire_packet(f1, 0u);
    const auto wire2 = encode_jam_tcp_wire_packet(f2, 0u);

    // Verify 3-byte 24-bit Big-Endian length header (+0xE65610)
    verify(wire1.size() == 3u + 2u + f1.compact_payload.size(), "24-bit BE length header + JAMStream");
    verify(wire1[0] == 0x00u && wire1[1] == 0x00u && wire1[2] == 6u, "wire1 24-bit BE length == 6");
    verify(wire2[0] == 0x00u && wire2[1] == 0x00u && wire2[2] == 7u, "wire2 24-bit BE length == 7");

    std::vector<std::uint8_t> combined;
    combined.insert(combined.end(), wire1.begin(), wire1.end());
    combined.insert(combined.end(), wire2.begin(), wire2.end());

    // Feed 1 byte at a time to simulate arbitrary TCP stream segmentation (+0xE65750)
    JAMTcpStreamAssembler assembler;
    std::vector<JAMTcpFrame> out_frames;
    for (std::uint8_t b : combined) {
        assembler.feed_bytes(std::span<const std::uint8_t>(&b, 1u));
        JAMTcpFrame decoded{};
        while (assembler.pop_frame(decoded, 0u)) {
            out_frames.push_back(std::move(decoded));
        }
    }
    verify(out_frames.size() == 2u, "Assembler reconstructed both fragmented TCP JAM frames");
    verify(out_frames[0].pool_index == f1.pool_index &&
           out_frames[0].relative_opcode == f1.relative_opcode &&
           out_frames[0].compact_payload == f1.compact_payload, "Reassembled frame 1 matches");
    verify(out_frames[1].pool_index == f2.pool_index &&
           out_frames[1].relative_opcode == f2.relative_opcode &&
           out_frames[1].compact_payload == f2.compact_payload, "Reassembled frame 2 matches");
}

static std::vector<std::uint8_t> build_client_wire_frame(
    std::uint8_t pool_index,
    std::uint32_t opcode,
    const JAMObject& fields) {

    const JAMMessageDesc* desc = find_jam_message_by_opcode(opcode);
    verify(desc != nullptr, "Client message descriptor must exist");
    const JAMPoolSpec* pool = find_jam_pool_by_hash(desc->protocol_hash);
    verify(pool != nullptr, "Client message pool must exist");

    JAMCompactWriter writer;
    verify(serialize_jam_schema(writer, desc->fields, fields), "Serialize client JAM message");

    JAMTcpFrame frame{};
    frame.pool_index      = pool_index;
    frame.relative_opcode = static_cast<std::uint8_t>(opcode - pool->start_opcode);
    frame.compact_payload = writer.take_bytes();
    return encode_jam_tcp_wire_packet(frame, 0u);
}

static void test_athena_lobby_handshake_both_roles() {
    const auto lobby_pools = athena::get_lobby_jam_pools();
    verify(lobby_pools.size() == 32u, "All 32 ClientInLobby*/ClientOutLobby* pools registered");

    // Find pool_index (1..32) of ClientOutLobbyConnect (0xD7D457DD), ClientInLobbyConnect (0x4E958DAF),
    // and ClientInLobbyInstance (0x6E5D38B1)
    std::uint8_t idx_out_connect = 0;
    std::uint8_t idx_in_connect  = 0;
    std::uint8_t idx_in_instance = 0;
    for (std::size_t i = 0; i < lobby_pools.size(); ++i) {
        if (lobby_pools[i].protocol_hash == 0xD7D457DDu) idx_out_connect = static_cast<std::uint8_t>(i + 1u);
        if (lobby_pools[i].protocol_hash == 0x4E958DAFu) idx_in_connect  = static_cast<std::uint8_t>(i + 1u);
        if (lobby_pools[i].protocol_hash == 0x6E5D38B1u) idx_in_instance = static_cast<std::uint8_t>(i + 1u);
    }
    verify(idx_out_connect != 0u && idx_in_connect != 0u && idx_in_instance != 0u, "Lobby pool indices found");

    // --------------------------------------------------------------------------
    // Mode A: PassiveListener (Client connects to Athena TCP port -> Client sends Base_0x0002 first)
    // --------------------------------------------------------------------------
    {
        athena::AthenaConfig cfg{};
        athena::AthenaJamSession session(cfg, athena::AthenaSessionRole::PassiveListener);
        verify(session.state() == athena::AthenaSessionState::AwaitingPeerHello_0x0002, "Initial state");

        // 1. Client sends Base_0x0002
        const auto client_id = athena::JAMConnectionId::make(
            athena::JAMConnectionId::kResourceClient, 0x01u, 42u, 0x7F000001u, 13000u, 1234u);
        const auto client_hello = athena::build_base_0x0002_hello(client_id, lobby_pools);
        verify(session.feed_incoming_bytes(build_client_wire_frame(0u, 0x0002u, client_hello)),
               "Athena processes Client Base_0x0002");
        verify(session.state() == athena::AthenaSessionState::AwaitingPeerReady_0x0003,
               "Athena transitions to AwaitingPeerReady_0x0003");

        // 2. Verify Athena queued Base_0x0002 with word0 resource_type == 0x000D (+0xC67442)
        std::vector<std::uint8_t> athena_hello_pkt;
        verify(session.pop_outbound_wire_packet(athena_hello_pkt), "Athena queued Base_0x0002 reply");
        JAMTcpStreamAssembler client_rx;
        client_rx.feed_bytes(athena_hello_pkt);
        JAMTcpFrame rx_hello_frame{};
        verify(client_rx.pop_frame(rx_hello_frame, 0u), "Client decodes Athena Base_0x0002 frame");
        verify(rx_hello_frame.pool_index == 0u && rx_hello_frame.relative_opcode == 1u, "Frame is Base_0x0002");

        const JAMMessageDesc* desc_0002 = find_jam_message_by_opcode(0x0002u);
        JAMCompactReader r0002(rx_hello_frame.compact_payload);
        JAMObject decoded_0002{};
        verify(deserialize_jam_schema(r0002, desc_0002->fields, decoded_0002), "Client deserializes Athena Base_0x0002");
        const JAMObject* id_obj = decoded_0002.get_struct(0x68);
        verify(id_obj != nullptr, "Base_0x0002 +0x68 connection ID struct present");
        const std::uint64_t athena_word0 = id_obj->get_uint(0x00);
        verify(((athena_word0 >> 40u) & 0xFFFFu) == 0x000Du,
               "CRITICAL (+0xC67442): Athena word0 resource_type MUST be 0x000D (Lobby)");

        // 3. Client sends Base_0x0003 -> Athena enters AwaitingLobbyConnect_0x5528
        verify(session.feed_incoming_bytes(build_client_wire_frame(0u, 0x0003u, {})),
               "Athena processes Client Base_0x0003");
        verify(session.state() == athena::AthenaSessionState::AwaitingLobbyConnect_0x5528,
               "Athena enters AwaitingLobbyConnect_0x5528");

        // 4. Client sends ClientOutLobbyConnect_0x5528 (+0xC669A0)
        JAMObject msg_5528{};
        msg_5528.set_string(0x68, "Tracer#24919");
        JAMObject bgs_ids{};
        bgs_ids.set_int(0x00, 0x1111222233334444ll);
        bgs_ids.set_int(0x08, 0x5555666677778888ll);
        msg_5528.set_struct(0x78, std::move(bgs_ids));
        msg_5528.set_uint(0x88, 24919u); // Client build version

        verify(session.feed_incoming_bytes(build_client_wire_frame(idx_out_connect, 0x5528u, msg_5528)),
               "Athena processes ClientOutLobbyConnect_0x5528");
        verify(session.state() == athena::AthenaSessionState::InstanceHandedOff,
               "Athena completes Lobby Connect and auto-handoffs to Chiron (InstanceHandedOff)");
        verify(session.client_identity().has_value() &&
               session.client_identity()->battle_tag == "Tracer#24919" &&
               session.client_identity()->bgs_account_id == 0x1111222233334444ull,
               "Athena recorded Client BattleTag and BGS Account IDs");

        // 5. Verify Athena queued 0x5014, 0x5015, 0x5016, and 0x5078!
        verify(session.pending_outbound_packets() == 4u, "Athena queued 0x5014, 0x5015, 0x5016, and 0x5078");
        std::vector<std::uint8_t> pkt;
        while (session.pop_outbound_wire_packet(pkt)) {
            client_rx.feed_bytes(pkt);
        }

        JAMTcpFrame f_5014{}, f_5015{}, f_5016{}, f_5078{};
        verify(client_rx.pop_frame(f_5014, 0u) && f_5014.pool_index == idx_in_connect && f_5014.relative_opcode == 0u,
               "Client receives 0x5014");
        verify(client_rx.pop_frame(f_5015, 0u) && f_5015.pool_index == idx_in_connect && f_5015.relative_opcode == 1u,
               "Client receives 0x5015");
        verify(client_rx.pop_frame(f_5016, 0u) && f_5016.pool_index == idx_in_connect && f_5016.relative_opcode == 2u,
               "Client receives 0x5016");
        verify(client_rx.pop_frame(f_5078, 0u) && f_5078.pool_index == idx_in_instance && f_5078.relative_opcode == 0u,
               "Client receives 0x5078 (ClientInLobbyInstance)");
    }

    // --------------------------------------------------------------------------
    // Mode B: ActiveConnector (Athena connects to Client's JAMListener on port 13000)
    // --------------------------------------------------------------------------
    {
        athena::AthenaConfig cfg{};
        athena::AthenaJamSession session(cfg, athena::AthenaSessionRole::ActiveConnector);
        // ActiveConnector queues Base_0x0002 immediately upon construction!
        verify(session.pending_outbound_packets() == 1u, "ActiveConnector immediately queues Base_0x0002");

        std::vector<std::uint8_t> athena_hello;
        verify(session.pop_outbound_wire_packet(athena_hello), "Pop Athena's initial Base_0x0002");

        // Client replies with Client's Base_0x0002 (+0xF2ADE0 at state == 2)
        const auto client_id = athena::JAMConnectionId::make(
            athena::JAMConnectionId::kResourceClient, 0x01u, 1u, 0x7F000001u, 13000u, 1u);
        const auto client_hello = athena::build_base_0x0002_hello(client_id, lobby_pools);
        verify(session.feed_incoming_bytes(build_client_wire_frame(0u, 0x0002u, client_hello)),
               "ActiveConnector processes Client Base_0x0002");

        // Athena immediately queues Base_0x0003 and enters AwaitingLobbyConnect_0x5528!
        verify(session.state() == athena::AthenaSessionState::AwaitingLobbyConnect_0x5528,
               "ActiveConnector enters AwaitingLobbyConnect_0x5528");
        std::vector<std::uint8_t> athena_ready;
        verify(session.pop_outbound_wire_packet(athena_ready), "Pop Athena's Base_0x0003");
    }
}

static void test_athena_live_loopback_tcp_socket() {
    athena::AthenaConfig cfg{};
    cfg.bind_address = "127.0.0.1";
    athena::AthenaServer server(cfg);

    // Bind on OS-assigned ephemeral loopback port (port 0)
    verify(server.start_listening(0u), "AthenaServer bind & listen on loopback");
    verify(server.bound_port() != 0u, "AthenaServer assigned non-zero ephemeral TCP port");

#if defined(_WIN32)
    SOCKET client_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    verify(client_sock != INVALID_SOCKET, "Create loopback client TCP socket");
#else
    int client_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    verify(client_sock >= 0, "Create loopback client TCP socket");
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(server.bound_port());
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    verify(::connect(client_sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0,
           "Connect loopback client socket to AthenaServer");

    const auto lobby_pools = athena::get_lobby_jam_pools();
    std::uint8_t idx_out_connect = 0;
    for (std::size_t i = 0; i < lobby_pools.size(); ++i) {
        if (lobby_pools[i].protocol_hash == 0xD7D457DDu) {
            idx_out_connect = static_cast<std::uint8_t>(i + 1u);
            break;
        }
    }

    // 1. Send Client Base_0x0002 over TCP socket
    const auto client_id = athena::JAMConnectionId::make(
        athena::JAMConnectionId::kResourceClient, 0x01u, 99u, 0x7F000001u, 13000u, 1u);
    const auto pkt_0002 = build_client_wire_frame(0u, 0x0002u, athena::build_base_0x0002_hello(client_id, lobby_pools));
    ::send(client_sock, reinterpret_cast<const char*>(pkt_0002.data()), static_cast<int>(pkt_0002.size()), 0);

    for (int i = 0; i < 20; ++i) {
        server.poll_once();
    }
    verify(server.active_session_count() == 1u, "AthenaServer accepted 1 TCP session");

    // 2. Send Client Base_0x0003 + ClientOutLobbyConnect_0x5528 over TCP socket
    const auto pkt_0003 = build_client_wire_frame(0u, 0x0003u, {});
    JAMObject msg_5528{};
    msg_5528.set_string(0x68, "Winston#24919");
    msg_5528.set_uint(0x88, 24919u);
    const auto pkt_5528 = build_client_wire_frame(idx_out_connect, 0x5528u, msg_5528);

    ::send(client_sock, reinterpret_cast<const char*>(pkt_0003.data()), static_cast<int>(pkt_0003.size()), 0);
    ::send(client_sock, reinterpret_cast<const char*>(pkt_5528.data()), static_cast<int>(pkt_5528.size()), 0);

    for (int i = 0; i < 20; ++i) {
        server.poll_once();
    }

    auto* sess = server.session_at(0);
    verify(sess != nullptr && sess->state() == athena::AthenaSessionState::InstanceHandedOff,
           "Loopback TCP session reached InstanceHandedOff");

    // 3. Read all 5 wire frames sent by AthenaServer (Base_0x0002, 0x5014, 0x5015, 0x5016, 0x5078)
    JAMTcpStreamAssembler rx_assembler;
    std::vector<JAMTcpFrame> rx_frames;
    std::array<std::uint8_t, 4096> buf{};
    while (rx_frames.size() < 5u) {
        server.poll_once();
        const int n = ::recv(client_sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
        verify(n > 0, "Receive AthenaServer TCP frames on client socket");
        rx_assembler.feed_bytes(std::span<const std::uint8_t>(buf.data(), static_cast<std::size_t>(n)));
        JAMTcpFrame f{};
        while (rx_assembler.pop_frame(f, 0u)) {
            rx_frames.push_back(std::move(f));
        }
    }
    verify(rx_frames.size() == 5u, "Client received all 5 TCP JAM frames from AthenaServer over loopback socket");

#if defined(_WIN32)
    closesocket(client_sock);
#else
    close(client_sock);
#endif
    server.stop();

    // --------------------------------------------------------------------------
    // Part B: Live TCP Socket Test of ActiveConnector (Athena connects to Client's JAMListener)
    // --------------------------------------------------------------------------
#if defined(_WIN32)
    SOCKET listener_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    verify(listener_sock != INVALID_SOCKET, "Create simulated Client JAMListener socket");
#else
    int listener_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    verify(listener_sock >= 0, "Create simulated Client JAMListener socket");
#endif
    sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port   = htons(0u);
    ::inet_pton(AF_INET, "127.0.0.1", &listen_addr.sin_addr);
    verify(::bind(listener_sock, reinterpret_cast<const sockaddr*>(&listen_addr), sizeof(listen_addr)) == 0 &&
           ::listen(listener_sock, 1) == 0,
           "Bind & listen simulated Client JAMListener");

    sockaddr_in bound_client_listener{};
#if defined(_WIN32)
    int blen = sizeof(bound_client_listener);
#else
    socklen_t blen = sizeof(bound_client_listener);
#endif
    verify(::getsockname(listener_sock, reinterpret_cast<sockaddr*>(&bound_client_listener), &blen) == 0,
           "Get simulated Client JAMListener port");
    const std::uint16_t client_listener_port = ntohs(bound_client_listener.sin_port);

    // Athena connects outbound to Client's JAMListener!
    auto* active_sess = server.connect_to_client_jam_listener("127.0.0.1", client_listener_port);
    verify(active_sess != nullptr && active_sess->role() == athena::AthenaSessionRole::ActiveConnector,
           "Athena connected to simulated Client JAMListener");

    sockaddr_in peer_addr{};
#if defined(_WIN32)
    int plen = sizeof(peer_addr);
    SOCKET accepted_athena = ::accept(listener_sock, reinterpret_cast<sockaddr*>(&peer_addr), &plen);
    verify(accepted_athena != INVALID_SOCKET, "Client JAMListener accepted Athena connection");
#else
    socklen_t plen = sizeof(peer_addr);
    int accepted_athena = ::accept(listener_sock, reinterpret_cast<sockaddr*>(&peer_addr), &plen);
    verify(accepted_athena >= 0, "Client JAMListener accepted Athena connection");
#endif

    // Poll Athena to flush Athena's initial Base_0x0002, then reply with Client's Base_0x0002 + 0x5528
    server.poll_once();
    ::send(accepted_athena, reinterpret_cast<const char*>(pkt_0002.data()), static_cast<int>(pkt_0002.size()), 0);
    for (int i = 0; i < 20; ++i) {
        server.poll_once();
    }
    verify(active_sess->state() == athena::AthenaSessionState::AwaitingLobbyConnect_0x5528,
           "ActiveConnector reached AwaitingLobbyConnect_0x5528 over live TCP socket");

    ::send(accepted_athena, reinterpret_cast<const char*>(pkt_5528.data()), static_cast<int>(pkt_5528.size()), 0);
    for (int i = 0; i < 20; ++i) {
        server.poll_once();
    }
    verify(active_sess->state() == athena::AthenaSessionState::InstanceHandedOff,
           "ActiveConnector reached InstanceHandedOff over live TCP socket");

#if defined(_WIN32)
    closesocket(accepted_athena);
    closesocket(listener_sock);
#else
    close(accepted_athena);
    close(listener_sock);
#endif
    server.stop();
}

int main() {
    test_gcm_header_and_hmac();
    test_jam_bit_packed_bools_and_0x5078_parity();
    test_all_52_pools_and_371_messages_round_trip();
    test_subchannel0_reliable_retransmission_and_combat_jams();
    test_tcp_24bit_framing_and_assembler();
    test_athena_lobby_handshake_both_roles();
    test_athena_live_loopback_tcp_socket();
    std::printf("[PASS] All olympus::codec::v24919 & olympus::athena verification suites succeeded.\n");
    return 0;
}
