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

int main() {
    test_gcm_header_and_hmac();
    test_jam_bit_packed_bools_and_0x5078_parity();
    test_all_52_pools_and_371_messages_round_trip();
    test_subchannel0_reliable_retransmission_and_combat_jams();
    std::printf("[PASS] All olympus::codec::v24919 verification suites (52 pools, 371 messages, GCM HMAC, Sub-Channel 0) succeeded.\n");
    return 0;
}
